/*
 * libtcp on Windows: the c/tcp.h contract over Winsock 2.
 *
 * No socket is inheritable, and no call blocks past its timeout.
 *
 * Listening and connecting run non-blocking: a call waits with select() up
 * to its timeout, then tries the operation, and a wake that finds nothing to
 * do (WSAEWOULDBLOCK) waits again until the deadline. select, not WSAPoll:
 * before Windows 10 2004 WSAPoll never reported a failed non-blocking
 * connect, and a refused connect sat out its timeout. select reports it
 * through exceptfds.
 *
 * A connection's blocking reads and writes use overlapped I/O instead: each
 * call starts the operation with its own event, waits on that, and cancels
 * it at the deadline. Readiness does not work here. Two threads waiting on
 * one socket, one to read and one to write, starve each other: with a reader
 * parked in select (or WSAPoll), a writer's wake comes late or not at all,
 * and a 2 MiB write that takes 16 ms alone times out after seconds.
 *
 * A connection stays in non-blocking mode, which overlapped calls ignore, so
 * the try calls are a plain non-overlapped recv or WSASend: one call that
 * answers WSAEWOULDBLOCK when it would wait, and reports exactly what it
 * took. Nothing is started that would have to be cancelled.
 *
 * tcp_cancel shuts the socket down and cancels every overlapped call on it
 * (CancelIoEx with no OVERLAPPED reaches every thread's), so a call blocked
 * on another thread returns at once; one that starts after it fails at once
 * on the shut socket.
 *
 * A wake is a UDP socket on loopback connected to itself: signalling sends
 * it a datagram, so it reads as readable both to select (an accept waiting
 * for it) and to wepoll, which only ever watches sockets.
 *
 * Readiness (tcp_poll_*) is wepoll (c/wepoll/wepoll.c, BSD-2), which polls
 * the AFD driver the way epoll polls a Linux socket.
 *
 * Failures are sorted into TCP_K_* kinds where they happen. Winsock and
 * Win32 codes share one space, and FormatMessage reads both, getaddrinfo's
 * included.
 *
 * Winsock starts once (WSAStartup), on the first call that makes a socket or
 * resolves a name: every other call takes a handle one of those made. It is
 * never cleaned up; the process ending does that.
 */

#define WIN32_LEAN_AND_MEAN

#ifndef _WIN32_WINNT
/* Windows 7 SP1: WSA_FLAG_NO_HANDLE_INHERIT */
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

/* the reparse tag of a unix socket's file (winnt.h in newer SDKs) */
#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX 0x80000023L
#endif

/*
 * FILE_ID_INFO and its class (Windows 8 and later), declared here for the same reason: a ReFS
 * file id is 128 bits, and the 64-bit index GetFileInformationByHandle gives is not unique there.
 */
typedef struct tcp_file_id_info {
    ULONGLONG volume;
    BYTE id[16];
} tcp_file_id_info;

#define TCP_FILE_ID_INFO ((FILE_INFO_BY_HANDLE_CLASS)18)

/*
 * afunix.h's SOCKADDR_UN (Windows 10 1803 and later), declared here so the build needs no newer
 * SDK. On an older Windows a unix socket fails to open, and the failure says so.
 */
struct sockaddr_un {
    ADDRESS_FAMILY sun_family;
    char sun_path[108];
};

#include "common.h"

/*
 * A listener: its socket and the wake tcp_listener_cancel signals. An accept waits in select,
 * and neither a shutdown nor a CancelIoEx ends a select on a listening socket.
 */
typedef struct listener {
    SOCKET s;
    int64_t wake;
} listener;

/* the most one send hands Winsock: see tcp_sendv */
#define SEND_CHUNK (64 * 1024)

/*
 * The wepoll API (c/wepoll/wepoll.c), declared here with this file's
 * HANDLE and SOCKET so windows.h and wepoll.h never have to meet. The
 * layout matches wepoll.h exactly.
 */
typedef union wep_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
    SOCKET sock;
    HANDLE hnd;
} wep_data;

struct wep_event {
    uint32_t events;
    wep_data data;
};

#define WEP_IN (1U << 0)
#define WEP_OUT (1U << 2)
#define WEP_ERR (1U << 3)
#define WEP_HUP (1U << 4)
#define WEP_RDHUP (1U << 13)
#define WEP_ONESHOT (1U << 31)
#define WEP_CTL_ADD 1
#define WEP_CTL_MOD 2
#define WEP_CTL_DEL 3

HANDLE epoll_create1(int flags);
int epoll_close(HANDLE ephnd);
int epoll_ctl(HANDLE ephnd, int op, SOCKET sock, struct wep_event *event);
int epoll_wait(HANDLE ephnd, struct wep_event *events, int maxevents, int timeout);

static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static int g_startup;

/* each thread's overlapped event, closed by the fiber-local destructor when the thread ends */
static DWORD g_event_slot = FLS_OUT_OF_INDEXES;

static int32_t kind_of(int code)
{
    switch (code) {
    case WSAECONNREFUSED:
        return TCP_K_REFUSED;
    case WSAECONNRESET:
    case WSAECONNABORTED:
    case WSAENETRESET:
    case WSAENOTCONN:
    case WSAEDISCON:
        return TCP_K_RESET;
    case WSAEHOSTUNREACH:
    case WSAENETUNREACH:
    case WSAENETDOWN:
    case WSAEHOSTDOWN:
        return TCP_K_UNREACHABLE;
    case WSAEADDRINUSE:
        return TCP_K_ADDR_IN_USE;
    case WSAEADDRNOTAVAIL:
        return TCP_K_ADDR_NOT_AVAILABLE;
    case WSAEMFILE:
        return TCP_K_NO_FILES;
    case WSAEACCES:
    case ERROR_ACCESS_DENIED:
        return TCP_K_DENIED;
    case WSAETIMEDOUT:
        return TCP_K_TIMED_OUT;
    case WSAEINVAL:
    case WSAEFAULT:
    case WSAENOTSOCK:
    case WSAEAFNOSUPPORT:
    case WSAEBADF:
    /* wepoll answers in Win32 codes: a closed or bad handle, a bad argument */
    case ERROR_INVALID_HANDLE:
    case ERROR_INVALID_PARAMETER:
        return TCP_K_INVALID;
    case WSAESHUTDOWN:
        return TCP_K_SHUTDOWN;
    default:
        return TCP_K_OTHER;
    }
}

static void WINAPI drop_event(PVOID event)
{
    if (event != NULL) {
        CloseHandle((HANDLE)event);
    }
}

/* this thread's event, reset and ready for one overlapped call; NULL with GetLastError() on failure */
static HANDLE thread_event(void)
{
    HANDLE event = g_event_slot == FLS_OUT_OF_INDEXES ? NULL : (HANDLE)FlsGetValue(g_event_slot);

    if (event == NULL) {
        event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (event == NULL) {
            return NULL;
        }

        if (g_event_slot == FLS_OUT_OF_INDEXES || !FlsSetValue(g_event_slot, event)) {
            CloseHandle(event);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }

        return event;
    }

    /* a call that completed at once signals it too, and nothing waited it back down */
    if (!ResetEvent(event)) {
        return NULL;
    }

    return event;
}

static BOOL CALLBACK startup(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    WSADATA data;

    (void)once;
    (void)param;
    (void)ctx;

    g_startup = WSAStartup(MAKEWORD(2, 2), &data);
    g_event_slot = FlsAlloc(drop_event);
    return TRUE;
}

/* 0 once Winsock is up, else TCP_ERR with the code it failed with */
static int ready(tcp_err *err)
{
    if (!InitOnceExecuteOnce(&g_once, startup, NULL, NULL)) {
        return (int)fail(err, (int)GetLastError());
    }

    if (g_startup != 0) {
        return (int)fail(err, g_startup);
    }

    return 0;
}

static int64_t now_ms(void)
{
    return (int64_t)GetTickCount64();
}

/* 1 ready, 0 timed out, 2 woken by wake (INVALID_SOCKET for none), TCP_ERR failed */
static int wait_for(SOCKET s, int writing, int64_t deadline, SOCKET wake, tcp_err *err)
{
    fd_set ready_set;
    fd_set errors;
    struct timeval tv;
    int ms;
    int rc;

    for (;;) {
        FD_ZERO(&ready_set);
        FD_ZERO(&errors);
        FD_SET(s, &ready_set);
        FD_SET(s, &errors);

        ms = left_ms(deadline);
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        if (wake != INVALID_SOCKET && !writing) {
            FD_SET(wake, &ready_set);
        }

        /* the first argument is ignored on Windows */
        rc = select(0, writing ? NULL : &ready_set, writing ? &ready_set : NULL, &errors, ms < 0 ? NULL : &tv);
        if (rc > 0) {
            if (wake != INVALID_SOCKET && !writing && FD_ISSET(wake, &ready_set)) {
                return 2;
            }

            /* an exception counts as ready: the operation reports what happened */
            return 1;
        }

        if (rc == 0) {
            return 0;
        }

        if (WSAGetLastError() != WSAEINTR) {
            return (int)fail(err, WSAGetLastError());
        }
    }
}

static int would_block(int code)
{
    return code == WSAEWOULDBLOCK || code == WSAEINTR;
}

/*
 * 0, or the code that failed: never handed to a child. A new connection needs nothing else: it
 * is already non-blocking (a connect sets it, and an accepted socket takes it from the listener)
 * and stays so for the try calls; the blocking calls are overlapped, which non-blocking mode does
 * not touch, and bound their own wait.
 */
static int no_inherit(SOCKET s)
{
    /* an accepted socket does not reliably carry WSA_FLAG_NO_HANDLE_INHERIT over */
    if (!SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0)) {
        return (int)GetLastError();
    }

    return 0;
}

/* 0, or the code that failed */
static int blocking(SOCKET s, int on)
{
    u_long mode = on ? 0 : 1;

    if (ioctlsocket(s, FIONBIO, &mode) != 0) {
        return WSAGetLastError();
    }

    return 0;
}

/* a stream socket no child process inherits from its first instant, able to do overlapped I/O */
static SOCKET open_socket(int family)
{
    /* afunix takes no protocol: IPPROTO_TCP on a unix socket is refused */
    int proto = family == AF_UNIX ? 0 : IPPROTO_TCP;

    return WSASocketW(family, SOCK_STREAM, proto, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
}

/*
 * One overlapped send or receive over up to two buffers, waiting up to timeout_ms (0: only what
 * completes at once). On the deadline the operation is cancelled and its result collected either
 * way, so bytes that landed in the race are reported, not lost. The count, TCP_EOF, TCP_TIMEOUT,
 * or TCP_ERR; a call cancelled by tcp_cancel on another thread is TCP_ERR of kind shutdown.
 */
static int64_t overlapped(SOCKET s, int sending, WSABUF *bufs, DWORD count, int32_t timeout_ms, tcp_err *err)
{
    WSAOVERLAPPED ov;
    DWORD done = 0;
    DWORD flags = 0;
    DWORD waited = WAIT_OBJECT_0;
    int lost = 0;
    int rc;
    int code;

    memset(&ov, 0, sizeof ov);
    ov.hEvent = thread_event();
    if (ov.hEvent == NULL) {
        return fail(err, (int)GetLastError());
    }

    if (sending) {
        rc = WSASend(s, bufs, count, &done, 0, &ov, NULL);
    } else {
        rc = WSARecv(s, bufs, count, &done, &flags, &ov, NULL);
    }

    if (rc != 0) {
        code = WSAGetLastError();
        if (code != WSA_IO_PENDING) {
            return fail(err, code);
        }

        waited = WaitForSingleObject(ov.hEvent, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
        if (waited == WAIT_FAILED) {
            /* not a deadline: the event itself is broken, and that is the failure to report */
            lost = (int)GetLastError();
        }

        if (waited != WAIT_OBJECT_0) {
            (void)CancelIoEx((HANDLE)s, &ov);
        }

        /* waits for the cancel to land: the buffer is the caller's again only after this */
        if (lost == 0) {
            rc = WSAGetOverlappedResult(s, &ov, &done, TRUE, &flags);
        } else {
            /*
             * a broken event is no use to wait on: poll the operation's own status instead. There is
             * no giving up here: ov and the buffers stay the kernel's until the I/O lands, and ov is
             * on this stack, so a return before that would let it write into a frame that is gone
             */
            while (!(rc = WSAGetOverlappedResult(s, &ov, &done, FALSE, &flags)) && WSAGetLastError() == WSA_IO_INCOMPLETE) {
                Sleep(1);
            }
        }

        if (!rc) {
            code = WSAGetLastError();
            if (code == WSA_OPERATION_ABORTED) {
                if (lost != 0) {
                    return fail(err, lost);
                }

                /* our own deadline cancelled it, or another thread's tcp_cancel did */
                if (waited != WAIT_OBJECT_0) {
                    return TCP_TIMEOUT;
                }

                return fail_as(err, TCP_K_SHUTDOWN, code);
            }

            return fail(err, code);
        }
    }

    /* a read of nothing is the end of the stream */
    if (done == 0 && !sending) {
        return TCP_EOF;
    }

    return (int64_t)done;
}

static int32_t lookup(const char *host, int32_t port, int flags, tcp_addr *out, int32_t max, tcp_err *err)
{
    ADDRINFOW hints;
    ADDRINFOW *res = NULL;
    ADDRINFOW *it;
    wchar_t whost[1024];
    wchar_t wport[16];
    char portstr[16];
    int32_t n = 0;
    int rc;

    if (host == NULL || host[0] == '\0' || port < 0 || port > 65535 || out == NULL || max <= 0) {
        return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (ready(err) != 0) {
        return TCP_ERR;
    }

    /* the wide form: a name is UTF-8, and the narrow one reads the system code page */
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host, -1, whost, (int)(sizeof whost / sizeof whost[0])) == 0) {
        return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    snprintf(portstr, sizeof portstr, "%d", (int)port);
    if (MultiByteToWideChar(CP_UTF8, 0, portstr, -1, wport, (int)(sizeof wport / sizeof wport[0])) == 0) {
        return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | flags;

    rc = GetAddrInfoW(whost, wport, &hints, &res);
    if (rc != 0) {
        /* a numeric parse that does not parse is bad input, not a failed lookup */
        if (flags & AI_NUMERICHOST) {
            return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
        }

        return (int32_t)fail_as(err, TCP_K_RESOLVE, rc);
    }

    for (it = res; it != NULL && n < max; it = it->ai_next) {
        if (it->ai_family == AF_INET || it->ai_family == AF_INET6) {
            from_sockaddr(it->ai_addr, (size_t)it->ai_addrlen, &out[n]);
            n++;
        }
    }

    FreeAddrInfoW(res);

    if (n == 0) {
        return (int32_t)fail_as(err, TCP_K_RESOLVE, WSAHOST_NOT_FOUND);
    }

    return n;
}

int32_t tcp_resolve(const char *host, int32_t port, int32_t passive, tcp_addr *out, int32_t max, tcp_err *err)
{
    return lookup(host, port, passive ? AI_PASSIVE : 0, out, max, err);
}

int32_t tcp_parse(const char *text, int32_t port, tcp_addr *out, tcp_err *err)
{
    int32_t n = lookup(text, port, AI_NUMERICHOST, out, 1, err);

    return n < 0 ? n : 0;
}

int32_t tcp_addr_text(const tcp_addr *addr, char *buf, int32_t len)
{
    SOCKADDR_STORAGE ss;
    int sl;

    if (buf == NULL || len <= 0) {
        return 0;
    }

    buf[0] = '\0';
    if (addr->family == TCP_FAMILY_UNIX) {
        return unix_text(addr, buf, len);
    }

    if (ready(NULL) != 0 || to_sockaddr(addr, &ss, &sl) != 0) {
        return 0;
    }

    /* NI_NUMERICHOST: no lookup, and an IPv6 scope comes out as %index */
    if (getnameinfo((struct sockaddr *)&ss, sl, buf, (DWORD)len, NULL, 0, NI_NUMERICHOST) != 0) {
        buf[0] = '\0';
        return 0;
    }

    return (int32_t)strlen(buf);
}

int64_t tcp_listen(const tcp_addr *at, int32_t backlog, int32_t flags, tcp_err *err)
{
    SOCKADDR_STORAGE ss;
    int sl;
    SOCKET s;
    listener *l;
    BOOL one = TRUE;
    DWORD v6only;
    int code;

    if (at == NULL || to_sockaddr(at, &ss, &sl) != 0) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (ready(err) != 0) {
        return TCP_ERR;
    }

    if (backlog <= 0) {
        backlog = SOMAXCONN;
    }

    s = open_socket(ss.ss_family);
    if (s == INVALID_SOCKET) {
        return fail(err, WSAGetLastError());
    }

    /* accept runs non-blocking: it waits in select, then takes what is there */
    code = no_inherit(s);
    if (code == 0) {
        code = blocking(s, 0);
    }

    if (code != 0) {
        closesocket(s);
        return fail(err, code);
    }

    /* not SO_REUSEADDR: on Windows that lets a second socket take a port that is already bound. A
       unix socket has no port: its file is what is taken */
    if (ss.ss_family != AF_UNIX && setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one) != 0) {
        goto failed;
    }

    if (ss.ss_family == AF_INET6) {
        /* one family unless asked: "::" then takes IPv4 too, as ::ffff:a.b.c.d */
        v6only = (flags & TCP_LISTEN_DUAL_STACK) ? 0 : 1;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof v6only) != 0) {
            goto failed;
        }
    }

    if (bind(s, (struct sockaddr *)&ss, sl) != 0 || listen(s, backlog) != 0) {
        goto failed;
    }

    l = (listener *)malloc(sizeof *l);
    if (l == NULL) {
        closesocket(s);
        return fail_as(err, TCP_K_OTHER, ERROR_NOT_ENOUGH_MEMORY);
    }

    l->s = s;
    l->wake = tcp_wake_open(err);
    if (l->wake == TCP_ERR) {
        closesocket(s);
        free(l);
        return TCP_ERR;
    }

    return (int64_t)(intptr_t)l;

failed:
    code = WSAGetLastError();
    closesocket(s);
    return fail(err, code);
}

/*
 * The accepted socket, or INVALID_SOCKET with the code in *code. accept() takes no flag, so the
 * socket is inheritable until no_inherit clears it: a CreateProcess with inheritance on, on
 * another thread in that moment, hands the child the connection. A process that spawns children
 * that way names their handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
 */
static SOCKET accept_one(SOCKET listener, tcp_addr *peer, int *code)
{
    SOCKADDR_STORAGE ss;
    int sl = (int)sizeof ss;
    SOCKET s;

    /* a unix peer's path is read up to the length the OS gives: never stack bytes it did not write */
    memset(&ss, 0, sizeof ss);

    s = accept(listener, (struct sockaddr *)&ss, &sl);
    if (s == INVALID_SOCKET) {
        *code = WSAGetLastError();
        return INVALID_SOCKET;
    }

    *code = no_inherit(s);
    if (*code != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (peer != NULL) {
        from_sockaddr((struct sockaddr *)&ss, (size_t)sl, peer);
    }

    return s;
}

/* a client that reset between the wake and the accept is not this listener's failure */
static int accept_again(int code)
{
    return would_block(code) || code == WSAECONNRESET;
}

int64_t tcp_listener_socket(int64_t l)
{
    return (int64_t)((listener *)(intptr_t)l)->s;
}

int64_t tcp_accept(int64_t l, int32_t timeout_ms, tcp_addr *peer, tcp_err *err)
{
    int64_t deadline;
    SOCKET sock = ((listener *)(intptr_t)l)->s;
    SOCKET wake_s = (SOCKET)((listener *)(intptr_t)l)->wake;
    int ready_now;
    int code = 0;
    SOCKET s;

    /* under load a connection is usually waiting already: take it before paying for a select */
    s = accept_one(sock, peer, &code);
    if (s != INVALID_SOCKET) {
        return (int64_t)s;
    }

    if (!accept_again(code)) {
        return fail(err, code);
    }

    deadline = deadline_of(timeout_ms);
    for (;;) {
        ready_now = wait_for(sock, 0, deadline, wake_s, err);
        if (ready_now < 0) {
            return TCP_ERR;
        }

        if (ready_now == 2) {
            return fail_as(err, TCP_K_SHUTDOWN, 0);
        }

        if (ready_now == 0) {
            return TCP_TIMEOUT;
        }

        s = accept_one(sock, peer, &code);
        if (s != INVALID_SOCKET) {
            return (int64_t)s;
        }

        if (!accept_again(code)) {
            return fail(err, code);
        }

        if (left_ms(deadline) == 0) {
            return TCP_TIMEOUT;
        }
    }
}

int64_t tcp_try_accept(int64_t l, tcp_addr *peer, tcp_err *err)
{
    int code = 0;
    SOCKET s = accept_one(((listener *)(intptr_t)l)->s, peer, &code);

    if (s != INVALID_SOCKET) {
        return (int64_t)s;
    }

    if (accept_again(code)) {
        return TCP_AGAIN;
    }

    return fail(err, code);
}

void tcp_listener_cancel(int64_t l)
{
    /* never drained: every accept after this finds it signalled */
    tcp_wake_signal(((listener *)(intptr_t)l)->wake);
}

void tcp_listener_close(int64_t l)
{
    listener *it = (listener *)(intptr_t)l;

    if (it == NULL || l < 0) {
        return;
    }

    closesocket(it->s);
    tcp_wake_close(it->wake);
    free(it);
}

int64_t tcp_connect_start(const tcp_addr *to, int32_t *done, tcp_err *err)
{
    SOCKADDR_STORAGE ss;
    int sl;
    SOCKET s;
    int code;

    *done = 0;
    if (to == NULL || to_sockaddr(to, &ss, &sl) != 0 || (to->family != TCP_FAMILY_UNIX && to->port == 0)) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (ready(err) != 0) {
        return TCP_ERR;
    }

    s = open_socket(ss.ss_family);
    if (s == INVALID_SOCKET) {
        return fail(err, WSAGetLastError());
    }

    code = no_inherit(s);
    if (code == 0) {
        code = blocking(s, 0);
    }

    if (code != 0) {
        closesocket(s);
        return fail(err, code);
    }

    if (ss.ss_family == AF_INET6) {
        /*
         * Windows makes an IPv6 socket v6-only, where macOS and Linux do not: an IPv4-mapped
         * address (a dual-stack listener's peer) is reachable only with it off. Best effort: a
         * system without IPv4 refuses, and the connect says what that means.
         */
        DWORD off = 0;

        (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof off);
    }

    if (connect(s, (struct sockaddr *)&ss, sl) == 0) {
        *done = 1;
        return (int64_t)s;
    }

    /* non-blocking: in progress is WSAEWOULDBLOCK, not EINPROGRESS */
    code = WSAGetLastError();
    if (code == WSAEWOULDBLOCK) {
        return (int64_t)s;
    }

    closesocket(s);
    return fail(err, code);
}

/* the outcome of a connect select has reported for: 0, or TCP_ERR */
static int32_t connect_result(SOCKET s, tcp_err *err)
{
    int soerr = 0;
    int solen = (int)sizeof soerr;

    /* always: a refused connect wakes select through exceptfds, not as a failure */
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &solen) != 0) {
        return (int32_t)fail(err, WSAGetLastError());
    }

    if (soerr != 0) {
        return (int32_t)fail(err, soerr);
    }

    return 0;
}

int32_t tcp_connect_finish(int64_t h, tcp_err *err)
{
    int ready_now = wait_for((SOCKET)h, 1, deadline_of(0), INVALID_SOCKET, err);

    if (ready_now < 0) {
        return TCP_ERR;
    }

    if (ready_now == 0) {
        return TCP_AGAIN;
    }

    return connect_result((SOCKET)h, err);
}

int64_t tcp_connect(const tcp_addr *to, int32_t timeout_ms, tcp_err *err)
{
    int64_t deadline = deadline_of(timeout_ms);
    int32_t done;
    int64_t h;
    int ready_now;

    h = tcp_connect_start(to, &done, err);
    if (h < 0 || done) {
        return h;
    }

    ready_now = wait_for((SOCKET)h, 1, deadline, INVALID_SOCKET, err);
    if (ready_now <= 0) {
        closesocket((SOCKET)h);
        return ready_now == 0 ? TCP_TIMEOUT : TCP_ERR;
    }

    if (connect_result((SOCKET)h, err) != 0) {
        closesocket((SOCKET)h);
        return TCP_ERR;
    }

    return h;
}

int32_t tcp_local(int64_t h, tcp_addr *out, tcp_err *err)
{
    SOCKADDR_STORAGE ss;
    int sl = (int)sizeof ss;

    memset(&ss, 0, sizeof ss);

    if (getsockname((SOCKET)h, (struct sockaddr *)&ss, &sl) != 0) {
        return (int32_t)fail(err, WSAGetLastError());
    }

    from_sockaddr((struct sockaddr *)&ss, (size_t)sl, out);
    return 0;
}

int32_t tcp_unix_path_max(void)
{
    struct sockaddr_un un;

    return (int32_t)sizeof un.sun_path - 1;
}

/*
 * The unix socket file at path, opened as itself (never what a reparse point leads to) for access
 * on top of reading its attributes, its identity in *id: a handle, or INVALID_HANDLE_VALUE when
 * path is not one.
 */
static HANDLE open_socket_file(const char *path, DWORD access, tcp_file_id *id)
{
    wchar_t wpath[MAX_PATH];
    FILE_ATTRIBUTE_TAG_INFO tag;
    BY_HANDLE_FILE_INFORMATION info;
    tcp_file_id_info full;
    HANDLE h;

    if (path == NULL || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wpath, MAX_PATH) == 0) {
        return INVALID_HANDLE_VALUE;
    }

    h = CreateFileW(wpath, access | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return h;
    }

    /* the AF_UNIX tag exactly: a symlink, a cloud placeholder or a deduplicated file is a reparse point too */
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof tag)
        || !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        || tag.ReparseTag != IO_REPARSE_TAG_AF_UNIX) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }

    /* the full 128-bit id where the system has it: its high half goes into dev, which it never is on NTFS */
    if (GetFileInformationByHandleEx(h, TCP_FILE_ID_INFO, &full, sizeof full)) {
        uint64_t lo;
        uint64_t hi;

        memcpy(&lo, full.id, sizeof lo);
        memcpy(&hi, full.id + 8, sizeof hi);
        id->dev = (uint64_t)full.volume ^ hi;
        id->ino = lo;
        return h;
    }

    if (!GetFileInformationByHandle(h, &info)) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }

    id->dev = (uint64_t)info.dwVolumeSerialNumber;
    id->ino = ((uint64_t)info.nFileIndexHigh << 32) | (uint64_t)info.nFileIndexLow;
    return h;
}

int32_t tcp_socket_id(const char *path, tcp_file_id *out)
{
    HANDLE h;

    if (out == NULL) {
        return -1;
    }

    h = open_socket_file(path, 0, out);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    CloseHandle(h);
    return 0;
}

int32_t tcp_unlink_socket(const char *path, const tcp_file_id *id)
{
    /* positional: the field's name is also a windows.h macro */
    FILE_DISPOSITION_INFO del = { TRUE };
    tcp_file_id now;
    HANDLE h;
    BOOL ok;

    if (id == NULL) {
        return -1;
    }

    h = open_socket_file(path, DELETE, &now);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (now.dev != id->dev || now.ino != id->ino) {
        CloseHandle(h);
        return -1;
    }

    /* through the handle that was checked: no other file can take the path in between */
    ok = SetFileInformationByHandle(h, FileDispositionInfo, &del, sizeof del);
    CloseHandle(h);
    return ok ? 0 : -1;
}

int32_t tcp_unlink_stale(const char *path)
{
    tcp_file_id id;
    tcp_addr at;
    tcp_err err;
    size_t n;
    int64_t h;

    if (tcp_socket_id(path, &id) != 0) {
        return -1;
    }

    n = strlen(path);
    if (n >= sizeof at.path) {
        return -1;
    }

    memset(&at, 0, sizeof at);
    at.family = TCP_FAMILY_UNIX;
    memcpy(at.path, path, n);

    /* only a refusal says nothing listens: a connect, a timeout or any other failure leaves the file be */
    h = tcp_connect(&at, 500, &err);
    if (h >= 0) {
        tcp_close(h);
        return -1;
    }

    if (h != TCP_ERR || err.kind != TCP_K_REFUSED) {
        return -1;
    }

    return tcp_unlink_socket(path, &id);
}

int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms, tcp_err *err)
{
    WSABUF wb;

    if (len <= 0) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    /* Winsock lengths are ULONG */
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    wb.buf = (char *)buf;
    wb.len = (ULONG)len;
    return overlapped((SOCKET)h, 0, &wb, 1, timeout_ms, err);
}

int64_t tcp_try_recv(int64_t h, uint8_t *buf, int64_t len, tcp_err *err)
{
    int got;
    int code;

    if (len <= 0) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (len > INT_MAX) {
        len = INT_MAX;
    }

    got = recv((SOCKET)h, (char *)buf, (int)len, 0);
    if (got > 0) {
        return (int64_t)got;
    }

    if (got == 0) {
        return TCP_EOF;
    }

    code = WSAGetLastError();
    if (would_block(code)) {
        return TCP_AGAIN;
    }

    return fail(err, code);
}

/*
 * a then b as at most two WSABUFs, cut to SEND_CHUNK in all: how many buffers. alen + blen must
 * be more than 0.
 */
static DWORD send_bufs(WSABUF wb[2], const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen)
{
    DWORD count = 1;
    int64_t room = SEND_CHUNK;

    /*
     * Winsock takes a whole send into the kernel whenever its buffer has any room, so one 64 MiB
     * call to a peer that never reads would return at once holding all 64 MiB. Small calls keep
     * what is queued near the send buffer, and a full buffer pushes back. The caller loops on a
     * short send. A send cut off by its deadline may have sent part of the chunk: after a write
     * times out the stream is no use, as the contract says.
     */
    if (alen > room) {
        alen = room;
    }

    room -= alen;
    if (blen > room) {
        blen = room;
    }

    wb[0].buf = (char *)a;
    wb[0].len = (ULONG)alen;
    if (blen > 0) {
        wb[1].buf = (char *)b;
        wb[1].len = (ULONG)blen;
        count = 2;
    }

    if (alen == 0) {
        wb[0] = wb[1];
        count = 1;
    }

    return count;
}

int64_t tcp_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, int32_t timeout_ms, tcp_err *err)
{
    WSABUF wb[2];
    DWORD count;
    int64_t put;

    /* a sum past INT64_MAX is no buffer anyone has, and would overflow below */
    if (alen < 0 || blen < 0 || alen > INT64_MAX - blen) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (alen + blen == 0) {
        return 0;
    }

    /*
     * A send nearly always finds room: take it with the non-blocking send the try call makes,
     * before starting an overlapped one. And on a full buffer with no time left nothing is
     * started: a deadline cancels an overlapped send, and a cancelled send can abort the whole
     * connection, where POSIX gives up on the write alone.
     */
    put = tcp_try_sendv(h, a, alen, b, blen, err);
    if (put != TCP_AGAIN) {
        return put;
    }

    if (timeout_ms == 0) {
        return TCP_TIMEOUT;
    }

    count = send_bufs(wb, a, alen, b, blen);
    return overlapped((SOCKET)h, 1, wb, count, timeout_ms, err);
}

/*
 * Non-overlapped, on a non-blocking socket: Winsock takes what fits and says how much, or
 * answers WSAEWOULDBLOCK having taken nothing, so no byte is ever sent twice.
 */
int64_t tcp_try_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, tcp_err *err)
{
    WSABUF wb[2];
    DWORD count;
    DWORD done = 0;
    int code;

    /* a sum past INT64_MAX is no buffer anyone has, and would overflow below */
    if (alen < 0 || blen < 0 || alen > INT64_MAX - blen) {
        return fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (alen + blen == 0) {
        return 0;
    }

    count = send_bufs(wb, a, alen, b, blen);
    if (WSASend((SOCKET)h, wb, count, &done, 0, NULL, NULL) == 0) {
        return (int64_t)done;
    }

    code = WSAGetLastError();
    if (would_block(code)) {
        return TCP_AGAIN;
    }

    return fail(err, code);
}

int32_t tcp_shutdown(int64_t h, int32_t how, tcp_err *err)
{
    int mode = how == TCP_SHUT_READ ? SD_RECEIVE : how == TCP_SHUT_WRITE ? SD_SEND : SD_BOTH;

    if (shutdown((SOCKET)h, mode) != 0) {
        return (int32_t)fail(err, WSAGetLastError());
    }

    return 0;
}

void tcp_cancel(int64_t h)
{
    if (h < 0) {
        return;
    }

    /* later calls fail at once on the shut socket; the cancel ends every call already waiting */
    (void)shutdown((SOCKET)h, SD_BOTH);
    (void)CancelIoEx((HANDLE)(SOCKET)h, NULL);
}

void tcp_close(int64_t h)
{
    if (h >= 0) {
        (void)closesocket((SOCKET)h);
    }
}

int32_t tcp_set_option(int64_t h, int32_t opt, int64_t value, tcp_err *err)
{
    /* clamped both ways: a cast alone keeps the low bits, and -(2^32) + 5 would be 5 */
    int v = value > 0x7fffffff ? 0x7fffffff : value < 0 ? 0 : (int)value;
    int rc;

    switch (opt) {
    case TCP_OPT_NODELAY: {
        BOOL on = v != 0;

        rc = setsockopt((SOCKET)h, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof on);
        break;
    }
    case TCP_OPT_KEEPALIVE: {
        /* the per-socket idle time: SIO_KEEPALIVE_VALS works back to Windows 2000 */
        struct tcp_keepalive ka;
        DWORD out = 0;

        /* milliseconds in a ULONG: an idle time past about 49 days is cut there, not wrapped */
        ULONG secs = v > 0 ? (ULONG)v : 0;

        if (secs > ULONG_MAX / 1000) {
            secs = ULONG_MAX / 1000;
        }

        ka.onoff = v > 0;
        ka.keepalivetime = secs * 1000;
        ka.keepaliveinterval = 1000;
        rc = WSAIoctl((SOCKET)h, SIO_KEEPALIVE_VALS, &ka, sizeof ka, NULL, 0, &out, NULL, NULL);
        break;
    }
    case TCP_OPT_SEND_BUFFER:
        rc = setsockopt((SOCKET)h, SOL_SOCKET, SO_SNDBUF, (const char *)&v, sizeof v);
        break;
    case TCP_OPT_RECV_BUFFER:
        rc = setsockopt((SOCKET)h, SOL_SOCKET, SO_RCVBUF, (const char *)&v, sizeof v);
        break;
    default:
        return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    if (rc != 0) {
        return (int32_t)fail(err, WSAGetLastError());
    }

    return 0;
}

/* a wake is a UDP socket on loopback, connected to itself; the handle is the socket */
int64_t tcp_wake_open(tcp_err *err)
{
    struct sockaddr_in addr;
    int len = (int)sizeof addr;
    BOOL one = TRUE;
    SOCKET s;
    int code;

    if (ready(err) != 0) {
        return TCP_ERR;
    }

    s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) {
        return fail(err, WSAGetLastError());
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* exclusive: no other process, the same user's included, can bind the port and take the wakes */
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one) != 0
        || bind(s, (struct sockaddr *)&addr, len) != 0
        || getsockname(s, (struct sockaddr *)&addr, &len) != 0
        || connect(s, (struct sockaddr *)&addr, len) != 0) {
        code = WSAGetLastError();
        closesocket(s);
        return fail(err, code);
    }

    code = blocking(s, 0);
    if (code != 0) {
        closesocket(s);
        return fail(err, code);
    }

    return (int64_t)s;
}

int64_t tcp_wake_handle(int64_t w)
{
    return w != 0 ? w : -1;
}

void tcp_wake_signal(int64_t w)
{
    char one = 1;

    /* a full queue is already signalled */
    if (w != 0) {
        (void)send((SOCKET)w, &one, 1, 0);
    }
}

void tcp_wake_drain(int64_t w)
{
    char buf[64];

    if (w == 0) {
        return;
    }

    while (recv((SOCKET)w, buf, sizeof buf, 0) > 0) {
    }
}

int32_t tcp_wake_wait(int64_t w, int32_t timeout_ms)
{
    if (w == 0) {
        return TCP_ERR;
    }

    return (int32_t)wait_for((SOCKET)w, 0, deadline_of(timeout_ms), INVALID_SOCKET, NULL);
}

void tcp_wake_close(int64_t w)
{
    if (w != 0) {
        closesocket((SOCKET)w);
    }
}

int32_t tcp_error_text(int32_t kind, int32_t code, char *buf, int32_t len)
{
    wchar_t wide[512];
    char utf8[1536];
    DWORD n;
    int m = 0;
    int cut;

    /* Winsock's resolve failures are WSA codes too: FormatMessage covers every kind */
    (void)kind;

    if (buf == NULL || len <= 0) {
        return 0;
    }

    buf[0] = '\0';

    /* the wide form, then UTF-8: the ANSI one is in the system code page, not what Echo strings hold */
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wide, (DWORD)(sizeof wide / sizeof wide[0]), NULL);

    /* the system text ends in ".\r\n"; strerror's does not */
    while (n > 0 && (wide[n - 1] == L'\r' || wide[n - 1] == L'\n' || wide[n - 1] == L' ' || wide[n - 1] == L'.')) {
        n--;
    }

    if (n > 0) {
        m = WideCharToMultiByte(CP_UTF8, 0, wide, (int)n, utf8, (int)sizeof utf8, NULL, NULL);
    }

    if (m <= 0) {
        snprintf(buf, (size_t)len, "error %d", (int)code);
        /* an old msvcrt snprintf leaves a cut text unterminated */
        buf[len - 1] = '\0';
        return (int32_t)strlen(buf);
    }

    cut = m;
    if (cut > len - 1) {
        cut = len - 1;

        /* never end on half a character */
        while (cut > 0 && ((unsigned char)utf8[cut] & 0xC0) == 0x80) {
            cut--;
        }
    }

    memcpy(buf, utf8, (size_t)cut);
    buf[cut] = '\0';
    return (int32_t)cut;
}

int64_t tcp_poll_open(tcp_err *err)
{
    HANDLE ep;

    if (ready(err) != 0) {
        return TCP_ERR;
    }

    ep = epoll_create1(0);
    if (ep == NULL) {
        return fail(err, (int)GetLastError());
    }

    return (int64_t)(intptr_t)ep;
}

int32_t tcp_poll_ctl(int64_t p, int32_t op, int64_t h, uint64_t token, int32_t interest, int32_t oneshot, tcp_err *err)
{
    struct wep_event ev;
    int how = op == TCP_POLL_ADD ? WEP_CTL_ADD : op == TCP_POLL_MODIFY ? WEP_CTL_MOD : WEP_CTL_DEL;

    /* an op it does not know is a mistake, never a remove */
    if (op != TCP_POLL_ADD && op != TCP_POLL_MODIFY && op != TCP_POLL_REMOVE) {
        return (int32_t)fail_as(err, TCP_K_INVALID, WSAEINVAL);
    }

    memset(&ev, 0, sizeof ev);
    if (interest & TCP_EV_READ) {
        ev.events |= WEP_IN | WEP_RDHUP;
    }

    if (interest & TCP_EV_WRITE) {
        ev.events |= WEP_OUT;
    }

    if (oneshot) {
        ev.events |= WEP_ONESHOT;
    }

    ev.data.u64 = token;

    if (epoll_ctl((HANDLE)(intptr_t)p, how, (SOCKET)h, &ev) != 0) {
        return (int32_t)fail(err, (int)GetLastError());
    }

    return 0;
}

int32_t tcp_poll_wait(int64_t p, tcp_event *out, int32_t max, int32_t timeout_ms, tcp_err *err)
{
    struct wep_event events[TCP_POLL_BATCH];
    int n;
    int i;

    if (max <= 0) {
        return 0;
    }

    if (max > TCP_POLL_BATCH) {
        max = TCP_POLL_BATCH;
    }

    n = epoll_wait((HANDLE)(intptr_t)p, events, max, timeout_ms < 0 ? -1 : timeout_ms);
    if (n < 0) {
        return (int32_t)fail(err, (int)GetLastError());
    }

    for (i = 0; i < n; i++) {
        uint32_t e = events[i].events;
        uint32_t flags = 0;

        if (e & WEP_IN) {
            flags |= TCP_EV_READ;
        }

        if (e & WEP_OUT) {
            flags |= TCP_EV_WRITE;
        }

        if (e & (WEP_HUP | WEP_RDHUP)) {
            flags |= TCP_EV_HANGUP;
        }

        if (e & WEP_ERR) {
            flags |= TCP_EV_ERROR;
        }

        out[i].token = events[i].data.u64;
        out[i].flags = flags;
        out[i].pad = 0;
    }

    return n;
}

void tcp_poll_close(int64_t p)
{
    if (p != 0 && p != TCP_ERR) {
        epoll_close((HANDLE)(intptr_t)p);
    }
}
