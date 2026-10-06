/*
 * libtcp on Windows: the c/tcp.h contract over Winsock 2.
 *
 * No socket is inheritable, and no call blocks past its timeout, so a thread
 * that loops on short timeouts can check a stop flag.
 *
 * Listening and connecting run non-blocking: a call waits with select() up
 * to its timeout, then tries the operation, and a wake that finds nothing to
 * do (WSAEWOULDBLOCK) waits again until the deadline. select, not WSAPoll:
 * before Windows 10 2004 WSAPoll never reported a failed non-blocking
 * connect, and a refused connect sat out its timeout. select reports it
 * through exceptfds.
 *
 * A connection reads and writes with overlapped I/O instead: each call
 * starts the operation with its own event, waits on that, and cancels it at
 * the deadline. Readiness does not work here. Two threads waiting on one
 * socket, one to read and one to write, starve each other: with a reader
 * parked in select (or WSAPoll), a writer's wake comes late or not at all,
 * and a 2 MiB write that takes 16 ms alone times out after seconds.
 *
 * The OS code of a failure is kept in a thread-local at the point of
 * failure, so whatever Echo does between the call and tcp_last_error()
 * cannot clobber it. Winsock and Win32 codes share one space, and
 * FormatMessage reads both.
 *
 * Winsock starts once (WSAStartup), on the first listen or connect: every
 * other call takes a handle one of those made. It is never cleaned up; the
 * process ending does that.
 */

#define WIN32_LEAN_AND_MEAN

#ifndef _WIN32_WINNT
/* Windows 7 SP1: WSA_FLAG_NO_HANDLE_INHERIT */
#define _WIN32_WINNT 0x0601
#endif

#include "tcp.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* the most one tcp_send hands Winsock: see tcp_send */
#define SEND_CHUNK (64 * 1024)

static __declspec(thread) int32_t g_last;

static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static int g_startup;

/* each thread's overlapped event, closed by the fiber-local destructor when the thread ends */
static DWORD g_event_slot = FLS_OUT_OF_INDEXES;

static int64_t fail(int code)
{
    g_last = (int32_t)code;
    return TCP_ERR;
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

/* 0 once Winsock is up, else the code it failed with */
static int ensure_init(void)
{
    if (!InitOnceExecuteOnce(&g_once, startup, NULL, NULL)) {
        return (int)GetLastError();
    }

    return g_startup;
}

static int64_t now_ms(void)
{
    return (int64_t)GetTickCount64();
}

/* -1 when timeout_ms is -1 (forever), else the absolute deadline */
static int64_t deadline_of(int32_t timeout_ms)
{
    if (timeout_ms < 0) {
        return -1;
    }

    return now_ms() + timeout_ms;
}

/* what to wait from now to the deadline: -1 forever, 0 when it has passed */
static int left_ms(int64_t deadline)
{
    int64_t left;

    if (deadline < 0) {
        return -1;
    }

    left = deadline - now_ms();
    if (left <= 0) {
        return 0;
    }

    if (left > 0x7fffffff) {
        return 0x7fffffff;
    }

    return (int)left;
}

/* 1 ready, 0 timed out, TCP_ERR failed */
static int wait_for(SOCKET s, int writing, int64_t deadline)
{
    fd_set ready;
    fd_set errors;
    struct timeval tv;
    int ms;
    int rc;

    for (;;) {
        FD_ZERO(&ready);
        FD_ZERO(&errors);
        FD_SET(s, &ready);
        FD_SET(s, &errors);

        ms = left_ms(deadline);
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        /* the first argument is ignored on Windows */
        rc = select(0, writing ? NULL : &ready, writing ? &ready : NULL, &errors, ms < 0 ? NULL : &tv);
        if (rc > 0) {
            /* an exception counts as ready: the operation reports what happened */
            return 1;
        }

        if (rc == 0) {
            return 0;
        }

        if (WSAGetLastError() != WSAEINTR) {
            return (int)fail(WSAGetLastError());
        }
    }
}

static int would_block(int code)
{
    return code == WSAEWOULDBLOCK || code == WSAEINTR;
}

static int closed_code(int code)
{
    return code == WSAECONNRESET || code == WSAECONNABORTED || code == WSAENOTCONN
        || code == WSAESHUTDOWN || code == WSAENETRESET;
}

/* 0, or the code that failed: non-blocking, and never handed to a child */
static int prepare(SOCKET s)
{
    u_long one = 1;

    if (ioctlsocket(s, FIONBIO, &one) != 0) {
        return WSAGetLastError();
    }

    /* an accepted socket does not reliably carry WSA_FLAG_NO_HANDLE_INHERIT over */
    if (!SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0)) {
        return (int)GetLastError();
    }

    return 0;
}

/* a socket no child process inherits from its first instant, able to do overlapped I/O */
static SOCKET open_socket(int family, int type, int proto)
{
    return WSASocketW(family, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
}

/*
 * 0, or the code that failed: a new connection leaves non-blocking mode, since every read and
 * write on it is overlapped and bounds its own wait. Small request and reply frames never wait
 * for a delayed ACK.
 */
static int connected(SOCKET s)
{
    u_long zero = 0;
    BOOL one = TRUE;

    if (ioctlsocket(s, FIONBIO, &zero) != 0) {
        return WSAGetLastError();
    }

    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    return 0;
}

/*
 * One overlapped read or write of at most len bytes, waiting up to timeout_ms. On the deadline
 * the operation is cancelled and its result collected either way, so bytes that landed in the
 * race are reported, not lost. The count, or TCP_TIMEOUT, TCP_CLOSED, TCP_ERR.
 */
static int64_t overlapped(SOCKET s, int sending, uint8_t *buf, int len, int32_t timeout_ms)
{
    WSAOVERLAPPED ov;
    WSABUF wb;
    DWORD done = 0;
    DWORD flags = 0;
    DWORD waited;
    int rc;
    int code;

    memset(&ov, 0, sizeof ov);
    ov.hEvent = thread_event();
    if (ov.hEvent == NULL) {
        return fail((int)GetLastError());
    }

    wb.buf = (char *)buf;
    wb.len = (ULONG)len;

    if (sending) {
        rc = WSASend(s, &wb, 1, &done, 0, &ov, NULL);
    } else {
        rc = WSARecv(s, &wb, 1, &done, &flags, &ov, NULL);
    }

    if (rc != 0) {
        code = WSAGetLastError();
        if (code != WSA_IO_PENDING) {
            if (closed_code(code)) {
                g_last = code;
                return TCP_CLOSED;
            }

            return fail(code);
        }

        waited = WaitForSingleObject(ov.hEvent, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
        if (waited != WAIT_OBJECT_0) {
            (void)CancelIoEx((HANDLE)s, &ov);
        }

        /* waits for the cancel to land: the buffer is the caller's again only after this */
        if (!WSAGetOverlappedResult(s, &ov, &done, TRUE, &flags)) {
            code = WSAGetLastError();
            if (code == WSA_OPERATION_ABORTED) {
                return TCP_TIMEOUT;
            }

            if (closed_code(code)) {
                g_last = code;
                return TCP_CLOSED;
            }

            return fail(code);
        }
    }

    /* a read of nothing is the end of the stream */
    if (done == 0 && !sending) {
        return TCP_CLOSED;
    }

    return (int64_t)done;
}

/* NULL on failure, with the lookup's own code in *code */
static struct addrinfo *resolve(const char *host, int32_t port, int passive, int *code)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char portstr[16];
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (passive) {
        hints.ai_flags |= AI_PASSIVE;
    }

    snprintf(portstr, sizeof portstr, "%d", (int)port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        *code = rc;
        return NULL;
    }

    return res;
}

int64_t tcp_listen(const char *host, int32_t port, int32_t backlog)
{
    struct addrinfo *res;
    struct addrinfo *it;
    SOCKET s = INVALID_SOCKET;
    int code;
    BOOL one = TRUE;

    /* every interface is "0.0.0.0", spelled out: an empty host never widens a bind by accident */
    if (host == NULL || host[0] == '\0' || port < 0 || port > 65535) {
        return fail(WSAEINVAL);
    }

    code = ensure_init();
    if (code != 0) {
        return fail(code);
    }

    if (backlog <= 0) {
        backlog = 16;
    }

    code = WSAEADDRNOTAVAIL;
    res = resolve(host, port, 1, &code);
    if (res == NULL) {
        return fail(code);
    }

    for (it = res; it != NULL; it = it->ai_next) {
        s = open_socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s == INVALID_SOCKET) {
            code = WSAGetLastError();
            continue;
        }

        code = prepare(s);
        if (code != 0) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }

        /* not SO_REUSEADDR: on Windows that lets a second socket take a port that is already bound */
        if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one) != 0
            || bind(s, it->ai_addr, (int)it->ai_addrlen) != 0
            || listen(s, backlog) != 0) {
            code = WSAGetLastError();
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        return fail(code);
    }

    return (int64_t)s;
}

int32_t tcp_port(int64_t h)
{
    struct sockaddr_in addr;
    int len = sizeof addr;

    memset(&addr, 0, sizeof addr);
    if (getsockname((SOCKET)h, (struct sockaddr *)&addr, &len) != 0) {
        return (int32_t)fail(WSAGetLastError());
    }

    return (int32_t)ntohs(addr.sin_port);
}

int64_t tcp_accept(int64_t listener, int32_t timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    int ready;
    int code;
    SOCKET s;

    for (;;) {
        ready = wait_for((SOCKET)listener, 0, deadline);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        s = accept((SOCKET)listener, NULL, NULL);
        if (s != INVALID_SOCKET) {
            break;
        }

        /* a client that reset between the wake and the accept is not this listener's failure */
        code = WSAGetLastError();
        if (would_block(code) || code == WSAECONNRESET) {
            if (left_ms(deadline) == 0) {
                return TCP_TIMEOUT;
            }

            continue;
        }

        return fail(code);
    }

    code = prepare(s);
    if (code == 0) {
        code = connected(s);
    }

    if (code != 0) {
        closesocket(s);
        return fail(code);
    }

    return (int64_t)s;
}

int64_t tcp_connect(const char *host, int32_t port, int32_t timeout_ms)
{
    struct addrinfo *res;
    struct addrinfo *it;
    int64_t deadline = deadline_of(timeout_ms);
    SOCKET s = INVALID_SOCKET;
    int code;
    int ready;
    int soerr;
    int solen;

    if (host == NULL || host[0] == '\0' || port <= 0 || port > 65535) {
        return fail(WSAEINVAL);
    }

    code = ensure_init();
    if (code != 0) {
        return fail(code);
    }

    code = WSAEHOSTUNREACH;
    res = resolve(host, port, 0, &code);
    if (res == NULL) {
        return fail(code);
    }

    code = WSAECONNREFUSED;
    for (it = res; it != NULL; it = it->ai_next) {
        s = open_socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (s == INVALID_SOCKET) {
            code = WSAGetLastError();
            continue;
        }

        code = prepare(s);
        if (code != 0) {
            closesocket(s);
            s = INVALID_SOCKET;
            continue;
        }

        /* non-blocking: in progress is WSAEWOULDBLOCK, not EINPROGRESS */
        if (connect(s, it->ai_addr, (int)it->ai_addrlen) != 0) {
            code = WSAGetLastError();
            if (code != WSAEWOULDBLOCK) {
                closesocket(s);
                s = INVALID_SOCKET;
                continue;
            }

            ready = wait_for(s, 1, deadline);
            if (ready <= 0) {
                code = ready == 0 ? WSAETIMEDOUT : g_last;
                closesocket(s);
                s = INVALID_SOCKET;
                if (ready == 0) {
                    freeaddrinfo(res);
                    return TCP_TIMEOUT;
                }

                continue;
            }

            /* always: a refused connect wakes select through exceptfds, not as a failure */
            soerr = 0;
            solen = sizeof soerr;
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &solen) != 0 || soerr != 0) {
                code = soerr != 0 ? soerr : WSAGetLastError();
                closesocket(s);
                s = INVALID_SOCKET;
                continue;
            }
        }

        break;
    }

    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        return fail(code);
    }

    code = connected(s);
    if (code != 0) {
        closesocket(s);
        return fail(code);
    }

    return (int64_t)s;
}

int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms)
{
    if (len <= 0) {
        return fail(WSAEINVAL);
    }

    /* Winsock lengths are int */
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    return overlapped((SOCKET)h, 0, buf, (int)len, timeout_ms);
}

int64_t tcp_send(int64_t h, const uint8_t *buf, int64_t len, int32_t timeout_ms)
{
    if (len < 0) {
        return fail(WSAEINVAL);
    }

    if (len == 0) {
        return 0;
    }

    /*
     * Winsock takes a whole send into the kernel whenever its buffer has any room, so one 64 MiB
     * call to a peer that never reads would return at once holding all 64 MiB. Small calls keep
     * what is queued near the send buffer, and a full buffer pushes back. The caller loops on a
     * short send. A send cut off by its deadline may have sent part of the chunk: after a write
     * times out the stream is no use, as the contract says.
     */
    if (len > SEND_CHUNK) {
        len = SEND_CHUNK;
    }

    return overlapped((SOCKET)h, 1, (uint8_t *)buf, (int)len, timeout_ms);
}

int32_t tcp_shutdown_write(int64_t h)
{
    if (shutdown((SOCKET)h, SD_SEND) != 0) {
        return (int32_t)fail(WSAGetLastError());
    }

    return 0;
}

void tcp_close(int64_t h)
{
    if (h >= 0) {
        (void)closesocket((SOCKET)h);
    }
}

int32_t tcp_last_error(void)
{
    return g_last;
}

int32_t tcp_error_text(int32_t code, char *buf, int32_t len)
{
    wchar_t wide[512];
    char utf8[1536];
    DWORD n;
    int m = 0;
    int cut;

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
