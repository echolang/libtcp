/*
 * libtcp: the platform contract.
 *
 * Every backend (c/posix.c, c/win32.c) implements exactly these symbols.
 * The C side is mechanism only: one socket call, bounded by a timeout, with
 * its failure sorted into a portable kind. Policy is Echo: deadlines that
 * span several calls, trying each resolved address, write-all loops,
 * frames, and when a handle may be released.
 *
 * Handles are int64_t, so a POSIX fd and a Winsock SOCKET (UINT_PTR) both
 * fit. Every call that can fail takes a tcp_err the backend fills on
 * failure: no thread-local, so nothing Echo does between the call and
 * reading the error can clobber it.
 *
 * timeout_ms: -1 waits forever, 0 polls once, > 0 waits at most that long.
 *
 * No call raises a signal (no SIGPIPE), and no handle is inherited by a
 * child process.
 */

#ifndef LIBTCP_TCP_H
#define LIBTCP_TCP_H

#include <stdint.h>

/* failed: err->kind and err->code say why */
#define TCP_ERR (-1)

/* the peer closed its side cleanly: a read saw the end of the stream */
#define TCP_EOF (-2)

/* timeout_ms passed with no progress */
#define TCP_TIMEOUT (-3)

/* a try call would have had to wait */
#define TCP_AGAIN (-4)

/*
 * Failure kinds: what a caller branches on, the same on every platform.
 * err->code keeps the OS number (errno, a WSA code, or for TCP_K_RESOLVE
 * the getaddrinfo code) for tcp_error_text.
 */
#define TCP_K_OTHER 0
#define TCP_K_REFUSED 1
#define TCP_K_RESET 2
#define TCP_K_UNREACHABLE 3
#define TCP_K_ADDR_IN_USE 4
#define TCP_K_ADDR_NOT_AVAILABLE 5
#define TCP_K_NO_FILES 6
#define TCP_K_RESOLVE 7
#define TCP_K_INVALID 8
#define TCP_K_DENIED 9
#define TCP_K_TIMED_OUT 10
#define TCP_K_SHUTDOWN 11

typedef struct tcp_err {
    int32_t kind;
    int32_t code;
} tcp_err;

/* tcp_addr.family: 4 and 6 are IPv4 and IPv6 */
#define TCP_FAMILY_UNIX 1

/*
 * An endpoint. IPv4 (family 4) keeps its address in bytes[0..3], IPv6 (6) in
 * all of bytes. A unix socket (TCP_FAMILY_UNIX) keeps its path in path,
 * NUL-terminated, and an empty path is an unnamed one (the client end of a
 * connection); port and bytes are 0.
 */
typedef struct tcp_addr {
    uint8_t family;
    uint8_t pad;
    uint16_t port;
    uint32_t scope;
    uint8_t bytes[16];
    uint8_t path[108];
} tcp_addr;

/* tcp_listen flags */
#define TCP_LISTEN_REUSE_PORT 1
#define TCP_LISTEN_DUAL_STACK 2

/* tcp_shutdown how */
#define TCP_SHUT_READ 0
#define TCP_SHUT_WRITE 1
#define TCP_SHUT_BOTH 2

/* tcp_set_option opt */
#define TCP_OPT_NODELAY 1
#define TCP_OPT_KEEPALIVE 2
#define TCP_OPT_SEND_BUFFER 3
#define TCP_OPT_RECV_BUFFER 4

/*
 * Resolve host:port into at most max addresses, in the order the system
 * prefers. passive asks for addresses to listen on. Returns how many (at
 * least 1), or TCP_ERR.
 */
int32_t tcp_resolve(const char *host, int32_t port, int32_t passive, tcp_addr *out, int32_t max, tcp_err *err);

/* a numeric address ("127.0.0.1", "::1", "fe80::1%en0") with no lookup; 0, or TCP_ERR (kind invalid) */
int32_t tcp_parse(const char *text, int32_t port, tcp_addr *out, tcp_err *err);

/* the address without its port, as text, into buf (always terminated); returns its length */
int32_t tcp_addr_text(const tcp_addr *addr, char *buf, int32_t len);

/* the longest unix socket path the platform takes, in bytes, without the NUL */
int32_t tcp_unix_path_max(void);

/*
 * Remove a unix socket's file, but only when path is one (never a plain
 * file someone named the same): 0 when removed, -1 otherwise.
 */
int32_t tcp_unlink_socket(const char *path);

/*
 * A listener is opaque, not a socket: each backend keeps in it what it
 * needs to cancel an accept (where a shutdown of a listening socket wakes
 * nobody, a wake). tcp_listener_socket is the socket inside, for
 * tcp_local and tcp_poll_ctl; the listener owns it.
 */

/* listen on one address: a listener, or TCP_ERR */
int64_t tcp_listen(const tcp_addr *at, int32_t backlog, int32_t flags, tcp_err *err);

int64_t tcp_listener_socket(int64_t l);

/* the next connection, its peer in *peer; TCP_TIMEOUT when nobody connected in time */
int64_t tcp_accept(int64_t l, int32_t timeout_ms, tcp_addr *peer, tcp_err *err);

/* the next connection if one is waiting, else TCP_AGAIN */
int64_t tcp_try_accept(int64_t l, tcp_addr *peer, tcp_err *err);

/* tcp_cancel for a listener: every accept waiting on l, and every one after, returns at once */
void tcp_listener_cancel(int64_t l);

/* release the listener and its socket; safe on a negative one */
void tcp_listener_close(int64_t l);

/* connect to one address: a handle, TCP_TIMEOUT, or TCP_ERR */
int64_t tcp_connect(const tcp_addr *to, int32_t timeout_ms, tcp_err *err);

/*
 * A connect that does not wait: the handle, with *done 1 when it connected
 * at once (loopback, a unix socket) and 0 while it is in progress, or
 * TCP_ERR. An in-progress handle turns writable when the connect is over,
 * either way; tcp_connect_finish says which.
 */
int64_t tcp_connect_start(const tcp_addr *to, int32_t *done, tcp_err *err);

/*
 * Where a started connect is: 0 connected, TCP_AGAIN still in progress, or
 * TCP_ERR with why it failed. It never closes the handle: the caller does.
 */
int32_t tcp_connect_finish(int64_t h, tcp_err *err);

/* the local endpoint of a handle; 0, or TCP_ERR */
int32_t tcp_local(int64_t h, tcp_addr *out, tcp_err *err);

/* > 0 bytes read, TCP_EOF, TCP_TIMEOUT, or TCP_ERR; never 0 */
int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms, tcp_err *err);

/* a gather send of a then b, either may be empty: bytes sent from the two in order (may be fewer than alen + blen), TCP_TIMEOUT, or TCP_ERR */
int64_t tcp_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, int32_t timeout_ms, tcp_err *err);

/* a recv that never waits: TCP_AGAIN instead */
int64_t tcp_try_recv(int64_t h, uint8_t *buf, int64_t len, tcp_err *err);

/* the gathered try send: bytes sent from a then b, in order, or TCP_AGAIN */
int64_t tcp_try_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, tcp_err *err);

/* half or full shutdown; 0, or TCP_ERR */
int32_t tcp_shutdown(int64_t h, int32_t how, tcp_err *err);

/*
 * Wake every call blocked on connection h, on any thread: it returns at
 * once, and so does every call made on h after this. The handle stays open
 * (and its number taken) until tcp_close.
 *
 * What a cancelled call returns is the backend's, not the contract's: data
 * already there, TCP_EOF, TCP_TIMEOUT, or TCP_ERR of any kind (POSIX cancels
 * with a shutdown, and a recv after it reads the end exactly as when the
 * peer closed). The caller that cancelled knows why the call ended; it must
 * not read the result as the peer's doing. The same holds for
 * tcp_listener_cancel.
 */
void tcp_cancel(int64_t h);

/* release a connection; safe on a negative one */
void tcp_close(int64_t h);

/* set one option; 0, or TCP_ERR. KEEPALIVE takes the idle seconds, 0 turns it off */
int32_t tcp_set_option(int64_t h, int32_t opt, int64_t value, tcp_err *err);

/*
 * A wake: something one thread signals so another stops waiting. Its
 * pollable handle is readable while it is signalled. Opaque, 0 is none.
 */
int64_t tcp_wake_open(tcp_err *err);
int64_t tcp_wake_handle(int64_t w);
void tcp_wake_signal(int64_t w);
void tcp_wake_drain(int64_t w);
void tcp_wake_close(int64_t w);

/* wait until w is signalled or timeout_ms passes: 1 signalled, 0 timed out, TCP_ERR */
int32_t tcp_wake_wait(int64_t w, int32_t timeout_ms);

/* the OS text for a failure into buf (always terminated); returns its length */
int32_t tcp_error_text(int32_t kind, int32_t code, char *buf, int32_t len);

/*
 * Readiness: epoll on Linux, kqueue on macOS, wepoll (AFD) on Windows.
 * Level or oneshot, never edge: wepoll has no edge mode, so neither does
 * the contract. A oneshot registration reports once, then stays quiet
 * until it is modified again.
 */

#define TCP_EV_READ 1
#define TCP_EV_WRITE 2
#define TCP_EV_HANGUP 4
#define TCP_EV_ERROR 8

/* the most events one tcp_poll_wait hands back, whatever max asks for */
#define TCP_POLL_BATCH 256

#define TCP_POLL_ADD 0
#define TCP_POLL_MODIFY 1
#define TCP_POLL_REMOVE 2

typedef struct tcp_event {
    uint64_t token;
    uint32_t flags;
    uint32_t pad;
} tcp_event;

int64_t tcp_poll_open(tcp_err *err);

/* interest is TCP_EV_READ and/or TCP_EV_WRITE; 0, or TCP_ERR */
int32_t tcp_poll_ctl(int64_t p, int32_t op, int64_t h, uint64_t token, int32_t interest, int32_t oneshot, tcp_err *err);

/* ready handles into out, one event per token; how many (0 on a timeout), or TCP_ERR */
int32_t tcp_poll_wait(int64_t p, tcp_event *out, int32_t max, int32_t timeout_ms, tcp_err *err);

void tcp_poll_close(int64_t p);

#endif
