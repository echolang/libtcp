/*
 * libtcp: the platform contract.
 *
 * Every backend (c/posix.c now, c/win32.c later) implements exactly these
 * symbols. Nothing above this header knows the operating system: framing,
 * read-exact, write-all and every loop are Echo.
 *
 * Handles are int64_t, so a POSIX fd and a Winsock SOCKET (UINT_PTR) both
 * fit. Every call returns >= 0 on success (a handle, a port or a byte
 * count), or one of the codes below.
 *
 * timeout_ms: -1 waits forever, 0 polls once, > 0 waits at most that long.
 *
 * No call raises a signal (no SIGPIPE), and no handle is inherited by a
 * child process.
 */

#ifndef LIBTCP_TCP_H
#define LIBTCP_TCP_H

#include <stdint.h>

/* failed: the OS code is tcp_last_error() on the same thread */
#define TCP_ERR (-1)

/* the peer closed: recv saw end of stream, or the connection was reset */
#define TCP_CLOSED (-2)

/* timeout_ms passed with no progress */
#define TCP_TIMEOUT (-3)

/* listen on host:port (IPv4). host "" or NULL is every interface; port 0 lets the OS pick */
int64_t tcp_listen(const char *host, int32_t port, int32_t backlog);

/* the bound local port of a listener or a connection */
int32_t tcp_port(int64_t h);

/* the next connection, TCP_TIMEOUT when none arrived in time */
int64_t tcp_accept(int64_t listener, int32_t timeout_ms);

/* connect to host:port (IPv4) */
int64_t tcp_connect(const char *host, int32_t port, int32_t timeout_ms);

/* > 0 bytes read; never returns 0 (end of stream is TCP_CLOSED) */
int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms);

/* bytes sent, may be fewer than len */
int64_t tcp_send(int64_t h, const uint8_t *buf, int64_t len, int32_t timeout_ms);

/* half-close: the peer reads end of stream, this side can still read */
int32_t tcp_shutdown_write(int64_t h);

/* safe on a negative handle */
void tcp_close(int64_t h);

/* errno, or WSAGetLastError() */
int32_t tcp_last_error(void);

/* the OS text for code into buf (always terminated); returns its length */
int32_t tcp_error_text(int32_t code, char *buf, int32_t len);

#endif
