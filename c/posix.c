/*
 * libtcp on POSIX (macOS, Linux): the c/tcp.h contract over BSD sockets.
 *
 * Every socket is non-blocking and CLOEXEC. A call waits with poll() up to
 * its timeout, then tries the operation; a wake that finds nothing to do
 * (EAGAIN) waits again until the deadline. So no call blocks past its
 * timeout, and a thread that loops on short timeouts can check a stop flag.
 *
 * The OS code of a failure is kept in a thread-local at the point of
 * failure, so whatever Echo does between the call and tcp_last_error()
 * cannot clobber it.
 *
 * On Linux a socket is born CLOEXEC (SOCK_CLOEXEC, accept4), so a fork and
 * exec on another thread never inherits it. macOS has no atomic form: the
 * flag is set right after, and a fork landing in that gap inherits the fd.
 */

#if defined(__linux__)
/* accept4 and SOCK_CLOEXEC; it also makes strerror_r the GNU one, handled below */
#define _GNU_SOURCE
#endif

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static __thread int32_t g_last;

static int64_t fail(int code)
{
    g_last = (int32_t)code;
    return TCP_ERR;
}

static int64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

/* -1 when timeout_ms is -1 (forever), else the absolute deadline */
static int64_t deadline_of(int32_t timeout_ms)
{
    if (timeout_ms < 0) {
        return -1;
    }

    return now_ms() + timeout_ms;
}

/* what poll() should wait from now to the deadline: -1 forever, 0 when it has passed */
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
static int wait_for(int fd, short events, int64_t deadline)
{
    struct pollfd p;
    int rc;

    for (;;) {
        p.fd = fd;
        p.events = events;
        p.revents = 0;

        rc = poll(&p, 1, left_ms(deadline));
        if (rc > 0) {
            if (p.revents & POLLNVAL) {
                return (int)fail(EBADF);
            }

            /* POLLHUP and POLLERR count as ready: the operation reports what happened */
            return 1;
        }

        if (rc == 0) {
            return 0;
        }

        if (errno != EINTR) {
            return (int)fail(errno);
        }
    }
}

static int would_block(int code)
{
    return code == EAGAIN || code == EWOULDBLOCK;
}

static int closed_code(int code)
{
    return code == ECONNRESET || code == EPIPE || code == ENOTCONN || code == ECONNABORTED;
}

static int prepare(int fd)
{
    int flags;
    int one = 1;

    flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }

    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

#ifdef SO_NOSIGPIPE
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) {
        return -1;
    }
#endif

    (void)one;
    return 0;
}

/* a socket that is CLOEXEC and non-blocking from its first instant where the OS allows it */
static int open_socket(int family, int type, int proto)
{
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    return socket(family, type | SOCK_CLOEXEC | SOCK_NONBLOCK, proto);
#else
    return socket(family, type, proto);
#endif
}

/* small request and reply frames: never wait for a delayed ACK */
static void nodelay(int fd)
{
    int one = 1;

    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static struct addrinfo *resolve(const char *host, int32_t port, int passive)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char portstr[16];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (passive) {
        hints.ai_flags |= AI_PASSIVE;
    }

    snprintf(portstr, sizeof portstr, "%d", (int)port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return NULL;
    }

    return res;
}

int64_t tcp_listen(const char *host, int32_t port, int32_t backlog)
{
    struct addrinfo *res;
    struct addrinfo *it;
    int fd = -1;
    int code = EADDRNOTAVAIL;
    int one = 1;

    /* every interface is "0.0.0.0", spelled out: an empty host never widens a bind by accident */
    if (host == NULL || host[0] == '\0' || port < 0 || port > 65535) {
        return fail(EINVAL);
    }

    if (backlog <= 0) {
        backlog = 16;
    }

    res = resolve(host, port, 1);
    if (res == NULL) {
        return fail(EADDRNOTAVAIL);
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = open_socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            code = errno;
            continue;
        }

        if (prepare(fd) != 0
            || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0
            || bind(fd, it->ai_addr, it->ai_addrlen) != 0
            || listen(fd, backlog) != 0) {
            code = errno;
            close(fd);
            fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (fd < 0) {
        return fail(code);
    }

    return fd;
}

int32_t tcp_port(int64_t h)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    memset(&addr, 0, sizeof addr);
    if (getsockname((int)h, (struct sockaddr *)&addr, &len) != 0) {
        return (int32_t)fail(errno);
    }

    return (int32_t)ntohs(addr.sin_port);
}

int64_t tcp_accept(int64_t listener, int32_t timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    int ready;
    int fd;

    for (;;) {
        ready = wait_for((int)listener, POLLIN, deadline);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

#if defined(__linux__)
        fd = accept4((int)listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
        fd = accept((int)listener, NULL, NULL);
#endif
        if (fd >= 0) {
            break;
        }

        /* a client that gave up between the wake and the accept is not this listener's failure */
        if (errno == EINTR || would_block(errno) || errno == ECONNABORTED) {
            if (left_ms(deadline) == 0) {
                return TCP_TIMEOUT;
            }

            continue;
        }

        return fail(errno);
    }

    if (prepare(fd) != 0) {
        int code = errno;

        close(fd);
        return fail(code);
    }

    nodelay(fd);
    return fd;
}

int64_t tcp_connect(const char *host, int32_t port, int32_t timeout_ms)
{
    struct addrinfo *res;
    struct addrinfo *it;
    int64_t deadline = deadline_of(timeout_ms);
    int fd = -1;
    int code = ECONNREFUSED;
    int rc;
    int ready;
    int soerr;
    socklen_t solen;

    if (host == NULL || host[0] == '\0' || port <= 0 || port > 65535) {
        return fail(EINVAL);
    }

    res = resolve(host, port, 0);
    if (res == NULL) {
        return fail(EHOSTUNREACH);
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = open_socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            code = errno;
            continue;
        }

        if (prepare(fd) != 0) {
            code = errno;
            close(fd);
            fd = -1;
            continue;
        }

        rc = connect(fd, it->ai_addr, it->ai_addrlen);
        if (rc != 0 && errno != EINPROGRESS && errno != EINTR) {
            code = errno;
            close(fd);
            fd = -1;
            continue;
        }

        if (rc != 0) {
            ready = wait_for(fd, POLLOUT, deadline);
            if (ready <= 0) {
                code = ready == 0 ? ETIMEDOUT : g_last;
                close(fd);
                fd = -1;
                if (ready == 0) {
                    freeaddrinfo(res);
                    return TCP_TIMEOUT;
                }

                continue;
            }

            soerr = 0;
            solen = sizeof soerr;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) != 0 || soerr != 0) {
                code = soerr != 0 ? soerr : errno;
                close(fd);
                fd = -1;
                continue;
            }
        }

        break;
    }

    freeaddrinfo(res);

    if (fd < 0) {
        return fail(code);
    }

    nodelay(fd);
    return fd;
}

int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    ssize_t got;
    int ready;

    if (len <= 0) {
        return fail(EINVAL);
    }

    for (;;) {
        ready = wait_for((int)h, POLLIN, deadline);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        got = recv((int)h, buf, (size_t)len, 0);
        if (got > 0) {
            return (int64_t)got;
        }

        if (got == 0) {
            return TCP_CLOSED;
        }

        if (errno == EINTR || would_block(errno)) {
            if (left_ms(deadline) == 0) {
                return TCP_TIMEOUT;
            }

            continue;
        }

        if (closed_code(errno)) {
            g_last = errno;
            return TCP_CLOSED;
        }

        return fail(errno);
    }
}

int64_t tcp_send(int64_t h, const uint8_t *buf, int64_t len, int32_t timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    ssize_t put;
    int flags = 0;
    int ready;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif

    if (len < 0) {
        return fail(EINVAL);
    }

    if (len == 0) {
        return 0;
    }

    for (;;) {
        ready = wait_for((int)h, POLLOUT, deadline);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        put = send((int)h, buf, (size_t)len, flags);
        if (put >= 0) {
            return (int64_t)put;
        }

        if (errno == EINTR || would_block(errno)) {
            if (left_ms(deadline) == 0) {
                return TCP_TIMEOUT;
            }

            continue;
        }

        if (closed_code(errno)) {
            g_last = errno;
            return TCP_CLOSED;
        }

        return fail(errno);
    }
}

int32_t tcp_shutdown_write(int64_t h)
{
    if (shutdown((int)h, SHUT_WR) != 0) {
        return (int32_t)fail(errno);
    }

    return 0;
}

void tcp_close(int64_t h)
{
    if (h >= 0) {
        (void)close((int)h);
    }
}

int32_t tcp_last_error(void)
{
    return g_last;
}

int32_t tcp_error_text(int32_t code, char *buf, int32_t len)
{
    if (buf == NULL || len <= 0) {
        return 0;
    }

    buf[0] = '\0';

    /* strerror shares one buffer for unknown codes; strerror_r writes into the caller's */
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    {
        /* the GNU form may hand back a static string instead of filling buf */
        const char *text = strerror_r((int)code, buf, (size_t)len);

        if (text != buf) {
            snprintf(buf, (size_t)len, "%s", text != NULL ? text : "unknown error");
        }
    }
#else
    if (strerror_r((int)code, buf, (size_t)len) != 0) {
        snprintf(buf, (size_t)len, "error %d", (int)code);
    }
#endif

    return (int32_t)strlen(buf);
}
