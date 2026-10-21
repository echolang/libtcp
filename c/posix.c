/*
 * libtcp on POSIX (macOS, Linux): the c/tcp.h contract over BSD sockets.
 *
 * Every socket is non-blocking and CLOEXEC. A call waits with poll() up to
 * its timeout, then tries the operation; a wake that finds nothing to do
 * (EAGAIN) waits again until the deadline. So no call blocks past its
 * timeout. A send and an accept try once before the first wait, since they
 * usually find room or a connection and the poll would be wasted. The try
 * calls skip the wait and answer TCP_AGAIN instead.
 *
 * A failure is sorted into a TCP_K_* kind right where it happens and handed
 * back through the caller's tcp_err, with errno kept beside it for the text.
 *
 * On Linux a socket is born CLOEXEC (SOCK_CLOEXEC, accept4), so a fork and
 * exec on another thread never inherits it. macOS has no atomic form: the
 * flag is set right after, and a fork landing in that gap inherits the fd.
 *
 * Readiness is epoll on Linux and kqueue on macOS, behind the same
 * tcp_poll_* calls. A wake is an eventfd on Linux and a pipe on macOS.
 */

#if defined(__linux__)
/* accept4, SOCK_CLOEXEC and eventfd; it also makes strerror_r the GNU one, handled below */
#define _GNU_SOURCE
#endif

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#define TCP_EPOLL 1
#else
#include <pthread.h>
#include <sys/event.h>
#define TCP_KQUEUE 1
#endif

#if defined(__APPLE__)
/* BSD sockaddrs carry their own length */
#define TCP_SUN_LEN 1
#endif

#include "common.h"

/*
 * A listener on Linux is its socket: a shutdown wakes a poll blocked on a listening socket, and
 * every accept after it fails. On macOS a shutdown wakes nothing, so a listener is a record that
 * also holds the wake tcp_listener_cancel signals.
 */
#if defined(__linux__)
#define LISTENER_IS_SOCKET 1
#else
typedef struct listener {
    int fd;
    int64_t wake;
} listener;
#endif

/* Linux makes a socket CLOEXEC and non-blocking in the call that creates it */
#if defined(__linux__) && defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
#define BORN_READY 1
#endif

#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

/*
 * The most one recv or sendmsg moves. Darwin refuses a single I/O over INT_MAX with EINVAL, and
 * Linux cuts one short near 2 GiB anyway: asking for less is a short count the callers handle.
 */
#define IO_MAX ((int64_t)1 << 30)

static int32_t kind_of(int code)
{
    switch (code) {
    case ECONNREFUSED:
        return TCP_K_REFUSED;
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:
    case ENOTCONN:
    case ENETRESET:
        return TCP_K_RESET;
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ENETDOWN:
#ifdef EHOSTDOWN
    case EHOSTDOWN:
#endif
        return TCP_K_UNREACHABLE;
    case EADDRINUSE:
        return TCP_K_ADDR_IN_USE;
    case EADDRNOTAVAIL:
        return TCP_K_ADDR_NOT_AVAILABLE;
    case EMFILE:
    case ENFILE:
        return TCP_K_NO_FILES;
    case EACCES:
    case EPERM:
        return TCP_K_DENIED;
    case ETIMEDOUT:
        return TCP_K_TIMED_OUT;
    case EINVAL:
    case EBADF:
    case ENOTSOCK:
    case EAFNOSUPPORT:
        return TCP_K_INVALID;
#ifdef ESHUTDOWN
    case ESHUTDOWN:
        return TCP_K_SHUTDOWN;
#endif
    default:
        return TCP_K_OTHER;
    }
}

static int64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

/* 1 ready, 0 timed out, 2 woken by wake_fd (-1 for none), TCP_ERR failed */
static int wait_for(int fd, short events, int64_t deadline, int wake_fd, tcp_err *err)
{
    struct pollfd p[2];
    nfds_t n = wake_fd >= 0 ? 2 : 1;
    int rc;

    for (;;) {
        p[0].fd = fd;
        p[0].events = events;
        p[0].revents = 0;
        p[1].fd = wake_fd;
        p[1].events = POLLIN;
        p[1].revents = 0;

        rc = poll(p, n, left_ms(deadline));
        if (rc > 0) {
            if (n == 2 && p[1].revents != 0) {
                return 2;
            }

            if (p[0].revents & POLLNVAL) {
                return (int)fail(err, EBADF);
            }

            /* POLLHUP and POLLERR count as ready: the operation reports what happened */
            return 1;
        }

        if (rc == 0) {
            return 0;
        }

        if (errno != EINTR) {
            return (int)fail(err, errno);
        }
    }
}

static int would_block(int code)
{
    return code == EAGAIN || code == EWOULDBLOCK;
}

/*
 * A failed call on a connected socket. macOS answers EINVAL to an option or getsockname on a
 * socket whose connection is already gone, which reads as a bad argument: when the socket has
 * no peer any more, it is reported as the reset it is.
 */
static int64_t fail_on(int fd, tcp_err *err, int code)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;

    if (code == EINVAL && getpeername(fd, (struct sockaddr *)&ss, &sl) != 0 && errno == ENOTCONN) {
        return fail(err, ENOTCONN);
    }

    return fail(err, code);
}

/* one ioctl per flag, where an fcntl would take a read and a write each */
static int nonblocking_cloexec(int fd)
{
    int one = 1;

    if (ioctl(fd, FIOCLEX) != 0 || ioctl(fd, FIONBIO, &one) != 0) {
        return -1;
    }

    return 0;
}

/* a new socket made CLOEXEC, non-blocking and SIGPIPE-free, where it was not born so */
static int prepare(int fd)
{
#ifdef BORN_READY
    /* already both, and every send passes MSG_NOSIGNAL: nothing is left to do */
    (void)fd;
    (void)nonblocking_cloexec;
    return 0;
#else
    int one = 1;

    if (nonblocking_cloexec(fd) != 0) {
        return -1;
    }

#ifdef SO_NOSIGPIPE
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) {
        return -1;
    }
#endif

    (void)one;
    return 0;
#endif
}

/* a socket that is CLOEXEC and non-blocking from its first instant where the OS allows it */
static int open_socket(int family)
{
#ifdef BORN_READY
    return socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
    return socket(family, SOCK_STREAM, 0);
#endif
}

static int64_t lookup(const char *host, int32_t port, int flags, tcp_addr *out, int32_t max, tcp_err *err)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char portstr[16];
    int32_t n = 0;
    int rc;

    if (host == NULL || host[0] == '\0' || port < 0 || port > 65535 || out == NULL || max <= 0) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | flags;

    snprintf(portstr, sizeof portstr, "%d", (int)port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        if (rc == EAI_SYSTEM) {
            return fail(err, errno);
        }

        /* a numeric parse that does not parse is bad input, not a failed lookup */
        if (flags & AI_NUMERICHOST) {
            return fail_as(err, TCP_K_INVALID, EINVAL);
        }

        return fail_as(err, TCP_K_RESOLVE, rc);
    }

    for (it = res; it != NULL && n < max; it = it->ai_next) {
        if (it->ai_family == AF_INET || it->ai_family == AF_INET6) {
            from_sockaddr(it->ai_addr, (size_t)it->ai_addrlen, &out[n]);
            n++;
        }
    }

    freeaddrinfo(res);

    if (n == 0) {
        return fail_as(err, TCP_K_RESOLVE, EAI_NONAME);
    }

    return n;
}

int32_t tcp_resolve(const char *host, int32_t port, int32_t passive, tcp_addr *out, int32_t max, tcp_err *err)
{
    return (int32_t)lookup(host, port, passive ? AI_PASSIVE : 0, out, max, err);
}

int32_t tcp_parse(const char *text, int32_t port, tcp_addr *out, tcp_err *err)
{
    int64_t n = lookup(text, port, AI_NUMERICHOST, out, 1, err);

    return n < 0 ? (int32_t)n : 0;
}

int32_t tcp_addr_text(const tcp_addr *addr, char *buf, int32_t len)
{
    struct sockaddr_storage ss;
    socklen_t sl;

    if (buf == NULL || len <= 0) {
        return 0;
    }

    buf[0] = '\0';
    if (addr->family == TCP_FAMILY_UNIX) {
        return unix_text(addr, buf, len);
    }

    if (to_sockaddr(addr, &ss, &sl) != 0) {
        return 0;
    }

    /* NI_NUMERICHOST: no lookup, and an IPv6 scope comes out as %interface */
    if (getnameinfo((struct sockaddr *)&ss, sl, buf, (socklen_t)len, NULL, 0, NI_NUMERICHOST) != 0) {
        buf[0] = '\0';
        return 0;
    }

    return (int32_t)strlen(buf);
}

int64_t tcp_listen(const tcp_addr *at, int32_t backlog, int32_t flags, tcp_err *err)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fd;
    int one = 1;
    int v6only;

    if (at == NULL || to_sockaddr(at, &ss, &sl) != 0) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    if (backlog <= 0) {
        backlog = SOMAXCONN;
    }

    fd = open_socket(ss.ss_family);
    if (fd < 0) {
        return fail(err, errno);
    }

    if (prepare(fd) != 0) {
        goto failed;
    }

    /* port reuse is a TCP matter: a unix socket's file is what is taken */
    if (ss.ss_family != AF_UNIX && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        goto failed;
    }

#ifdef SO_REUSEPORT
    if (ss.ss_family != AF_UNIX && (flags & TCP_LISTEN_REUSE_PORT) && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0) {
        goto failed;
    }
#endif

    if (ss.ss_family == AF_INET6) {
        /* one family unless asked: "::" then takes IPv4 too, as ::ffff:a.b.c.d */
        v6only = (flags & TCP_LISTEN_DUAL_STACK) ? 0 : 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) != 0) {
            goto failed;
        }
    }

    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 || listen(fd, backlog) != 0) {
        goto failed;
    }

#ifdef LISTENER_IS_SOCKET
    return fd;
#else
    {
        listener *l = (listener *)malloc(sizeof *l);

        if (l == NULL) {
            close(fd);
            return fail_as(err, TCP_K_OTHER, ENOMEM);
        }

        l->fd = fd;
        l->wake = tcp_wake_open(err);
        if (l->wake == TCP_ERR) {
            close(fd);
            free(l);
            return TCP_ERR;
        }

        return (int64_t)(intptr_t)l;
    }
#endif

failed:
    {
        int code = errno;

        close(fd);
        return fail(err, code);
    }
}

/* the accepted fd, or -1 with errno set */
static int accept_one(int listener, tcp_addr *peer)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd;

#ifdef BORN_READY
    fd = accept4(listener, (struct sockaddr *)&ss, &sl, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
    fd = accept(listener, (struct sockaddr *)&ss, &sl);
#endif
    if (fd < 0) {
        return -1;
    }

    /*
     * macOS answers EINVAL to setting up a socket whose peer has already gone (a unix client
     * that connected and closed before the accept): that connection died on the way in, which
     * is its failure and not the listener's, so it is skipped like any aborted one
     */
    if (prepare(fd) != 0) {
        close(fd);
        errno = ECONNABORTED;
        return -1;
    }

    if (peer != NULL) {
        from_sockaddr((struct sockaddr *)&ss, (size_t)sl, peer);
    }

    return fd;
}

/* a client that gave up between the wake and the accept is not this listener's failure */
static int accept_again(int code)
{
#if defined(__linux__)
    /*
     * Linux hands a new connection's pending network error back from accept itself, and
     * accept(2) says to retry these as EAGAIN: it is that connection's, not the listener's.
     */
    switch (code) {
    case ENETDOWN:
    case EPROTO:
    case ENOPROTOOPT:
    case EHOSTDOWN:
    case ENONET:
    case EHOSTUNREACH:
    case EOPNOTSUPP:
    case ENETUNREACH:
        return 1;
    default:
        break;
    }
#endif

    return code == EINTR || would_block(code) || code == ECONNABORTED;
}

int64_t tcp_listener_socket(int64_t l)
{
#ifdef LISTENER_IS_SOCKET
    return l;
#else
    return ((listener *)(intptr_t)l)->fd;
#endif
}

int64_t tcp_accept(int64_t l, int32_t timeout_ms, tcp_addr *peer, tcp_err *err)
{
    int64_t deadline;
    int sock = (int)tcp_listener_socket(l);
#ifdef LISTENER_IS_SOCKET
    int wake_fd = -1;
#else
    int wake_fd = (int)tcp_wake_handle(((listener *)(intptr_t)l)->wake);
#endif
    int ready;
    int fd;

    /* under load a connection is usually waiting already: take it before paying for a poll */
    fd = accept_one(sock, peer);
    if (fd >= 0) {
        return fd;
    }

    if (!accept_again(errno)) {
        return fail(err, errno);
    }

    deadline = deadline_of(timeout_ms);
    for (;;) {
        ready = wait_for(sock, POLLIN, deadline, wake_fd, err);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 2) {
            return fail_as(err, TCP_K_SHUTDOWN, 0);
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        fd = accept_one(sock, peer);
        if (fd >= 0) {
            return fd;
        }

        if (!accept_again(errno)) {
            return fail(err, errno);
        }

        if (left_ms(deadline) == 0) {
            return TCP_TIMEOUT;
        }
    }
}

int64_t tcp_try_accept(int64_t l, tcp_addr *peer, tcp_err *err)
{
    int fd = accept_one((int)tcp_listener_socket(l), peer);

    if (fd >= 0) {
        return fd;
    }

    if (accept_again(errno)) {
        return TCP_AGAIN;
    }

    return fail(err, errno);
}

void tcp_listener_cancel(int64_t l)
{
#ifdef LISTENER_IS_SOCKET
    (void)shutdown((int)l, SHUT_RDWR);
#else
    /* never drained: every accept after this finds it signalled */
    tcp_wake_signal(((listener *)(intptr_t)l)->wake);
#endif
}

void tcp_listener_close(int64_t l)
{
#ifdef LISTENER_IS_SOCKET
    if (l >= 0) {
        close((int)l);
    }
#else
    listener *it = (listener *)(intptr_t)l;

    if (it == NULL || l < 0) {
        return;
    }

    close(it->fd);
    tcp_wake_close(it->wake);
    free(it);
#endif
}

int64_t tcp_connect_start(const tcp_addr *to, int32_t *done, tcp_err *err)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fd;
    int code;

    *done = 0;
    if (to == NULL || to_sockaddr(to, &ss, &sl) != 0 || (to->family != TCP_FAMILY_UNIX && to->port == 0)) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    fd = open_socket(ss.ss_family);
    if (fd < 0) {
        return fail(err, errno);
    }

    if (prepare(fd) != 0) {
        code = errno;
        close(fd);
        return fail(err, code);
    }

    if (connect(fd, (struct sockaddr *)&ss, sl) == 0) {
        *done = 1;
        return fd;
    }

    code = errno;
    if (code == EINPROGRESS || code == EINTR) {
        return fd;
    }

    close(fd);
    /* a unix listener whose backlog is full answers EAGAIN: nobody takes the connection */
    if (code == EAGAIN && ss.ss_family == AF_UNIX) {
        return fail_as(err, TCP_K_REFUSED, ECONNREFUSED);
    }

    return fail(err, code);
}

/* the outcome of a connect the socket has reported writable for: 0, or TCP_ERR */
static int32_t connect_result(int fd, tcp_err *err)
{
    int soerr = 0;
    socklen_t solen = sizeof soerr;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) != 0) {
        return (int32_t)fail(err, errno);
    }

    if (soerr != 0) {
        return (int32_t)fail(err, soerr);
    }

    return 0;
}

int32_t tcp_connect_finish(int64_t h, tcp_err *err)
{
    int ready = wait_for((int)h, POLLOUT, deadline_of(0), -1, err);

    if (ready < 0) {
        return TCP_ERR;
    }

    if (ready == 0) {
        return TCP_AGAIN;
    }

    return connect_result((int)h, err);
}

int64_t tcp_connect(const tcp_addr *to, int32_t timeout_ms, tcp_err *err)
{
    int64_t deadline = deadline_of(timeout_ms);
    int32_t done;
    int64_t fd;
    int ready;

    fd = tcp_connect_start(to, &done, err);
    if (fd < 0 || done) {
        return fd;
    }

    ready = wait_for((int)fd, POLLOUT, deadline, -1, err);
    if (ready <= 0) {
        close((int)fd);
        return ready == 0 ? TCP_TIMEOUT : TCP_ERR;
    }

    if (connect_result((int)fd, err) != 0) {
        close((int)fd);
        return TCP_ERR;
    }

    return fd;
}

int32_t tcp_local(int64_t h, tcp_addr *out, tcp_err *err)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;

    if (getsockname((int)h, (struct sockaddr *)&ss, &sl) != 0) {
        return (int32_t)fail_on((int)h, err, errno);
    }

    from_sockaddr((struct sockaddr *)&ss, (size_t)sl, out);
    return 0;
}

int32_t tcp_unix_path_max(void)
{
    struct sockaddr_un un;

    return (int32_t)sizeof un.sun_path - 1;
}

int32_t tcp_socket_id(const char *path, tcp_file_id *out)
{
    struct stat st;

    /* lstat: a symlink to a socket is not one, and is never removed in its place */
    if (path == NULL || out == NULL || lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        return -1;
    }

    out->dev = (uint64_t)st.st_dev;
    out->ino = (uint64_t)st.st_ino;
    return 0;
}

int32_t tcp_unlink_socket(const char *path, const tcp_file_id *id)
{
    tcp_file_id now;

    if (id == NULL || tcp_socket_id(path, &now) != 0 || now.dev != id->dev || now.ino != id->ino) {
        return -1;
    }

    /* POSIX has no unlink by identity: one that swaps the file in between can write the directory, and could remove it as well */
    return unlink(path) == 0 ? 0 : -1;
}

int32_t tcp_unlink_stale(const char *path)
{
    tcp_file_id id;
    tcp_addr at;
    struct sockaddr_storage ss;
    socklen_t sl;
    size_t n;
    int fd;
    int rc;
    int code;

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
    if (to_sockaddr(&at, &ss, &sl) != 0) {
        return -1;
    }

    fd = open_socket(AF_UNIX);
    if (fd < 0) {
        return -1;
    }

    if (prepare(fd) != 0) {
        close(fd);
        return -1;
    }

    rc = connect(fd, (struct sockaddr *)&ss, sl);
    code = errno;
    close(fd);

    /*
     * Only a refusal says nothing listens. A live listener whose backlog is full answers EAGAIN on
     * Linux, and is left be; macOS refuses it with ECONNREFUSED like a dead one (c/tcp.h). The file
     * removed is the one probed, never one put on the path since.
     */
    if (rc == 0 || code != ECONNREFUSED) {
        return -1;
    }

    return tcp_unlink_socket(path, &id);
}

int64_t tcp_try_recv(int64_t h, uint8_t *buf, int64_t len, tcp_err *err)
{
    ssize_t got;

    if (len <= 0) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    if (len > IO_MAX) {
        len = IO_MAX;
    }

    do {
        got = recv((int)h, buf, (size_t)len, 0);
    } while (got < 0 && errno == EINTR);

    if (got > 0) {
        return (int64_t)got;
    }

    if (got == 0) {
        return TCP_EOF;
    }

    if (would_block(errno)) {
        return TCP_AGAIN;
    }

    return fail(err, errno);
}

int64_t tcp_recv(int64_t h, uint8_t *buf, int64_t len, int32_t timeout_ms, tcp_err *err)
{
    int64_t deadline = deadline_of(timeout_ms);
    int64_t got;
    int ready;

    if (len <= 0) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    for (;;) {
        ready = wait_for((int)h, POLLIN, deadline, -1, err);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        got = tcp_try_recv(h, buf, len, err);
        if (got != TCP_AGAIN) {
            return got;
        }

        if (left_ms(deadline) == 0) {
            return TCP_TIMEOUT;
        }
    }
}

/* one sendmsg of up to two buffers, IO_MAX in all, that never waits: bytes sent, TCP_AGAIN, or TCP_ERR */
static int64_t send_now(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, tcp_err *err)
{
    struct iovec iov[2];
    struct msghdr msg;
    ssize_t put;

    if (alen >= IO_MAX) {
        alen = IO_MAX;
        blen = 0;
    } else if (blen > IO_MAX - alen) {
        blen = IO_MAX - alen;
    }

    memset(&msg, 0, sizeof msg);
    iov[0].iov_base = (void *)a;
    iov[0].iov_len = (size_t)alen;
    iov[1].iov_base = (void *)b;
    iov[1].iov_len = (size_t)blen;
    msg.msg_iov = iov;
    msg.msg_iovlen = blen > 0 ? 2 : 1;

    do {
        put = sendmsg((int)h, &msg, SEND_FLAGS);
    } while (put < 0 && errno == EINTR);

    if (put >= 0) {
        return (int64_t)put;
    }

    if (would_block(errno)) {
        return TCP_AGAIN;
    }

    return fail(err, errno);
}

int64_t tcp_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, int32_t timeout_ms, tcp_err *err)
{
    int64_t deadline;
    int64_t put;
    int ready;

    /* a sum past INT64_MAX is no buffer anyone has, and would overflow below */
    if (alen < 0 || blen < 0 || alen > INT64_MAX - blen) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    if (alen + blen == 0) {
        return 0;
    }

    /* a send nearly always finds room: try it before paying for a poll */
    put = send_now(h, a, alen, b, blen, err);
    if (put != TCP_AGAIN) {
        return put;
    }

    deadline = deadline_of(timeout_ms);
    for (;;) {
        ready = wait_for((int)h, POLLOUT, deadline, -1, err);
        if (ready < 0) {
            return TCP_ERR;
        }

        if (ready == 0) {
            return TCP_TIMEOUT;
        }

        put = send_now(h, a, alen, b, blen, err);
        if (put != TCP_AGAIN) {
            return put;
        }

        if (left_ms(deadline) == 0) {
            return TCP_TIMEOUT;
        }
    }
}

int64_t tcp_try_sendv(int64_t h, const uint8_t *a, int64_t alen, const uint8_t *b, int64_t blen, tcp_err *err)
{
    /* a sum past INT64_MAX is no buffer anyone has, and would overflow below */
    if (alen < 0 || blen < 0 || alen > INT64_MAX - blen) {
        return fail_as(err, TCP_K_INVALID, EINVAL);
    }

    if (alen + blen == 0) {
        return 0;
    }

    return send_now(h, a, alen, b, blen, err);
}

int32_t tcp_shutdown(int64_t h, int32_t how, tcp_err *err)
{
    int mode = how == TCP_SHUT_READ ? SHUT_RD : how == TCP_SHUT_WRITE ? SHUT_WR : SHUT_RDWR;

    if (shutdown((int)h, mode) != 0) {
        return (int32_t)fail(err, errno);
    }

    return 0;
}

void tcp_cancel(int64_t h)
{
    /* a poll() on h wakes with POLLHUP, and every recv after this reads the end, every send fails */
    if (h >= 0) {
        (void)shutdown((int)h, SHUT_RDWR);
    }
}

void tcp_close(int64_t h)
{
    if (h >= 0) {
        (void)close((int)h);
    }
}

int32_t tcp_set_option(int64_t h, int32_t opt, int64_t value, tcp_err *err)
{
    /* clamped both ways: a cast alone keeps the low bits, and -(2^32) + 5 would be 5 */
    int v = value > 0x7fffffff ? 0x7fffffff : value < 0 ? 0 : (int)value;
    int rc;

    switch (opt) {
    case TCP_OPT_NODELAY:
        v = v != 0;
        rc = setsockopt((int)h, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v);
        break;
    case TCP_OPT_KEEPALIVE: {
        int on = v > 0;

        rc = setsockopt((int)h, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
        if (rc == 0 && on) {
#if defined(TCP_KEEPIDLE)
            rc = setsockopt((int)h, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v);
#elif defined(TCP_KEEPALIVE)
            rc = setsockopt((int)h, IPPROTO_TCP, TCP_KEEPALIVE, &v, sizeof v);
#endif
        }
        break;
    }
    case TCP_OPT_SEND_BUFFER:
        rc = setsockopt((int)h, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
        break;
    case TCP_OPT_RECV_BUFFER:
        rc = setsockopt((int)h, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
        break;
    default:
        return (int32_t)fail_as(err, TCP_K_INVALID, EINVAL);
    }

    if (rc != 0) {
        return (int32_t)fail_on((int)h, err, errno);
    }

    return 0;
}

/* a wake: the read end polls readable while signalled; on Linux both ends are one eventfd */
typedef struct wake {
    int rd;
    int wr;
} wake;

int64_t tcp_wake_open(tcp_err *err)
{
    wake *w = (wake *)malloc(sizeof *w);

    if (w == NULL) {
        return fail_as(err, TCP_K_OTHER, ENOMEM);
    }

#if defined(__linux__)
    w->rd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (w->rd < 0) {
        int code = errno;

        free(w);
        return fail(err, code);
    }

    w->wr = w->rd;
#else
    {
        int fds[2];

        if (pipe(fds) != 0) {
            int code = errno;

            free(w);
            return fail(err, code);
        }

        if (nonblocking_cloexec(fds[0]) != 0 || nonblocking_cloexec(fds[1]) != 0) {
            int code = errno;

            close(fds[0]);
            close(fds[1]);
            free(w);
            return fail(err, code);
        }

        w->rd = fds[0];
        w->wr = fds[1];
    }
#endif

    return (int64_t)(intptr_t)w;
}

int64_t tcp_wake_handle(int64_t w)
{
    return w != 0 ? ((wake *)(intptr_t)w)->rd : -1;
}

void tcp_wake_signal(int64_t w)
{
    uint64_t one = 1;
    ssize_t put;

    if (w == 0) {
        return;
    }

    /* a full pipe or a saturated counter is already signalled */
    do {
#if defined(__linux__)
        put = write(((wake *)(intptr_t)w)->wr, &one, sizeof one);
#else
        put = write(((wake *)(intptr_t)w)->wr, &one, 1);
#endif
    } while (put < 0 && errno == EINTR);
}

void tcp_wake_drain(int64_t w)
{
    uint8_t buf[64];
    ssize_t got;

    if (w == 0) {
        return;
    }

    do {
        got = read(((wake *)(intptr_t)w)->rd, buf, sizeof buf);
    } while (got > 0 || (got < 0 && errno == EINTR));
}

int32_t tcp_wake_wait(int64_t w, int32_t timeout_ms)
{
    if (w == 0) {
        return TCP_ERR;
    }

    return (int32_t)wait_for((int)tcp_wake_handle(w), POLLIN, deadline_of(timeout_ms), -1, NULL);
}

void tcp_wake_close(int64_t w)
{
    wake *it = (wake *)(intptr_t)w;

    if (it == NULL) {
        return;
    }

    close(it->rd);
    if (it->wr != it->rd) {
        close(it->wr);
    }

    free(it);
}

int32_t tcp_error_text(int32_t kind, int32_t code, char *buf, int32_t len)
{
    if (buf == NULL || len <= 0) {
        return 0;
    }

    buf[0] = '\0';

    if (kind == TCP_K_RESOLVE) {
        /* getaddrinfo codes: negative on glibc, positive on macOS, and never errno */
        snprintf(buf, (size_t)len, "%s", gai_strerror(code));
        return (int32_t)strlen(buf);
    }

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

#if defined(TCP_EPOLL)

int64_t tcp_poll_open(tcp_err *err)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);

    if (ep < 0) {
        return fail(err, errno);
    }

    return ep;
}

int32_t tcp_poll_ctl(int64_t p, int32_t op, int64_t h, uint64_t token, int32_t interest, int32_t oneshot, tcp_err *err)
{
    struct epoll_event ev;
    int how = op == TCP_POLL_ADD ? EPOLL_CTL_ADD : op == TCP_POLL_MODIFY ? EPOLL_CTL_MOD : EPOLL_CTL_DEL;

    /* an op it does not know is a mistake, never a remove */
    if (op != TCP_POLL_ADD && op != TCP_POLL_MODIFY && op != TCP_POLL_REMOVE) {
        return (int32_t)fail_as(err, TCP_K_INVALID, EINVAL);
    }

    memset(&ev, 0, sizeof ev);
    if (interest & TCP_EV_READ) {
        ev.events |= EPOLLIN | EPOLLRDHUP;
    }

    if (interest & TCP_EV_WRITE) {
        ev.events |= EPOLLOUT;
    }

    if (oneshot) {
        ev.events |= EPOLLONESHOT;
    }

    ev.data.u64 = token;

    if (epoll_ctl((int)p, how, (int)h, &ev) != 0) {
        return (int32_t)fail(err, errno);
    }

    return 0;
}

int32_t tcp_poll_wait(int64_t p, tcp_event *out, int32_t max, int32_t timeout_ms, tcp_err *err)
{
    struct epoll_event events[TCP_POLL_BATCH];
    int64_t deadline = deadline_of(timeout_ms);
    int n;
    int i;

    if (max <= 0) {
        return 0;
    }

    if (max > TCP_POLL_BATCH) {
        max = TCP_POLL_BATCH;
    }

    /* a signal cuts the wait short; 0 has to mean the deadline passed, so wait out the rest */
    do {
        n = epoll_wait((int)p, events, max, left_ms(deadline));
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        return (int32_t)fail(err, errno);
    }

    for (i = 0; i < n; i++) {
        uint32_t e = events[i].events;
        uint32_t flags = 0;

        if (e & EPOLLIN) {
            flags |= TCP_EV_READ;
        }

        if (e & EPOLLOUT) {
            flags |= TCP_EV_WRITE;
        }

        if (e & (EPOLLHUP | EPOLLRDHUP)) {
            flags |= TCP_EV_HANGUP;
        }

        if (e & EPOLLERR) {
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
    if (p >= 0) {
        close((int)p);
    }
}

#else

/*
 * kqueue has no registration, only a filter per handle and direction, so the contract is
 * rebuilt on top of it. The poller keeps the token each handle was added with, by fd: an ADD of
 * a handle it holds probes the kernel with that token (any touch rewrites udata, so the probe
 * carries the one already there) and refuses with EEXIST. A probe that finds nothing means the
 * handle was closed without a remove, and the kernel dropped its filters with the fd. A MODIFY
 * deletes both filters and adds them again, the only way to clear EV_DISPATCH; finding neither
 * to delete, it takes its add back and answers ENOENT, as a REMOVE does.
 */
typedef struct kpoll {
    int kq;
    pthread_mutex_t lock;
    uint64_t *tokens;
    uint8_t *held;
    int cap;
} kpoll;

/*
 * Merging the two kevents of one handle looks each token up in a table on
 * the stack, linear probing: twice TCP_POLL_BATCH slots, so it never fills, and
 * a full batch costs n lookups rather than n * n / 2 comparisons.
 */
#define MERGE_SLOTS (TCP_POLL_BATCH * 2)

static uint32_t merge_slot(uint64_t token)
{
    /* the murmur3 finalizer: tokens are often small and sequential */
    token ^= token >> 33;
    token *= 0xff51afd7ed558ccdULL;
    token ^= token >> 33;
    return (uint32_t)token & (MERGE_SLOTS - 1);
}

int64_t tcp_poll_open(tcp_err *err)
{
    kpoll *p = calloc(1, sizeof *p);
    int code;

    if (p == NULL) {
        return fail(err, ENOMEM);
    }

    /* a kqueue is never inherited by a child, and takes no fcntl flags */
    p->kq = kqueue();
    if (p->kq < 0) {
        code = errno;
        free(p);
        return fail(err, code);
    }

    pthread_mutex_init(&p->lock, NULL);
    return (int64_t)(intptr_t)p;
}

/* room for fd in the token table: 0, or -1 out of memory */
static int poll_reserve(kpoll *p, int fd)
{
    int cap = p->cap > 0 ? p->cap : 64;
    uint64_t *tokens;
    uint8_t *held;

    if (fd < p->cap) {
        return 0;
    }

    /* the doubling below would overflow an int */
    if (fd >= 0x3fffffff) {
        return -1;
    }

    while (cap <= fd) {
        cap *= 2;
    }

    tokens = realloc(p->tokens, (size_t)cap * sizeof *tokens);
    if (tokens == NULL) {
        return -1;
    }

    p->tokens = tokens;
    held = realloc(p->held, (size_t)cap);
    if (held == NULL) {
        return -1;
    }

    memset(held + p->cap, 0, (size_t)(cap - p->cap));
    p->held = held;
    p->cap = cap;
    return 0;
}

static void poll_change(struct kevent *ev, int fd, int16_t filter, unsigned short flags, uint64_t token)
{
    EV_SET(ev, (uintptr_t)fd, filter, flags | EV_RECEIPT, 0, 0, (void *)(uintptr_t)token);
}

/*
 * Apply changes that each carry EV_RECEIPT, so the kernel answers every one and never waits: how
 * many found no filter (ENOENT), or -1 with err set on any other failure.
 */
static int poll_apply(kpoll *p, struct kevent *changes, int n, tcp_err *err)
{
    struct kevent results[4];
    int missing = 0;
    int got;
    int i;

    got = kevent(p->kq, changes, n, results, n, NULL);
    if (got < 0) {
        fail(err, errno);
        return -1;
    }

    for (i = 0; i < got; i++) {
        int code = (int)results[i].data;

        if (!(results[i].flags & EV_ERROR) || code == 0) {
            continue;
        }

        if (code != ENOENT) {
            fail(err, code);
            return -1;
        }

        missing++;
    }

    return missing;
}

int32_t tcp_poll_ctl(int64_t handle, int32_t op, int64_t h, uint64_t token, int32_t interest, int32_t oneshot, tcp_err *err)
{
    kpoll *p = (kpoll *)(intptr_t)handle;
    struct kevent changes[4];
    unsigned short on = EV_ADD | EV_ENABLE | (oneshot ? EV_DISPATCH : 0);
    int fd = (int)h;
    int n = 0;
    int missing;
    int32_t rc = 0;

    if (fd < 0) {
        return (int32_t)fail(err, EBADF);
    }

    /* an op it does not know is a mistake, never a remove */
    if (op != TCP_POLL_ADD && op != TCP_POLL_MODIFY && op != TCP_POLL_REMOVE) {
        return (int32_t)fail_as(err, TCP_K_INVALID, EINVAL);
    }

    pthread_mutex_lock(&p->lock);

    if (op == TCP_POLL_ADD) {
        if (fd < p->cap && p->held[fd]) {
            poll_change(&changes[0], fd, EVFILT_READ, 0, p->tokens[fd]);
            poll_change(&changes[1], fd, EVFILT_WRITE, 0, p->tokens[fd]);
            missing = poll_apply(p, changes, 2, err);
            if (missing < 0) {
                rc = TCP_ERR;
                goto out;
            }

            if (missing < 2) {
                rc = (int32_t)fail(err, EEXIST);
                goto out;
            }

            p->held[fd] = 0;
        }

        if (poll_reserve(p, fd) != 0) {
            rc = (int32_t)fail(err, ENOMEM);
            goto out;
        }
    } else {
        poll_change(&changes[n++], fd, EVFILT_READ, EV_DELETE, token);
        poll_change(&changes[n++], fd, EVFILT_WRITE, EV_DELETE, token);
    }

    if (op != TCP_POLL_REMOVE) {
        if (interest & TCP_EV_READ) {
            poll_change(&changes[n++], fd, EVFILT_READ, on, token);
        }

        if (interest & TCP_EV_WRITE) {
            poll_change(&changes[n++], fd, EVFILT_WRITE, on, token);
        }
    }

    missing = poll_apply(p, changes, n, err);
    if (missing < 0) {
        rc = TCP_ERR;
        goto out;
    }

    /* only a delete can miss: an add never answers ENOENT */
    if (op != TCP_POLL_ADD && missing == 2) {
        if (op == TCP_POLL_MODIFY) {
            /* it was never added: take back what this added */
            poll_change(&changes[0], fd, EVFILT_READ, EV_DELETE, token);
            poll_change(&changes[1], fd, EVFILT_WRITE, EV_DELETE, token);
            poll_apply(p, changes, 2, NULL);
        }

        if (fd < p->cap) {
            p->held[fd] = 0;
        }

        rc = (int32_t)fail(err, ENOENT);
        goto out;
    }

    if (fd < p->cap) {
        p->held[fd] = op != TCP_POLL_REMOVE;
        p->tokens[fd] = token;
    }

out:
    pthread_mutex_unlock(&p->lock);
    return rc;
}

int32_t tcp_poll_wait(int64_t handle, tcp_event *out, int32_t max, int32_t timeout_ms, tcp_err *err)
{
    kpoll *p = (kpoll *)(intptr_t)handle;
    struct kevent events[TCP_POLL_BATCH];
    struct kevent twins[TCP_POLL_BATCH];
    int idents[TCP_POLL_BATCH];
    uint8_t fired[TCP_POLL_BATCH];
    uint8_t dispatch[TCP_POLL_BATCH];
    int16_t slots[MERGE_SLOTS];
    struct timespec ts;
    int64_t deadline = deadline_of(timeout_ms);
    int wait;
    int n;
    int i;
    int k = 0;
    int32_t count = 0;

    if (max <= 0) {
        return 0;
    }

    if (max > TCP_POLL_BATCH) {
        max = TCP_POLL_BATCH;
    }

    /* a signal cuts the wait short; 0 has to mean the deadline passed, so wait out the rest */
    do {
        wait = left_ms(deadline);
        ts.tv_sec = wait / 1000;
        ts.tv_nsec = (long)(wait % 1000) * 1000000L;
        n = kevent(p->kq, NULL, 0, events, max, wait < 0 ? NULL : &ts);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        return (int32_t)fail(err, errno);
    }

    /* a handle ready both ways comes back as two kevents: one event per token */
    memset(slots, 0xff, sizeof slots);
    for (i = 0; i < n; i++) {
        uint64_t token = (uint64_t)(uintptr_t)events[i].udata;
        uint32_t flags = 0;
        uint32_t at;

        if (events[i].filter == EVFILT_READ) {
            flags |= TCP_EV_READ;
        } else if (events[i].filter == EVFILT_WRITE) {
            flags |= TCP_EV_WRITE;
        }

        if (events[i].flags & EV_EOF) {
            flags |= TCP_EV_HANGUP;
            if (events[i].fflags != 0) {
                flags |= TCP_EV_ERROR;
            }
        }

        if (events[i].flags & EV_ERROR) {
            flags |= TCP_EV_ERROR;
        }

        at = merge_slot(token);
        while (slots[at] >= 0 && out[slots[at]].token != token) {
            at = (at + 1) & (MERGE_SLOTS - 1);
        }

        if (slots[at] >= 0) {
            out[slots[at]].flags |= flags;
            fired[slots[at]] |= (uint8_t)(flags & (TCP_EV_READ | TCP_EV_WRITE));
            continue;
        }

        slots[at] = (int16_t)count;
        out[count].token = token;
        out[count].flags = flags;
        out[count].pad = 0;
        idents[count] = (int)events[i].ident;
        fired[count] = (uint8_t)(flags & (TCP_EV_READ | TCP_EV_WRITE));
        dispatch[count] = (events[i].flags & EV_DISPATCH) != 0;
        count++;
    }

    /*
     * A oneshot .both is two knotes, and EV_DISPATCH stops only the one that fired: stop its twin
     * before the token goes out, so the registration reports once until a MODIFY. The twin may
     * not exist (a oneshot .read), which is an ENOENT receipt and nothing to stop. Two threads
     * waiting on one poller can still each take one half in the moment between.
     */
    for (i = 0; i < count; i++) {
        if (dispatch[i] && fired[i] != (TCP_EV_READ | TCP_EV_WRITE)) {
            int16_t twin = (fired[i] & TCP_EV_READ) ? EVFILT_WRITE : EVFILT_READ;

            poll_change(&twins[k++], idents[i], twin, EV_DISABLE, out[i].token);
        }
    }

    if (k > 0) {
        /* the receipts land in events, which is spent */
        kevent(p->kq, twins, k, events, k, NULL);
    }

    return count;
}

void tcp_poll_close(int64_t handle)
{
    kpoll *p = (kpoll *)(intptr_t)handle;

    if (p == NULL) {
        return;
    }

    close(p->kq);
    pthread_mutex_destroy(&p->lock);
    free(p->tokens);
    free(p->held);
    free(p);
}

#endif
