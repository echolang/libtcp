/*
 * libtcp: what both backends share. Not part of the contract: each of
 * c/posix.c and c/win32.c includes this once, after its platform headers,
 * and defines the two hooks (kind_of, now_ms).
 *
 * struct sockaddr_storage and socklen_t are spelled the same on both:
 * Winsock's ws2tcpip.h defines socklen_t as int.
 */

#ifndef LIBTCP_COMMON_H
#define LIBTCP_COMMON_H

#include "tcp.h"

#include <stddef.h>
#include <string.h>

/* the platform's error number as a TCP_K_* kind */
static int32_t kind_of(int code);

/* a monotonic clock in milliseconds */
static int64_t now_ms(void);

static int64_t fail_as(tcp_err *err, int32_t kind, int code)
{
    if (err != NULL) {
        err->kind = kind;
        err->code = (int32_t)code;
    }

    return TCP_ERR;
}

static int64_t fail(tcp_err *err, int code)
{
    return fail_as(err, kind_of(code), code);
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

/* 0, or -1 for an unknown family or a unix path that is empty or does not fit */
static int to_sockaddr(const tcp_addr *a, struct sockaddr_storage *ss, socklen_t *len)
{
    memset(ss, 0, sizeof *ss);

    if (a->family == TCP_FAMILY_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)ss;
        size_t n = strnlen((const char *)a->path, sizeof a->path);

        if (n == 0 || n >= sizeof un->sun_path) {
            return -1;
        }

        un->sun_family = AF_UNIX;
        memcpy(un->sun_path, a->path, n);
#ifdef TCP_SUN_LEN
        un->sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
#endif
        *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
        return 0;
    }

    if (a->family == 4) {
        struct sockaddr_in *in = (struct sockaddr_in *)ss;

        in->sin_family = AF_INET;
        in->sin_port = htons(a->port);
        memcpy(&in->sin_addr, a->bytes, 4);
        *len = (socklen_t)sizeof *in;
        return 0;
    }

    if (a->family == 6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;

        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(a->port);
        in6->sin6_scope_id = a->scope;
        memcpy(&in6->sin6_addr, a->bytes, 16);
        *len = (socklen_t)sizeof *in6;
        return 0;
    }

    return -1;
}

/* sl is the length the OS gave: a unix peer that never bound comes back with no path in it */
static void from_sockaddr(const struct sockaddr *sa, size_t sl, tcp_addr *a)
{
    memset(a, 0, sizeof *a);

    if (sa->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
        size_t off = offsetof(struct sockaddr_un, sun_path);
        size_t n;

        a->family = TCP_FAMILY_UNIX;
        if (sl <= off || un->sun_path[0] == '\0') {
            return;
        }

        n = sl - off;
        if (n > sizeof un->sun_path) {
            n = sizeof un->sun_path;
        }

        n = strnlen(un->sun_path, n);
        if (n >= sizeof a->path) {
            n = sizeof a->path - 1;
        }

        memcpy(a->path, un->sun_path, n);
        return;
    }

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;

        a->family = 4;
        a->port = ntohs(in->sin_port);
        memcpy(a->bytes, &in->sin_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;

        a->family = 6;
        a->port = ntohs(in6->sin6_port);
        a->scope = in6->sin6_scope_id;
        memcpy(a->bytes, &in6->sin6_addr, 16);
    }
}

/* the address as text: a unix path is itself, so there is nothing to ask the OS */
static int32_t unix_text(const tcp_addr *addr, char *buf, int32_t len)
{
    size_t n = strnlen((const char *)addr->path, sizeof addr->path);

    if ((size_t)len <= n) {
        n = (size_t)len - 1;
    }

    memcpy(buf, addr->path, n);
    buf[n] = '\0';
    return (int32_t)n;
}

#endif
