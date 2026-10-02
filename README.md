# libtcp

TCP sockets and length-prefixed frames for Echo. IPv4, blocking calls with explicit timeouts, no TLS, no HTTP.

The platform layer is C behind one contract (`c/tcp.h`). Everything above it is Echo: the read and write loops, the frames, and the threads that use them (`std::thread`).

| Platform | Backend | State |
|---|---|---|
| macOS, Linux | `c/posix.c` | done |
| Windows | `c/win32.c` (Winsock) | TODO |

## Use

```echo
#[depends: "../libtcp"]
```

```echo
tcp::Listener $l = guard tcp::Listener::open('127.0.0.1', 0) else ($e) {
    die($e->message());
}
int32 $port = $l->port();

// accept with a timeout so the loop can check a stop flag
tcp::Stream? $maybe = guard $l->accept(100) else ($e) {
    die($e->message());
}

tcp::Stream $client = guard tcp::Stream::connect('127.0.0.1', $port) else ($e) {
    die($e->message());
}
guard tcp::writeFrame($client, 'ping') else ($e) {
    die($e->message());
}
```

- `Listener::open(host, port, backlog = 16)`: `0.0.0.0` is every interface. An empty host is refused (`badHost`), so nothing listens wider than it asked. Port 0 lets the OS pick one; `port()` reads it back. `accept(timeoutMs)` returns null when nobody connected in time.
- `Stream::connect(host, port, timeoutMs = 5000)`, `recv(buf, n, timeoutMs)`, `append(string&, most, timeoutMs)`, `writeAll(bytes, timeoutMs)`, `shutdownWrite()`, `close()`. A `Stream` closes when it is dropped.
- `writeAll`'s timeout covers the whole write, not each send, so a peer that reads a byte at a time cannot hold the writer past it. A `timeout` there leaves an unknown part sent; drop the stream.
- `Error` covers `bind`, `connect`, `accept` and `io` (each with the OS text), plus `closed`, `timeout`, `badPort`, `badHost` and `tooLarge`. A `timeout` on a read or an accept loses nothing: call again.

## Frames

A frame is a `uint32` big-endian byte count followed by that many bytes.

- `frame(body)`, `frameHeader(uint32)`, `frameLength(bytes)` and `frameFits(size)` are pure. A body over `FRAME_MAX` (4 GiB - 1) is `tooLarge`, never a prefix cut to 32 bits: a wrapped length would make the receiver read the rest of the body as frames of its own.
- `writeFrame(stream, body, timeoutMs)` sends prefix and body in one write.
- `FrameReader(max, idleMs = -1)` turns a connection's bytes back into frames. `read(stream, timeoutMs)` returns a body, or null when the timeout passed first. A partial frame is kept for the next call, so short timeouts never drop bytes. With `idleMs`, a reader that gets no whole frame for that long (from construction, or from the last frame) answers `FrameError.idle`. Bytes that trickle in without completing a frame do not reset it.

A prefix over `max` is `FrameError.tooLarge` before anything is allocated. Text that is not a frame lands there: an HTTP request line (`GET `) reads as more than a gigabyte. A peer that closes between frames is `closed`; one that closes partway through a frame is `truncated`.

## The platform contract

`c/tcp.h` is the only thing a backend implements:

- **Handles** are `int64_t`, so a POSIX fd and a Winsock `SOCKET` both fit.
- **Return codes:** every call returns 0 or more on success, `TCP_ERR` (-1) on failure (the OS code from `tcp_last_error()`, kept per thread), `TCP_CLOSED` (-2) when the peer closed, and `TCP_TIMEOUT` (-3) when the wait ran out.
- **`timeout_ms`:** -1 waits forever, 0 polls once.
- No call raises a signal, and no handle is inherited by a child process.

| Concern | `posix.c` | `win32.c` (to write) |
|---|---|---|
| Init | nothing | `WSAStartup(2.2)` once (`InitOnceExecuteOnce`) in `tcp_listen` / `tcp_connect` |
| Socket | `socket`, `FD_CLOEXEC`, `O_NONBLOCK` | `WSASocketW(..., WSA_FLAG_NO_HANDLE_INHERIT)`, `ioctlsocket(FIONBIO)` |
| Rebind | `SO_REUSEADDR` | `SO_EXCLUSIVEADDRUSE` |
| Wait | `poll` | `WSAPoll` |
| Connect | non-blocking connect, wait writable, `SO_ERROR` | the same; always check `SO_ERROR` |
| No SIGPIPE | `MSG_NOSIGNAL` / `SO_NOSIGPIPE` | not needed |
| Closed | `recv` 0, `ECONNRESET`, `EPIPE` | `recv` 0, `WSAECONNRESET`, `WSAECONNABORTED` |
| Lengths | `size_t` | `int`: clamp each call to `INT_MAX` |
| Close | `close`, `shutdown(SHUT_WR)` | `closesocket`, `shutdown(SD_SEND)` |
| Errors | `errno`, `strerror` | `WSAGetLastError`, `FormatMessageA` |

The manifest picks the backend:

```
#[if: os == windows]
#[cc: sources "c/win32.c"]
#[link: lib "ws2_32"]
#[else]
#[cc: sources "c/posix.c"]
#[end]
```

## Limits

- **Name lookup is not bounded.** `connect` resolves a host name with `getaddrinfo` before its timeout starts, and a DNS stall blocks it. Pass an address where that matters.
- **One thread per `Stream` at a time.** Closing a stream on one thread while another reads it can hit a recycled descriptor. Hand a stream over; do not share it.
- **CLOEXEC on macOS.** Linux creates every socket `CLOEXEC` atomically (`SOCK_CLOEXEC`, `accept4`). macOS has no such call: the flag is set right after, and a `fork` + `exec` on another thread in that gap inherits the descriptor. Spawn children with `POSIX_SPAWN_CLOEXEC_DEFAULT` where it matters.
- **Slow peers are the caller's policy.** Use `FrameReader`'s `idleMs` and a `writeAll` deadline, and cap connections; the library does not.

`tests/` is the conformance suite. It is written against the Echo API only, so a backend is done when `echoc test` passes unchanged on its platform.

## Test

```bash
echoc test
```
