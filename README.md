# libtcp

TCP sockets and length-prefixed frames for Echo. IPv4, blocking calls with explicit timeouts, no TLS, no HTTP.

The platform layer is C behind one contract (`c/tcp.h`). Everything above it is Echo: the read and write loops, the frames, and the threads that use them (`std::thread`).

| Platform | Backend | State |
|---|---|---|
| macOS, Linux | `c/posix.c` | done |
| Windows | `c/win32.c` (Winsock) | done |

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
- `writeFrame(stream, body, timeoutMs)` sends prefix and body under one deadline. A body up to 64 KiB is copied behind its prefix and goes out as one write (one packet); a larger one is sent as prefix, then body, never copied.
- A body `read` hands back shares the reader's buffer when it is most of it, and is copied out when it is small, so a caller that keeps small bodies does not keep 64 KiB read buffers alive.
- `FrameReader(max, idleMs = -1)` turns a connection's bytes back into frames. `read(stream, timeoutMs)` waits up to the timeout for a whole frame, however many reads that takes, and returns its body; null means the timeout passed first. A partial frame is kept for the next call, so short timeouts never drop bytes. With `idleMs`, a reader that gets no whole frame for that long (from construction, or from the last frame) answers `FrameError.idle`, even partway through a longer or endless `read`. Bytes that trickle in without completing a frame do not reset it.

A prefix over `max` is `FrameError.tooLarge` before anything is allocated. Text that is not a frame lands there: an HTTP request line (`GET `) reads as more than a gigabyte. A peer that closes between frames is `closed`; one that closes partway through a frame is `truncated`.

## The platform contract

`c/tcp.h` is the only thing a backend implements:

- **Handles** are `int64_t`, so a POSIX fd and a Winsock `SOCKET` both fit.
- **Return codes:** every call returns 0 or more on success, `TCP_ERR` (-1) on failure (the OS code from `tcp_last_error()`, kept per thread), `TCP_CLOSED` (-2) when the peer closed, and `TCP_TIMEOUT` (-3) when the wait ran out.
- **`timeout_ms`:** -1 waits forever, 0 polls once.
- No call raises a signal, and no handle is inherited by a child process.

| Concern | `posix.c` | `win32.c` |
|---|---|---|
| Init | nothing | `WSAStartup(2.2)` once (`InitOnceExecuteOnce`) in `tcp_listen` / `tcp_connect` |
| Socket | `socket`, `FD_CLOEXEC`, `O_NONBLOCK` | `WSASocketW(..., WSA_FLAG_NO_HANDLE_INHERIT)`, `ioctlsocket(FIONBIO)`; accepted sockets also `SetHandleInformation` |
| Rebind | `SO_REUSEADDR` | `SO_EXCLUSIVEADDRUSE` (Windows `SO_REUSEADDR` lets a second socket take a bound port) |
| Wait | `poll` | accept and connect: `select` with `exceptfds` (`WSAPoll` missed failed connects before Windows 10 2004); recv and send: overlapped `WSARecv` / `WSASend` on an event of their own, `CancelIoEx` at the deadline (see below) |
| Connect | non-blocking connect, wait writable, `SO_ERROR` | the same; `WSAEWOULDBLOCK` is in progress, always check `SO_ERROR` |
| No SIGPIPE | `MSG_NOSIGNAL` / `SO_NOSIGPIPE` | not needed |
| Closed | `recv` 0, `ECONNRESET`, `EPIPE` | `recv` 0, `WSAECONNRESET`, `WSAECONNABORTED`, `WSAESHUTDOWN` |
| Lengths | `size_t` | `int`: `recv` clamps to `INT_MAX`, `send` to 64 KiB (see below) |
| Close | `close`, `shutdown(SHUT_WR)` | `closesocket`, `shutdown(SD_SEND)` |
| Clock | `CLOCK_MONOTONIC` | `GetTickCount64` |
| Last error | `__thread` | `__declspec(thread)` |
| Errors | `errno`, `strerror_r` | `WSAGetLastError`, `FormatMessageW` as UTF-8 |

A Winsock `send` takes the whole call into the kernel whenever the buffer has any room, so one large call to a peer that never reads would return at once. `win32.c` hands it at most 64 KiB per call, so a full buffer pushes back and `writeAll`'s deadline holds.

Reads and writes on a connection are overlapped, not readiness-based, because readiness fails on Windows when two threads use one socket. While one thread waits in `select` (or `WSAPoll`) to read, another thread's wait to write wakes late or not at all, and a 2 MiB write that takes 16 ms alone times out after seconds. Each overlapped call waits on its own event, so a reader thread and a writer thread never meet.

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
- **One reader and one writer per `Stream` at a time.** One thread may read while another writes (full duplex). Two readers, or two writers, interleave bytes. Closing a stream on one thread while another is in a call on it can hit a recycled descriptor (or `SOCKET`), so close only once the others are done.
- **CLOEXEC on macOS.** Linux creates every socket `CLOEXEC` atomically (`SOCK_CLOEXEC`, `accept4`). macOS has no such call: the flag is set right after, and a `fork` + `exec` on another thread in that gap inherits the descriptor. Spawn children with `POSIX_SPAWN_CLOEXEC_DEFAULT` where it matters.
- **Windows.** A connect to a closed port can come back as `timeout` rather than a connect error: Windows retries a refused SYN for about two seconds. A reset from the peer drops bytes this side has not read yet. A listener's port cannot be bound again while connections it accepted are still open (`SO_EXCLUSIVEADDRUSE`).
- **Slow peers are the caller's policy.** Use `FrameReader`'s `idleMs` and a `writeAll` deadline, and cap connections; the library does not.

`tests/` is the conformance suite. It is written against the Echo API only, so a backend is done when `echoc test` passes unchanged on its platform.

## Test

```bash
echoc test
```
