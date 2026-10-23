# libtcp

TCP sockets for Echo. Bind, connect, accept, and move bytes, with a deadline on every wait.

- `Listener`, `Stream`, `Address`
- IPv4, IPv6, and unix sockets
- a `Poller` (epoll, kqueue, wepoll)
- a buffered `Reader`, an `Outbox`, length-prefixed frames

## Installation

From your project directory:

```bash
epm add echolang/libtcp --git https://github.com/echolang/libtcp --range ^0.2
```

That writes a `#[requires:]` line and vendors the sources. The C shim travels with the module, so you never write a `#[cc:]` yourself.

darwin, linux, and windows, matching Echo's prebuilts. Windows is Winsock, with readiness from the wepoll copy under `c/wepoll/`.

## Quick start

Bind, connect, accept, write, read:

```echo
tcp::Listener $l = guard tcp::Listener::bind(tcp::Address(loopback: 0)) else ($e) {
    die("listen: {$e}");
}

tcp::Stream $client = guard tcp::Stream::connect($l->local, tcp::Deadline(ms: 1000)) else ($e) {
    die("connect: {$e}");
}

tcp::Stream? $maybe = guard $l->accept(tcp::Deadline(ms: 1000)) else ($e) {
    die("accept: {$e}");
}
tcp::Stream $server = guard $maybe else {
    die('no client');
}

guard $client->write('hello', tcp::Deadline(ms: 1000)) else ($e) {
    die("write: {$e}");
}

string $buf = '';
guard $server->read($buf, 5, tcp::Deadline(ms: 1000)) else ($e) {
    die("read: {$e}");
}

echo $buf;
```

Port `0` is ephemeral. `$l->local->port` is the one the OS picked.

`accept` and `read` returning null means the deadline passed with nothing. That is not an error. Nothing was lost. Call again.

`Stream::pair($by)` is this setup without the listener left around: two ends of one loopback connection, for tests.

The poller shape lives in `examples/reactor/`.

## Addresses

A listener and a connect take an `Address`. Names come in through `resolve`, a call of its own, so it can be made once, on another thread, or not at all.

```echo
tcp::Address $loop = tcp::Address(loopback: 8080);          // 127.0.0.1
tcp::Address $v6   = tcp::Address(loopback: 8080, .v6);     // ::1
tcp::Address $all  = tcp::Address(any: 8080);               // 0.0.0.0
tcp::Address $sock = tcp::Address(unix: '/tmp/app.sock');
```

`Address::parse` is numeric, no DNS: `'127.0.0.1:80'`, `'[::1]:80'`, `'unix:/tmp/app.sock'`. An IPv6 address without brackets is refused, not split at its last colon: `1::2:3` is an address of its own, not `[1::2]:3`. IPv4 shorthands (`127.1`, `2130706433`) are `.invalid`. `"{$a}"` prints the same forms, and `parse` reads them back.

An empty host is refused. If you mean every interface, write `0.0.0.0` or `::`.

```echo
array<tcp::Address> $addrs = guard tcp::resolve('example.com', 443) else ($e) {
    die("{$e}");
}
```

That lookup waits as long as DNS takes. A deadline needs the other `resolve`, which runs `getaddrinfo` on a thread of its own:

```echo
array<tcp::Address> $addrs = guard tcp::resolve('example.com', 443, tcp::Deadline(ms: 2000)) else ($e) {
    die("{$e}");
}
```

A lookup that outlives its deadline finishes on its thread and the answer is dropped. `Lookup::start` is the same thing when you want to poll for it, or have a `Poller` woken when it is in (`start($host, $port, notify: $poller)`). A numeric host starts no thread. At most 64 lookups run at once; past that, `start` fails.

## Deadlines

One deadline flows through every step of a composed call: each resolved address of a connect, the prefix and body of a frame. The whole call is bounded, not each step.

```echo
tcp::Deadline $by = tcp::Deadline(ms: 1000);
```

`Deadline(after: $span)` is the same idea from a `time::duration`. A duration converts implicitly, so `connect($addr, time::duration::secs(1))` is a deadline too. `never()` waits as long as it takes. `now()` looks once and does not wait.

`earlier` takes whichever of two passes first. `remaining` is the time left, zero once passed, null for `never()`.

## Listen and accept

`bind` takes an address, or a host and a port. The host form resolves for listening and binds the first address that takes.

```echo
tcp::Listener $l = guard tcp::Listener::bind(tcp::Address(loopback: 0)) else ($e) {
    die("{$e}");
}

tcp::Listener $l = guard tcp::Listener::bind(host: '127.0.0.1', 8080) else ($e) {
    die("{$e}");
}
```

`accept($by)` waits for a connection, or returns null if nobody connected in time. `tryAccept` is the same with no wait, for a reactor. A connection the peer reset before it could be set up is skipped, not reported.

`close` is safe from any thread. An accept blocked on the listener wakes with `.closed`, and the port is free as soon as no call is inside.

`ListenOptions` is plain data, applied at bind:

- `backlog` 128: how many finished handshakes may wait for an accept
- `reusePort` off: several listeners on the same port, POSIX only (`SO_REUSEPORT`)
- `dualStack` off: a listener takes the family it was given. On, an IPv6 `::` listener takes IPv4 too
- `accepted`: the `StreamOptions` every accepted stream starts with

## Connect

One address, before the deadline:

```echo
tcp::Stream $s = guard tcp::Stream::connect($addr, tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
}
```

A host name resolves and connects to whichever of its addresses answers first, all before the one deadline. The addresses race Happy Eyeballs style (RFC 8305): the families take turns, a new attempt starts every 250ms (or as soon as the latest fails) while the earlier ones keep going, so one address that drops packets cannot use up the deadline. A failure is the last attempt's.

```echo
tcp::Stream $s = guard tcp::Stream::connect(host: 'example.com', 443, tcp::Deadline(ms: 5000)) else ($e) {
    die("{$e}");
}
```

For a reactor, `Stream::start` does not wait. Register the `Connecting` with a `Poller` for `.write`, and call `tryFinish` when it reports. On success the handle belongs to the stream, and a registration with a poller carries over: `modify` it with the stream from here on. A failure leaves the handle here for `close`, after the poller has let go of it.

```echo
tcp::Connecting $c = guard tcp::Stream::start($addr) else ($e) {
    die("{$e}");
}
guard $poller->add($c, 1, .write, .oneshot) else ($e) {
    die("{$e}");
}
```

A connect needs a port 1..65535. Port 0 is `.invalid`.

## Read and write

`read` appends at most `$most` bytes onto `$into`: how many arrived, or null when the deadline passed with nothing. `.eof` once the peer has closed. The read after the last byte is the eof, not the one that took it.

`write` sends every byte before the deadline, so a peer that reads a byte at a time cannot hold the writer past it. `write($head, $body)` is one gathered write, neither copied, one packet when they fit.

```echo
guard $s->write('hello', tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
}

string $buf = '';
usize? $n = guard $s->read($buf, 4096, tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
}
```

A write `.timeout` leaves an unknown part sent and breaks the write side. Every later write is `.broken`. That is the catch: you cannot know how much the peer saw.

`tryRead` and `tryWrite` never wait. A partial `tryWrite` is normal; the reactor keeps the offset (`$from`). `tryWrite($head, $body, $from)` counts across both, so one offset covers the pair.

`readExactly` and `readAll` sit on any `Source`. Bytes that did arrive stay in `$into` even when the call fails.

## Shutdown and close

`shutdown(.write)` is a half-close: the peer reads the end of the stream while this side can still read. A read after `.read` or `.both` answers `.closed`, and so does a write after `.write` or `.both`. Asking again is not an error.

The read side is this stream's alone. The peer is not told. Bytes it still sends wait unread. A `close` with them there is a reset, and a reset can destroy the reply the peer has not read yet.

`finish($by)` shuts the write side, drains whatever the peer still sends until it closes too or the deadline passes, then closes. Use it when the peer might still be reading.

`close` from any thread wakes every call blocked on the stream with `.closed`. The descriptor is released once the last of them has left. `Stream` is `#[atomic]`: an accept thread can hand it to the thread that serves it, and one thread may read while another writes.

## Unix sockets

A path on this machine instead of an address and a port. Local Postgres, MySQL, Redis.

```echo
tcp::Listener $l = guard tcp::Listener::bind(tcp::Address(unix: '/tmp/app.sock')) else ($e) {
    die("{$e}");
}
```

The socket file is made at bind and removed when the listener is released. A file left by a listener that is gone (the process died) is replaced: one that nothing answers on is stale. A live listener on the path stays `.addressInUse`, and a file that is not a socket is never touched.

A path that is empty, holds a NUL, or is longer than the platform takes (103 bytes on macOS, 107 on Linux and Windows) is `.invalid`.

## Options

`StreamOptions` is applied when a stream is connected or accepted. Fields with defaults, set by assignment.

```echo
tcp::StreamOptions $opt = tcp::StreamOptions();
$opt->keepAlive = time::duration::secs(30);
$opt->sendBuffer = 256 * 1024;
```

`noDelay` is on: request and reply traffic should never wait for a delayed ACK. `keepAlive` is off. Kernel buffer sizes of `0` keep the system's choice.

Unix sockets skip no-delay and keepalive. Setting them on the stream after the fact is `.invalid`: a unix peer cannot vanish without the kernel knowing, and there is no Nagle delay to turn off.

## Errors

The cases are what a caller branches on. `"{$e}"` is the sentence. `name()` is the case without a match: `'eof'`, `'reset'`, and so on.

| Case | Means |
|---|---|
| `eof` | the peer closed cleanly, and more was wanted |
| `timeout` | a connect or a write ran out of time |
| `closed` | this side closed the handle, or shut that direction |
| `broken` | an earlier write failed partway |
| `refused` | nothing listens at the address |
| `reset` | the peer reset the connection, or it died another way |
| `unreachable` | no route to the host or its network |
| `addressInUse` | the address is already taken |
| `tooManyFiles` | the process or the system is out of descriptors |
| `resolve` | the host name did not resolve |
| `invalid` | a port out of range, an empty host, an address that does not parse |
| `os` | anything else, with the OS sentence |
| `tooLarge` | a message over a reader's `max` |

`gone()` is eof or reset: nothing more will come, and nothing sent will reach it. `sys()` is the failed system call behind the cases that carry one.

Nothing-yet is never an error. A read or an accept that ran out of time hands back null, and so does a try call that would have had to wait.

## Poller

A reactor that serves many connections from one thread: register streams and listeners, wait for some to be ready, then call their try methods until they answer null. epoll on Linux, kqueue on macOS, wepoll on Windows.

Level or oneshot, never edge-triggered. Windows has no edge mode, so the portable surface does not either. A handle registered with a poller is driven with the try calls only.

```echo
tcp::Poller $poller = guard tcp::Poller::open() else ($e) {
    die("{$e}");
}

guard $poller->add($listener, 0, .read) else ($e) {
    die("{$e}");
}

array<tcp::Event> $events = array<tcp::Event>();
guard $poller->wait($events, tcp::Deadline::never()) else ($e) {
    die("{$e}");
}
```

Keep one `$events` across waits. Its room is reused, so a wait allocates nothing after the first. Still empty means the deadline passed.

`Event` carries the token you registered with: `readable()`, `writable()`, `hangup()`, `error()`. `woken()` is another thread calling `Poller::wake`. Several wakes before a wait sees them are one wake.

`modify` changes interest, or arms a oneshot registration again. Remove a source before closing it. Removing a closed source is `.closed`: the OS dropped its registration with the handle, and the number may belong to another socket by now.

`Stream`, `Listener`, and `Connecting` are `Pollable`. Token `0xFFFFFFFFFFFFFFFF` is the poller's own and is refused.

`Waker` is the piece a poller is woken with, and it works on its own too: a timed wait across threads, which the standard library's `condition` does not have. One thread calls `wait($by)`, another `wake()`. A wake stays until `reset()`, so one that comes before the wait is not lost.

## Outbox

The bytes a reactor owes one connection. A try write takes what the socket has room for, and the rest waits here until the stream reports writable again.

```echo
tcp::Outbox $out = tcp::Outbox();
guard $out->push('hello') else ($e) {
    die("{$e}");   // .tooLarge: the bytes owed would pass the limit
}
guard $out->flush($stream) else ($e) {
    die("{$e}");
}

tcp::Interest? $want = $out->interest($stream, reading: true);
```

The default limit is 16 MiB. A push that would pass it is `.tooLarge`, with nothing queued.

`interest` is `.read` while reading and nothing is owed, `.write` or `.both` while bytes are owed, null once the connection is done. The stream has the last word (`Pollable::needs`), so a layer over a socket can ask for more than the caller named.

## Reader

A buffered reader for any wire format: a line protocol, a length in a header, or both. The core is free of I/O (`feed` bytes in, `take` and `until` out), so it also parses bytes that come from somewhere else.

```echo
tcp::Reader $r = tcp::Reader(max: 65536);

string? $line = guard $r->until($stream, "\n", tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
}

string $header = guard $r->peek(4) else {
    // not four bytes yet
    return;
};
uint32 $n = tcp::wire::be32($header);
string? $body = guard $r->exactly($stream, $n as usize, tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
};
```

`exactly($n)` and `until($delim)` wait. `pullExactly` and `pullUntil` never wait: a reactor calls them until they answer null. Bytes read past a message stay buffered for the next one. `rest()` hands them over whole, to a TLS layer after a plaintext start.

`window` is the same bytes as `peek`, without a copy. Valid until the reader next reads, skips, or takes.

`max` (default 1 MiB) is the longest message held. A larger one is `.tooLarge` before it is read, so a peer cannot make a reader grow without end.

## Frames

Length-prefixed messages: a uint32 big-endian byte count, then that many bytes. The encoding is pure; `Reader` and `write` move frames over any `Source` and `Sink`.

```echo
guard tcp::frame::write($stream, 'hello', tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
}

tcp::frame::Reader $frames = tcp::frame::Reader(max: 65536, idle: time::duration::secs(30));
string? $body = guard $frames->read($stream, tcp::Deadline(ms: 1000)) else ($e) {
    die("{$e}");
};
```

Prefix and body go in one gathered write, neither copied. `frame::push($out, $body)` queues the same pair on an `Outbox`. A body past `frame::MAX` (what a 4-byte prefix can announce) is `.tooLarge`, with nothing sent.

`frame::Reader::pull` is the reactor form: call it until it answers null, then wait on the poller. Frames that arrived with the peer's close still come out first, then `.end`, or `.truncated` when the close cut a frame short.

`$idle` ends a conversation that delivers no whole frame for that long. Bytes trickling in do not count, so a peer that sends one byte a minute is still idle. `read` answers `.idle` itself. A reactor waits no later than its readers' earliest `idleAt()`, and a frame already in the socket still beats the limit.

A prefix over `max` is `.tooLarge` before any body is buffered. Text that is not a frame lands here: `GET ` reads as over a gigabyte.

`frame::Error::end` is the peer closing between frames, the clean end of a conversation. That is not `tcp::Error::closed`, which is this side closing. `transport` keeps the connection's error whole. `"{$e}"` and `name()` work the same way (`'transport:reset'`).

## Wire

Fixed-width integers as wire protocols lay them out, read at an offset of a string and appended onto one. Big-endian is network order (frames, Postgres). Little-endian is MySQL and most game protocols. `le24` is MySQL's packet length.

A read expects the bytes to be there. Check `size()` or a reader's `buffered()` first. One past the end stops the program, in a release build too.

```echo
uint32 $n = tcp::wire::be32($bytes, 0);
tcp::wire::putBe32($out, $n);
```

## Source and Sink

`Stream` is a `Source` and a `Sink`. The layers above it (frames today, a test double, TLS tomorrow) take those interfaces, not one concrete socket. `Pollable::needs` is the matching hook for a poller: a plain socket answers what you asked; a layer over one may need write readiness to flush ciphertext a read produced.

There is no TLS in this module, and no HTTP. The seams are there so a layer can sit on a stream without the stream knowing.

## Working here

```bash
echoc test
echoc run -m examples/reactor
```

The example is a frame echo server on one thread: a `Poller`, `frame::Reader::pull`, an `Outbox`. It runs for a couple of seconds, then the main thread stops it with `Poller::wake`.

## License

MIT. Copyright Mario Döring, Boris Stock.
