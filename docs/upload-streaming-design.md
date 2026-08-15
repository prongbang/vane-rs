# Upload (request-body) streaming: core design and FFI plan

Status: the Rust core is implemented on both transports with tests (this
phase); the C ABI, UniFFI exports and binding wrappers are phase 4 and only
planned here. The response-streaming doc's phase-3 sketch ("roles flip, the
caller pushes, backpressure is `write_chunk` blocking") survived as the
outline; what it did not say — replay, framing, timeouts, teardown — turned
out to be most of the design, and one of its structural choices (a
handle-returning method) was replaced. Differences are called out at the end.

## The core API, as shipped

```rust
/// Registry-id surface, the same dialect as cancel tokens and progress —
/// every FFI layer already speaks it. One stream feeds exactly one request.
pub fn create_body_stream(content_length: Option<u64>) -> u64;
pub fn write_body_stream_chunk(id: u64, chunk: Vec<u8>) -> Result<(), VaneError>;
pub fn finish_body_stream(id: u64) -> Result<(), VaneError>;
pub fn free_body_stream(id: u64);

pub struct VaneRequest {
    // ...
    /// Mutually exclusive with `body` and `body_file_path`.
    pub body_stream_id: Option<u64>,
}
```

- `write_body_stream_chunk` **blocks** while the transport's send window and
  the stream's internal buffer (256 KiB, `BODY_STREAM_BUFFER_BYTES`) are
  full. That blocking is the backpressure; there is no other mechanism.
- `finish_body_stream` marks end of body. With a declared `content_length`,
  finishing at any other byte count is `InvalidRequest` and also fails the
  in-flight request — a short body never turns into a clean FIN.
- `free_body_stream` before `finish` **aborts** the in-flight request
  (`Cancelled`). After a clean `finish` it only drops the id; queued bytes
  still drain, so "write, finish, free, await response" is a legal order.
- Once the request stops consuming the stream — completed, failed, or a
  redirect dropped the body — the writer's next call returns the request's
  terminal error instead of parking forever. A writer blocked *inside*
  `write` is woken by the same latch.
- Works with both `execute` (buffered response) and `execute_streaming`
  (streamed response); on HTTP/3 an upload the server answered early keeps
  pumping from the response stream's pulls (`H3BodyStream.upload`).

Errors seen by the writer are the same errors the request fails with
(`BodyLimitExceeded`, `InvalidRequest`, `Cancelled`, transport kinds), so
either side of a binding wrapper can report the outcome.

## The replay decisions

A streamed body is one-shot: consumed bytes sit in quiche's or hyper's send
buffers or on the wire, and the caller cannot produce them again. Every
mechanism in Vane that re-sends a request had to take a position. The gate
for all of them is `RequestBodyStream::consumed()` — bytes pulled out of the
queue by a transport — because "nothing consumed" means the queue is intact
and a fresh attempt can take it over from byte 0.

**Retry: a streamed request runs exactly one attempt per transport.**
`execute_with_retry` short-circuits — no error retry, no 408/5xx retry,
whatever `retry_max_attempts` says. Deliberately *not* softened to "retry
while nothing was consumed": whether the server's 500 raced ahead of the
writer's first chunk is timing, and a retry policy that fires on a timing
race is worse than one that never fires. (OkHttp's `isOneShot` and Go's
`GetBody == nil` make the same call.) Test:
`streamed_upload_is_attempted_exactly_once_despite_retry_config` — a
buffered POST against the same 500 endpoint burns all 3 configured attempts
(the control that proves the discriminator), the streamed one is seen once.

**Redirects: body-keeping hops are refused; body-dropping hops are followed.**
`redirect_rewrite` refuses any hop that would need the body again —
307/308 with any method, 301/302 on GET — with the 3xx handed back carrying
`vane-redirect-refused: streamed-body`, the same refusal surface every other
gate uses. Same origin included (where the buffered path happily replays),
and regardless of `consumed()`: a 307 landing before the writer's first
chunk would otherwise follow while the same 307 a millisecond later refuses.
303 (and 301/302 on non-GET) rewrite to a bodyless GET, drop the body, and
are followed; the writer is released at the rewrite. Both transports run the
same shared function; the property test asserts `Keep` is unreachable with a
streamed body. Tests:
`streamed_upload_refuses_the_same_origin_307_a_buffered_body_follows`
(control shows the buffered 307 replaying),
`streamed_upload_follows_a_303_as_a_bodyless_get`,
`redirect_rewrite_refuses_streamed_bodies_on_every_body_keeping_hop`, and
`proptests::redirect_rewrite_never_replays_a_body_cross_origin` (extended
with `streamed`).

**H3→TCP fallback: allowed if and only if `consumed() == 0`.** This is the
one replay a streamed request gets, and it is the one that matters: on a
UDP-blocked network the HTTP/3 attempt dies at connect, provably before any
body byte was pulled, and refusing fallback there would make streamed
uploads dead on that whole class of networks. `dispatch_via` gains one arm —
after the existing transport-failure and method gates, before `tcp()` — that
returns the H3 error when `consumed() > 0`. Both halves are tested with PUT
(a retryable method) so the consumed gate, not the method gate, is the
decision under test:
`tcp::tests::upload::streamed_upload_falls_back_to_tcp_while_nothing_was_consumed`
(no UDP listener; TCP twin of the h3.test origin serves the upload, response
arrives as HTTP/1.1) and
`h3_offline::tests::streamed_upload_mid_body_transport_failure_does_not_fall_back`
(server kills the connection after consuming body bytes; the error must not
carry the "TCP fallback also failed" marker).

The pooled-stale-connection retries inside each transport (H3 hop and
`tcp::follow`) get the same `consumed() == 0` gate. In practice both stacks
buffer body bytes before a silently-dead pooled connection is detected, so a
streamed upload on a stale checkout usually fails instead of silently
retrying — the documented cost of a one-shot body, identical to OkHttp/Go.

## Content-Length vs chunked

`create_body_stream(Some(n))`:
- HTTP/3 sends `content-length: n` (appended in `build_h3_headers`;
  `content-length` is in `RESERVED_HEADERS`, so no caller value conflicts).
- TCP uses `reqwest::blocking::Body::sized(reader, n)` → `Content-Length: n`.
- The core enforces exactly `n`: writes past it fail (`InvalidRequest`,
  latched), `finish` below it fails and aborts the request.

`create_body_stream(None)`:
- HTTP/3 sends no length: DATA frames, FIN on finish (H3 has no chunked TE
  and needs none).
- TCP uses `Body::new(reader)`: `Transfer-Encoding: chunked` on HTTP/1.1,
  plain DATA on h2.

Wire-verified in `streamed_upload_sends_content_length_when_declared_and_chunked_otherwise`
(a raw HTTP/1.1 server asserts which framing actually arrived and digests
the reassembled body) and the two H3 round-trip tests (the offline server
logs the verbatim `content-length` header, or its absence).

Pre-existing asymmetry, unchanged by this work: the *buffered* H3 path has
never sent `content-length` (FIN delimits). Streamed-with-declared-length
now does. Aligning the buffered path is a separate, caller-visible change;
flagged as follow-up, not smuggled in here.

## Backpressure — the verified mechanism, per transport

The sketch's claim ("`write_chunk` blocks while the send window is full") is
true, but only through a chain that had to be verified link by link:

**Writer → core:** the stream's queue is bounded at 256 KiB; `write` parks
on a condvar past that. Bound on caller-side buffering: 256 KiB + one chunk.

**H3:** the drive loop pulls a chunk from the queue only when the previous
one is fully fed to quiche. `send_body` returns `Done` past the peer's
flow-control credit (verified in quiche 0.29.1 `do_send_body`: writes are
capped to `conn.stream_capacity`), which parks the pending chunk, which
stops pulls, which fills the queue, which parks the writer. Evidence:
`streamed_upload_backpressure_parks_the_writer_against_the_flow_window` —
server window pinned to 64 KiB with HTTP/3 reads held; the writer of a 1 MiB
body must stall at ≤ window + buffer + two chunks (asserted numerically) and
completes only after the server reads.

**TCP:** reqwest 0.13.4's blocking client pumps the `Read` body **on the
calling thread** (`blocking/client.rs execute_request` → `send_future`) into
a zero-capacity futures channel that hyper drains only as the connection
accepts bytes. A full TCP send window parks `send_future`, which stops
calling our `Read`, which stops draining the queue, which parks the writer.
Evidence: `streamed_upload_backpressure_parks_the_writer_until_the_server_reads`
— 24 MiB (far beyond loopback socket buffering) against a server that reads
nothing until released; the writer's progress counter must go stable short
of the total, then complete after release.

## Timeouts — one total budget (documented ceiling)

The request timeout bounds the whole exchange **including the upload**, on
both transports:

- TCP: reqwest wraps body-send + response-headers in a single
  `wait::timeout` (verified in source; the response-*body* phase still
  re-anchors per read as before). Nothing Vane controls can re-anchor the
  send phase.
- H3: the drive loop's deadline is the same shared `HopTimeouts` deadline as
  ever.

So a streamed upload must complete within `timeout_seconds`; callers moving
gigabytes set it accordingly. In exchange, a writer that never finishes can
never hang a request (test: `streamed_upload_whose_writer_never_finishes_times_out`,
which also forced one honesty fix: a QUIC *idle-timeout* death now reports
`Timeout`, not `Transport` — `conn.is_timed_out()` distinguishes it).
Upgrade path if real uploads outgrow this: re-arm the H3 deadline on upload
progress (per-chunk inactivity budget), and accept the H3/TCP asymmetry the
response side already documents. Not built until a workload asks.

The cancel token stays responsive throughout: the H3 loop ticks ≤ 50 ms, and
the TCP reader's blocking pull checks the token every 50 ms and latches
`Cancelled` so the request fails with the right kind (the
`streamed_send_error` recovery — reqwest itself would only say `Transport`).

## Teardown, release, and the pool

One latch (`RequestBodyStream.terminal`) serves every direction:

- **Request ends first** (success, failure, 303 rewrite, early server
  answer): `release()` runs — from `execute`, the TCP streaming entry
  (uploads are over before headers surface there, a consequence of the
  sequential reqwest bridge), the H3 hop's parked path, or
  `H3BodyStream`'s Eof/abandon/error paths — and a parked or late writer
  gets `Cancelled` with a message saying the request no longer consumes.
  A cleanly-finished, fully-drained stream is left alone, so late `finish`
  stays idempotent and post-success `write` reports "already finished".
- **Writer aborts first**: `free_body_stream` latches; the transport's next
  pull fails the request with `Cancelled`
  (`streamed_upload_freed_mid_flight_cancels_the_request`).
- **Neither side moves**: the total budget fires (test above).

Pool invariant, unchanged in statement: a cleanly completed exchange pools
its connection (asserted in the round-trip test with a handshake count); any
errored exchange closes it (asserted in the mid-body-failure test). The
pre-existing ceiling #9 from the response doc — a server that answers before
the upload finished leaves the request stream un-FINed on a parked
connection — now also covers streamed uploads, deliberately: fixing it
belongs to both body shapes at once (`stream_shutdown` on the request
stream) or neither.

## Body limits

- Declared length > `max_request_body_bytes`: refused in
  `resolve_body_stream`, before any connection exists — the same error text
  an oversized buffered body gets.
- Unknown length: enforced at pull time, the moment bytes would become
  unrecoverable, so the request fails `BodyLimitExceeded` at the exact
  configured byte on either transport and the writer receives the same
  error (`streamed_upload_enforces_the_request_body_limit_incrementally`).

## Phase 4 — how it crosses the three bindings

Nothing here is implemented; this is the reviewable plan, shaped by what
phases 1→2 proved about each boundary.

**Why caller-push works everywhere pull did:** every binding *initiates* a
blocking call into the core — the direction that always works. Upload is the
caller making `write` calls instead of `read_chunk` calls; the core never
calls out. No callback interfaces anywhere, same as the response side.

**UniFFI (Kotlin, Swift).** Export the four functions exactly as cancel
tokens were exported (task #1 precedent):
`create_body_stream(content_length: Option<u64>) -> u64`,
`write_body_stream_chunk(id, chunk) -> Result`, `finish_body_stream(id) ->
Result`, `free_body_stream(id)`. `VaneRequest` already carries
`body_stream_id: Option<u64>` with `#[uniffi(default = None)]`, so decoding
stays compatible for callers that never set it. Checksums change; both
binding repos regenerate in the same change, as always.

- Kotlin wrapper: `VaneRequestBuilder.body(flow: Flow<ByteArray>)` (and a
  `body(InputStream)` convenience). Implementation: create the id; launch
  the upload as `async(Dispatchers.IO)` *sibling* of the execute call —
  collect the flow, one blocking `write` per element, then `finish`;
  `free` in a `finally`. The phase-2a lesson applies verbatim: the writer
  coroutine parks a thread inside `write`, and only the core's release
  latch (or `free`) unparks it — so cancellation must fire
  `free_body_stream` (and the request's cancel token) from a
  non-parked path, never wait for the collector to notice. The
  execute-side wrapper is unchanged.
- Swift wrapper: `body(_ stream: AsyncSequence<Data>)`; a `Task` iterates
  and calls `write` via the existing `vaneFFIQueue` hop (QoS note from
  phase 2a applies — these calls park like reads do), `finish` at the end,
  `free` on cancellation or error. Same rule: abort = token +
  `free_body_stream`, both callable while a `write` is parked.
- Both must surface the write-side error to the caller's stream (the error
  IS the request's error) without double-reporting against the execute
  result — suggested rule: the execute result is authoritative, the writer
  loop just stops on first error.

**C ABI / Dart — ABI v3 → v4.** New exported symbols
(`vane_ffi_body_stream_create/write/finish/free`, all `catch_unwind`-wrapped,
write returning the standard error buffer + kind) and one new field
`body_stream_id: u64` (0 = none) on `VaneFfiRequest` — a struct layout
change, hence the version bump and the Dart-side constant moving in the same
commit, per the documented rule. No registry map is needed beyond the core's
own `BODY_STREAMS`.

- Dart surface: `VaneRequestBuilder.bodyStream(Stream<Uint8List>)`. The
  plugin subscribes with a **paused-by-default pump**: on each `onData`,
  pause the subscription, post the chunk to a worker isolate that makes the
  blocking `vane_ffi_body_stream_write` call, resume on completion. That is
  push-with-pause — Dart's native backpressure — and it composes with the
  demand-driven response pump because they are separate isolates making
  independent blocking calls. `onDone` → finish; `onError`/cancel → free.
  The execute call itself runs on its worker isolate exactly as today.
- The response-side rule holds mirrored: the pump must never buffer ahead
  (no free-running `listen` that queues chunks while a write is in flight).

**Binding-visible decisions to document on every surface:** one stream per
request; streamed requests never retry; 307/308 come back refused with
`vane-redirect-refused: streamed-body`; fallback only before the first
consumed byte; the whole upload must fit the request timeout; `free` before
`finish` aborts the request.

## What changed from the phase-3 sketch

1. **Handle → registry id.** The sketch's `request_body_stream()` returning
   an object was replaced by `create_body_stream() -> u64` + a
   `VaneRequest.body_stream_id` field, because cancel tokens and progress
   already cross all three FFI boundaries in exactly that dialect, and a
   UniFFI object + a C-ABI handle + a record field would have been three
   spellings of one thing.
2. **The sketch said nothing about replay** — retry, redirects, fallback,
   stale-pool retries. Those decisions (above) are most of this design.
3. **"Backpressure is `write_chunk` blocking while the send window is
   full"** is true only through the bounded queue and, on TCP, reqwest's
   calling-thread pump — both now verified against source and tested, not
   assumed. The sketch also never mentioned that the request timeout is a
   total budget over the upload, which is the ceiling callers will actually
   notice.
4. **Teardown was unspecified.** The release latch — who unparks a writer
   when the request ends first, and what `free` means mid-flight — did not
   exist in the sketch and is where the deadlock risk lived.

## Where the risk actually is

Ranked, most worrying first:

1. **The Dart write pump's pause/resume discipline.** Same class of risk as
   the phase-2 response pump (which was rank 1 then, and was real): an eager
   subscription buffers unboundedly and looks fine in a demo. Prototype
   first, with a slow-network test wired to a fat upload.
2. **Kotlin/Swift abort-while-parked.** A writer parked in `write` is only
   released by the core's latch; a wrapper that routes cancellation through
   the parked path deadlocks. Each binding needs the "abort from a non-parked
   path" test, mirroring the phase-2a cancel-ordering tests.
3. **`VaneFfiRequest` layout change.** Mechanical, but it is the first
   struct-shape change since the ABI guard landed; the v4 bump must move in
   lockstep with the Dart constant or old plugins load a new core.
4. **Error double-reporting in wrappers** (writer loop vs execute result).
   A rule is stated above; wrappers can still get it subtly wrong in both
   directions (swallowed error / reported twice).
