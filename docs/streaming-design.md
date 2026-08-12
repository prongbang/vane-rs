# Response-body streaming: core design and FFI plan

Status: phase 1 (Rust core) is implemented; this document is the reviewed
design for phase 2 (Kotlin/Swift via UniFFI, Dart via the C ABI). Nothing in
phase 2 is built yet. Upload (request-body) streaming is out of scope and only
sketched at the end.

## The core API, as shipped

```rust
impl VaneClient {
    /// Arc receiver: the stream keeps the client alive so it can return its
    /// connection to the pool when the body is drained.
    pub fn execute_streaming(
        self: Arc<Self>,
        request: VaneRequest,
    ) -> Result<VaneResponseStream, VaneError>;
}

pub struct VaneResponseStream { /* head + Mutex<body state> */ }

impl VaneResponseStream {
    /// Status, headers, final URL, Set-Cookie list, negotiated protocol.
    /// `body` is empty by contract — the stream itself delivers it.
    pub fn head(&self) -> VaneResponse;

    /// Blocks until body bytes arrive; `Ok(None)` = end of body. Chunk
    /// boundaries carry no meaning. After any error the stream is dead and
    /// every later pull repeats the same error. After `close`, `Ok(None)`.
    pub fn read_chunk(&self) -> Result<Option<Vec<u8>>, VaneError>;

    /// Idempotent early release; discards the connection.
    pub fn close(&self);
}
```

`head()` returns the existing `VaneResponse` record with an empty body rather
than a new head type: all three bindings already decode that record, and one
reused type beats six duplicated getters. The `body`-is-empty contract is the
cost; it is stated on every surface.

`execute_streaming` behaves exactly like `execute` up to the final headers:
same URL building, same request-body loading and limit, same redirect chain
(intermediate 3xx bodies drained internally under the intermediate cap), same
retry policy and HTTP/3→TCP fallback — both apply only until headers are
delivered; a returned stream is never silently replayed — same cookies, pins,
progress, and the one shared deadline. `response_body_path` is refused
(`InvalidRequest`): the stream replaces the file escape hatch. The
`max_response_body_bytes` limit applies cumulatively across chunks — streaming
is not a bypass route for a configured bound.

Internally there is one delivery-mode fork, placed as low as possible
(`H3HopMode` in `execute_http3_hop`, `follow`/`read_body` split in `tcp.rs`).
Redirects, retry, and fallback run through the same generic machinery for both
modes (`RedirectHopResponse` trait; `dispatch_via`), so the policies cannot
drift apart.

## Pull, not push — and why the FFI boundary decides it

Two shapes were on the table:

1. **Pull**: the caller repeatedly makes a blocking `read_chunk()` call.
2. **Push**: the core drives the transport and invokes a caller-supplied
   callback per chunk.

For a pure-Rust library, push is arguably the smaller diff (thread a sink
through `push_body`). It loses on the boundary this library exists to cross:

- **Dart kills push.** The existing Dart pattern is a blocking FFI call on a
  worker isolate. Rust cannot synchronously call back into a Dart isolate
  that is blocked inside an FFI call, and `NativeCallable.listener` is
  asynchronous fire-and-forget — no return value, therefore **no
  backpressure**. A push design on Dart either buffers unboundedly (the exact
  failure this feature must not have) or grows a hand-rolled ack/semaphore
  protocol. Pull is simply the existing blocking-call-on-worker pattern
  repeated per chunk.
- **Backpressure is free with pull.** Not pulling means the core is not
  reading. On H3 the peer stalls against QUIC flow control (1 MiB stream
  window, 10 MiB connection window — bounded bytes in quiche plus the kernel
  socket buffer); on TCP it stalls against the receive window via hyper.
  There is no buffering code because there is no buffer.
- **Threading stays trivial.** No core-owned threads, no "which thread does
  the callback run on" per language, no re-entrancy. Kotlin, Swift and Dart
  each park the blocking pull on the executor they already use for
  `execute`.
- Cancellation and mid-stream errors have one natural home (the pull's
  return value) instead of extra callbacks.

The accepted price of pull is one FFI round trip and one buffer copy per
chunk, and one parked worker thread per active stream. Both are the same
costs a buffered request already pays, just spread over the stream's
lifetime; against network latency they do not register.

## How each concern resolves in the core

**Backpressure.** Between pulls nothing reads the transport. H3: the peer can
send at most the advertised flow-control windows; excess sits in quiche's
receive buffers and the kernel socket buffer, both bounded; window credit is
only granted as the caller consumes. TCP: hyper stops reading, the TCP window
closes. A stalled consumer costs bounded memory, ever.

**Cancellation.** The stream holds the request's `VaneCancelToken` handle.
Every pull checks it up front, and the H3 drive loop checks it every socket
tick (≤50 ms), so a cancel interrupts a *blocked* H3 pull promptly. A blocked
TCP pull notices at the next chunk or at the per-read timeout — the same
chunk-boundary granularity the buffered TCP path has always had. A cancelled
stream is terminal: the connection is discarded, `Cancelled` replays on every
later pull.

**The pool.** The invariant, stated once and enforced in one place
(`park_or_close_h3` / hyper's own EOF rule): **only a stream read to end of
body returns its connection; abandonment (close, drop, error, cancel) always
discards it.** H3 discard is `conn.close` + flush; TCP discard is dropping the
reqwest response mid-body, which hyper already treats as non-reusable.
Draining-on-abandon was rejected: an unbounded server body would turn "close"
into "download the rest first". Intermediate redirect hops are fully drained
by construction, so they pool exactly as before.

**Errors mid-stream.** After the headers are out, a transport failure, body
limit hit, cancel, or idle timeout surfaces as `Err` from `read_chunk` — the
request did not "fail", the stream did. The error latches: the source is torn
down once, progress `done` latches, and every subsequent pull returns a clone
of the same error. `Ok(None)` after an error is impossible by construction
(terminal state is checked first), so EOF can never masquerade as recovery.

**Timeouts.** The configured timeout bounds the whole chain *up to the final
headers* exactly as it bounds a buffered request. After that it becomes a
per-pull inactivity budget: a pull that sees no bytes for ~the timeout fails
with `Timeout`. On H3 this is an explicit per-pull deadline; on TCP it falls
out of reqwest's blocking `Response::read`, which re-anchors the request
timeout on every read call. An SSE stream with heartbeats inside the window
lives indefinitely on both transports.

**Progress.** Download counters advance per chunk against the content-length
hint; at EOF the final `received == total` is published and `done` latches.
`done` also latches on error, close, and drop — a poller is never left
hanging. A retried (5xx) streaming attempt drops its stream, and the next
attempt's `progress_init` resets the counters, same as buffered retry.

## Phase 2a — UniFFI (Kotlin, Swift)

**Mechanism: plain synchronous object export. Not UniFFI callback interfaces,
not UniFFI async.** The core is blocking; both existing bindings already own
the "run blocking FFI on a background executor" pattern (`runBlockingFFI` in
VaneSwift, `Dispatchers.IO` in VaneKotlin). Callback interfaces would
reintroduce the push problems; UniFFI async would demand an async core or
hidden spawning for zero caller-visible gain over language-side wrappers.

Rust-side change (mechanical):

```rust
#[derive(uniffi::Object)]                  // added to the existing struct
pub struct VaneResponseStream { ... }

#[uniffi::export]
impl VaneResponseStream {
    pub fn head(&self) -> VaneResponse;
    pub fn read_chunk(&self) -> Result<Option<Vec<u8>>, VaneError>;
    pub fn close(&self);
}

// added to the existing `#[uniffi::export] impl VaneClient` block:
pub fn execute_streaming(self: Arc<Self>, request: VaneRequest)
    -> Result<Arc<VaneResponseStream>, VaneError>;
```

The core method already takes `self: Arc<Self>` for exactly this reason; the
export wrapper only wraps the result in `Arc`. UniFFI supports `Arc<Self>`
receivers on exported methods; if the proc-macro rejects that form in
practice, the fallback is a free exported function
`execute_streaming(client: Arc<VaneClient>, request) -> Result<Arc<VaneResponseStream>>`
— same generated surface, different spelling. Regenerating bindings changes
the UniFFI checksum, so VaneKotlin and VaneSwift must regenerate in the same
change.

Generated API (what binding authors build on):

- Kotlin: `class VaneResponseStream { fun head(): VaneResponse;
  fun readChunk(): ByteArray?; fun close() }` (plus `Disposable`).
- Swift: `public class VaneResponseStream { public func head() -> VaneResponse;
  public func readChunk() throws -> Data?; public func close() }`.

Idiomatic wrappers (thin, hand-written, in each binding repo):

Kotlin — `Flow<ByteArray>`:

```kotlin
suspend fun Vane.executeStreaming(request: VaneRequest): VaneStreamingResponse {
    val inner = withContext(Dispatchers.IO) { client.executeStreaming(request) }
    return VaneStreamingResponse(head = inner.head(), body = flow {
        while (true) emit(inner.readChunk() ?: break)
    }.flowOn(Dispatchers.IO).onCompletion { inner.close() })
}
```

Coroutine cancellation must cancel the request's `VaneCancelToken` (the
wrapper should create one per streaming request when the caller didn't)
*before* `close()`: `close()` waits for an in-flight `readChunk` to return,
and the token is what interrupts it. This ordering is the one sharp edge in
the Kotlin wrapper; it belongs in one place — `onCompletion` — not in caller
code.

Swift — `AsyncThrowingStream<Data, Error>`:

```swift
public func executeStreaming(_ request: VaneRequest) async throws -> VaneStreamingResponse {
    let inner = try await runBlockingFFI { try self.client.executeStreaming(request: request) }
    let body = AsyncThrowingStream<Data, Error> { continuation in
        let task = Task.detached {
            do {
                while let chunk = try inner.readChunk() { continuation.yield(chunk) }
                continuation.finish()
            } catch { continuation.finish(throwing: error) }
        }
        continuation.onTermination = { _ in task.cancel(); /* cancel token */; inner.close() }
    }
    return VaneStreamingResponse(head: inner.head(), body: body)
}
```

Same cancel-token-then-close rule as Kotlin. Note the `Task.detached` loop
parks one thread per active stream — accepted, see ceilings.

## Phase 2b — the C ABI and Dart

The existing pattern — one blocking call returning one `#[repr(C)]` struct —
cannot express a stream. What replaces it is a **handle + per-chunk blocking
call**, which is that same pattern applied per chunk:

```rust
/// Head via the existing VaneFfiResponse (body buffer empty; error fields
/// filled on failure exactly as vane_ffi_execute fills them). On success
/// *out_stream is a nonzero handle; on failure it is 0.
#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_execute_streaming(
    handle: u64,
    request: *const VaneFfiRequest,
    body_data: *const u8,
    body_len: usize,
    out_stream: *mut u64,
) -> *mut VaneFfiResponse;

/// One blocking pull. By-value return, mirroring VaneFfiProgress.
/// eof=false, empty error => body holds a chunk (caller frees it with
/// vane_ffi_buffer_free). eof=true => end of body. Non-empty error =>
/// terminal failure (error_kind = VaneError::ffi_kind).
#[repr(C)]
pub struct VaneFfiStreamChunk {
    pub body: VaneFfiBuffer,
    pub error: VaneFfiBuffer,
    pub error_kind: u32,
    pub eof: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_stream_read(stream: u64) -> VaneFfiStreamChunk;

/// Idempotent; also frees the handle. Safe on unknown handles.
#[unsafe(no_mangle)]
pub extern "C" fn vane_ffi_stream_close(stream: u64);
```

Streams live in a `FFI_STREAMS: Mutex<HashMap<u64, Arc<VaneResponseStream>>>`
registry mirroring `FFI_CLIENTS`. `vane_ffi_stream_read` clones the `Arc` out
and releases the registry lock **before** blocking — a blocked read must
never hold the map lock, or every other stream's close would queue behind it.
All three functions get the standard `catch_unwind` wrapper.

**`vane_ffi_abi_version` bumps 2 → 3.** New exported symbols and a new
`VaneFfi*` struct both meet the documented bump rule; the constant in
`vane_flutter/lib/vane_flutter_ffi.dart` moves in the same change.

Dart-side surface — `Stream<Uint8List>`:

The one-shot `Isolate.run`-per-request pattern does not fit a stream (an
isolate per chunk is absurd). The design is a **persistent pump isolate per
stream** driven by demand:

- `executeStreaming` runs the header phase as one blocking call on a worker
  isolate (existing pattern) and gets back the decoded head + stream handle.
- A `StreamController<Uint8List>` with `onListen`/`onResume` requesting the
  next pull from a long-lived pump isolate that owns the handle; the pump
  makes one `vane_ffi_stream_read` call per request and posts the result
  back. `onPause` simply stops requesting — **the pump must be
  demand-driven, never a free-running loop**, or Dart-side buffering
  reintroduces exactly the unbounded buffer pull exists to prevent.
- `onCancel` → cancel token (if any) then `vane_ffi_stream_close` on the pump
  isolate, then kill the pump.
- Chunks should cross the isolate boundary as `TransferableTypedData` to
  avoid a second copy of every chunk.

## Ceilings

Accepted, deliberately:

1. One FFI round trip + one buffer copy per chunk (per-isolate copy on Dart
   unless transferred). Irrelevant next to network cost at 16 KiB+ chunks.
2. One parked worker thread (or pump isolate) per active stream, for the
   stream's lifetime. Identical in kind to a buffered request, longer in
   duration.
3. TCP stream inactivity timeout is the per-request timeout captured when the
   final hop was sent (so: configured timeout minus time spent reaching the
   headers). H3 uses the configured value exactly, per pull. The small
   asymmetry is documented rather than engineered away.
4. Trailers on a streamed response are consumed and discarded — the head was
   already delivered. Upgrade path: a `trailers()` accessor post-EOF.
5. An abandoned H3 stream closes its whole connection. QUIC could
   STOP_SENDING just the stream and keep the connection, but reusable-after-
   abort means draining aborted-stream events without wedging the pool; one
   extra handshake per abandon is the price until a workload earns that.
6. A consumer that stops pulling (as opposed to being blocked *in* a pull —
   that keeps QUIC timers serviced) for longer than the QUIC idle timeout or
   the peer's patience may find the connection dead on resume; that surfaces
   as a mid-stream `Timeout`/`Transport` error. No background keepalive
   thread — that would be the core growing threads it otherwise doesn't have.
7. TLS session tickets are banked at headers-time; a ticket arriving mid-body
   is not. (Buffered path banks at body-end; tickets in practice arrive with
   the handshake flight, so both catch the normal case.)
8. `close()` waits for an in-flight `read_chunk` (they serialize on the
   stream's mutex). The cancel token is the asynchronous abort; every binding
   wrapper encodes "cancel, then close".
9. Pre-existing corner shared with the buffered path, unchanged: a connection
   whose response finished before the request body fully uploaded is still
   pooled with the request stream un-FINed. Rare (server answered early and
   successfully); flagged here so the review sees it, fixing it belongs to
   both paths at once or neither.

Not accepted — these were requirements, not preferences:

- Unbounded buffering anywhere when the consumer stalls (core, FFI layer, or
  Dart pump).
- Push callbacks across any FFI boundary.
- A second copy of the redirect/retry/fallback policy for the streaming path.
- Streaming as a bypass of `max_response_body_bytes`.
- A mid-stream failure reported as a failed *request* (the caller has a
  response object; the failure belongs to the stream).

## Where the risk actually is

Ranked, most worrying first:

1. **The Dart demand-driven pump.** Backpressure across isolate ports is easy
   to get subtly wrong (an eager loop looks identical in a demo and buffers
   unboundedly in production), and pause/resume/cancel interleavings with an
   in-flight blocking read need a real state machine. This is the piece to
   prototype first in phase 2, with a slow-consumer test wired to a fat body.
2. **UniFFI `Arc<Self>` receiver on the exported method.** Believed supported
   by the proc-macro; if not, the free-function fallback is defined above and
   costs only spelling. Verify before building wrappers on it.
3. **Kotlin/Swift cancellation ordering.** The token-then-close rule is easy
   to state and easy for a wrapper refactor to silently break; each binding
   should carry one test that cancels a blocked read and asserts prompt
   return.
4. **reqwest's per-read timeout re-anchoring** is load-bearing for TCP stream
   idle timeouts and is an implementation detail of reqwest's blocking
   `Read` impl (verified against 0.13.1: `wait::timeout` re-anchors per
   call). A reqwest upgrade that changes it would silently turn the idle
   budget into a total budget; the TCP `first_chunk_arrives_before_the_body_is_complete`
   test plus a long-stream test in CI is the tripwire.

## Does the shape extend to upload streaming?

Yes, mirrored. For upload the *core* is the consumer, so the roles flip: the
caller pushes with blocking calls — `request_body_stream()` returning a
handle with `write_chunk(bytes)` / `finish()` — and backpressure is the
`write_chunk` call blocking while QUIC/TCP send windows are full. That is
caller-driven push *into* the core, which works on Dart for the same reason
pull works (Dart initiates every call). It does not require callback
interfaces on any binding. Not designed further here; phase 3.
