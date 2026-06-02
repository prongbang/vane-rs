# Vane - Cross-Platform HTTP Client [In-Progress]

A lightweight, **Rust-powered** HTTP client that feels native on both
iOS (Alamofire-style) and Android (Retrofit2-style).

---

## Protocol Strategy

The current Rust core supports HTTP/3 through Cloudflare `quiche`, plus
HTTP/2 and HTTP/1.1 through a `hyper`/`hyper-util`/`hyper-rustls` TCP fallback backend. The default
protocol mode is `HTTP/3 -> HTTP/2 -> HTTP/1.1`.

A smaller Swift-only artifact can be built with `make build_swift_small`. That
profile is intended for HTTP/3-only apps that need minimum static archive size:
it disables the HTTP/1.1/HTTP/2 fallback backend and supports certificate DER
pins (`sha256-cert/<base64>`) without SPKI pin parsing (`sha256/<base64>`).

HTTP/1.0 and dynamic DNS callback resolvers are explicitly unsupported in the
first production candidate. Static custom DNS overrides are available for
routing a hostname to a specific IP while preserving the original hostname for
SNI, authority, and certificate verification. HTTP, HTTPS endpoint, SOCKS5, and
SOCKS5h proxy support is available for the HTTP/1.1 and HTTP/2 TCP fallback
backend; HTTPS origins use CONNECT or SOCKS tunnels before origin TLS. HTTP/3
over QUIC does not use the proxy path, so proxy-enabled default mode falls back
to the TCP backend. HTTP/3 proxying is not supported yet because it requires a
MASQUE/CONNECT-UDP transport path. Certificate pinning is available as opt-in
host-scoped pins for the HTTP/3 backend. The TCP fallback refuses pinned hosts
until TCP/TLS pin verification is implemented, so fallback cannot silently
bypass pins. Optional retry policy, HTTP/3 connection pooling, and in-memory
cookies are available behind explicit configuration. Remaining production work
is tracked in the repository root `PLAN.md`.

---

## Release Verification

Run the full local release verification from the repository root:

```bash
./scripts/release-build.sh
```

The script checks Rust formatting, tests, and clippy; regenerates Kotlin and
Swift UniFFI bindings; rebuilds Android and Swift native artifacts; runs Kotlin
unit tests, Android release AAR assembly, and Swift tests; and fails if
accidental `.DS_Store` files appear in Android native output.

GitHub Actions runs the same release verification in
`.github/workflows/release.yml`, checks that regenerated artifacts are current,
uploads the Android AAR and Swift XCFramework, and reports artifact sizes in the
workflow summary.

Live HTTP/3 tests are opt-in and require an HTTPS endpoint that supports
HTTP/3:

```bash
VANE_TEST_BASE_URL=https://<http3-enabled-host> cargo test --release
VANE_TEST_BASE_URL=https://<http3-enabled-host> swift test
```

The Rust live certificate pin test is also opt-in:

```bash
VANE_TEST_BASE_URL=https://<http3-enabled-host> \
VANE_TEST_CERT_PIN='sha256/<base64-spki-sha256>' \
cargo test --release live_http3_certificate_pin_when_env_pin_is_set
```

Android instrumented live tests read `VANE_TEST_BASE_URL` from instrumentation
arguments:

```bash
./gradlew :library:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.VANE_TEST_BASE_URL=https://<http3-enabled-host>
```

`https://httpbin.org` is useful for validating the default fallback path in
some environments, but in the current release verification environment it does
not complete Vane's HTTP/3-only QUIC handshake. Use a confirmed HTTP/3 endpoint
for HTTP/3-only validation.

---

## Core Features

| Rust Core |
|-----------|
| • [quiche](https://github.com/cloudflare/quiche) HTTP/3 backend
| • [hyper](https://github.com/hyperium/hyper), hyper-util, and hyper-rustls HTTP/2 and HTTP/1.1 fallback backend
| • [UniFFI](https://github.com/mozilla/uniffi-rs) bindings
| • GET, POST, PUT, DELETE, PATCH
| • Headers, query params, timeouts, static DNS overrides
| • HTTP proxy support for HTTP/1.1 and HTTP/2 fallback
| • Optional host-scoped certificate pinning
| • Optional retry policy and HTTP/3 connection pooling
| • Optional in-memory cookie jar
| • Configurable request and response body limits
| • Rich error handling

---

## iOS (Swift) – Alamofire-like API

• Request builder pattern with `async/await`
• `VaneSession` + `VaneRequestBuilder`
• JSON encode / decode
• Configuration builder

```swift
import VaneClient

// 1-liner
let session = try VaneSession()
let users   = try await session.get("https://api.example.com/users")

// With custom config
let config = VaneConfigurationBuilder()
    .baseURL("https://api.example.com")
    .defaultHeaders(["Authorization": "Bearer token"])
    .dnsOverride(host: "api.example.com", ipAddress: "203.0.113.10")
    .proxy("http://proxy.example.com:8080", authorization: "Basic <base64>")
    .certificatePin(host: "api.example.com", pins: [
        "sha256/<base64-spki-sha256>",
        "sha256/<backup-base64-spki-sha256>"
    ])
    .cookiesEnabled(true)
    .connectionPooling(enabled: true, maxIdleConnections: 4, idleTimeoutSeconds: 30)
    .retry(maxAttempts: 3, initialDelayMillis: 100, maxDelayMillis: 1_000)
    .bodyLimits(maxRequestBodyBytes: 64 * 1024 * 1024, maxResponseBodyBytes: 64 * 1024 * 1024)
    .http3ThenHttp2ThenHttp1()
    .timeout(30)
    .build()

let session = try VaneSession(configuration: config)

let authenticatedSession = try VaneSession(
    configuration: config,
    requestInterceptors: [
        { request in
            var request = request
            request.headers["Authorization"] = "Bearer \(token)"
            return request
        }
    ],
    responseInterceptors: [
        { response in
            // Inspect or normalize responses before callers receive them.
            response
        }
    ]
)

// Builder pattern
struct User: Codable { let id, name, email: String }
let list = try await session.request("/users")
    .header("Accept", "application/json")
    .queryParam("page", "1")
    .responseJSON([User].self)
```

---

## Android (Kotlin) – Retrofit2-like API

• Coroutine support
• Annotation-driven service interfaces
• Kotlinx-serialization integration
• Custom exceptions

**Usage**
```kotlin
import com.example.vane.*
import kotlinx.coroutines.launch

@Serializable
data class User(
    val id: String? = null,
    val name: String,
    val email: String
)

val config = VaneConfigurationBuilder()
    .baseUrl("https://api.example.com")
    .defaultHeaders(mapOf("Authorization" to "Bearer token"))
    .dnsOverride("api.example.com", "203.0.113.10")
    .proxy("http://proxy.example.com:8080", authorization = "Basic <base64>")
    .certificatePin(
        "api.example.com",
        listOf(
            "sha256/<base64-spki-sha256>",
            "sha256/<backup-base64-spki-sha256>"
        )
    )
    .cookiesEnabled(true)
    .connectionPooling(enabled = true, maxIdleConnections = 4u, idleTimeoutSeconds = 30u)
    .retry(maxAttempts = 3u, initialDelayMillis = 100u, maxDelayMillis = 1_000u)
    .bodyLimits(maxRequestBodyBytes = 64u * 1024u * 1024u, maxResponseBodyBytes = 64u * 1024u * 1024u)
    .http3ThenHttp2ThenHttp1()
    .timeout(30u)
    .build()

val session = VaneSession(config)

val authenticatedSession = VaneSession(
    configuration = config,
    requestInterceptors = listOf { request ->
        request.copy(headers = request.headers + ("Authorization" to "Bearer $token"))
    },
    responseInterceptors = listOf { response ->
        response
    }
)

class UserViewModel : ViewModel() {
    private val session = VaneSession(config)

    fun loadUsers() = viewModelScope.launch {
        try {
            val users = session.request("/users")
                .header("Accept", "application/json")
                .queryParam("page", "1")
                .responseJson<List<User>>()
            // update UI
        } catch (e: VaneHttpException) {
            // handle error
        }
    }
}
```

Certificate pin formats:

- `sha256/<base64>`: SHA-256 of the certificate SubjectPublicKeyInfo. Prefer
  this for production because it supports certificate renewal with the same key.
  This format requires the default `spki-pinning` feature.
- `sha256-cert/<base64>`: SHA-256 of the full DER leaf certificate. This is
  stricter, but rotates whenever the certificate changes.

Retry defaults to disabled through `retryMaxAttempts = 1`. When configured,
Vane retries transient transport failures and HTTP status `408`, `425`, `429`,
`500`, `502`, `503`, and `504` for idempotent methods only. Retrying `POST` and
`PATCH` requires `retryUnsafeMethods = true`.

Connection pooling defaults to disabled. When enabled, Vane keeps idle HTTP/3
connections by origin, DNS override, protocol mode, and certificate pin set.
The HTTP/1.1 and HTTP/2 fallback backend uses hyper-util's internal pooling.

Proxy support is explicit and opt-in. Configure `proxyUrl` with an
`http://host:port`, `https://host:port`, `socks5://host:port`, or
`socks5h://host:port` proxy URL. Plain HTTP requests are forwarded through HTTP
or HTTPS proxy endpoints; HTTPS origins use CONNECT before TLS/ALPN negotiation
with the origin. SOCKS5 proxies create a TCP tunnel to the origin, and
`socks5h` asks the proxy to resolve the target hostname. `proxyAuthorization`
accepts a full HTTP proxy header value such as `Basic <base64>`; SOCKS5
username/password auth can be supplied as URL userinfo. Proxy support is limited
to the HTTP/1.1/HTTP/2 TCP fallback backend. HTTP/3 proxying is not supported
yet because QUIC proxying requires a MASQUE/CONNECT-UDP transport path. The
Rust test suite includes local proxy coverage for HTTP forwarding, HTTPS
CONNECT, and SOCKS5 tunnels. Real proxy smoke tests can be run by setting
`VANE_TEST_PROXY_URL`, optional `VANE_TEST_PROXY_AUTHORIZATION`, and
`VANE_TEST_BASE_URL`.

Protocol modes:

- `Http3ThenHttp2ThenHttp1`: default. Try HTTP/3 first, then fall back to
  HTTP/2 or HTTP/1.1 over TCP/TLS.
- `Http3Only`: force HTTP/3 over QUIC.
- `Http2ThenHttp1`: use the TCP/TLS backend with ALPN for HTTP/2 or HTTP/1.1.
- `Http2Only`: force HTTP/2 through the TCP/TLS backend.
- `Http1Only`: force HTTP/1.1 through the TCP/TLS backend.

Cookies default to disabled. When enabled, Vane keeps an in-memory cookie jar
inside each `VaneClient`/`VaneSession`. The jar handles common `Set-Cookie`
flows with host/domain scoping, path scoping, Secure cookies, and `Max-Age`
expiration/deletion. Platform persistence is not implemented yet.

Swift and Kotlin sessions support request, response, and error interceptors.
Use them for auth header injection, token refresh wrappers, response
normalization, or stable app-level error mapping. Interceptors are applied
before and after the Rust transport client, and direct methods route through
the same interceptor chain as request builders.

---

## Feature Matrix

| Alamofire-like ✅ | Retrofit2-like ✅ |
|------------------|------------------|
| Request / Response handling | Service-interface pattern |
| JSON (de)serialization | Annotation-based API |
| Request builders | Coroutines |
| Header management | Path & query parameters |
| Query parameters | Request / response interceptors |
| Timeout configuration | Base-URL configuration |
| async / await | Error handling |
| Response validation | – |

---

## Custom Serialization

```swift
// iOS
extension VaneResponse {
    func decode<T: Decodable>(_ type: T.Type,
                              using decoder: JSONDecoder = .init()) throws -> T {
        guard let data = body.data(using: .utf8) else { throw VaneError(...) }
        return try decoder.decode(type, from: data)
    }
}
```

```kotlin
// Android
inline fun <reified T> VaneResponse.decode(
    json: Json = Json.Default
): T = json.decodeFromString(body)
```

---

## Interceptors / Global Headers

```swift
// iOS – per request
let response = try await session.request("/data")
    .header("X-Custom-Header", "value")
    .execute()
```

```kotlin
// Android – global via config
val config = VaneConfigurationBuilder()
    .defaultHeaders(mapOf(
        "X-Request-ID" to UUID.randomUUID().toString()
    ))
    .build()
```

---

## Testing

```swift
// iOS (XCTest)
import XCTest
@testable import VaneClient

class VaneClientTests: XCTestCase {
    func testGetRequest() async throws {
        let session = try VaneSession()
        let response = try await session.get("https://httpbin.org/get")
        XCTAssertTrue(response.isSuccessful)
    }
}
```

## Benchmark

### iOS

🦀 Vane 1.0 — High Performance Profile


delivers ≈ 4 – 5× faster execution and lower memory usage than Alamofire on iOS

#### Vane
```sh
BenchmarkVaneGET           100	    91460 ns/op	   5930.2 B/op	(total 0.009s)
BenchmarkVanePOST          100	    91801 ns/op	   n/a B/op	    (total 0.009s)
BenchmarkVanePUT           100	    98230 ns/op	     45.9 B/op	(total 0.010s)
BenchmarkVanePATCH         100	    87650 ns/op	   n/a B/op	    (total 0.009s)
BenchmarkVaneDELETE        100	    83600 ns/op	    197.3 B/op	(total 0.008s)
```

#### Alamofire
```sh
BenchmarkAlamofireGET      100	   364710 ns/op	     47.5 B/op	(total 0.036s)
BenchmarkAlamofirePOST     100	   462700 ns/op	    430.9 B/op	(total 0.046s)
BenchmarkAlamofirePUT      100	   427270 ns/op	    353.9 B/op	(total 0.043s)
BenchmarkAlamofirePATCH    100	   467421 ns/op	     69.9 B/op	(total 0.047s)
BenchmarkAlamofireDELETE   100	   326899 ns/op	    127.4 B/op	(total 0.033s)
```

## Android

🦀 Vane 1.0 — High Performance Profile (Android)

Vane delivers ≈ 2.5 – 3× faster execution and ≈ 3× lower memory usage than Retrofit2 on Android.

- Vane
```sh
BenchmarkVaneGET           100	  1002041 ns/op	  12320.0 B/op	(total 0.100s)
BenchmarkVanePOST          100	   963228 ns/op	  12483.0 B/op	(total 0.096s)
BenchmarkVanePUT           100	   785213 ns/op	  13139.0 B/op	(total 0.079s)
BenchmarkVanePATCH         100	   444038 ns/op	  11500.0 B/op	(total 0.044s)
BenchmarkVaneDELETE        100	   452196 ns/op	  11500.0 B/op	(total 0.045s)
```

- Retrofit2
```sh
BenchmarkRetrofitGET       100	  2219359 ns/op	  27033.0 B/op	(total 0.222s)
BenchmarkRetrofitPOST      100	  1417330 ns/op	  38206.0 B/op	(total 0.142s)
BenchmarkRetrofitPUT       100	  1273835 ns/op	  38944.0 B/op	(total 0.127s)
BenchmarkRetrofitPATCH     100	  1155910 ns/op	  38370.0 B/op	(total 0.116s)
BenchmarkRetrofitDELETE    100	  1224208 ns/op	  27279.0 B/op	(total 0.122s)
```
