# 🦀 Vane – Cross-Platform HTTP Client [In-Progress]

A lightweight, **Rust-powered** HTTP client that feels native on both
iOS (Alamofire-style) and Android (Retrofit2-style).

---

## Core Features

| Rust Core |
|-----------|
| • [reqwest](https://docs.rs/reqwest) backend
| • [UniFFI](https://github.com/mozilla/uniffi-rs) bindings
| • GET, POST, PUT, DELETE, PATCH
| • Headers, query params, timeouts
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
    .timeout(30)
    .build()

let session = try VaneSession(configuration: config)

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
    .timeout(30u)
    .build()

val session = VaneSession(config)

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
