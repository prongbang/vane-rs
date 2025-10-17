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

### Vane
```
Benchmark summary:
BenchmarkGET                 5	   584388 ns/op	    374.4 B/op	(total 0.003s)
BenchmarkPOST                5	   205588 ns/op	     64.0 B/op	(total 0.001s)
BenchmarkPUT                 5	   188398 ns/op	      0.0 B/op	(total 0.001s)
BenchmarkPATCH               5	   164008 ns/op	      0.0 B/op	(total 0.001s)
BenchmarkDELETE              5	   148201 ns/op	      0.0 B/op	(total 0.001s)
```

### Alamofire

Go-style Vane benchmark summary:
BenchmarkVaneGET             5	   762796 ns/op	  46822.4 B/op	(total 0.004s)
BenchmarkVanePOST            5	   197411 ns/op	   1536.0 B/op	(total 0.001s)
BenchmarkVanePUT             5	   190210 ns/op	   n/a B/op	(total 0.001s)
BenchmarkVanePATCH           5	   177002 ns/op	  13811.2 B/op	(total 0.001s)
BenchmarkVaneDELETE          5	   175810 ns/op	   3171.2 B/op	(total 0.001s)

Go-style Alamofire benchmark summary:
BenchmarkAlamofireGET        5	  4641199 ns/op	 114710.4 B/op	(total 0.023s)
BenchmarkAlamofirePOST       5	   622797 ns/op	   n/a B/op	(total 0.003s)
BenchmarkAlamofirePUT        5	   536203 ns/op	    147.2 B/op	(total 0.003s)
BenchmarkAlamofirePATCH      5	   516796 ns/op	   8083.2 B/op	(total 0.003s)
BenchmarkAlamofireDELETE     5	   335598 ns/op	   3516.8 B/op	(total 0.002s)

Go-style Vane benchmark summary:
BenchmarkVaneGET            20	   184351 ns/op	   6085.6 B/op	(total 0.004s)
BenchmarkVanePOST           20	   185901 ns/op	  25052.0 B/op	(total 0.004s)
BenchmarkVanePUT            20	   167352 ns/op	    552.0 B/op	(total 0.003s)
BenchmarkVanePATCH          20	   174099 ns/op	   n/a B/op	(total 0.003s)
BenchmarkVaneDELETE         20	   169152 ns/op	   1961.6 B/op	(total 0.003s)
✔ Test benchmarkHTTPMethods() passed after 0.026 seconds.

Go-style Alamofire benchmark summary:
BenchmarkAlamofireGET       20	   381005 ns/op	   n/a B/op	(total 0.008s)
BenchmarkAlamofirePOST      20	   594747 ns/op	   n/a B/op	(total 0.012s)
BenchmarkAlamofirePUT       20	   504297 ns/op	    448.0 B/op	(total 0.010s)
BenchmarkAlamofirePATCH     20	   499952 ns/op	   1478.4 B/op	(total 0.010s)
BenchmarkAlamofireDELETE    20	   333846 ns/op	   n/a B/op	(total 0.007s)

Go-style Vane benchmark summary:
BenchmarkVaneGET            20	   170350 ns/op	   6241.6 B/op	(total 0.003s)
BenchmarkVanePOST           20	   156647 ns/op	   7536.0 B/op	(total 0.003s)
BenchmarkVanePUT            20	   139350 ns/op	   9622.4 B/op	(total 0.003s)
BenchmarkVanePATCH          20	   146401 ns/op	    250.4 B/op	(total 0.003s)
BenchmarkVaneDELETE         20	   165200 ns/op	     32.8 B/op	(total 0.003s)
✔ Test benchmarkHTTPMethods() passed after 0.022 seconds.

Go-style Alamofire benchmark summary:
BenchmarkAlamofireGET       20	   372797 ns/op	   n/a B/op	(total 0.007s)
BenchmarkAlamofirePOST      20	   621200 ns/op	   n/a B/op	(total 0.012s)
BenchmarkAlamofirePUT       20	   501955 ns/op	    392.0 B/op	(total 0.010s)
BenchmarkAlamofirePATCH     20	   540745 ns/op	   1841.6 B/op	(total 0.011s)
BenchmarkAlamofireDELETE    20	   347149 ns/op	    691.2 B/op	(total 0.007s)

Go-style Vane benchmark summary:
BenchmarkVaneGET            35	   160371 ns/op	   5481.1 B/op	(total 0.006s)
BenchmarkVanePOST           35	   166001 ns/op	   4829.7 B/op	(total 0.006s)
BenchmarkVanePUT            35	   190088 ns/op	   n/a B/op	(total 0.007s)
BenchmarkVanePATCH          35	   194427 ns/op	   1407.1 B/op	(total 0.007s)
BenchmarkVaneDELETE         35	   181430 ns/op	    475.9 B/op	(total 0.006s)
✔ Test benchmarkHTTPMethods() passed after 0.046 seconds.

Go-style Alamofire benchmark summary:
BenchmarkAlamofireGET       35	   451313 ns/op	   n/a B/op	(total 0.016s)
BenchmarkAlamofirePOST      35	   689254 ns/op	   n/a B/op	(total 0.024s)
BenchmarkAlamofirePUT       35	   517886 ns/op	    483.7 B/op	(total 0.018s)
BenchmarkAlamofirePATCH     35	   516599 ns/op	    514.7 B/op	(total 0.018s)
BenchmarkAlamofireDELETE    35	   314059 ns/op	    103.8 B/op	(total 0.011s)
