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
