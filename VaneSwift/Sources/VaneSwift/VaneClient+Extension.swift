import Foundation

#if canImport(vaneFFI)
    import vaneFFI
#endif

// MARK: - Usage Examples

/*
// Basic usage
let session = try VaneSession()
let response = try await session.get("https://api.example.com/users")

// With configuration
let config = VaneConfigurationBuilder()
    .baseURL("https://api.example.com")
    .defaultHeaders(["Authorization": "Bearer token"])
    .timeout(30)
    .build()

let session = try VaneSession(configuration: config)

// Request builder pattern
let users = try await session.request("/users")
    .header("Accept", "application/json")
    .queryParam("page", "1")
    .responseJSON([User].self)

// POST with JSON
let newUser = User(name: "John", email: "john@example.com")
let response = try await session.request("/users", method: .post)
    .jsonBody(newUser)
    .execute()
*/

// MARK: - Swift Extensions and Helpers

extension VaneClient {

    // MARK: - Async/Await Support

    @available(iOS 13.0, *)
    public func get(_ url: String) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.getRequest(url: url)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    @available(iOS 13.0, *)
    public func post(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.postRequest(url: url, body: body)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    @available(iOS 13.0, *)
    public func put(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.putRequest(url: url, body: body)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    @available(iOS 13.0, *)
    public func delete(_ url: String) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.deleteRequest(url: url)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    @available(iOS 13.0, *)
    public func patch(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.patchRequest(url: url, body: body)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    @available(iOS 13.0, *)
    public func execute(_ request: VaneRequest) async throws -> VaneResponse {
        return try await withCheckedThrowingContinuation { continuation in
            Task.detached(priority: .utility) { @Sendable in
                do {
                    let response = try self.executeRequest(request: request)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

// MARK: - Alamofire-style Interface

@available(iOS 13.0, *)
public class VaneSession {
    private let client: VaneClient

    public init(configuration: VaneClientConfig = createDefaultConfig()) throws {
        self.client = try createVaneClient(config: configuration)
    }

    // MARK: - Request Building

    public func request(_ url: String, method: HTTPMethod = .get) -> VaneRequestBuilder {
        return VaneRequestBuilder(client: client, url: url, method: method)
    }

    // MARK: - Direct Methods

    public func get(_ url: String) async throws -> VaneResponse {
        return try await client.get(url)
    }

    public func post(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await client.post(url, body: body)
    }

    public func put(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await client.put(url, body: body)
    }

    public func delete(_ url: String) async throws -> VaneResponse {
        return try await client.delete(url)
    }

    public func patch(_ url: String, body: Data? = nil) async throws -> VaneResponse {
        return try await client.patch(url, body: body)
    }
}

// MARK: - HTTP Methods

public enum HTTPMethod: String, CaseIterable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case delete = "DELETE"
    case patch = "PATCH"
    case head = "HEAD"
    case options = "OPTIONS"
}

// MARK: - Request Builder

@available(iOS 13.0, *)
public class VaneRequestBuilder {
    private let client: VaneClient
    private var request: VaneRequest

    internal init(client: VaneClient, url: String, method: HTTPMethod) {
        self.client = client
        self.request = VaneRequest(
            url: url,
            method: method.rawValue,
            headers: [:],
            queryParams: [:],
            body: nil,
            timeoutSeconds: nil,
            followRedirects: true
        )
    }

    // MARK: - Builder Methods

    public func headers(_ headers: [String: String]) -> VaneRequestBuilder {
        request.headers = headers
        return self
    }

    public func header(_ key: String, _ value: String) -> VaneRequestBuilder {
        request.headers[key] = value
        return self
    }

    public func queryParams(_ params: [String: String]) -> VaneRequestBuilder {
        request.queryParams = params
        return self
    }

    public func queryParam(_ key: String, _ value: String) -> VaneRequestBuilder {
        request.queryParams[key] = value
        return self
    }

    public func body(_ body: Data) -> VaneRequestBuilder {
        request.body = body
        return self
    }

    public func jsonBody<T: Codable>(_ object: T) throws -> VaneRequestBuilder {
        request.body = try JSONEncoder().encode(object)
        request.headers["Content-Type"] = "application/json"
        return self
    }

    public func timeout(_ seconds: UInt64) -> VaneRequestBuilder {
        request.timeoutSeconds = seconds
        return self
    }

    public func followRedirects(_ follow: Bool) -> VaneRequestBuilder {
        request.followRedirects = follow
        return self
    }

    // MARK: - Execution

    public func execute() async throws -> VaneResponse {
        return try await client.execute(request)
    }

    public func responseJSON<T: Codable>(_ type: T.Type) async throws -> T {
        let response = try await execute()

        guard response.isSuccess else {
            throw VaneError.Generic("Request failed with status \(response.statusCode)")
        }

        return try JSONDecoder().decode(type, from: response.body)
    }

    public func responseString() async throws -> String {
        let response = try await execute()

        guard response.isSuccess else {
            throw VaneError.Generic("Request failed with status \(response.statusCode)")
        }

        if let string = String(data: response.body, encoding: .utf8) {
            return string
        }
        return ""
    }
}

// MARK: - Configuration Builder

public class VaneConfigurationBuilder {
    private var config = createDefaultConfig()

    public func baseURL(_ url: String) -> VaneConfigurationBuilder {
        config.baseUrl = url
        return self
    }

    public func defaultHeaders(_ headers: [String: String]) -> VaneConfigurationBuilder {
        config.defaultHeaders = headers
        return self
    }

    public func timeout(_ seconds: UInt64) -> VaneConfigurationBuilder {
        config.timeoutSeconds = seconds
        return self
    }

    public func userAgent(_ agent: String) -> VaneConfigurationBuilder {
        config.userAgent = agent
        return self
    }

    public func followRedirects(_ follow: Bool) -> VaneConfigurationBuilder {
        config.followRedirects = follow
        return self
    }

    public func build() -> VaneClientConfig {
        return config
    }
}

// MARK: - Convenience Extensions

extension VaneResponse {

    public var isSuccessful: Bool {
        return isSuccess
    }

    public func json<T: Codable>(_ type: T.Type) throws -> T {
        return try JSONDecoder().decode(type, from: body)
    }

    public var prettyJSON: String? {
        return try? parseJsonResponse(resp: self)
    }
}
