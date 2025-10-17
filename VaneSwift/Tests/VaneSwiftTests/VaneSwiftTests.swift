import Testing

@testable import VaneSwift

struct VaneSwiftTests {

    @Test
    func get() async throws {
        let session = try VaneSession()
        let response = try await session.get("https://httpbin.org/get")
        print("response[get]: \(response)")
    }
    @Test
    func post() async throws {
        let config = VaneConfigurationBuilder()
            .baseURL("https://httpbin.org")
            .defaultHeaders(["Authorization": "Bearer token"])
            .timeout(30)
            .build()

        let session = try VaneSession(configuration: config)
        let response = try await session.post("post", body: "{\"message\": \"post\"}")
        print("response[post]: \(response)")
    }
}
