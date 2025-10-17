import Alamofire
import Foundation
import Testing

@testable import VaneSwift

#if canImport(Darwin)
    import Darwin
#endif

#if canImport(Darwin)
    private func currentMallocUsageInBytes() -> UInt64? {
        var stats = malloc_statistics_t()
        malloc_zone_statistics(nil, &stats)
        return UInt64(stats.size_in_use)
    }
#else
    private func currentMallocUsageInBytes() -> UInt64? { nil }
#endif

struct VaneSwiftTests {
    private let baseURL = "http://127.0.0.1:8000"
    private let warmups = 10
    private let iterations = 100

    private func runBenchmark(
        summaryName: String,
        labelPrefix: String,
        iterations: Int,
        warmups: Int = 0,
        operations: [(label: String, action: () async throws -> Void)]
    ) async throws {
        var measurements: [(label: String, elapsed: TimeInterval, bytes: UInt64?)] = []

        for (label, action) in operations {
            if warmups > 0 {
                for _ in 0..<warmups {
                    try await action()
                }
            }

            let memBefore = currentMallocUsageInBytes()
            let start = Date()
            for _ in 0..<iterations {
                try await action()
            }
            let elapsed = Date().timeIntervalSince(start)
            let memAfter = currentMallocUsageInBytes()
            let bytesUsed = memAfter.flatMap { after in
                memBefore.flatMap { before in
                    after >= before ? after - before : nil
                }
            }
            measurements.append((label, elapsed, bytesUsed))
        }

        print("\nGo-style \(summaryName) summary:")
        for (label, elapsed, bytesUsed) in measurements {
            let name = "Benchmark\(labelPrefix)\(label)"
            let paddedName = name.padding(toLength: 24, withPad: " ", startingAt: 0)
            let nsPerOp = (elapsed / Double(iterations)) * 1_000_000_000
            let bytesColumn: String
            if let bytes = bytesUsed {
                bytesColumn = String(format: "%9.1f B/op", Double(bytes) / Double(iterations))
            } else {
                bytesColumn = "   n/a B/op"
            }
            let formattedLine = String(
                format: "%@%6d\t%9.0f ns/op\t%@\t(total %.3fs)",
                paddedName as NSString,
                iterations,
                nsPerOp,
                bytesColumn,
                elapsed
            )
            print(formattedLine)
        }
    }

    @Test
    func get() async throws {
        let session = try VaneSession()
        let response = try await session.get("\(baseURL)/get")
        print("response[get]: \(response)")
    }
    @Test
    func post() async throws {
        let config = VaneConfigurationBuilder()
            .baseURL(baseURL)
            .defaultHeaders(["Authorization": "Bearer token"])
            .timeout(30)
            .build()

        let session = try VaneSession(configuration: config)
        let response = try await session.post(
            "/post", body: "{\"message\": \"post\"}".data(using: .utf8))
        print("response[post]: \(response)")
    }

    @Test
    func benchmarkHTTPMethods() async throws {
        let config = VaneConfigurationBuilder()
            .baseURL(baseURL)
            .defaultHeaders(["Authorization": "Bearer token"])
            .timeout(30)
            .build()

        let session = try VaneSession(configuration: config)
        let operations: [(label: String, action: () async throws -> Void)] = [
            ("GET", { _ = try await session.get("/get") }),
            (
                "POST",
                {
                    _ = try await session.post(
                        "/post", body: "{\"message\": \"post\"}".data(using: .utf8))
                }
            ),
            (
                "PUT",
                {
                    _ = try await session.put(
                        "/put", body: "{\"message\": \"put\"}".data(using: .utf8))
                }
            ),
            (
                "PATCH",
                {
                    _ = try await session.patch(
                        "/patch", body: "{\"message\": \"patch\"}".data(using: .utf8))
                }
            ),
            ("DELETE", { _ = try await session.delete("/delete") }),
        ]

        try await runBenchmark(
            summaryName: "Vane benchmark",
            labelPrefix: "Vane",
            iterations: iterations,
            warmups: warmups,
            operations: operations
        )
    }

    @Test
    func benchmarkAlamofireHTTPMethods() async throws {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30
        let session = Session(configuration: configuration)
        let headers: HTTPHeaders = ["Authorization": "Bearer token"]

        let operations: [(label: String, action: () async throws -> Void)] = [
            (
                "GET",
                {
                    _ =
                        try await session
                        .request("\(baseURL)/get", headers: headers)
                        .serializingData()
                        .value
                }
            ),
            (
                "POST",
                {
                    _ =
                        try await session
                        .request(
                            "\(baseURL)/post",
                            method: .post,
                            parameters: ["message": "post"],
                            encoder: JSONParameterEncoder.default,
                            headers: headers
                        )
                        .serializingData()
                        .value
                }
            ),
            (
                "PUT",
                {
                    _ =
                        try await session
                        .request(
                            "\(baseURL)/put",
                            method: .put,
                            parameters: ["message": "put"],
                            encoder: JSONParameterEncoder.default,
                            headers: headers
                        )
                        .serializingData()
                        .value
                }
            ),
            (
                "PATCH",
                {
                    _ =
                        try await session
                        .request(
                            "\(baseURL)/patch",
                            method: .patch,
                            parameters: ["message": "patch"],
                            encoder: JSONParameterEncoder.default,
                            headers: headers
                        )
                        .serializingData()
                        .value
                }
            ),
            (
                "DELETE",
                {
                    _ =
                        try await session
                        .request("\(baseURL)/delete", method: .delete, headers: headers)
                        .serializingData()
                        .value
                }
            ),
        ]

        try await runBenchmark(
            summaryName: "Alamofire benchmark",
            labelPrefix: "Alamofire",
            iterations: iterations,
            warmups: warmups,
            operations: operations
        )
    }
}
