package com.inteniquetic.vane

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.Serializable
import com.inteniquetic.vane.* // Generated UniFFI bindings

// MARK: - Kotlin Extensions and Helpers

enum class HttpMethod(val value: String) {
    GET("GET"),
    POST("POST"),
    PUT("PUT"),
    DELETE("DELETE"),
    PATCH("PATCH"),
    HEAD("HEAD"),
    OPTIONS("OPTIONS")
}

// MARK: - Coroutine Extensions

suspend fun VaneClient.getAsync(url: String): VaneResponse {
    return withContext(Dispatchers.IO) {
        getRequest(url)
    }
}

suspend fun VaneClient.postAsync(url: String, body: String? = null): VaneResponse {
    return withContext(Dispatchers.IO) {
        postRequest(url, body)
    }
}

suspend fun VaneClient.putAsync(url: String, body: String? = null): VaneResponse {
    return withContext(Dispatchers.IO) {
        putRequest(url, body)
    }
}

suspend fun VaneClient.deleteAsync(url: String): VaneResponse {
    return withContext(Dispatchers.IO) {
        deleteRequest(url)
    }
}

suspend fun VaneClient.patchAsync(url: String, body: String? = null): VaneResponse {
    return withContext(Dispatchers.IO) {
        patchRequest(url, body)
    }
}

suspend fun VaneClient.executeAsync(request: VaneRequest): VaneResponse {
    return withContext(Dispatchers.IO) {
        executeRequest(request)
    }
}

// MARK: - Retrofit-style Interface

class VaneSession(private val configuration: VaneClientConfig = createDefaultConfig()) {
    private val client: VaneClient by lazy {
        createVaneClient(configuration)
    }

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    // MARK: - Request Building

    fun request(url: String, method: HttpMethod = HttpMethod.GET): VaneRequestBuilder {
        return VaneRequestBuilder(client, url, method, json)
    }

    // MARK: - Direct Methods

    suspend fun get(url: String): VaneResponse {
        return client.getAsync(url)
    }

    suspend fun post(url: String, body: String? = null): VaneResponse {
        return client.postAsync(url, body)
    }

    suspend fun put(url: String, body: String? = null): VaneResponse {
        return client.putAsync(url, body)
    }

    suspend fun delete(url: String): VaneResponse {
        return client.deleteAsync(url)
    }

    suspend fun patch(url: String, body: String? = null): VaneResponse {
        return client.patchAsync(url, body)
    }
}

// MARK: - Request Builder

class VaneRequestBuilder internal constructor(
    private val client: VaneClient,
    private val url: String,
    private val method: HttpMethod,
    private val json: Json
) {
    private var headers = mutableMapOf<String, String>()
    private var queryParams = mutableMapOf<String, String>()
    private var body: String? = null
    private var timeoutSeconds: ULong? = null
    private var followRedirects = true

    // MARK: - Builder Methods

    fun headers(headers: Map<String, String>): VaneRequestBuilder {
        this.headers.putAll(headers)
        return this
    }

    fun header(key: String, value: String): VaneRequestBuilder {
        headers[key] = value
        return this
    }

    fun queryParams(params: Map<String, String>): VaneRequestBuilder {
        queryParams.putAll(params)
        return this
    }

    fun queryParam(key: String, value: String): VaneRequestBuilder {
        queryParams[key] = value
        return this
    }

    fun body(body: String): VaneRequestBuilder {
        this.body = body
        return this
    }

    inline fun <reified T> jsonBody(obj: T): VaneRequestBuilder {
        val jsonString = json.encodeToString(obj)
        this.body = createJsonBody(jsonString)
        header("Content-Type", "application/json")
        return this
    }

    fun timeout(seconds: ULong): VaneRequestBuilder {
        timeoutSeconds = seconds
        return this
    }

    fun followRedirects(follow: Boolean): VaneRequestBuilder {
        followRedirects = follow
        return this
    }

    // MARK: - Execution

    suspend fun execute(): VaneResponse {
        val request = VaneRequest(
            url = url,
            method = method.value,
            headers = headers,
            queryParams = queryParams,
            body = body,
            timeoutSeconds = timeoutSeconds,
            followRedirects = followRedirects
        )
        return client.executeAsync(request)
    }

    suspend inline fun <reified T> responseJson(): T {
        val response = execute()

        if (!response.isSuccess) {
            throw VaneHttpException(
                message = "Request failed with status ${response.statusCode}",
                statusCode = response.statusCode,
                response = response
            )
        }

        return json.decodeFromString<T>(response.body)
    }

    suspend fun responseString(): String {
        val response = execute()

        if (!response.isSuccess) {
            throw VaneHttpException(
                message = "Request failed with status ${response.statusCode}",
                statusCode = response.statusCode,
                response = response
            )
        }

        return response.body
    }
}

// MARK: - Configuration Builder

class VaneConfigurationBuilder {
    private var config = createDefaultConfig()

    fun baseUrl(url: String): VaneConfigurationBuilder {
        config.baseUrl = url
        return this
    }

    fun defaultHeaders(headers: Map<String, String>): VaneConfigurationBuilder {
        config.defaultHeaders = headers.toMutableMap()
        return this
    }

    fun timeout(seconds: ULong): VaneConfigurationBuilder {
        config.timeoutSeconds = seconds
        return this
    }

    fun userAgent(agent: String): VaneConfigurationBuilder {
        config.userAgent = agent
        return this
    }

    fun followRedirects(follow: Boolean): VaneConfigurationBuilder {
        config.followRedirects = follow
        return this
    }

    fun build(): VaneClientConfig {
        return config
    }
}

// MARK: - Custom Exceptions

class VaneHttpException(
    message: String,
    val statusCode: UShort,
    val response: VaneResponse
) : Exception(message)

class VaneNetworkException(
    message: String,
    val errorType: String,
    cause: Throwable? = null
) : Exception(message, cause)

// MARK: - Extensions

val VaneResponse.isSuccessful: Boolean
    get() = isSuccess

inline fun <reified T> VaneResponse.json(): T {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    return json.decodeFromString<T>(body)
}

val VaneResponse.prettyJson: String?
    get() = try {
        parseJsonResponse(this)
    } catch (e: Exception) {
        null
    }

// MARK: - Retrofit-style Service Interface

interface VaneService {
    suspend fun get(url: String): VaneResponse
    suspend fun post(url: String, body: String? = null): VaneResponse
    suspend fun put(url: String, body: String? = null): VaneResponse
    suspend fun delete(url: String): VaneResponse
    suspend fun patch(url: String, body: String? = null): VaneResponse
}

class VaneServiceImpl(private val session: VaneSession) : VaneService {
    override suspend fun get(url: String): VaneResponse = session.get(url)
    override suspend fun post(url: String, body: String?): VaneResponse = session.post(url, body)
    override suspend fun put(url: String, body: String?): VaneResponse = session.put(url, body)
    override suspend fun delete(url: String): VaneResponse = session.delete(url)
    override suspend fun patch(url: String, body: String?): VaneResponse = session.patch(url, body)
}

// MARK: - Annotation-based Service (Retrofit-style)

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class GET(val value: String)

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class POST(val value: String)

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class PUT(val value: String)

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class DELETE(val value: String)

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class PATCH(val value: String)

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Path(val value: String)

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Query(val value: String)

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Header(val value: String)

@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
annotation class Body

// MARK: - Example Service Interface

interface ApiService {
    @GET("/users")
    suspend fun getUsers(): List<User>

    @GET("/users/{id}")
    suspend fun getUser(@Path("id") id: String): User

    @POST("/users")
    suspend fun createUser(@Body user: User): User

    @PUT("/users/{id}")
    suspend fun updateUser(@Path("id") id: String, @Body user: User): User

    @DELETE("/users/{id}")
    suspend fun deleteUser(@Path("id") id: String): VaneResponse

    @GET("/search")
    suspend fun searchUsers(@Query("q") query: String): List<User>
}

@Serializable
data class User(
    val id: String? = null,
    val name: String,
    val email: String
)

// MARK: - Usage Examples

/*
// Basic usage
val session = VaneSession()
val response = session.get("https://api.example.com/users")

// With configuration
val config = VaneConfigurationBuilder()
    .baseUrl("https://api.example.com")
    .defaultHeaders(mapOf("Authorization" to "Bearer token"))
    .timeout(30u)
    .build()

val session = VaneSession(config)

// Request builder pattern
val users = session.request("/users")
    .header("Accept", "application/json")
    .queryParam("page", "1")
    .responseJson<List<User>>()

// POST with JSON
val newUser = User(name = "John", email = "john@example.com")
val response = session.request("/users", HttpMethod.POST)
    .jsonBody(newUser)
    .execute()

// Using in ViewModel
class UserViewModel : ViewModel() {
    private val apiService = VaneServiceImpl(VaneSession(config))

    fun loadUsers() {
        viewModelScope.launch {
            try {
                val response = apiService.get("/users")
                val users = response.json<List<User>>()
                // Update UI
            } catch (e: VaneHttpException) {
                // Handle HTTP error
            } catch (e: Exception) {
                // Handle other errors
            }
        }
    }
}
*/
