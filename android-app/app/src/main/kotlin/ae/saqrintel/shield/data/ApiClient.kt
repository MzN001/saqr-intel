package ae.saqrintel.shield.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** How the content reached SAQR (the backend's `interception_channel`). */
enum class Interception(val wire: String) {
    GUARD("ANDROID_APP_GUARD"),
    MANUAL("CITIZEN_MANUAL_CHECK"),
}

/**
 * SAQR-INTEL HTTP client. Every call is `suspend`, runs on [Dispatchers.IO] and returns an
 * [ApiResult]; no exception reaches the caller (cancellation aside).
 *
 * @param baseUrl the current API base URL (read from [Settings] on each call).
 */
class ApiClient(private val baseUrl: suspend () -> String) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    /**
     * The live server may not know ANDROID_APP_GUARD yet (422 literal_error on that field until a
     * deploy). After the first such 422 we send AUTO_SMS_GUARD for the rest of the process lifetime.
     */
    @Volatile
    var guardChannelFallback: Boolean = false
        private set

    private fun channelWire(c: Interception) =
        if (c == Interception.GUARD && guardChannelFallback) FALLBACK_GUARD_CHANNEL else c.wire

    suspend fun analyzeMessage(
        text: String,
        sender: String?,
        channel: String,
        reporterId: String?,
        useLlm: Boolean,
        followLinks: Boolean,
        interception: Interception,
    ): ApiResult<ScanResponse> = postScan("/api/analyze-message", ScanResponse.serializer(), interception) { ch ->
        put("text", text.take(MAX_TEXT))
        sender?.trim()?.take(64)?.takeIf { it.isNotEmpty() }?.let { put("sender", it) }
        put("channel", channel)
        reporterId?.let { put("reporter_id", it) }
        put("use_llm", useLlm)
        put("follow_links", followLinks)
        put("interception_channel", ch)
    }

    /** [url] for a link, or [messageText] for text that contains one (the server extracts it). */
    suspend fun analyzeUrl(
        url: String?,
        messageText: String?,
        reporterId: String?,
        runSandbox: Boolean,
        useLlm: Boolean,
        interception: Interception,
        channel: String = "web",
        /** Whole-call deadline (web blocker: 15 s fast, 75 s deep); null = the client defaults. */
        timeoutMs: Long? = null,
    ): ApiResult<ScanResponse> = postScan("/api/analyze-url", ScanResponse.serializer(), interception, timeoutMs) { ch ->
        url?.takeIf { it.isNotBlank() }?.let { put("url", it.trim().take(2048)) }
        messageText?.takeIf { it.isNotBlank() }?.let { put("message_text", it.take(MAX_TEXT)) }
        put("channel", channel)
        reporterId?.let { put("reporter_id", it) }
        put("run_sandbox", runSandbox)
        put("use_llm", useLlm)
        put("include_screenshot", false)
        put("interception_channel", ch)
    }

    suspend fun analyzeEmail(
        text: String,
        raw: Boolean,
        reporterId: String?,
        useLlm: Boolean,
        interception: Interception,
    ): ApiResult<ScanResponse> = postScan("/api/analyze-email", ScanResponse.serializer(), interception) { ch ->
        put("source", if (raw) "raw" else "text")
        put("text", text.take(200_000))
        put("channel", "email")
        reporterId?.let { put("reporter_id", it) }
        put("use_llm", useLlm)
        put("follow_links", true)
        put("interception_channel", ch)
    }

    suspend fun scanMaps(
        mapsUrl: String?,
        businessName: String?,
        website: String?,
        phone: String?,
        reporterId: String?,
        interception: Interception,
    ): ApiResult<ScanResponse> = postScan("/api/scan-maps", ScanResponse.serializer(), interception) { ch ->
        mapsUrl?.takeIf { it.isNotBlank() }?.let { put("maps_url", it.trim().take(2048)) }
        businessName?.takeIf { it.isNotBlank() }?.let { put("business_name", it.trim().take(200)) }
        website?.takeIf { it.isNotBlank() }?.let { put("website", it.trim().take(512)) }
        phone?.takeIf { it.isNotBlank() }?.let { put("phone", it.trim().take(32)) }
        reporterId?.let { put("reporter_id", it) }
        put("interception_channel", ch)
    }

    suspend fun checkPhone(phone: String, claimedEntity: String? = null): ApiResult<PhoneCheckResponse> =
        post("/api/check-phone", PhoneCheckResponse.serializer(), buildJsonObject {
            put("phone", phone.trim().take(40))
            claimedEntity?.takeIf { it.isNotBlank() }?.let { put("claimed_entity", it.take(200)) }
        }).result

    suspend fun logXAlert(domain: String, entity: String?): ApiResult<XAlertLogResponse> =
        post("/api/police/log-x-alert", XAlertLogResponse.serializer(), buildJsonObject {
            put("domain", domain.take(253))
            entity?.takeIf { it.isNotBlank() }?.let { put("impersonated_entity", it.take(120)) }
        }).result

    suspend fun reportFalseAlarm(scanId: String, note: String? = null): ApiResult<FalseAlarmResponse> =
        post("/api/feedback/false-alarm", FalseAlarmResponse.serializer(), buildJsonObject {
            put("scan_id", scanId.take(64))
            note?.takeIf { it.isNotBlank() }?.let { put("note", it.take(500)) }
        }).result

    /** GET /api/dns-blocklist: Saqr's published scam-domain list (public, the telecom feed). */
    suspend fun dnsBlocklist(): ApiResult<BlocklistResponse> {
        val root = safeBase() ?: return ApiResult.Failed("bad_base_url")
        val request = try {
            Request.Builder().url("$root/api/dns-blocklist").get().build()
        } catch (_: IllegalArgumentException) {
            return ApiResult.Failed("bad_base_url")
        }
        return execute(request, BlocklistResponse.serializer()).result
    }

    /** GET /health on [base] (or the saved URL). Ok carries the round-trip latency. */
    suspend fun health(base: String? = null): ApiResult<HealthResponse> {
        val root = base ?: safeBase() ?: return ApiResult.Failed("bad_base_url")
        val request = try {
            Request.Builder().url("$root/health").get().build()
        } catch (_: IllegalArgumentException) {
            return ApiResult.Failed("bad_base_url")
        }
        return execute(request, HealthResponse.serializer()).result
    }

    // ------------------------------------------------------------------------------------------

    private class Outcome<T>(val result: ApiResult<T>, val rawError: String?)

    private suspend fun <T> postScan(
        path: String,
        serializer: KSerializer<T>,
        interception: Interception,
        timeoutMs: Long? = null,
        body: JsonObjectBuilder.(channel: String) -> Unit,
    ): ApiResult<T> {
        val first = post(path, serializer, buildJsonObject { body(channelWire(interception)) }, timeoutMs)
        if (interception == Interception.GUARD && !guardChannelFallback && isChannelLiteralError(first)) {
            guardChannelFallback = true
            return post(path, serializer, buildJsonObject { body(FALLBACK_GUARD_CHANNEL) }, timeoutMs).result
        }
        return first.result
    }

    private fun isChannelLiteralError(o: Outcome<*>): Boolean {
        if (o.result !is ApiResult.Invalid) return false
        val raw = o.rawError ?: return false
        return raw.contains("literal_error") && raw.contains("interception_channel")
    }

    private suspend fun safeBase(): String? = try {
        baseUrl().trimEnd('/').takeIf { it.isNotEmpty() }
    } catch (e: Exception) {
        if (e is kotlinx.coroutines.CancellationException) throw e
        null
    }

    private suspend fun <T> post(
        path: String,
        serializer: KSerializer<T>,
        json: JsonObject,
        timeoutMs: Long? = null,
    ): Outcome<T> {
        val root = safeBase() ?: return Outcome(ApiResult.Failed("bad_base_url"), null)
        val request = try {
            Request.Builder()
                .url(root + path)
                .post(json.toString().toRequestBody(JSON_TYPE))
                .header("Accept", "application/json")
                .build()
        } catch (_: IllegalArgumentException) {
            return Outcome(ApiResult.Failed("bad_base_url"), null)
        }
        return execute(request, serializer, timeoutMs)
    }

    private suspend fun <T> execute(request: Request, serializer: KSerializer<T>, timeoutMs: Long? = null): Outcome<T> =
        withContext(Dispatchers.IO) {
            val started = System.nanoTime()
            val response = try {
                val call = http.newCall(request)
                timeoutMs?.let { call.timeout().timeout(it, TimeUnit.MILLISECONDS) }
                await(call)
            } catch (e: IOException) {
                return@withContext Outcome(mapIo(e), null)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                return@withContext Outcome(ApiResult.Failed(e.javaClass.simpleName), null)
            }
            response.use { r ->
                val text = try {
                    r.body.string()
                } catch (e: IOException) {
                    return@withContext Outcome(mapIo(e), null)
                }
                val latency = (System.nanoTime() - started) / 1_000_000
                when (r.code) {
                    in 200..299 -> try {
                        Outcome(ApiResult.Ok(ApiJson.decodeFromString(serializer, text), latency), null)
                    } catch (_: Exception) {
                        // SerializationException (an IllegalArgumentException) or anything odd in the body.
                        Outcome(ApiResult.Failed("bad_response"), null)
                    }
                    429 -> Outcome(ApiResult.RateLimited, text)
                    502, 503, 504 -> Outcome(ApiResult.ServerWaking, text)
                    422 -> Outcome(ApiResult.Invalid(detailOf(text) ?: "invalid"), text)
                    else -> Outcome(ApiResult.Failed(detailOf(text) ?: "HTTP ${r.code}"), text)
                }
            }
        }

    private suspend fun await(call: Call): Response = suspendCancellableCoroutine { cont ->
        cont.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (cont.isActive) cont.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                if (cont.isActive) cont.resume(response) else response.close()
            }
        })
    }

    private fun mapIo(e: IOException): ApiResult<Nothing> = when (e) {
        is ConnectException, is NoRouteToHostException, is InterruptedIOException -> ApiResult.ServerWaking
        else -> ApiResult.Failed(e.javaClass.simpleName)
    }

    companion object {
        const val DEFAULT_BASE_URL = "https://saqr-intel-api.onrender.com"
        const val FALLBACK_GUARD_CHANNEL = "AUTO_SMS_GUARD"
        const val MAX_TEXT = 4000
        private val JSON_TYPE = "application/json; charset=utf-8".toMediaType()

        /** FastAPI error body: {"detail": "text"} or {"detail": [{"msg": "...", ...}]}. */
        fun detailOf(body: String?): String? {
            if (body.isNullOrBlank()) return null
            return try {
                val root = ApiJson.parseToJsonElement(body)
                val detail: JsonElement = (root as? JsonObject)?.get("detail") ?: return null
                when (detail) {
                    is JsonPrimitive -> detail.contentOrNull
                    is JsonArray -> (detail.firstOrNull() as? JsonObject)?.get("msg")?.jsonPrimitive?.contentOrNull
                    else -> null
                }?.take(300)
            } catch (_: Exception) {
                null
            }
        }
    }
}
