package ae.saqrintel.shield.data

/** Outcome of one API call. Nothing in [ApiClient] throws to callers. */
sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T, val latencyMs: Long) : ApiResult<T>

    /** HTTP 429: the shared 30-per-minute bucket is used up. */
    data object RateLimited : ApiResult<Nothing>

    /** Timeouts, connect failures, 502/503/504: Render's free tier is cold-starting. */
    data object ServerWaking : ApiResult<Nothing>

    /** HTTP 422 with the server's message. */
    data class Invalid(val message: String) : ApiResult<Nothing>

    /** Anything else (offline, 4xx/5xx, a response that could not be read). */
    data class Failed(val message: String) : ApiResult<Nothing>
}
