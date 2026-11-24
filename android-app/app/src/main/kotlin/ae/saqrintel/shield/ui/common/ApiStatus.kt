package ae.saqrintel.shield.ui.common

import ae.saqrintel.shield.data.ApiResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The top bar's API status dot, from REAL calls only (a scanner check or a /health ping in the API
 * dialog); nothing is pinged just to colour the dot. In memory for this process.
 *  - NEVER: no call made yet (grey)
 *  - WAKING: a call is slow / the server is waking / the last call failed (amber)
 *  - OK: the last call answered (emerald)
 */
enum class ApiHealth { NEVER, WAKING, OK }

object ApiStatus {
    private val _health = MutableStateFlow(ApiHealth.NEVER)
    val health: StateFlow<ApiHealth> = _health.asStateFlow()

    fun waking() {
        _health.value = ApiHealth.WAKING
    }

    /** The server URL changed: nothing is known about the new one yet. */
    fun reset() {
        _health.value = ApiHealth.NEVER
    }

    fun record(result: ApiResult<*>) {
        _health.value = when (result) {
            is ApiResult.Ok -> ApiHealth.OK
            // A 4xx answer still means the server is up.
            ApiResult.RateLimited, is ApiResult.Invalid -> ApiHealth.OK
            ApiResult.ServerWaking, is ApiResult.Failed -> ApiHealth.WAKING
        }
    }
}
