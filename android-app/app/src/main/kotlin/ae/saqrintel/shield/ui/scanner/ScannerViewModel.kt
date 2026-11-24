package ae.saqrintel.shield.ui.scanner

import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.AutoRouter
import ae.saqrintel.shield.data.Interception
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.ScanRoute
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.data.toVerdictInfo
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class ScanMode { AUTO, WEB, MESSAGE, EMAIL, PHONE, MAPS }

sealed interface ScanError {
    data object Empty : ScanError
    data object RateLimited : ScanError
    data object Waking : ScanError
    data object Failed : ScanError
    data class Invalid(val message: String) : ScanError
}

data class ScannerState(
    val mode: ScanMode = ScanMode.AUTO,
    val input: String = "",
    val sender: String = "",
    val mapsWebsite: String = "",
    val mapsPhone: String = "",
    val loading: Boolean = false,
    /** True after 8 s of waiting: the free server is probably cold-starting. */
    val slow: Boolean = false,
    val error: ScanError? = null,
    val result: VerdictInfo? = null,
    val showSheet: Boolean = false,
)

class ScannerViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow(ScannerState())
    val state: StateFlow<ScannerState> = _state.asStateFlow()
    private var job: Job? = null

    fun setMode(m: ScanMode) = _state.update { it.copy(mode = m, error = null) }
    fun setInput(s: String) = _state.update { it.copy(input = s.take(MAX_INPUT), error = null) }
    fun setSender(s: String) = _state.update { it.copy(sender = s.take(64)) }
    fun setMapsWebsite(s: String) = _state.update { it.copy(mapsWebsite = s.take(512)) }
    fun setMapsPhone(s: String) = _state.update { it.copy(mapsPhone = s.take(32)) }
    fun dismissSheet() = _state.update { it.copy(showSheet = false) }
    fun reopenSheet() = _state.update { it.copy(showSheet = it.result != null) }

    fun useSample(mode: ScanMode, text: String) =
        _state.update { it.copy(mode = mode, input = text, sender = "", error = null) }

    fun check() {
        val s = _state.value
        val input = s.input.trim()
        if (input.isEmpty() && !(s.mode == ScanMode.MAPS && s.mapsWebsite.isNotBlank())) {
            _state.update { it.copy(error = ScanError.Empty) }
            return
        }
        val graph = getApplication<Application>().appGraph ?: return
        job?.cancel()
        _state.update { it.copy(loading = true, slow = false, error = null) }
        job = viewModelScope.launch {
            val slowTimer = launch {
                delay(SLOW_AFTER_MS)
                _state.update { it.copy(slow = true) }
            }
            val reporter = try {
                graph.settings.reporterId()
            } catch (_: Exception) {
                null
            }
            val route = when (s.mode) {
                ScanMode.AUTO -> AutoRouter.route(input)
                ScanMode.WEB -> ScanRoute.WEB
                ScanMode.MESSAGE -> ScanRoute.MESSAGE
                ScanMode.EMAIL -> ScanRoute.EMAIL
                ScanMode.PHONE -> ScanRoute.PHONE
                ScanMode.MAPS -> ScanRoute.MAPS
            }
            val api = graph.api
            val m = Interception.MANUAL
            val result: ApiResult<VerdictInfo> = when (route) {
                ScanRoute.WEB -> {
                    val single = AutoRouter.isSingleUrl(input)
                    api.analyzeUrl(
                        url = if (single) input else null,
                        messageText = if (single) null else input,
                        reporterId = reporter, runSandbox = true, useLlm = true, interception = m,
                    ).map { it.toVerdictInfo(ScanKind.WEB) }
                }
                ScanRoute.MAPS -> {
                    val isUrl = AutoRouter.isSingleUrl(input)
                    api.scanMaps(
                        mapsUrl = if (isUrl) input else null,
                        businessName = if (isUrl) null else input,
                        website = s.mapsWebsite, phone = s.mapsPhone, reporterId = reporter, interception = m,
                    ).map { it.toVerdictInfo(ScanKind.MAPS) }
                }
                ScanRoute.PHONE -> api.checkPhone(input).map { it.toVerdictInfo() }
                ScanRoute.EMAIL -> api.analyzeEmail(
                    text = input, raw = AutoRouter.looksLikeRawEmail(input), reporterId = reporter,
                    useLlm = true, interception = m,
                ).map { it.toVerdictInfo(ScanKind.EMAIL) }
                ScanRoute.MESSAGE -> api.analyzeMessage(
                    text = input, sender = s.sender.takeIf { s.mode == ScanMode.MESSAGE }, channel = "sms",
                    reporterId = reporter, useLlm = true, followLinks = true, interception = m,
                ).map { it.toVerdictInfo(ScanKind.MESSAGE) }
            }
            slowTimer.cancel()
            when (result) {
                is ApiResult.Ok -> {
                    val info = result.value
                    _state.update { it.copy(loading = false, slow = false, result = info, showSheet = true) }
                    try {
                        graph.settings.incrementChecked()
                        if (info.verdict != Verdict.SAFE) graph.alertStore.add(AlertRecord.from(info, AlertKind.MANUAL))
                    } catch (_: Exception) {
                        // Counters are best effort.
                    }
                }
                ApiResult.RateLimited -> fail(ScanError.RateLimited)
                ApiResult.ServerWaking -> fail(ScanError.Waking)
                is ApiResult.Invalid -> fail(ScanError.Invalid(result.message))
                is ApiResult.Failed -> fail(ScanError.Failed)
            }
        }
    }

    private fun fail(e: ScanError) = _state.update { it.copy(loading = false, slow = false, error = e) }

    companion object {
        const val SLOW_AFTER_MS = 8_000L
        /** Email raw source can be long; message / URL calls cap their own fields. */
        const val MAX_INPUT = 20_000
    }
}

private inline fun <T, R> ApiResult<T>.map(f: (T) -> R): ApiResult<R> = when (this) {
    is ApiResult.Ok -> ApiResult.Ok(f(value), latencyMs)
    ApiResult.RateLimited -> ApiResult.RateLimited
    ApiResult.ServerWaking -> ApiResult.ServerWaking
    is ApiResult.Invalid -> this
    is ApiResult.Failed -> this
}
