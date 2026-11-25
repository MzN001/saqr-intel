package ae.saqrintel.shield.guard

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.BlockEntry
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.locale.LocaleController
import ae.saqrintel.shield.util.Defang
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Scam-site firewall. A local "VPN" that receives ONLY the phone's DNS questions (one virtual address,
 * 10.111.222.2): no web traffic, no other packets, and nothing is sent to a VPN server.
 *
 * Each question is compared, on the phone, with Saqr's published scam-domain list ([ae.saqrintel.shield.data.Blocklist]).
 * A listed name gets "no such site" and one alert; every other question is passed, unchanged, to the
 * network's own DNS server and its answer is handed back. The names a phone looks up never leave it.
 *
 * Limits (also in the README): plain DNS over IPv4 only. A phone set to a fixed "Private DNS" provider,
 * or an app that brings its own encrypted DNS, bypasses it.
 */
class SaqrDnsVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var refreshJob: Job? = null
    private val lastAlert = ConcurrentHashMap<String, Long>()

    @Volatile
    private var upstream: List<InetAddress> = emptyList()

    @Volatile
    private var upstreamAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        startTunnel()
        return START_STICKY
    }

    /** The user turned the VPN off in Android's settings, or another VPN took over. */
    override fun onRevoke() {
        shutdown()
        appGraph?.let { g -> g.appScope.launch { g.settings.setDnsFirewall(false) } }
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        scope.cancel()
        super.onDestroy()
    }

    private fun startTunnel() {
        if (tun != null) return
        val graph = appGraph ?: return
        val fd = try {
            Builder()
                .setSession(getString(R.string.fw_session))
                .addAddress(TUN_ADDRESS, 32)
                .addDnsServer(DNS_ADDRESS)
                .addRoute(DNS_ADDRESS, 32) // the ONLY traffic that enters the tunnel
                .setMtu(1500)
                .setBlocking(true)
                .apply { if (android.os.Build.VERSION.SDK_INT >= 29) setMetered(false) }
                .establish()
        } catch (e: Exception) {
            Log.w(TAG, "could not start the firewall: ${e.javaClass.simpleName}")
            null
        }
        if (fd == null) {
            stopSelf()
            return
        }
        tun = fd
        pool = ThreadPoolExecutor(2, 12, 30, TimeUnit.SECONDS, LinkedBlockingQueue(256), ThreadPoolExecutor.DiscardOldestPolicy())
        reader = Thread({ readLoop(fd) }, "saqr-dns").also { it.start() }
        running.value = true
        refreshJob = scope.launch {
            graph.blocklist.loadSaved()
            while (isActive) {
                graph.blocklist.refresh(graph.api)
                delay(REFRESH_MS)
            }
        }
    }

    private fun shutdown() {
        running.value = false
        refreshJob?.cancel()
        refreshJob = null
        reader?.interrupt()
        reader = null
        pool?.shutdownNow()
        pool = null
        try {
            tun?.close()
        } catch (_: IOException) {
            // already closed
        }
        tun = null
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted) {
                val n = input.read(buffer)
                if (n <= 0) continue
                val query = DnsPacket.parse(buffer, n) ?: continue
                val entry = appGraph?.blocklist?.match(query.host)
                if (entry != null) {
                    DnsPacket.nxdomain(query.dns)?.let { write(output, DnsPacket.wrap(query, it)) }
                    onBlocked(query.host.orEmpty(), entry)
                } else {
                    try {
                        pool?.execute { forward(query, output) }
                    } catch (_: RuntimeException) {
                        // shutting down
                    }
                }
            }
        } catch (_: IOException) {
            // tunnel closed
        } catch (_: RuntimeException) {
            // never crash the app over one odd packet
        }
    }

    private fun write(output: FileOutputStream, packet: ByteArray) {
        try {
            synchronized(output) { output.write(packet) }
        } catch (_: IOException) {
            // tunnel closed
        }
    }

    /** Asks the network's own DNS server and hands its answer back, untouched. */
    private fun forward(query: DnsPacket.Query, output: FileOutputStream) {
        try {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = UPSTREAM_TIMEOUT_MS
                val answer = ByteArray(4096)
                for (server in resolvers()) {
                    try {
                        socket.send(DatagramPacket(query.dns, query.dns.size, server, 53))
                        val packet = DatagramPacket(answer, answer.size)
                        socket.receive(packet)
                        write(output, DnsPacket.wrap(query, answer.copyOf(packet.length)))
                        return
                    } catch (_: IOException) {
                        // next server
                    }
                }
            }
        } catch (_: Exception) {
            // no answer: the app that asked simply retries
        }
    }

    /** DNS servers of the real (non-VPN) network; refreshed every 30 s so Wi-Fi <-> mobile changes are picked up. */
    private fun resolvers(): List<InetAddress> {
        val now = System.currentTimeMillis()
        if (upstream.isNotEmpty() && now - upstreamAt < 30_000) return upstream
        val found = mutableListOf<InetAddress>()
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            @Suppress("DEPRECATION")
            for (network in cm?.allNetworks.orEmpty()) {
                val caps = cm?.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                cm.getLinkProperties(network)?.dnsServers?.filterIsInstance<Inet4Address>()?.let(found::addAll)
            }
        } catch (_: RuntimeException) {
            // fall through to the public resolvers
        }
        FALLBACK.forEach { if (it !in found) found += it }
        upstream = found
        upstreamAt = now
        return found
    }

    /** One alert per blocked site per minute (a browser asks for the same name several times). */
    private fun onBlocked(host: String, entry: BlockEntry) {
        val now = System.currentTimeMillis()
        val key = entry.domain
        val last = lastAlert[key]
        if (last != null && now - last < ALERT_GAP_MS) return
        lastAlert[key] = now
        if (lastAlert.size > 500) lastAlert.clear()
        val graph = appGraph ?: return
        val ctx: Context = LocaleController.wrap(this)
        val record = AlertRecord(
            id = UUID.randomUUID().toString(),
            time = now,
            kind = AlertKind.WEB,
            label = Defang.defang(entry.domain),
            score = (entry.riskScore ?: 70.0).toInt().coerceIn(65, 100),
            verdict = Verdict.SCAM.wire,
            entityEn = entry.entity,
            reasonsEn = listOf("This website is on Saqr's scam list, so the phone was stopped from opening it."),
            reasonsAr = listOf("هذا الموقع مدرج في قائمة صقر لمواقع الاحتيال، لذلك مُنع الهاتف من فتحه."),
            scanKind = ScanKind.WEB,
        )
        graph.appScope.launch {
            graph.alertStore.add(record)
            AlertNotifier.notify(ctx, record, xEligible = true)
        }
        Log.i(TAG, "blocked a listed site (${host.length} chars)")
    }

    companion object {
        private const val TAG = "SaqrFirewall"
        private const val ACTION_STOP = "ae.saqrintel.shield.FIREWALL_STOP"
        private const val TUN_ADDRESS = "10.111.222.1"
        private const val DNS_ADDRESS = "10.111.222.2"
        private const val UPSTREAM_TIMEOUT_MS = 4000
        private const val REFRESH_MS = 10 * 60 * 1000L
        private const val ALERT_GAP_MS = 60_000L
        private val FALLBACK: List<InetAddress> = listOf(
            InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1)),
            InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
        )

        private val running = MutableStateFlow(false)

        /** True while the tunnel is up in this process. */
        val isRunning: StateFlow<Boolean> = running.asStateFlow()

        /** Android's "allow this VPN" screen, or null when the user already allowed it. */
        fun consentIntent(context: Context): Intent? = try {
            prepare(context)
        } catch (_: RuntimeException) {
            null
        }

        fun start(context: Context) {
            try {
                context.startService(Intent(context, SaqrDnsVpnService::class.java))
            } catch (_: RuntimeException) {
                // app in the background: it starts the next time the app is opened
            }
        }

        fun stop(context: Context) {
            try {
                context.startService(Intent(context, SaqrDnsVpnService::class.java).setAction(ACTION_STOP))
            } catch (_: RuntimeException) {
                // not running
            }
        }
    }
}
