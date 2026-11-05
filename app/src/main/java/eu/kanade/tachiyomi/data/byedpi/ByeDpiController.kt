package eu.kanade.tachiyomi.data.byedpi

import eu.kanade.tachiyomi.network.NetworkPreferences
import eu.kanade.tachiyomi.network.byedpi.ByeDpiProxyServer
import eu.kanade.tachiyomi.network.byedpi.ByeDpiRuntime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import logcat.LogPriority
import tachiyomi.core.common.util.system.logcat
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the lifecycle of the local ByeDPI SOCKS5 proxy and keeps the global [ProxySelector] in sync
 * with the user preference.
 */
class ByeDpiController(
    private val preferences: NetworkPreferences,
    private val webViewProxy: ByeDpiWebViewProxy,
) {

    private val server = ByeDpiProxyServer()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val initialized = AtomicBoolean(false)

    fun initialize() {
        if (!initialized.compareAndSet(false, true)) return

        // Clients created outside NetworkHelper still pick this up if they use the default selector.
        ProxySelector.setDefault(ByeDpiRuntime.selector)
        apply()

        combine(
            preferences.byeDpiEnabled().changes(),
            preferences.byeDpiPort().changes(),
            preferences.byeDpiMode().changes(),
        ) { enabled, port, mode -> Config(enabled, port, mode) }
            .distinctUntilChanged()
            .onEach { apply() }
            .launchIn(scope)
    }

    fun refresh() {
        apply()
    }

    @Synchronized
    private fun apply() {
        if (!preferences.byeDpiEnabled().get()) {
            server.stop()
            ByeDpiRuntime.setProxy(null)
            webViewProxy.clear()
            return
        }

        val mode = preferences.byeDpiMode().get()
        val configuredPort = preferences.byeDpiPort().get().toIntOrNull() ?: DEFAULT_PORT
        val port = configuredPort.takeIf { it in 1..65535 } ?: DEFAULT_PORT

        try {
            server.stop()
            val boundPort = try {
                server.start(port, mode)
            } catch (_: IOException) {
                logcat(LogPriority.WARN) { "ByeDPI: port $port is unavailable, falling back to an ephemeral port" }
                server.start(0, mode)
            }
            ByeDpiRuntime.setProxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(LOOPBACK, boundPort)))
            webViewProxy.apply(boundPort)
            logcat { "ByeDPI: local SOCKS5 proxy listening on $LOOPBACK:$boundPort (mode=$mode)" }
        } catch (e: Throwable) {
            logcat(LogPriority.ERROR, e) { "ByeDPI: failed to start the local proxy" }
            server.stop()
            ByeDpiRuntime.setProxy(null)
            webViewProxy.clear()
        }
    }

    private data class Config(
        val enabled: Boolean,
        val port: String,
        val mode: Int,
    )

    private companion object {
        private const val LOOPBACK = "127.0.0.1"
        private const val DEFAULT_PORT = 1080
    }
}
