package eu.kanade.tachiyomi.data.byedpi

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import logcat.LogPriority
import tachiyomi.core.common.util.system.logcat

/**
 * Applies the local ByeDPI SOCKS5 proxy to every WebView in the process.
 *
 * WebView traffic does not go through [java.net.ProxySelector], so it has to be configured through
 * the androidx.webkit proxy override API instead.
 */
class ByeDpiWebViewProxy(context: Context) {

    private val executor = ContextCompat.getMainExecutor(context)
    private val handler = Handler(Looper.getMainLooper())

    fun apply(port: Int) {
        if (!isSupported()) {
            logcat(LogPriority.WARN) { "ByeDPI: WebView proxy override is not supported" }
            return
        }

        val config = ProxyConfig.Builder()
            .addProxyRule("$SOCKS_SCHEME://$LOOPBACK:$port")
            .bypassSimpleHostnames()
            .addBypassRule(LOOPBACK)
            .addBypassRule(IPV6_LOOPBACK)
            .build()

        handler.post {
            runCatching {
                ProxyController.getInstance().setProxyOverride(config, executor) {
                    logcat { "ByeDPI: WebView proxy override enabled on $LOOPBACK:$port" }
                }
            }.onFailure {
                logcat(LogPriority.ERROR, it) { "ByeDPI: failed to set WebView proxy override" }
            }
        }
    }

    fun clear() {
        if (!isSupported()) return

        handler.post {
            runCatching {
                ProxyController.getInstance().clearProxyOverride(executor) {
                    logcat { "ByeDPI: WebView proxy override cleared" }
                }
            }.onFailure {
                logcat(LogPriority.ERROR, it) { "ByeDPI: failed to clear WebView proxy override" }
            }
        }
    }

    private fun isSupported(): Boolean = runCatching {
        WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)
    }.getOrDefault(false)

    private companion object {
        private const val SOCKS_SCHEME = "socks5"
        private const val LOOPBACK = "127.0.0.1"
        private const val IPV6_LOOPBACK = "[::1]"
    }
}
