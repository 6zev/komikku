package eu.kanade.tachiyomi.network.byedpi

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

object ByeDpiMode {
    /**
     * Split the TLS ClientHello around the SNI extension. This is enough for most ISPs.
     */
    const val SNI = 0

    /**
     * Additionally split non-TLS connections byte by byte and mangle the HTTP `Host` header.
     */
    const val AGGRESSIVE = 1
}

/**
 * Holds the local SOCKS5 proxy that [ByeDpiProxyServer] exposes so that every OkHttp client can
 * consult it lazily instead of capturing a proxy at build time.
 */
object ByeDpiRuntime {

    @Volatile
    private var currentProxy: Proxy? = null

    val selector: ProxySelector = object : ProxySelector() {
        override fun select(uri: URI?): List<Proxy> = listOf(currentProxy ?: Proxy.NO_PROXY)

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) {
            // No-op: OkHttp handles connection failures and retries itself.
        }
    }

    fun setProxy(proxy: Proxy?) {
        currentProxy = proxy
    }

    fun proxy(): Proxy? = currentProxy

    fun isEnabled(): Boolean = currentProxy != null

    fun localPort(): Int? = (currentProxy?.address() as? InetSocketAddress)?.port
}
