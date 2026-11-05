package eu.kanade.tachiyomi.network.byedpi

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.concurrent.thread

/**
 * Minimal SOCKS5 server bound to the loopback interface. Every CONNECT tunnel forwards the first
 * payload through [DpiBypassOutputStream] so DPI systems see split TLS/HTTP handshakes.
 */
class ByeDpiProxyServer {

    private val clients: MutableSet<Socket> = Collections.synchronizedSet(mutableSetOf())
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var running = false

    @Synchronized
    fun start(port: Int, mode: Int): Int {
        if (running) {
            return serverSocket?.localPort ?: throw IOException("ByeDPI proxy is not running")
        }

        val socket = ServerSocket()
        try {
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(InetAddress.getByName(LOOPBACK), port))
        } catch (e: IOException) {
            runCatching { socket.close() }
            throw e
        }

        serverSocket = socket
        running = true

        thread(name = "ByeDpiProxy-accept", isDaemon = true) {
            acceptLoop(socket, mode)
        }

        return socket.localPort
    }

    @Synchronized
    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        synchronized(clients) {
            clients.toList().forEach { runCatching { it.close() } }
            clients.clear()
        }
    }

    fun isRunning(): Boolean = running

    fun localPort(): Int? = serverSocket?.localPort

    private fun acceptLoop(server: ServerSocket, mode: Int) {
        while (running) {
            val client = try {
                server.accept()
            } catch (_: IOException) {
                // The socket was closed (stop/restart). Do not spin on a dead socket even when a
                // new instance has already set `running` back to true.
                if (running && !server.isClosed) continue else break
            }
            clients += client
            thread(name = "ByeDpiProxy-client", isDaemon = true) {
                handle(client, mode)
            }
        }
    }

    private fun handle(client: Socket, mode: Int) {
        var remote: Socket? = null
        try {
            client.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = client.getInputStream().buffered()
            val output = client.getOutputStream()

            // Greeting: version, method count, methods.
            if (input.read() != SOCKS_VERSION) return
            val methodCount = input.read()
            if (methodCount <= 0) return
            val methods = readBytes(input, methodCount)
            if (methods.none { it.toInt() and 0xFF == AUTH_NONE }) {
                output.write(byteArrayOf(SOCKS_VERSION.toByte(), AUTH_UNACCEPTABLE.toByte()))
                output.flush()
                return
            }
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), AUTH_NONE.toByte()))
            output.flush()

            // Request: version, command, reserved, address type, address, port.
            if (input.read() != SOCKS_VERSION) return
            val command = input.read()
            input.read() // reserved
            val addressType = input.read()
            val host = when (addressType) {
                ATYP_IPV4 -> InetAddress.getByAddress(readBytes(input, 4)).hostAddress
                ATYP_DOMAIN -> {
                    val length = input.read()
                    if (length <= 0) {
                        reply(output, REP_GENERAL_FAILURE)
                        return
                    }
                    String(readBytes(input, length), Charsets.UTF_8)
                }
                ATYP_IPV6 -> InetAddress.getByAddress(readBytes(input, 16)).hostAddress
                else -> {
                    reply(output, REP_ADDRESS_UNSUPPORTED)
                    return
                }
            }
            val port = (input.read() shl 8) or input.read()

            if (command != CMD_CONNECT) {
                reply(output, REP_COMMAND_UNSUPPORTED)
                return
            }
            if (host.isBlank() || port !in 1..65535) {
                reply(output, REP_GENERAL_FAILURE)
                return
            }

            val remoteSocket = Socket()
            remoteSocket.tcpNoDelay = true
            try {
                remoteSocket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            } catch (e: IOException) {
                runCatching { remoteSocket.close() }
                reply(output, REP_HOST_UNREACHABLE)
                return
            }
            remote = remoteSocket
            reply(output, REP_SUCCEEDED)
            client.soTimeout = 0

            val downstream = remoteSocket.getInputStream()
            val upstream = DpiBypassOutputStream(remoteSocket.getOutputStream(), mode)
            val uploader = thread(name = "ByeDpiProxy-upload", isDaemon = true) {
                try {
                    copy(input, upstream)
                } catch (_: IOException) {
                } finally {
                    runCatching { upstream.flush() }
                    runCatching { remoteSocket.shutdownOutput() }
                }
            }

            try {
                copy(downstream, output)
            } catch (_: IOException) {
            } finally {
                runCatching { output.flush() }
                uploader.interrupt()
            }
        } catch (_: IOException) {
            // Malformed handshake or a closed socket: drop the client quietly.
        } finally {
            clients -= client
            runCatching { client.close() }
            remote?.let { runCatching { it.close() } }
        }
    }

    private fun reply(output: OutputStream, code: Int) {
        output.write(byteArrayOf(SOCKS_VERSION.toByte(), code.toByte(), 0, ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun copy(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read == -1) break
            output.write(buffer, 0, read)
            output.flush()
        }
    }

    private fun readBytes(input: InputStream, length: Int): ByteArray {
        val bytes = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(bytes, offset, length - offset)
            if (read == -1) throw IOException("Unexpected end of stream")
            offset += read
        }
        return bytes
    }

    private companion object {
        private const val LOOPBACK = "127.0.0.1"
        private const val BUFFER_SIZE = 8 * 1024
        private const val HANDSHAKE_TIMEOUT_MS = 15_000
        private const val CONNECT_TIMEOUT_MS = 20_000

        private const val SOCKS_VERSION = 0x05
        private const val AUTH_NONE = 0x00
        private const val AUTH_UNACCEPTABLE = 0xFF

        private const val CMD_CONNECT = 0x01

        private const val ATYP_IPV4 = 0x01
        private const val ATYP_DOMAIN = 0x03
        private const val ATYP_IPV6 = 0x04

        private const val REP_SUCCEEDED = 0x00
        private const val REP_GENERAL_FAILURE = 0x01
        private const val REP_HOST_UNREACHABLE = 0x04
        private const val REP_COMMAND_UNSUPPORTED = 0x07
        private const val REP_ADDRESS_UNSUPPORTED = 0x08
    }
}
