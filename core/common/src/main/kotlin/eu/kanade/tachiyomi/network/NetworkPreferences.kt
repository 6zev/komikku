package eu.kanade.tachiyomi.network

import tachiyomi.core.common.preference.Preference
import tachiyomi.core.common.preference.PreferenceStore

class NetworkPreferences(
    private val preferenceStore: PreferenceStore,
) {

    /* KMK --> fun verboseLogging(): Preference<Boolean> {
        return preferenceStore.getBoolean("verbose_logging", verboseLogging)
    } KMK <-- */

    fun dohProvider(): Preference<Int> {
        return preferenceStore.getInt("doh_provider", -1)
    }

    fun defaultUserAgent(): Preference<String> {
        return preferenceStore.getString(
            "default_user_agent",
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
        )
    }

    // KMK -->
    fun byeDpiEnabled(): Preference<Boolean> = preferenceStore.getBoolean("byedpi_enabled", false)

    fun byeDpiPort(): Preference<String> = preferenceStore.getString("byedpi_port", "1080")

    fun byeDpiMode(): Preference<Int> = preferenceStore.getInt("byedpi_mode", 0)
    // KMK <--
}
