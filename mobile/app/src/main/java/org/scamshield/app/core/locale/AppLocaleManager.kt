package org.scamshield.app.core.locale

import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import java.util.Locale

object AppLocaleManager {
    private const val PREFS_NAME = "scamshield_prefs"
    private const val KEY_SELECTED_LANGUAGE = "selected_language"

    fun getLanguageCode(context: Context): String {
        val saved = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_SELECTED_LANGUAGE, "English")
        return when {
            saved?.contains("Tamil", ignoreCase = true) == true || saved?.contains("தமிழ்") == true -> "ta"
            saved?.contains("Hindi", ignoreCase = true) == true || saved?.contains("हिन्दी") == true -> "hi"
            else -> "en"
        }
    }

    fun applyStoredLocale(context: Context): Context {
        return applyLocale(context, getLanguageCode(context))
    }

    fun setLocale(activity: Activity, languageLabel: String) {
        val code = when {
            languageLabel.contains("Tamil", ignoreCase = true) || languageLabel.contains("தமிழ்") -> "ta"
            languageLabel.contains("Hindi", ignoreCase = true) || languageLabel.contains("हिन्दी") -> "hi"
            else -> "en"
        }
        activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_SELECTED_LANGUAGE, languageLabel)
            .apply()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.getSystemService(LocaleManager::class.java)
                .applicationLocales = LocaleList.forLanguageTags(code)
        }
        applyLocale(activity, code)
        activity.recreate()
    }

    private fun applyLocale(context: Context, languageCode: String): Context {
        val locale = Locale(languageCode)
        Locale.setDefault(locale)
        val config = Configuration(context.resources.configuration)
        config.setLocale(locale)
        config.setLayoutDirection(locale)
        return context.createConfigurationContext(config)
    }
}
