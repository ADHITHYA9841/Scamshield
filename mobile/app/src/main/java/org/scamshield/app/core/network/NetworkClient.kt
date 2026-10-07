package org.scamshield.app.core.network

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object NetworkClient {
    // 10.0.13.251 is the host PC Wi-Fi IP address
    const val DEFAULT_BASE_URL = "http://10.0.13.251:8000/"
    const val DEFAULT_VT_KEY = "2cc4dbf8486c0dff0863e3ac7196b7b83ab8b7d04481e94c67d690b27d04a007"
    private const val PREFS_NAME = "scamshield_preferences"
    private const val KEY_BASE_URL = "key_base_url"
    private const val KEY_VT_API_KEY = "key_virustotal_api_key"

    private var currentBaseUrl: String = DEFAULT_BASE_URL
    private var virustotalApiKey: String = DEFAULT_VT_KEY
    private var cachedApi: ScamShieldApi? = null
    private var prefs: SharedPreferences? = null

    fun init(context: Context) {
        val sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs = sp
        currentBaseUrl = sp.getString(KEY_BASE_URL, DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        virustotalApiKey = sp.getString(KEY_VT_API_KEY, DEFAULT_VT_KEY) ?: DEFAULT_VT_KEY
    }

    private val okHttpClient by lazy {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        OkHttpClient.Builder()
            .addInterceptor { chain ->
                val original = chain.request()
                val requestBuilder = original.newBuilder()
                if (virustotalApiKey.isNotBlank()) {
                    requestBuilder.addHeader("X-VirusTotal-Key", virustotalApiKey)
                }
                chain.proceed(requestBuilder.build())
            }
            .addInterceptor(logging)
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .writeTimeout(4, TimeUnit.SECONDS)
            .build()
    }

    fun getApi(customBaseUrl: String? = null): ScamShieldApi {
        val url = if (!customBaseUrl.isNullOrBlank()) {
            if (customBaseUrl.endsWith("/")) customBaseUrl else "$customBaseUrl/"
        } else {
            currentBaseUrl
        }

        if (cachedApi == null || currentBaseUrl != url) {
            currentBaseUrl = url
            prefs?.edit()?.putString(KEY_BASE_URL, currentBaseUrl)?.apply()
            cachedApi = Retrofit.Builder()
                .baseUrl(currentBaseUrl)
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(ScamShieldApi::class.java)
        }
        return cachedApi!!
    }

    fun getBaseUrl(): String = currentBaseUrl

    fun setBaseUrl(newUrl: String) {
        val cleaned = if (newUrl.endsWith("/")) newUrl.trim() else "${newUrl.trim()}/"
        currentBaseUrl = cleaned
        cachedApi = null
        prefs?.edit()?.putString(KEY_BASE_URL, cleaned)?.apply()
    }

    fun getVirusTotalApiKey(): String = virustotalApiKey

    fun setVirusTotalApiKey(key: String?) {
        val cleaned = key?.trim()?.takeIf { it.isNotBlank() } ?: DEFAULT_VT_KEY
        virustotalApiKey = cleaned
        prefs?.edit()?.putString(KEY_VT_API_KEY, cleaned)?.apply()
    }

    suspend fun checkServerConnection(): Boolean = withContext(Dispatchers.IO) {
        try {
            val req = Request.Builder()
                .url("${currentBaseUrl}api/v1/health")
                .build()
            val resp = okHttpClient.newCall(req).execute()
            resp.isSuccessful
        } catch (e: Exception) {
            false
        }
    }
}
