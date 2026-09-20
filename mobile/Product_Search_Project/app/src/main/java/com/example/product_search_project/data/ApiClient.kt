package com.example.product_search_project.data

import android.content.Context
import com.example.product_search_project.BuildConfig
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/**
 * Builds the single Retrofit/OkHttp instance the whole app shares. Two
 * things worth calling out for the security review:
 *  - The request-logging interceptor is only ever added when
 *    BuildConfig.DEBUG is true, i.e. it is compiled out of the release
 *    build entirely (ProGuard/R8 strips the unreachable branch), so tokens
 *    and response bodies are never written to logcat in a shipped APK.
 *  - TLS/cleartext policy is enforced declaratively via
 *    res/xml/network_security_config.xml (different per build type), not in
 *    this file -- OkHttp automatically honours it on Android.
 */
object ApiClient {

    private var retrofit: Retrofit? = null
    private lateinit var tokenStore: TokenStore

    fun init(context: Context) {
        if (retrofit != null) return
        tokenStore = TokenStore(context.applicationContext)

        val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

        val authInterceptor = Interceptor { chain ->
            val original = chain.request()
            val request = if (original.header("Authorization") == null && tokenStore.accessToken != null) {
                original.newBuilder()
                    .addHeader("Authorization", "Bearer ${tokenStore.accessToken}")
                    .build()
            } else {
                original
            }
            chain.proceed(request)
        }

        // Simple synchronous refresh-on-401: on the FIRST 401 for a request
        // that carried our access token, try one refresh and retry once.
        // okhttp3.Authenticator would also work here; a response interceptor
        // is used instead to keep the retry to a strict one-shot and avoid
        // interfering with the deliberately-unauthenticated MFA endpoints.
        val refreshInterceptor = Interceptor { chain ->
            val response: Response = chain.proceed(chain.request())
            if (response.code == 401 && tokenStore.refreshToken != null &&
                chain.request().header("Authorization") != null
            ) {
                response.close()
                val refreshed = runBlocking { tryRefresh() }
                if (refreshed) {
                    val retried = chain.request().newBuilder()
                        .header("Authorization", "Bearer ${tokenStore.accessToken}")
                        .build()
                    return@Interceptor chain.proceed(retried)
                }
            }
            response
        }

        val clientBuilder = OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(refreshInterceptor)

        if (BuildConfig.DEBUG) {
            clientBuilder.addInterceptor(
                HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BASIC }
            )
        }

        retrofit = Retrofit.Builder()
            .baseUrl(BuildConfig.API_BASE_URL)
            .client(clientBuilder.build())
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    private suspend fun tryRefresh(): Boolean {
        val refresh = tokenStore.refreshToken ?: return false
        return try {
            val resp = service().refresh(RefreshRequest(refresh))
            val body = resp.body()
            if (resp.isSuccessful && body != null) {
                tokenStore.accessToken = body.access_token
                tokenStore.refreshToken = body.refresh_token
                true
            } else {
                tokenStore.clear()
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    fun tokens(): TokenStore = tokenStore

    fun service(): ApiService = retrofit!!.create(ApiService::class.java)
}
