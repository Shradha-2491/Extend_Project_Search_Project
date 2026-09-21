package com.example.product_search_project.data

import android.content.Context
import android.content.Intent
import com.example.product_search_project.BuildConfig
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues

/**
 * Mobile Google Sign-In via OAuth 2.0 Authorization Code + PKCE, using
 * AppAuth's Chrome Custom Tab flow. There is no client secret here -- native
 * apps can't keep one confidential, so PKCE (a per-request code_verifier /
 * code_challenge pair AppAuth generates automatically) replaces it as the
 * proof that the code-exchange request came from the same app instance that
 * started the flow. The resulting id_token is sent to
 * POST /api/v1/auth/google/mobile, where the backend independently verifies
 * it against Google's public keys (see security.verify_google_id_token_mobile
 * / validate_google_userinfo on the server) this app never decides for
 * itself whether the email is verified.
 */
object GoogleAuthConfig {
    private val serviceConfig = AuthorizationServiceConfiguration(
        android.net.Uri.parse("https://accounts.google.com/o/oauth2/v2/auth"),
        android.net.Uri.parse("https://oauth2.googleapis.com/token"),
    )

    private const val REDIRECT_URI = "com.example.product_search_project:/oauth2redirect"

    fun buildAuthRequest(): AuthorizationRequest {
        return AuthorizationRequest.Builder(
            serviceConfig,
            BuildConfig.GOOGLE_CLIENT_ID_MOBILE,
            ResponseTypeValues.CODE,
            android.net.Uri.parse(REDIRECT_URI),
        )
            .setScope("openid email profile")
            .build()
    }

    fun launchIntent(context: Context): Intent {
        val authService = AuthorizationService(context)
        return authService.getAuthorizationRequestIntent(buildAuthRequest())
    }
}
