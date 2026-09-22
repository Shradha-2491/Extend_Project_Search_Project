package com.example.product_search_project.data

import android.content.Context
import android.util.Base64
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import com.example.product_search_project.BuildConfig
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import java.security.SecureRandom

/**
 * Mobile Google Sign-In via Credential Manager -- Google's current
 * recommended native flow for Android (custom-scheme OAuth redirects, which
 * an earlier version of this file used via AppAuth, are no longer supported
 * by Google for Android apps). The app itself is authenticated to Google by
 * its package name + signing-certificate SHA-1 fingerprint (registered in
 * Google Cloud Console), not by any redirect URI. The resulting id_token is
 * sent to POST /api/v1/auth/google/mobile, where the backend independently
 * verifies it against Google's public keys (see
 * security.verify_google_id_token_mobile / validate_google_userinfo on the
 * server) -- this app never decides for itself whether the email is
 * verified.
 */
object GoogleAuthConfig {

    private fun freshNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    /** Shows Google's account picker and returns a verified Google id_token. */
    suspend fun signIn(context: Context): String {
        val option = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false)
            .setServerClientId(BuildConfig.GOOGLE_CLIENT_ID_MOBILE)
            .setNonce(freshNonce())
            .build()
        val request = GetCredentialRequest.Builder().addCredentialOption(option).build()

        val credential = CredentialManager.create(context).getCredential(context, request).credential
        require(credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
            "Unexpected credential type"
        }
        return GoogleIdTokenCredential.createFrom(credential.data).idToken
    }
}
