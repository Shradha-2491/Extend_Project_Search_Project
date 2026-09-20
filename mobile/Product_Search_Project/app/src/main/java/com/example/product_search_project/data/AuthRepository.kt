package com.example.product_search_project.data

/** Thin wrapper turning Retrofit's Response<T> into a small sealed result so
 * screens don't each re-implement HTTP status/error-body handling. */
sealed class ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>()
    data class Failure(val code: Int, val error: String) : ApiResult<Nothing>()
}

class AuthRepository(private val api: ApiService, private val tokens: TokenStore) {

    suspend fun register(username: String, email: String, password: String): ApiResult<Unit> {
        val resp = api.register(RegisterRequest(username, email, password))
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun login(username: String, password: String): ApiResult<LoginResponse> {
        val resp = api.login(LoginRequest(username, password))
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body)
        else fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun googleMobile(idToken: String): ApiResult<LoginResponse> {
        val resp = api.googleMobile(GoogleMobileRequest(idToken))
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body)
        else fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun mfaEnroll(pendingToken: String): ApiResult<MfaEnrollResponse> {
        val resp = api.mfaEnroll("Bearer $pendingToken")
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body)
        else fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun mfaVerify(pendingToken: String, code: String): ApiResult<TokenResponse> {
        val resp = api.mfaVerify("Bearer $pendingToken", MfaCodeRequest(code))
        val body = resp.body()
        if (resp.isSuccessful && body != null) {
            tokens.accessToken = body.access_token
            tokens.refreshToken = body.refresh_token
            tokens.role = body.role
            tokens.username = body.username
            return ApiResult.Ok(body)
        }
        return fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun requestPasswordReset(identifier: String) {
        runCatching { api.passwordResetRequest(PasswordResetRequest(identifier)) }
    }

    suspend fun confirmPasswordReset(token: String, newPassword: String): ApiResult<Unit> {
        val resp = api.passwordResetConfirm(PasswordResetConfirmRequest(token, newPassword))
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else fail(resp.code(), resp.errorBody()?.string())
    }

    suspend fun logout() {
        val refresh = tokens.refreshToken
        if (refresh != null) runCatching { api.logout(RefreshRequest(refresh)) }
        tokens.clear()
    }

    private fun <T> fail(code: Int, errorBody: String?): ApiResult<T> {
        val message = errorBody?.let {
            Regex("\"error\"\\s*:\\s*\"([^\"]+)\"").find(it)?.groupValues?.get(1)
        } ?: "request_failed"
        return ApiResult.Failure(code, message)
    }
}
