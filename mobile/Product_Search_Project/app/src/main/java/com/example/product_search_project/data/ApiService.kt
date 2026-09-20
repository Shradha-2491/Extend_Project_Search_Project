package com.example.product_search_project.data

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface ApiService {

    @POST("api/v1/auth/register")
    suspend fun register(@Body body: RegisterRequest): Response<Unit>

    @POST("api/v1/auth/login")
    suspend fun login(@Body body: LoginRequest): Response<LoginResponse>

    @POST("api/v1/auth/google/mobile")
    suspend fun googleMobile(@Body body: GoogleMobileRequest): Response<LoginResponse>

    // The pending-MFA token is short-lived and issued outside the normal
    // logged-in session, so it's passed explicitly rather than relying on
    // ApiClient's "attach the stored access token" interceptor.
    @POST("api/v1/auth/mfa/enroll")
    suspend fun mfaEnroll(@Header("Authorization") bearer: String): Response<MfaEnrollResponse>

    @POST("api/v1/auth/mfa/verify")
    suspend fun mfaVerify(
        @Header("Authorization") bearer: String,
        @Body body: MfaCodeRequest,
    ): Response<TokenResponse>

    @POST("api/v1/auth/refresh")
    suspend fun refresh(@Body body: RefreshRequest): Response<RefreshResponse>

    @POST("api/v1/auth/logout")
    suspend fun logout(@Body body: RefreshRequest): Response<Unit>

    @POST("api/v1/auth/password-reset/request")
    suspend fun passwordResetRequest(@Body body: PasswordResetRequest): Response<Unit>

    @POST("api/v1/auth/password-reset/confirm")
    suspend fun passwordResetConfirm(@Body body: PasswordResetConfirmRequest): Response<Unit>

    @GET("api/v1/products")
    suspend fun listProducts(@Query("q") term: String = ""): Response<ProductListResponse>

    @GET("api/v1/products/{id}")
    suspend fun getProduct(@Path("id") id: Int): Response<Product>

    @POST("api/v1/products")
    suspend fun createProduct(@Body body: CreateProductRequest): Response<Map<String, Int>>

    // Idempotency-Key must be a fresh random value per logical user action
    // (generated client-side, see ProductDetailScreen) and reused only if the
    // exact same request needs to be retried after a timeout/network error.
    @PATCH("api/v1/products/{id}/price")
    suspend fun updatePrice(
        @Path("id") id: Int,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: PriceUpdateRequest,
    ): Response<Product>

    @DELETE("api/v1/products/{id}")
    suspend fun deleteProduct(@Path("id") id: Int): Response<Unit>

    @GET("api/v1/admin/users")
    suspend fun listUsers(): Response<AdminUserListResponse>

    @POST("api/v1/admin/users")
    suspend fun createUser(@Body body: Map<String, String>): Response<Map<String, Int>>

    @PATCH("api/v1/admin/users/{id}")
    suspend fun updateUser(@Path("id") id: Int, @Body body: UpdateUserRequest): Response<Unit>

    @DELETE("api/v1/admin/users/{id}")
    suspend fun deactivateUser(@Path("id") id: Int): Response<Unit>
}
