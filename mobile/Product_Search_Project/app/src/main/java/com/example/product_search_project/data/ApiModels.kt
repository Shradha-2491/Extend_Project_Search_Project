package com.example.product_search_project.data

import kotlinx.serialization.Serializable

@Serializable
data class RegisterRequest(val username: String, val email: String, val password: String)

@Serializable
data class LoginRequest(val username: String, val password: String)

@Serializable
data class LoginResponse(
    val mfa_required: Boolean = true,
    val mfa_enrolled: Boolean = false,
    val pending_token: String,
)

@Serializable
data class GoogleMobileRequest(val id_token: String)

@Serializable
data class MfaCodeRequest(val code: String)

@Serializable
data class MfaEnrollResponse(val secret: String, val otpauth_uri: String, val qr_data_uri: String)

@Serializable
data class TokenResponse(
    val access_token: String,
    val refresh_token: String,
    val role: String,
    val username: String,
)

@Serializable
data class RefreshRequest(val refresh_token: String)

@Serializable
data class RefreshResponse(val access_token: String, val refresh_token: String)

@Serializable
data class PasswordResetRequest(val identifier: String)

@Serializable
data class PasswordResetConfirmRequest(val token: String, val new_password: String)

/** Mirrors backend/products.py's role-scoped field set: customers get only
 * id/name/category/price; vendors add cost/stock/active/version; admins add
 * vendor_id/timestamps/created_by/updated_by. All fields are therefore
 * nullable here since which ones are present depends on the caller's role --
 * the server, not the client, decides what's visible (OWASP A01). */
@Serializable
data class Product(
    val id: Int,
    val name: String,
    val category: String,
    val price: Double,
    val cost: Double? = null,
    val stock: Int? = null,
    val active: Int? = null,
    val vendor_id: Int? = null,
    val version: Int? = null,
    val created_at: String? = null,
    val updated_at: String? = null,
    val created_by: String? = null,
    val updated_by: String? = null,
)

@Serializable
data class ProductListResponse(val results: List<Product>)

@Serializable
data class CreateProductRequest(
    val name: String,
    val category: String,
    val price: Double,
    val cost: Double,
    val stock: Int,
)

@Serializable
data class PriceUpdateRequest(val price: Double, val version: Int)

@Serializable
data class AdminUser(
    val id: Int,
    val username: String,
    val email: String?,
    val role: String,
    val auth_provider: String,
    val active: Int,
    val mfa_enabled: Int,
    val created_at: String,
)

@Serializable
data class AdminUserListResponse(val results: List<AdminUser>)

@Serializable
data class UpdateUserRequest(
    val role: String? = null,
    val active: Boolean? = null,
    val reset_mfa: Boolean? = null,
)

@Serializable
data class ErrorResponse(val error: String? = null)
