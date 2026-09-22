package com.example.product_search_project.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.product_search_project.data.AdminRepository
import com.example.product_search_project.data.AdminUser
import com.example.product_search_project.data.ApiClient
import com.example.product_search_project.data.ApiResult
import com.example.product_search_project.data.AuthRepository
import com.example.product_search_project.data.Product
import com.example.product_search_project.data.ProductRepository
import kotlinx.coroutines.launch

sealed class Screen {
    data object Login : Screen()
    data object Register : Screen()
    data object PasswordReset : Screen()
    data class MfaSetup(val pendingToken: String) : Screen()
    data class MfaVerify(val pendingToken: String) : Screen()
    data object Products : Screen()
    data class ProductDetail(val productId: Int) : Screen()
    data object AdminUsers : Screen()
}

/**
 * Single app-wide ViewModel driving a small manual "screen" state machine
 * (deliberately not androidx.navigation, to keep the graph easy to audit
 * for one property: no screen that requires a role is reachable without a
 * full, MFA-verified session -- see requireRole()/screen setter usage in
 * MainActivity).
 */
class AppViewModel : ViewModel() {

    private val tokenStore get() = ApiClient.tokens()
    private val authRepo by lazy { AuthRepository(ApiClient.service(), tokenStore) }
    private val productRepo by lazy { ProductRepository(ApiClient.service()) }
    private val adminRepo by lazy { AdminRepository(ApiClient.service()) }

    var screen by mutableStateOf<Screen>(Screen.Login)
        private set

    var errorMessage by mutableStateOf<String?>(null)
    var loading by mutableStateOf(false)

    var mfaSecret by mutableStateOf<String?>(null)
    var mfaQrDataUri by mutableStateOf<String?>(null)

    var products by mutableStateOf<List<Product>>(emptyList())
    var selectedProduct by mutableStateOf<Product?>(null)
    var users by mutableStateOf<List<AdminUser>>(emptyList())

    val role get() = tokenStore.role
    val username get() = tokenStore.username

    fun start() {
        screen = if (tokenStore.isLoggedIn()) Screen.Products else Screen.Login
    }

    fun goTo(s: Screen) {
        errorMessage = null
        screen = s
        when (s) {
            is Screen.Products -> loadProducts("")
            is Screen.ProductDetail -> loadProduct(s.productId)
            is Screen.AdminUsers -> loadUsers()
            else -> {}
        }
    }

    fun login(username: String, password: String) = launchGuarded {
        when (val result = authRepo.login(username, password)) {
            is ApiResult.Ok -> {
                val body = result.value
                screen = if (body.mfa_enrolled) Screen.MfaVerify(body.pending_token)
                else Screen.MfaSetup(body.pending_token)
            }
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun register(username: String, email: String, password: String) = launchGuarded {
        when (val result = authRepo.register(username, email, password)) {
            is ApiResult.Ok -> {
                errorMessage = null
                screen = Screen.Login
            }
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun beginMfaEnroll(pendingToken: String) = launchGuarded {
        when (val result = authRepo.mfaEnroll(pendingToken)) {
            is ApiResult.Ok -> {
                mfaSecret = result.value.secret
                mfaQrDataUri = result.value.qr_data_uri
            }
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun verifyMfa(pendingToken: String, code: String) = launchGuarded {
        when (val result = authRepo.mfaVerify(pendingToken, code)) {
            is ApiResult.Ok -> goTo(Screen.Products)
            is ApiResult.Failure -> errorMessage = "Invalid or expired code"
        }
    }

    fun requestPasswordReset(identifier: String) = launchGuarded {
        when (val result = authRepo.requestPasswordReset(identifier)) {
            is ApiResult.Ok -> errorMessage = "If an account exists, reset instructions were sent."
            is ApiResult.Failure -> errorMessage = if (result.code == 429)
                "Too many requests. Please wait and try again." else result.error
        }
    }

    fun confirmPasswordReset(token: String, newPassword: String) = launchGuarded {
        when (val result = authRepo.confirmPasswordReset(token, newPassword)) {
            is ApiResult.Ok -> errorMessage = "Password updated. You can log in now."
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun logout() = launchGuarded {
        authRepo.logout()
        screen = Screen.Login
    }

    fun loadProducts(term: String) = launchGuarded {
        when (val result = productRepo.search(term)) {
            is ApiResult.Ok -> products = result.value
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun loadProduct(id: Int) = launchGuarded {
        when (val result = productRepo.get(id)) {
            is ApiResult.Ok -> selectedProduct = result.value
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun updatePrice(id: Int, newPrice: Double, knownVersion: Int, onDone: () -> Unit) = launchGuarded {
        when (val result = productRepo.updatePrice(id, newPrice, knownVersion)) {
            is ApiResult.Ok -> {
                selectedProduct = result.value
                onDone()
            }
            is ApiResult.Failure -> errorMessage = if (result.error == "version_conflict")
                "Someone else changed this price first -- reload and retry." else result.error
        }
    }

    fun loadUsers() = launchGuarded {
        when (val result = adminRepo.listUsers()) {
            is ApiResult.Ok -> users = result.value
            is ApiResult.Failure -> errorMessage = result.error
        }
    }

    fun setRole(id: Int, role: String) = launchGuarded {
        adminRepo.setRole(id, role)
        loadUsers()
    }

    fun deactivateUser(id: Int) = launchGuarded {
        adminRepo.deactivate(id)
        loadUsers()
    }

    private fun launchGuarded(block: suspend () -> Unit) {
        viewModelScope.launch {
            loading = true
            errorMessage = null
            try {
                block()
            } catch (e: Exception) {
                e.printStackTrace()
                errorMessage = "Something went wrong. Please try again."
            } finally {
                loading = false
            }
        }
    }
}
