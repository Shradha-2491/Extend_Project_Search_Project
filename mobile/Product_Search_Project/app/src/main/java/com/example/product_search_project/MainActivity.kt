package com.example.product_search_project

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.example.product_search_project.data.ApiClient
import com.example.product_search_project.data.ApiResult
import com.example.product_search_project.data.AuthRepository
import com.example.product_search_project.data.GoogleAuthConfig
import com.example.product_search_project.ui.AppViewModel
import com.example.product_search_project.ui.Screen
import com.example.product_search_project.ui.screens.AdminUsersScreen
import com.example.product_search_project.ui.screens.LoginScreen
import com.example.product_search_project.ui.screens.MfaSetupScreen
import com.example.product_search_project.ui.screens.MfaVerifyScreen
import com.example.product_search_project.ui.screens.PasswordResetScreen
import com.example.product_search_project.ui.screens.ProductDetailScreen
import com.example.product_search_project.ui.screens.ProductListScreen
import com.example.product_search_project.ui.screens.RegisterScreen
import com.example.product_search_project.ui.theme.Product_Search_ProjectTheme
import kotlinx.coroutines.launch
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.TokenResponse
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

class MainActivity : ComponentActivity() {

    private val vm: AppViewModel by viewModels()
    private lateinit var authService: AuthorizationService

    private val googleSignInLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val data = result.data ?: return@registerForActivityResult
        val authResponse = AuthorizationResponse.fromIntent(data)
        val authException = AuthorizationException.fromIntent(data)
        if (authResponse == null) {
            vm.errorMessage = authException?.errorDescription ?: "google_sign_in_cancelled"
            return@registerForActivityResult
        }
        lifecycleScope.launch {
            exchangeGoogleCode(authResponse)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ApiClient.init(applicationContext)
        authService = AuthorizationService(this)
        enableEdgeToEdge()

        setContent {
            Product_Search_ProjectTheme {
                LaunchedEffect(Unit) { vm.start() }
                Scaffold(modifier = Modifier.fillMaxSize()) { padding ->
                    when (val screen = vm.screen) {
                        is Screen.Login -> LoginScreen(vm, onGoogleSignIn = { launchGoogleSignIn() })
                        is Screen.Register -> RegisterScreen(vm)
                        is Screen.PasswordReset -> PasswordResetScreen(vm)
                        is Screen.MfaSetup -> MfaSetupScreen(vm, screen.pendingToken)
                        is Screen.MfaVerify -> MfaVerifyScreen(vm, screen.pendingToken)
                        is Screen.Products -> ProductListScreen(vm)
                        is Screen.ProductDetail -> ProductDetailScreen(vm, screen.productId)
                        is Screen.AdminUsers -> AdminUsersScreen(vm)
                    }
                }
            }
        }
    }

    private fun launchGoogleSignIn() {
        if (BuildConfig.GOOGLE_CLIENT_ID_MOBILE.isBlank()) {
            vm.errorMessage = "Mobile Google Sign-In is not configured (set GOOGLE_CLIENT_ID_MOBILE)."
            return
        }
        googleSignInLauncher.launch(GoogleAuthConfig.launchIntent(this))
    }

    /**
     * Exchanges the authorization code for tokens directly with Google
     * (PKCE code_verifier is tracked internally by AppAuth's AuthState/
     * AuthorizationResponse), then hands ONLY the resulting id_token to our
     * backend at POST /api/v1/auth/google/mobile -- the backend re-verifies
     * it independently rather than trusting anything the client asserts.
     */
    private suspend fun exchangeGoogleCode(authResponse: AuthorizationResponse) {
        val tokenResponse = suspendCoroutine<TokenResponse?> { cont ->
            authService.performTokenRequest(authResponse.createTokenExchangeRequest()) { resp, ex ->
                if (ex != null) {
                    vm.errorMessage = ex.errorDescription ?: "google_token_exchange_failed"
                    cont.resume(null)
                } else {
                    cont.resume(resp)
                }
            }
        }
        val idToken = tokenResponse?.idToken ?: return
        val authRepo = AuthRepository(ApiClient.service(), ApiClient.tokens())
        when (val result = authRepo.googleMobile(idToken)) {
            is ApiResult.Ok -> {
                val body = result.value
                vm.goTo(if (body.mfa_enrolled) Screen.MfaVerify(body.pending_token) else Screen.MfaSetup(body.pending_token))
            }
            is ApiResult.Failure -> vm.errorMessage = result.error
        }
    }

    override fun onDestroy() {
        authService.dispose()
        super.onDestroy()
    }
}
