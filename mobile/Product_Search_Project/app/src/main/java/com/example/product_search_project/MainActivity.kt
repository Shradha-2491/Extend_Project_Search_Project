package com.example.product_search_project

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
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

class MainActivity : ComponentActivity() {

    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ApiClient.init(applicationContext)
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
            vm.errorMessage = "Google Sign-In isn't available right now."
            return
        }
        lifecycleScope.launch {
            try {
                val idToken = GoogleAuthConfig.signIn(this@MainActivity)
                val authRepo = AuthRepository(ApiClient.service(), ApiClient.tokens())
                when (val result = authRepo.googleMobile(idToken)) {
                    is ApiResult.Ok -> {
                        val body = result.value
                        vm.goTo(if (body.mfa_enrolled) Screen.MfaVerify(body.pending_token) else Screen.MfaSetup(body.pending_token))
                    }
                    is ApiResult.Failure -> vm.errorMessage = result.error
                }
            } catch (e: GetCredentialCancellationException) {
                // User dismissed the account picker -- not an error worth showing.
            } catch (e: GetCredentialException) {
                e.printStackTrace()
                vm.errorMessage = "Google sign-in failed. Please try again."
            }
        }
    }
}
