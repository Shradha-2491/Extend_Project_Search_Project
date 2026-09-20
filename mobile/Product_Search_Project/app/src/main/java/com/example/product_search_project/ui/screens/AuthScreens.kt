package com.example.product_search_project.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.example.product_search_project.ui.AppViewModel
import com.example.product_search_project.ui.Screen

@Composable
fun LoginScreen(vm: AppViewModel, onGoogleSignIn: () -> Unit) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Column(
        Modifier.fillMaxWidth().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Product Search Lab -- Log in")
        OutlinedTextField(username, { username = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            password, { password = it }, label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        vm.errorMessage?.let { Text("Error: $it") }
        Button(onClick = { vm.login(username, password) }, enabled = !vm.loading, modifier = Modifier.fillMaxWidth()) {
            Text(if (vm.loading) "..." else "Log in")
        }
        Button(onClick = onGoogleSignIn, modifier = Modifier.fillMaxWidth()) { Text("Sign in with Google") }
        TextButton(onClick = { vm.goTo(Screen.Register) }) { Text("Create an account") }
        TextButton(onClick = { vm.goTo(Screen.PasswordReset) }) { Text("Forgot password?") }
    }
}

@Composable
fun RegisterScreen(vm: AppViewModel) {
    var username by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Column(
        Modifier.fillMaxWidth().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Register (creates a customer account)")
        OutlinedTextField(username, { username = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(email, { email = it }, label = { Text("Email") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            password, { password = it }, label = { Text("Password (min 10 chars)") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        vm.errorMessage?.let { Text("Error: $it") }
        Button(onClick = { vm.register(username, email, password) }, enabled = !vm.loading, modifier = Modifier.fillMaxWidth()) {
            Text("Register")
        }
        TextButton(onClick = { vm.goTo(Screen.Login) }) { Text("Back to login") }
    }
}

@Composable
fun PasswordResetScreen(vm: AppViewModel) {
    var identifier by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxWidth().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Forgot password")
        OutlinedTextField(identifier, { identifier = it }, label = { Text("Username or email") }, modifier = Modifier.fillMaxWidth())
        vm.errorMessage?.let { Text(it) }
        Button(onClick = { vm.requestPasswordReset(identifier) }, modifier = Modifier.fillMaxWidth()) {
            Text("Send reset instructions")
        }
        TextButton(onClick = { vm.goTo(Screen.Login) }) { Text("Back to login") }
    }
}

@Composable
fun MfaSetupScreen(vm: AppViewModel, pendingToken: String) {
    var code by remember { mutableStateOf("") }

    androidx.compose.runtime.LaunchedEffect(pendingToken) {
        if (vm.mfaSecret == null) vm.beginMfaEnroll(pendingToken)
    }

    Column(
        Modifier.fillMaxWidth().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Set up MFA (required)")
        Text("Scan the QR in an authenticator app, or enter the secret manually:")
        vm.mfaSecret?.let { Text(it) }
        Text("(QR image is returned as a data URI by /api/v1/auth/mfa/enroll; render it with " +
            "Coil's data-URI support or android.graphics.BitmapFactory if you want it on-screen.)")
        OutlinedTextField(code, { code = it }, label = { Text("6-digit code") }, modifier = Modifier.fillMaxWidth())
        vm.errorMessage?.let { Text("Error: $it") }
        Button(onClick = { vm.verifyMfa(pendingToken, code) }, modifier = Modifier.fillMaxWidth()) {
            Text("Activate MFA")
        }
    }
}

@Composable
fun MfaVerifyScreen(vm: AppViewModel, pendingToken: String) {
    var code by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxWidth().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Two-factor verification")
        OutlinedTextField(code, { code = it }, label = { Text("6-digit code") }, modifier = Modifier.fillMaxWidth())
        vm.errorMessage?.let { Text("Error: $it") }
        Button(onClick = { vm.verifyMfa(pendingToken, code) }, modifier = Modifier.fillMaxWidth()) {
            Text("Verify")
        }
    }
}
