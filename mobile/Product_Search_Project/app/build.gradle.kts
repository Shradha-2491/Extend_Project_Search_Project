plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.cyclonedx.bom)
}

android {
    namespace = "com.example.product_search_project"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.example.product_search_project"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            // Debug builds only: talk to the classroom server over plain HTTP
            // on the emulator loopback (10.0.2.2) via <debug-overrides> in
            // network_security_config.xml. This block, and cleartext access,
            // are switched off entirely in the release build below.
            buildConfigField("String", "API_BASE_URL", "\"http://10.0.2.2:5001/\"")
            // Credential Manager's setServerClientId() needs the WEB client id
            // (its aud claim is what the backend verifies against) -- not an
            // Android-type client id. Same value as backend's GOOGLE_CLIENT_ID_MOBILE.
            buildConfigField("String", "GOOGLE_CLIENT_ID_MOBILE", "\"822229929166-0up1j5kfbbd9c2p7slefr6kp5407eotv.apps.googleusercontent.com\"")
            isDebuggable = true
        }
        release {
            // Assignment objective: the release APK must not be debuggable,
            // must be minified/shrunk, and must not embed secrets. There is
            // no client secret to embed either way -- Credential Manager's
            // flow (see GoogleAuthConfig) has no client-secret concept, the
            // same way PKCE removes it for authorization-code flows; the
            // GOOGLE_CLIENT_ID_MOBILE value below is a public identifier,
            // not a secret (same value as the debug build's, and as
            // backend's GOOGLE_CLIENT_ID_MOBILE).
            //
            // No real classroom host was provided for this assignment, so
            // this points at a synthetic local HTTPS host instead (backend/
            // run_https.py + backend/certs/, self-signed, gitignored) --
            // see network_security_config.xml's release variant for the
            // certificate-pinning half of this. Swap this URL (and that
            // file's domain/pins) if you later get a real host.
            buildConfigField("String", "API_BASE_URL", "\"https://10.0.2.2:5443/\"")
            buildConfigField("String", "GOOGLE_CLIENT_ID_MOBILE", "\"822229929166-0up1j5kfbbd9c2p7slefr6kp5407eotv.apps.googleusercontent.com\"")
            isDebuggable = false
            optimization {
                enable = true
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    // Networking: Retrofit + OkHttp + kotlinx.serialization (no reflection-
    // based Gson, keeps the release/minified build smaller and safer).
    implementation(libs.retrofit)
    implementation(libs.retrofit.kotlinx.serialization.converter)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging.interceptor)

    // Encrypted local storage for access/refresh tokens (never plain
    // SharedPreferences) -- see data/TokenStore.kt.
    implementation(libs.androidx.security.crypto)

    // Google Sign-In via Credential Manager (Google's current recommended
    // native flow -- validates the app via package name + SHA-1 fingerprint,
    // no OAuth redirect URI involved; see GoogleAuthConfig).
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services.auth)
    implementation(libs.googleid)

    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
