plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
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

        // AppAuth needs a redirect scheme for the OAuth callback; keep this
        // in sync with GoogleAuthConfig.REDIRECT_URI.
        manifestPlaceholders["appAuthRedirectScheme"] = "com.example.product_search_project"
    }

    buildTypes {
        debug {
            // Debug builds only: talk to the classroom server over plain HTTP
            // on the emulator loopback (10.0.2.2) via <debug-overrides> in
            // network_security_config.xml. This block, and cleartext access,
            // are switched off entirely in the release build below.
            buildConfigField("String", "API_BASE_URL", "\"http://10.0.2.2:5001/\"")
            buildConfigField("String", "GOOGLE_CLIENT_ID_MOBILE", "\"\"")
            isDebuggable = true
        }
        release {
            // Assignment objective: the release APK must not be debuggable,
            // must be minified/shrunk, and must not embed secrets -- the API
            // base URL is the only build-time config baked in, and there is
            // no client secret to embed (the mobile OAuth client is
            // public/PKCE-based, see GoogleAuthConfig).
            buildConfigField("String", "API_BASE_URL", "\"https://YOUR-CLASSROOM-HOST:5001/\"")
            buildConfigField("String", "GOOGLE_CLIENT_ID_MOBILE", "\"\"")
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
    debugImplementation(libs.okhttp.logging.interceptor)

    // Encrypted local storage for access/refresh tokens (never plain
    // SharedPreferences) -- see data/TokenStore.kt.
    implementation(libs.androidx.security.crypto)

    // Google Sign-In via Authorization Code + PKCE, no client secret on device.
    implementation(libs.appauth)

    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
