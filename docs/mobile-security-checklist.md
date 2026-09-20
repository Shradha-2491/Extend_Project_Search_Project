# Mobile security checklist (run these yourself in Android Studio)

This sandbox has no JDK/Android SDK, so the app in `mobile/Product_Search_Project`
could be written and reviewed here but not compiled, signed, or run on a
device/emulator. Everything below is what the assignment's mobile objective
asks for; do these on your own machine and drop the output (a short text
file or screenshot per step) into `docs/scans/mobile/`.

## 0. Before you start

1. Open `mobile/Product_Search_Project` in Android Studio (it will resolve
   the Gradle/AGP/Kotlin versions in `gradle/libs.versions.toml` on first
   sync -- if any version conflicts, Android Studio's Upgrade Assistant will
   suggest the fix; bump the affected line in that file).
2. Fill in `backend/.env`: `GOOGLE_CLIENT_ID_MOBILE` (register a separate
   **Android** OAuth client in Google Cloud Console, package name
   `com.example.product_search_project`, SHA-1 from your debug/release
   keystore). Native Android clients have no client secret -- PKCE is the
   proof of possession instead (see `data/GoogleAuthConfig.kt`).
3. Edit `app/build.gradle.kts`'s `release` block: point `API_BASE_URL` at
   your real classroom host (HTTPS), and edit
   `app/src/release/res/xml/network_security_config.xml` with your real
   host and the two SHA-256 SPKI pins (command is in that file's comment).

## 1. Build and sign the release APK

```bash
cd mobile/Product_Search_Project
keytool -genkeypair -v -keystore release.jks -alias lab -keyalg RSA -keysize 2048 -validity 3650
./gradlew assembleRelease
apksigner sign --ks release.jks --out app-release-signed.apk app/build/outputs/apk/release/app-release-unsigned.apk
apksigner verify app-release-signed.apk
```

Keep `release.jks` out of the submission ZIP (it's a secret, not source).

## 2. Inspect the release APK for hardcoded secrets / debug flags

```bash
apktool d app-release-signed.apk -o apk-inspect
grep -RniE "client_secret|api[_-]?key|password|BEGIN (RSA|EC) PRIVATE KEY" apk-inspect/ \
  | tee docs/scans/mobile/apk_secret_scan.txt
aapt dump badging app-release-signed.apk | grep -i "application-debuggable" \
  | tee docs/scans/mobile/apk_debuggable_check.txt   # should print NOTHING
jadx -d apk-jadx app-release-signed.apk   # read the decompiled source for anything embedded
```

**What a clean result looks like:** the secret grep finds nothing (there is
no `GOOGLE_CLIENT_SECRET` anywhere in the mobile app -- only the web backend
has one, and it never ships in the APK); the debuggable check prints nothing
(release `isDebuggable = false` in `app/build.gradle.kts`); the class names
in `apk-jadx` are shortened/obfuscated (R8 minification is on for release).
Explain in your submission whether that matched, and if not, what you fixed.

## 3. Verify secure local storage

1. Log in on a rooted device/emulator, enroll MFA, reach the product list.
2. `adb shell run-as com.example.product_search_project ls -la
   shared_prefs/ databases/` -- you should find
   `secure_auth_prefs.xml` from `data/TokenStore.kt`.
3. `adb shell run-as com.example.product_search_project cat
   shared_prefs/secure_auth_prefs.xml` -- the values must be unreadable
   ciphertext (EncryptedSharedPreferences / AES-256-GCM), never a plaintext
   JWT. Save this output as `docs/scans/mobile/local_storage_check.txt`.
4. Confirm `android:allowBackup="false"` in the built manifest (`aapt dump
   xmltree app-release-signed.apk AndroidManifest.xml | grep allowBackup`)
   -- this stops `adb backup`/auto-backup from exporting the app's private
   storage at all, on top of the encryption.

## 4. MITM / TLS enforcement demonstration

1. Install `mitmproxy` (or Burp) on your machine and its CA certificate on
   the test device as a **user** CA (not system) -- this simulates a
   real hostile network where the attacker cannot get their CA into the
   OS trust store, which is exactly the case network security config's
   `<trust-anchors><certificates src="system"/>` is designed to reject: by
   default Android only trusts the system CA store, so a user-installed MITM
   CA is not honoured for this app's connections in the first place.
2. Route the device's Wi-Fi through the proxy and use the app normally
   (login, MFA, price update) against the **release** build pointed at your
   real HTTPS host.
3. Expected result: the app's requests fail the TLS handshake (certificate
   pinning mismatch, since the proxy presents its own leaf cert, not one
   matching either pin in `network_security_config.xml`) and mitmproxy shows
   no decrypted traffic for this app's flows -- capture that screen as
   `docs/scans/mobile/mitm_pinning_blocked.png`.
4. As a control, temporarily remove the `<pin-set>` block and confirm
   mitmproxy CAN read traffic when relying on the system trust store alone
   with a user CA installed pre-Android-7 style trust (or on an emulator
   image where you've added the CA to the system store) -- this demonstrates
   *why* pinning specifically (not just HTTPS) is the control that stopped
   step 3, and that no sensitive data (tokens, prices) appeared in transit
   once pinning was restored.

## 5. SBOM for the mobile app's dependencies

The sandbox that authored this project has no Java/Gradle, so
`docs/sbom/mobile-sbom.json` here was generated by hand from
`gradle/libs.versions.toml` (documented at the top of that file). Once you
can run Gradle yourself, regenerate a real one:

```bash
# in mobile/Product_Search_Project/build.gradle.kts, add:
#   plugins { id("org.cyclonedx.bom") version "1.8.2" }
./gradlew cyclonedxBom
cp app/build/reports/bom.json ../../docs/sbom/mobile-sbom.json
```
