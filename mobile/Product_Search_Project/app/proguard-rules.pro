# Release build hardening: keep this file's rules minimal and specific --
# broad `-dontobfuscate`/`-dontshrink` escape hatches would defeat the point
# of enabling minification (see build.gradle.kts release block / the
# assignment's "unsafe configuration/debug flags" APK-inspection objective).

# kotlinx.serialization needs its generated serializer classes kept.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclasseswithmembers class com.example.product_search_project.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-if @kotlinx.serialization.Serializable class com.example.product_search_project.data.**
-keepclassmembers class <1> {
    static <1>$Companion Companion;
}

# Retrofit / OkHttp
-dontwarn okhttp3.**
-dontwarn retrofit2.**
-keepattributes Signature, Exceptions

# Credential Manager / Google ID (androidx.credentials, googleid) ship their
# own consumer-proguard-rules bundled in their AARs, auto-merged by R8 --
# no manual -keep needed here. (This file previously had a leftover -keep
# for net.openid.appauth, a dependency removed when mobile Google Sign-In
# was migrated to Credential Manager; harmless dead config, since a -keep
# for an absent class is a no-op, but removed for accuracy.)
