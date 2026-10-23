import com.android.build.api.dsl.CommonExtension

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

extensions.configure<CommonExtension>("android") {
    compileSdk = 36
    // NDK fixé : AGP retire les symboles des .so Rust et les archive à part pour Play.
    ndkVersion = libs.findVersion("ndk").get().requiredVersion
    defaultConfig.minSdk = 36
    compileOptions.sourceCompatibility = JavaVersion.VERSION_21
    compileOptions.targetCompatibility = JavaVersion.VERSION_21
    testOptions.unitTests.all { it.useJUnitPlatform() }
}

dependencies {
    "testImplementation"(platform(libs.findLibrary("junit-bom").get()))
    "testImplementation"(libs.findLibrary("junit-jupiter").get())
    "testImplementation"(libs.findLibrary("mockito-junit-jupiter").get())
    "testImplementation"(libs.findLibrary("assertj-core").get())
    // Gradle 9 ne fournit plus le launcher JUnit Platform implicitement.
    "testRuntimeOnly"(libs.findLibrary("junit-platform-launcher").get())
}
