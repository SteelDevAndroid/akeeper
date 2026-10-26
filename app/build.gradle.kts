plugins {
    id("akeeper.android-application")
}

// Pinning TLS du serveur de règles : mêmes propriétés que :rules pour l'URL, empreintes SPKI (scripts/rules-pins.sh).
val rulesUrl = providers.gradleProperty("akeeper.rulesUrl").getOrElse("")
val rulesPins = providers.gradleProperty("akeeper.rulesPins").getOrElse("")
    .split(',').map(String::trim).filter(String::isNotEmpty)
val rulesPinsExpiration = providers.gradleProperty("akeeper.rulesPinsExpiration").getOrElse("")
val rulesHost = Regex("https://([A-Za-z0-9.-]+)(:[0-9]+)?(/.*)?").matchEntire(rulesUrl)?.groupValues?.get(1).orEmpty()

// Valeurs écrites dans un XML : validées pour qu'aucune propriété ne puisse y injecter de balise.
require(rulesPins.all { Regex("[A-Za-z0-9+/]{43}=").matches(it) }) {
    "akeeper.rulesPins : empreintes SHA-256 en base64 (44 caractères), séparées par une virgule"
}
require(rulesPins.isEmpty() || (rulesHost.isNotEmpty() && rulesPins.size >= 2)) {
    "akeeper.rulesPins : exige akeeper.rulesUrl et au moins deux empreintes (dont une de secours)"
}
require(rulesPins.isEmpty() || Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}").matches(rulesPinsExpiration)) {
    "akeeper.rulesPinsExpiration : date AAAA-MM-JJ, obligatoire avec akeeper.rulesPins"
}

val networkSecurityConfig = tasks.register<NetworkSecurityConfig>("networkSecurityConfig") {
    host.set(rulesHost)
    pins.set(rulesPins)
    expiration.set(rulesPinsExpiration)
    outputDir.set(layout.buildDirectory.dir("generated/res/networkSecurityConfig"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.res?.addGeneratedSourceDirectory(networkSecurityConfig, NetworkSecurityConfig::outputDir)
    }
}

android {
    namespace = "com.akeeper"

    defaultConfig {
        applicationId = "com.akeeper"
        versionCode = 1
        versionName = "0.1.0"
        // Les ABI du moteur Rust (cargo-ndk) : SQLCipher n'embarque pas de .so pour les autres.
        ndk.abiFilters += listOf("arm64-v8a", "x86_64")
    }

    // Robolectric charge les ressources, le manifeste et les thèmes réels : il attrape les plantages d'inflation.
    testOptions.unitTests.isIncludeAndroidResources = true
    testOptions.unitTests.all {
        // Robolectric instrumente des classes du JDK 21 : ces modules internes doivent lui être ouverts.
        it.jvmArgs(
            "--add-exports=java.base/jdk.internal.access=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-opens=java.base/java.net=ALL-UNNAMED",
            "--add-opens=java.base/java.nio=ALL-UNNAMED",
            "--add-opens=java.base/java.util=ALL-UNNAMED",
            "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
            "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
        )
    }

    // R8 : code et ressources réduits ; les règles JNI viennent de engine/consumer-rules.pro.
    buildTypes.getByName("release") {
        isMinifyEnabled = true
        isShrinkResources = true
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }

    // Clé de release fournie par la CI (secrets) : jamais dans le dépôt. Sans elle, l'APK release reste non signé.
    val keystore = providers.environmentVariable("AKEEPER_KEYSTORE").orNull
    if (keystore != null) {
        signingConfigs.create("release") {
            storeFile = file(keystore)
            storePassword = providers.environmentVariable("AKEEPER_KEYSTORE_PASSWORD").get()
            keyAlias = providers.environmentVariable("AKEEPER_KEY_ALIAS").get()
            keyPassword = providers.environmentVariable("AKEEPER_KEY_PASSWORD").get()
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("release")
    }

    packaging {
        // .so non compressées et alignées 16 KB : exigence Play.
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation(project(":vpn"))
    implementation(project(":engine"))
    implementation(project(":rules"))
    implementation(libs.material)
    implementation(libs.recyclerview)

    // Robolectric tourne sous JUnit 4 : le moteur vintage le branche sur la plateforme JUnit 5 du projet.
    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testRuntimeOnly(libs.junit.vintage.engine)
}
