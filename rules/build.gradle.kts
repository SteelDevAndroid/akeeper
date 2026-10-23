plugins {
    id("akeeper.android-library")
}

// Clés publiques Ed25519 du serveur de règles (hex, deux au plus pour la rotation). Jamais de clé privée ici.
val rulePublicKeys = providers.gradleProperty("akeeper.rulePublicKeys").getOrElse("")
val minRuleVersion = providers.gradleProperty("akeeper.minRuleVersion").getOrElse("0")
val rulesUrl = providers.gradleProperty("akeeper.rulesUrl").getOrElse("")

// Valeurs injectées dans BuildConfig : validées pour qu'aucune propriété ne puisse y glisser du code Java.
require(rulePublicKeys.isEmpty() || Regex("[0-9a-f]{64}(,[0-9a-f]{64})?").matches(rulePublicKeys)) {
    "akeeper.rulePublicKeys : une ou deux clés hex de 64 caractères, séparées par une virgule"
}
require(Regex("[0-9]{1,18}").matches(minRuleVersion)) { "akeeper.minRuleVersion : entier positif" }
require(rulesUrl.isEmpty() || Regex("https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?").matches(rulesUrl)) {
    "akeeper.rulesUrl : URL https sans paramètres"
}

android {
    namespace = "com.akeeper.rules"
    buildFeatures.buildConfig = true
    defaultConfig {
        buildConfigField("String", "RULE_PUBLIC_KEYS", "\"$rulePublicKeys\"")
        buildConfigField("long", "MIN_RULE_VERSION", "${minRuleVersion}L")
        buildConfigField("String", "RULES_URL", "\"$rulesUrl\"")
    }
}

dependencies {
    implementation(libs.tink.android)
    implementation(libs.work.runtime)
}
