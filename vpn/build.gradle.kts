plugins {
    id("akeeper.android-library")
}

android {
    namespace = "com.akeeper.vpn"
}

dependencies {
    api(project(":engine"))
    implementation(project(":rules"))
    implementation(libs.tink.android)
    implementation(libs.sqlcipher.android)
    implementation(libs.androidx.sqlite)
}
