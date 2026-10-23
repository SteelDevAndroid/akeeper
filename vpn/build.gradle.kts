plugins {
    id("akeeper.android-library")
}

android {
    namespace = "com.akeeper.vpn"
}

dependencies {
    api(project(":engine"))
    implementation(libs.tink.android)
}
