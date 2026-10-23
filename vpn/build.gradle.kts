plugins {
    id("akeeper.android-library")
}

android {
    namespace = "com.akeeper.vpn"
}

dependencies {
    implementation(project(":engine"))
}
