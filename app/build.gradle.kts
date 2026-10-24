plugins {
    id("akeeper.android-application")
}

android {
    namespace = "com.akeeper"

    defaultConfig {
        applicationId = "com.akeeper"
        versionCode = 1
        versionName = "0.1.0"
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
}
