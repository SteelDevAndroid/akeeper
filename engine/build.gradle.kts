plugins {
    id("akeeper.android-library")
}

android {
    namespace = "com.akeeper.engine"
}

androidComponents {
    onVariants { variant ->
        val cargo = tasks.register<CargoNdkBuild>("cargoNdk${variant.name.replaceFirstChar(Char::titlecase)}") {
            workspaceDir.set(rootProject.layout.projectDirectory.dir("rust"))
            sources.from(rootProject.fileTree("rust") {
                include("Cargo.toml", "Cargo.lock", ".cargo/**", "crates/**")
            })
            release.set(variant.buildType == "release")
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargo, CargoNdkBuild::outputDir)
    }
}
