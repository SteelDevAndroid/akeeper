plugins {
    id("akeeper.android-library")
}

// Bibliothèque native compilée pour la machine hôte : les tests JVM exécutent les vrais points d'entrée JNI.
val cargoHost = tasks.register<Exec>("cargoHostBuild") {
    workingDir = rootProject.layout.projectDirectory.dir("rust").asFile
    commandLine("cargo", "build", "-p", "akeeper-ffi")
    inputs.files(rootProject.fileTree("rust") {
        include("Cargo.toml", "Cargo.lock", ".cargo/**", "crates/**")
    }, rootProject.fileTree("rules/sources"))
    outputs.dir(rootProject.layout.projectDirectory.dir("rust/target/debug"))
}

android {
    namespace = "com.akeeper.engine"
    defaultConfig.consumerProguardFiles("consumer-rules.pro")
    testOptions.unitTests.all {
        it.dependsOn(cargoHost)
        it.systemProperty("java.library.path", rootProject.layout.projectDirectory.dir("rust/target/debug").asFile.absolutePath)
        // Le test lit le descripteur brut de ses sockets pour les céder au moteur, comme le fait le service avec le TUN.
        it.jvmArgs("--add-exports=java.base/sun.nio.ch=ALL-UNNAMED", "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED")
    }
}

androidComponents {
    onVariants { variant ->
        val cargo = tasks.register<CargoNdkBuild>("cargoNdk${variant.name.replaceFirstChar(Char::titlecase)}") {
            workspaceDir.set(rootProject.layout.projectDirectory.dir("rust"))
            sources.from(rootProject.fileTree("rust") {
                include("Cargo.toml", "Cargo.lock", ".cargo/**", "crates/**")
            })
            // Listes compilées dans le moteur (include_str!) : un changement doit relancer cargo.
            sources.from(rootProject.fileTree("rules/sources"))
            release.set(variant.buildType == "release")
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargo, CargoNdkBuild::outputDir)
    }
}
