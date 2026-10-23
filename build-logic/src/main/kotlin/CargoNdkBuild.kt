import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import javax.inject.Inject

abstract class CargoNdkBuild @Inject constructor(private val exec: ExecOperations) : DefaultTask() {

    @get:Internal
    abstract val workspaceDir: DirectoryProperty

    // target/ est exclu par l'appelant : sinon chaque build cargo invalide la tâche.
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input
    abstract val release: Property<Boolean>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        exec.exec {
            workingDir = workspaceDir.get().asFile
            commandLine(buildList {
                addAll(listOf(
                    "cargo", "ndk",
                    "-t", "arm64-v8a", "-t", "x86_64",
                    "--platform", "36",
                    "-o", outputDir.get().asFile.absolutePath,
                    "build", "-p", "akeeper-ffi",
                ))
                if (release.get()) add("--release")
            })
        }
    }
}
