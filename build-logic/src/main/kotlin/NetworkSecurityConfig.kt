import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction

/**
 * Génère res/xml/network_security_config.xml : pas de trafic en clair, CA système seules, et pin-set du serveur de
 * règles quand l'hôte et les empreintes sont fournis. Généré parce que l'hôte et les empreintes sont des propriétés
 * de build, comme les clés publiques des bundles.
 */
abstract class NetworkSecurityConfig : DefaultTask() {

    /** Hôte du serveur de règles ; vide : aucun pin-set. */
    @get:Input
    abstract val host: Property<String>

    /** Empreintes SHA-256 (base64) des SubjectPublicKeyInfo admises dans la chaîne validée. */
    @get:Input
    abstract val pins: ListProperty<String>

    /** Date (AAAA-MM-JJ) après laquelle Android cesse d'appliquer les pins : une ancienne version reste à jour. */
    @get:Input
    abstract val expiration: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val file = outputDir.get().dir("xml").file("network_security_config.xml").asFile
        file.parentFile.mkdirs()
        file.writeText(xml(host.get(), pins.get(), expiration.get()))
    }

    companion object {
        fun xml(host: String, pins: List<String>, expiration: String): String = buildString {
            appendLine("""<?xml version="1.0" encoding="utf-8"?>""")
            appendLine("""<network-security-config>""")
            appendLine("""    <base-config cleartextTrafficPermitted="false">""")
            appendLine("""        <trust-anchors>""")
            appendLine("""            <certificates src="system" />""")
            appendLine("""        </trust-anchors>""")
            appendLine("""    </base-config>""")
            if (host.isNotEmpty() && pins.isNotEmpty()) {
                appendLine("""    <domain-config cleartextTrafficPermitted="false">""")
                appendLine("""        <domain includeSubdomains="false">$host</domain>""")
                appendLine("""        <pin-set expiration="$expiration">""")
                pins.forEach { appendLine("""            <pin digest="SHA-256">$it</pin>""") }
                appendLine("""        </pin-set>""")
                appendLine("""    </domain-config>""")
            }
            appendLine("""</network-security-config>""")
        }
    }
}
