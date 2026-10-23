# aKeeper — Préconisation technique d'initialisation

Complément à `etude_technique_cybersecurite_android_mobileshield_2026-v2.md`. L'objectif est d'organiser le projet selon les fonctions à livrer (DNS filtrant, pare-feu par app, anti-évasion, règles signées, fail-closed) et de placer les optimisations là où se trouve le coût réel : le chemin paquet.

## Avancement

**J0 livré** : chaîne de build Java + Rust, CI, contrôle 16 KB et fuzzing. Écarts avec ce document, volontaires pour ne livrer aucun code mort :

- Modules `:app`, `:vpn` et `:engine` seulement. `:rules` et `:storage` arrivent en J5, avec leur contenu.
- Le contrat JNI se limite pour l'instant à `nativeStart(fd)`, `nativeCounter(handle, index)` et `nativeStop(handle)`, sans aucun objet Java. `Host` (`protect`, `ownerUid`, `onEvents`) arrive en J1 avec le résolveur DNS, `reloadRules` en J5.
- Le moteur compte puis abandonne chaque paquet : rien ne ressort du tunnel tant qu'aucun verdict n'existe.
- Versions retenues : AGP 9.4.1, Gradle 9.8.1, NDK 30.0.16248370, JUnit 5.14.4, Mockito 5.24.0, AssertJ 3.27.7, Material 1.14.0. Le Kotlin intégré d'AGP 9 est désactivé (modules 100 % Java).
- L'audit `cargo-deny` n'est pas encore dans la CI : il faut d'abord écrire sa politique (`deny.toml`).

**J1 livré (VPN DNS seul)** : moteur (résolveur filtrant), service et onboarding + accueil. Écarts et points ouverts :

- **Résolveurs amont** : Java crée et protège un socket UDP connecté par serveur DNS du réseau sous-jacent, puis le cède au moteur (`setUpstream`). Le moteur n'a donc pas besoin de rappeler Java pour `protect()` : le `Host` JNI reste reporté à J2, où chaque flux sortant devra être protégé.
- **Liste de blocage** : en J1, c'est un simple fichier texte (`filesDir/blocklist.txt`) transformé en FST au démarrage. Il n'existe encore ni liste par défaut ni écran pour l'éditer : les catégories arrivent avec les bundles signés (J5) et l'écran avec R2. Le texte de divulgation O1 promet donc plus que J1 ne fait.
- **Pas encore livrés** : l'écran O6 (guide OEM), la pause, l'alerte « DNS privé strict » (J4) et les compteurs « aujourd'hui ». L'accueil affiche les compteurs depuis le démarrage du moteur.
- **À valider sur appareil**, faute d'émulateur dans l'environnement de build :
  - le comportement du verrouillage (*Bloquer les connexions sans VPN*) avec des routes limitées au résolveur. Si Android bloque alors tout le trafic hors tunnel, l'étape O4 bloquante doit attendre le tunnel complet (J2) ;
  - le repli rapide de Private DNS « automatique » grâce au RST TCP.

**J2 livré (tunnel complet)** :
- **Routes** : `0.0.0.0/0` et `::/0`.
- **TCP** : terminaison en espace utilisateur (smoltcp, `any_ip`) et relais par sockets protégés. Pas de MITM.
- **UDP** : NAT protégé.
- **DNS** : tout DNS en clair est intercepté (DNAT vers le résolveur local).
- **QUIC et DoQ** : refusés par ICMP « port inaccessible ».
- **DoT** : RST vers tout serveur.
- **`protect()`** : il passe par un rappel JNI vers `NativeEngine.Host`. Un socket que le système refuse de protéger n'émet jamais.

Écarts et limites :
- **Réseau local** : pas d'exclusion LAN, l'option opt-in (R1) n'existe pas encore, et `AdvancedProtectionPolicy` n'est donc pas encore branchée. Tout le LAN passe par le filtre, ce qui reste le comportement par défaut voulu.
- **Fragments IPv4** : abandonnés, au risque de casser de rares protocoles UDP qui envoient des datagrammes de plus de 1 472 octets.
- **DNS/TCP vers le résolveur** : réinitialisé. Une réponse DNS tronquée en UDP échoue donc au lieu de se replier sur TCP.
- **ICMP** : ni relayé ni répondu, donc `ping` ne fonctionne pas.
- **Sans attribution** : attribution UID et pare-feu par app viennent en J3.
- **Non validé sur appareil**, faute d'émulateur dans l'environnement de build :
  - débit, latence et consommation batterie du relais ;
  - comportement avec le verrouillage, désormais sans objet pour le trafic hors tunnel puisque tout est routé ;
  - réseaux IPv6 seuls et 464XLAT ;
  - survie sous Doze.
- **Rappel JNI `protect()`** : non testé hors appareil, les tests Rust injectent un `Protector` en mémoire.

Les extraits de code ci-dessous restent la cible. Le code du dépôt fait foi pour l'état courant.

## 1. Décisions structurantes

| Sujet | Choix | Gain |
|---|---|---|
| I/O TUN | Le fd est détaché (`ParcelFileDescriptor.detachFd()`) et lu/écrit **uniquement en Rust** | Aucune copie Java ni JNI par paquet |
| Boucle moteur | Un seul thread `mio` (TUN + sockets), `FlowTable` sans verrou | Pas de contention ; latence prévisible |
| Attribution UID | Upcall JNI **une fois par flux**, sur un thread natif dédié attaché à la JVM une seule fois ; le premier paquet du flux est retenu jusqu'au verdict | L'appel Binder ne bloque jamais la boucle |
| Cache d'attribution | `FlowTable` Rust = **cache unique** (verdict + UID) | Supprime le doublon avec le LRU Java de `FlowOwnerResolver` |
| Pile TCP userspace | `smoltcp` | Pile éprouvée, sans `unsafe` côté appelant, buffers bornés |
| Blocklists domaines | **FST** (`fst` crate) sur les labels inversés (`com.example.ads`), mappé en mémoire | Recherche par suffixe en O(longueur), quelques Mo pour des millions d'entrées, aucun parsing au chargement |
| Blocklists IP (DoH) | Plages triées `u128`, recherche dichotomique | Même structure pour IPv4/IPv6 |
| Format du bundle de règles | Enveloppe binaire fixe + payload FST/plages, signature **Ed25519** | Parsing trivial à taille fixe (surface réduite), pas de protobuf côté Java |
| Événements / journaux | Ring buffer natif vidé chaque seconde vers Java (`ByteBuffer` direct), puis insertion Room **par lot** dans une transaction | Une écriture DB par seconde au lieu d'une par flux |
| Injection de dépendances | Racine de composition manuelle (`AppGraph` dans `Application`), injection par constructeur | Démarrage rapide, sans annotation processing |
| UI | Java + Views Material 3 | Code homogène avec la spec (Java 21) ; périmètre UI réduit |
| Package | **`com.akeeper`** (minuscules) | Convention Java ; `com.aKeeper` est source d'erreurs (casse des chemins) |

## 2. Découpage

```
akeeper/
├─ build-logic/                 convention plugin akeeper.android-library + tâche CargoNdkBuild
├─ app/                         UI, onboarding lockdown, AppGraph
├─ vpn/                         ShieldVpnService, ShieldPolicy, LockdownStatus, FlowOwnerResolver, AdvancedProtectionPolicy
├─ engine/                      ◄ module Android : NativeEngine (JNI) + intégration cargo
│   └─ (sources Rust à la racine : voir rust/)
├─ rules/                       enveloppe signée, vérification Ed25519 (Tink), anti-rollback, activation atomique
├─ storage/                     Room + SQLCipher, préférences chiffrées (AtomicFile + Tink Aead), wrapping Keystore
└─ rust/
    ├─ Cargo.toml               workspace
    ├─ .cargo/config.toml       alignement 16 KB
    ├─ crates/akeeper-proto     parseurs purs : IPv4/IPv6/TCP/UDP, DNS, TLS ClientHello — sans I/O, fuzzés
    ├─ crates/akeeper-engine    FlowTable, politique, résolveur, forwarder smoltcp/mio, boucle
    ├─ crates/akeeper-ffi       seule crate autorisée à contenir de l'unsafe (JNI)
    └─ fuzz/                    cibles cargo-fuzz : packet, dns, sni
```

Toute la logique sans API Android (`ShieldPolicy`, `LockdownStatus`, enveloppe de règles, anti-rollback) se teste en JUnit 5 sur la JVM, sans émulateur.

## 3. Fichiers d'initialisation

### `settings.gradle.kts`

```kotlin
pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "akeeper"
include(":app", ":vpn", ":engine", ":rules", ":storage")
```

### `gradle/libs.versions.toml`

AGP 9.2.0 et Tink 1.23.0 viennent des docs officielles, SQLCipher 4.18.0 de l'annonce Zetetic (août 2026). Les autres versions sont à revérifier au moment de l'initialisation : ce catalogue est le seul endroit à modifier.

```toml
[versions]
agp = "9.2.0"
tink = "1.23.0"
sqlcipher = "4.18.0"
room = "2.7.2"
work = "2.10.2"
material = "1.13.0"
junit = "5.11.4"
mockito = "5.14.2"
assertj = "3.27.3"

[libraries]
android-gradle-plugin = { module = "com.android.tools.build:gradle", version.ref = "agp" }
tink-android = { module = "com.google.crypto.tink:tink-android", version.ref = "tink" }
sqlcipher-android = { module = "net.zetetic:sqlcipher-android", version.ref = "sqlcipher" }
room-runtime = { module = "androidx.room:room-runtime", version.ref = "room" }
room-compiler = { module = "androidx.room:room-compiler", version.ref = "room" }
work-runtime = { module = "androidx.work:work-runtime", version.ref = "work" }
material = { module = "com.google.android.material:material", version.ref = "material" }
junit-bom = { module = "org.junit:junit-bom", version.ref = "junit" }
junit-jupiter = { module = "org.junit.jupiter:junit-jupiter" }
junit-platform-launcher = { module = "org.junit.platform:junit-platform-launcher" }
mockito-junit-jupiter = { module = "org.mockito:mockito-junit-jupiter", version.ref = "mockito" }
assertj-core = { module = "org.assertj:assertj-core", version.ref = "assertj" }

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
android-library = { id = "com.android.library", version.ref = "agp" }
```

### `build-logic/settings.gradle.kts`

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    versionCatalogs {
        create("libs") { from(files("../gradle/libs.versions.toml")) }
    }
}

rootProject.name = "build-logic"
```

### `build-logic/build.gradle.kts`

```kotlin
plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.android.gradle.plugin)
}
```

### `build-logic/src/main/kotlin/akeeper.android-library.gradle.kts`

```kotlin
plugins {
    id("com.android.library")
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

android {
    compileSdk = 36
    defaultConfig { minSdk = 36 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

dependencies {
    "testImplementation"(platform(libs.findLibrary("junit-bom").get()))
    "testImplementation"(libs.findLibrary("junit-jupiter").get())
    "testImplementation"(libs.findLibrary("mockito-junit-jupiter").get())
    "testImplementation"(libs.findLibrary("assertj-core").get())
    // Gradle 9 ne fournit plus le launcher JUnit Platform implicitement.
    "testRuntimeOnly"(libs.findLibrary("junit-platform-launcher").get())
}
```

### `build-logic/src/main/kotlin/CargoNdkBuild.kt`

```kotlin
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
```

### `engine/build.gradle.kts`

```kotlin
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
```

### `engine/src/main/java/com/akeeper/engine/NativeEngine.java`

```java
package com.akeeper.engine;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

public final class NativeEngine implements AutoCloseable {

    static {
        System.loadLibrary("akeeper_ffi");
    }

    public interface Host {
        // Thread natif de la boucle : doit rester non bloquant.
        boolean protect(int fd);

        // Thread natif de résolution, une fois par nouveau flux ; INVALID_UID si inconnu.
        int ownerUid(int protocol, byte[] localAddr, int localPort, byte[] remoteAddr, int remotePort);

        // Lot d'événements sérialisés ; le buffer direct n'est valide que pendant l'appel.
        void onEvents(ByteBuffer batch);
    }

    // AtomicLong : close() peut venir d'onRevoke() et d'onDestroy() en concurrence ; un double free natif serait exploitable.
    private final AtomicLong handle;

    private NativeEngine(long handle) {
        this.handle = new AtomicLong(handle);
    }

    /** Le moteur prend possession de {@code detachedTunFd} et le ferme à l'arrêt. */
    public static NativeEngine start(int detachedTunFd, String rulesPath, Host host) {
        long h = nativeStart(detachedTunFd, rulesPath, host);
        if (h == 0) {
            throw new IllegalStateException("Démarrage du moteur natif impossible");
        }
        return new NativeEngine(h);
    }

    public void reloadRules(String rulesPath) {
        long h = handle.get();
        if (h != 0) {
            nativeReloadRules(h, rulesPath);
        }
    }

    @Override
    public void close() {
        long h = handle.getAndSet(0);
        if (h != 0) {
            nativeStop(h);
        }
    }

    private static native long nativeStart(int tunFd, String rulesPath, Host host);

    private static native void nativeReloadRules(long handle, String rulesPath);

    private static native void nativeStop(long handle);
}
```

> Côté Rust, `nativeReloadRules` envoie un message à la boucle, qui remplace l'`Arc` des règles entre deux itérations : aucun verrou sur le chemin paquet. Chaque point d'entrée JNI est enveloppé dans `catch_unwind`. Un panic est converti en événement « moteur arrêté » côté Java (redémarrage + alerte, spec §8) au lieu de tuer le processus.

### `rust/Cargo.toml`

```toml
[workspace]
resolver = "3"
members = ["crates/*"]

[workspace.package]
edition = "2024"
license = "GPL-3.0-or-later"

# akeeper-ffi ne reprend pas ces lints : c'est la seule crate où l'unsafe (JNI) est permis.
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
indexing_slicing = "deny"

[workspace.dependencies]
smoltcp = { version = "0.12", default-features = false, features = ["std", "medium-ip", "proto-ipv4", "proto-ipv6", "socket-tcp", "socket-udp"] }
mio = { version = "1", features = ["os-poll", "net"] }
etherparse = "0.18"
hickory-proto = { version = "0.25", default-features = false, features = ["std"] }
fst = "0.4"
memmap2 = "0.9"
lru = "0.16"
jni = "0.21"

[profile.release]
lto = "fat"
codegen-units = 1
# unwind (pas abort) : catch_unwind à la frontière FFI permet de redémarrer le moteur sans tuer l'app.
panic = "unwind"
debug = "line-tables-only"
```

`indexing_slicing = "deny"` impose `get()` partout dans les parseurs : sur des paquets hostiles, un index hors bornes devient un `None` et pas un panic.

### `rust/.cargo/config.toml`

```toml
[target.aarch64-linux-android]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384"]

[target.x86_64-linux-android]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384"]
```

### `scripts/check-16kb.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

apk="$1"
build_tools="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
"$build_tools/zipalign" -c -P 16 -v 4 "$apk" > /dev/null

readelf="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$apk" 'lib/*' -d "$tmp"

status=0
while IFS= read -r so; do
    while IFS= read -r align; do
        if (( align < 16384 )); then
            echo "Segment LOAD non aligné 16 KB ($align) : ${so#"$tmp"/}"
            status=1
        fi
    done < <("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }')
done < <(find "$tmp/lib" -name '*.so')
exit "$status"
```

### `.github/workflows/ci.yml`

```yaml
name: ci

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 2 * * *"

jobs:
  rust:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-24.04
    defaults:
      run:
        working-directory: rust
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          manifest-path: rust/Cargo.toml

  android:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-linux-android, x86_64-linux-android
      - run: echo "ANDROID_NDK_HOME=$ANDROID_NDK_LATEST_HOME" >> "$GITHUB_ENV"
      - run: cargo install cargo-ndk --locked
      - uses: gradle/actions/setup-gradle@v4
      - run: ./gradlew check :app:assembleRelease
      - run: scripts/check-16kb.sh app/build/outputs/apk/release/app-release-unsigned.apk

  fuzz:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        target: [packet, dns, sni]
    defaults:
      run:
        working-directory: rust
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz --locked
      # Runners hébergés limités à 6 h par job : 5 h 30 par cible.
      - run: cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=19800
```

## 4. Optimisations par fonction

| Fonction | Implémentation recommandée | Point de vigilance |
|---|---|---|
| Résolveur DNS local | Parsing `hickory-proto`, décision FST, cache de réponses LRU borné respectant le TTL, upstream via sockets `protect()` vers les DNS du réseau sous-jacent (transmis par Java depuis `LinkProperties`) | Rafraîchir les DNS upstream à chaque `onLinkPropertiesChanged` du réseau par défaut |
| NODATA type 65, canari DoH | Court-circuit avant toute requête upstream | — |
| Forwarding TCP | `smoltcp` : une socket par flux, buffers 32 KiB rx/tx, plafond de flux TCP simultanés (ex. 1024) | **Mémoire** : flux × (rx + tx). 4096 flux × 2 × 64 KiB = 512 MiB, d'où un plafond distinct de la taille du `FlowTable` |
| NAT UDP | Table par flux, timeout d'inactivité 60 s (5 s pour le DNS upstream) | Épuisement des fd : borne + éviction LRU |
| Attribution / pare-feu par app | Verdict calculé une fois par flux et mis en cache dans `FlowTable` ; tables d'autorisation par UID en `HashMap<u32, Verdict>` remplacée atomiquement à chaque modification UI | Flux en attente d'UID : file bornée, rejet si saturée |
| Anti-évasion (DNAT 53, RST 853, ICMP UDP/443) | Décidé au premier paquet, dans le parseur, sans allocation | — |
| SNI | Parseur ClientHello borné (taille max, `get()` partout) dans `akeeper-proto` | L'extraction du SNI QUIC Initial est **reportée** : UDP/443 est rejeté, donc inutile au MVP, et cela évite une surface crypto |
| Mise à jour des règles | `WorkManager` → téléchargement en fichier temporaire → vérification Ed25519 (Tink) + version > version persistée → `rename` atomique → `reloadRules()` | Clé publique et version minimale embarquées dans l'APK |
| Journaux | Lots horodatés en Room, index sur `ts`, purge quotidienne `DELETE WHERE ts < now − 7 j` | WAL activé ; aucune requête DB sur le thread du service |
| Cycle de vie VPN | `onStartCommand` : `startForeground` immédiatement, puis `establish()` et `NativeEngine.start` hors thread principal | Respecter le délai de `startForeground` ; `onRevoke` → `close()` idempotent |

## 5. Jalons

| # | Livrable | Valide |
|---|---|---|
| J0 | Squelette ci-dessus, CI verte, contrôle 16 KB, harnais de test instrumenté (API 36 en Gradle Managed Device ; consentement VPN accordé par `UiAutomation.executeShellCommand("appops set com.akeeper ACTIVATE_VPN allow")`) | Chaîne de build complète Java + Rust |
| J1 | **VPN DNS seul** : routes limitées à `10.111.0.53/32` et `fd00:6d73::53/128`, `addDnsServer`, résolveur filtrant FST, NODATA 65, canari ; détection lockdown, `onRevoke`, FGS. Fuzzing nightly actif dès ce jalon | Valeur utilisateur immédiate sans pile TCP ; cycle de vie et Play éprouvés tôt |
| J2 | Full-tunnel : `0.0.0.0/0` + `::/0`, `smoltcp`, NAT UDP, `protect()` | Fuite au kill, IPv6-only/464XLAT, débit et batterie mesurés |
| J3 | Attribution UID + pare-feu par app + UI | Exactitude d'attribution TCP/UDP |
| J4 | Anti-évasion complète (§6 de la spec) + SNI TLS | Plan de validation DoT/ECH/QUIC |
| J5 | Règles signées + mise à jour + stockage SQLCipher + journaux | Rejet du rollback, purge 7 jours |
| J6 | Durcissement : Advanced Protection, guide OEM, `ApplicationExitInfo`, dossier Play VpnService | Survie > 72 h sous Doze, conformité Play |

J1 sépare deux risques : le cycle de vie Android et la politique Play d'un côté, la pile réseau userspace de l'autre. Le premier est validé avant d'investir dans le second.

## 6. Écarts avec la spec à acter

1. ~~Package `com.akeeper` au lieu de `com.aKeeper`.~~ **Acté** : spec mise à jour.
2. ~~`FlowOwnerResolver` sans cache Java : c'est `FlowTable` (Rust) qui met en cache, une seule résolution par flux.~~ **Acté** : l'UID est rangé dans l'entrée de flux du moteur (`TcpStack`, `UdpNat`).
3. Préférences en `AtomicFile` + Tink `Aead` plutôt que DataStore, dont l'API coroutines est peu adaptée à une base Java.
4. Bundle de règles en enveloppe binaire fixe + FST, sans protobuf.
5. Extraction SNI QUIC Initial reportée après le MVP.
6. Fuzzing nightly à 5 h 30 par cible sur runners hébergés. Les 24 h prévues exigent un runner auto-hébergé ou ClusterFuzzLite.
