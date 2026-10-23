Projet d'application ANdroid : aKeeper
| **Cible plateforme** | **minSdk 36 (Android 16)** · targetSdk 36 · compileSdk = dernière API stable · matrice de tests Android 16 → 17 |

> **Décision de cadrage** : le plancher Android 16 supprime toutes les branches de compatibilité (API 29/31/33/34/35 garanties) et permet de s'appuyer sans repli sur : types FGS obligatoires, `isLockdownEnabled()`, `excludeRoute()`, Private DNS DoH natif, Private Space, alignement mémoire 16 KB, Advanced Protection Mode. **Contrepartie : base installée réduite** (cf. §2, risque R-01).


## 1. Corrections des affirmations

| # | Affirmation initiale | Verdict | Correction |
|---|---|---|---|
| 1 | « Il faut utiliser le type FGS dédié VPN » | ❌ Faux | **Aucun type `vpn` n'existe.** Type correct : `systemExempted` (prérequis runtime : l'app est le VPN actif, consentement `VpnService.prepare()` accordé) + permission `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`. Repli : `specialUse` avec justification Play Console. |
| 2 | « Rejet Google Play instantané » | ⚠️ Imprécis | Le filtre réel est la **politique Play VpnService** : formulaire de déclaration, VPN = fonctionnalité principale (catégorie *device security / firewall* admise), divulgation explicite. |
| 3 | « VpnService coupé sans bascule fail-closed → fuite » | ⚠️ Mal posé | **Une app morte ne bascule rien.** Le fail-closed est exclusivement OS : *Always-on VPN* + *Block connections without VPN* (lockdown), activé par l'utilisateur ou par MDM (`DevicePolicyManager.setAlwaysOnVpnPackage(..., lockdown = true, ...)`). L'app **détecte** (`isAlwaysOn()` / `isLockdownEnabled()`) et alerte. |
| 4 | « Doze coupe le VpnService » | ⚠️ Partiel | Doze ne tue pas un VPN établi (service lié par le système via `BIND_VPN_SERVICE`). Risques réels : surcouches OEM (HyperOS, ColorOS, One UI *Deep sleeping apps*), `onRevoke()` (autre VPN), crash du moteur natif. |
| 5 | « Android 13+ utilise par défaut Private DNS DoH/DoT » | ❌ Inexact | DoT depuis Android 9, **mode automatique (opportuniste)** par défaut. DoH (Android 13+) uniquement en mode **strict** vers des fournisseurs reconnus. |
| 6 | « Capturer spécifiquement le port 853 » | ⚠️ Mal posé | VpnService route **par IP**, pas par port. En full-tunnel le 853 arrive déjà dans le TUN ; le traitement est en userspace : **RST TCP/853** vers l'IP DNS virtuelle ⇒ repli clair en mode auto. Mode strict ⇒ DNS opaque : blocage + alerte. |
| 7 | ECH amalgamé avec DoH | ❌ Confusion | ECH chiffre le **SNI**, pas le DNS. Sa configuration est distribuée par l'enregistrement **HTTPS/SVCB (type 65)** ⇒ le résolveur local répond **NODATA** au type 65 ⇒ ClientHello classique, SNI filtrable. |
| 8 | « Absence de gestion QUIC dégrade les performances » | ⚠️ Inversé | Bloquer UDP/443 **est** la stratégie standard : repli TCP/TLS transparent. Le SNI d'un paquet *Initial* QUIC est lisible sans MITM (clés Initial dérivées du DCID, RFC 9001 §5.2). |
| 9 | « `getConnectionOwnerUid()` nécessite des permissions spécifiques » | ❌ Faux | Aucune permission ; il faut être **le VPN actif** (sinon `SecurityException`). Coût = un appel Binder par **nouveau flux**, absorbé par cache LRU 5-tuple. |
| 10 | Attribution « Moyenne » jugée optimiste | ⚠️ Sur-correction | **Bonne** pour TCP/UDP, **faible** pour DNS (émis par le résolveur système) ⇒ corrélation DNS → IP → flux. UID partagés non attribuables. |
| 11 | `/proc/net` bloqué par SELinux depuis Android 10 | ✅ Correct | — |
| 12 | « EncryptedSharedPreferences » | ❌ Obsolète | `androidx.security:security-crypto` est **déprécié** ⇒ DataStore + **Tink** (AEAD), clé maîtresse Keystore (StrongBox si disponible). |
| 13 | « Chiffrement opportuniste » | ❌ Terme faux | Terme réseau. Ici : **chiffrement au repos**. |
| 14 | « Clés HMAC » pour l'intégrité des règles | ❌ Erreur de conception | Secret symétrique sur l'appareil = extractible ⇒ règles forgeables. **Signature asymétrique Ed25519**, clé publique embarquée, version monotone anti-rollback. |
| 15 | « Sauvegardes ADB » | ⚠️ Daté | `adb backup` désactivé par défaut (target ≥ 31). Risque réel : **Auto Backup cloud** et **device-to-device transfer** ⇒ `allowBackup="false"` + `dataExtractionRules` excluant tout. |
| 16 | Cible API 31+ (Android 12–16) | ⚠️ Révisé | **Plancher porté à API 36** : suppression des chemins de compatibilité, surface de test réduite, garanties homogènes (cf. §0 Partie II). |

## 2. Lacunes non couvertes

- **Politique Play VpnService** : déclaration, `isVpnApp`, divulgation in-app, Data Safety. Premier risque projet.
- **Profils séparés** : le VPN du profil personnel ne couvre ni le **profil professionnel**, ni le **Private Space**, ni le **trafic de tethering**.
- **Un seul VPN actif** : conflit avec VPN d'entreprise ou grand public ; `onRevoke()` à traiter.
- **`allowBypass()` / `allowFamily()`** : interdits. Router explicitement `::/0` (réseaux IPv6-only / 464XLAT).
- **Boucle de routage** : sockets sortants via `protect()` ; ne pas s'auto-exclure par `addDisallowedApplication` (canal de contournement).
- **DoH applicatif** : Chrome Secure DNS, Firefox TRR ⇒ blocklist IP/SNI signée + canari `use-application-dns.net` → NXDOMAIN.
- **Moteur natif** : parsing de paquets hostiles = surface d'attaque n°1 ⇒ Rust, fuzzing continu, binaires **alignés 16 KB**.
- **Modèle de menace** absent (STRIDE, typologie d'attaquants).
- **Spécificités Android 16+ non exploitées** : Advanced Protection Mode, durcissement des intents, quotas JobScheduler révisés, contraintes d'accès réseau local en cours d'introduction (cf. Partie II §0).

---

# Partie II — Spécification révisée (Android 16+)

## 0. Impact du plancher Android 16 (API 36)

| Fonctionnalité / contrainte | Introduite | Conséquence avec minSdk 36 |
|---|---|---|
| `getConnectionOwnerUid()` | API 29 | Disponible sans garde de version |
| `isAlwaysOn()` / `isLockdownEnabled()` | API 29 | Détection fail-closed systématique |
| `dataExtractionRules`, fin d'`adb backup` | API 31 | Configuration unique, plus de `fullBackupContent` legacy nécessaire (conservé à `false` par défense en profondeur) |
| `Builder.excludeRoute()` | API 33 | Exclusion LAN propre (ex. `192.168.0.0/16`) au lieu du découpage manuel de routes |
| Private DNS DoH natif | API 33 | Toujours présent ⇒ gestion du mode strict obligatoire |
| Types FGS obligatoires | API 34 | `systemExempted` déclaré au manifeste et à `startForeground()` |
| Export explicite des receivers dynamiques | API 34 | `RECEIVER_NOT_EXPORTED` systématique |
| Restrictions FGS au `BOOT_COMPLETED` | API 35 | Ne pas démarrer le service au boot : **Always-on VPN démarre le service lui-même** |
| Private Space | API 35 | Hors couverture, à afficher |
| Pages mémoire 16 KB | Exigence Play (target ≥ 35) | Toutes les `.so` alignées 16 KB, vérifié en CI |
| Advanced Protection Mode (`AdvancedProtectionManager`) | API 36 | Lecture de l'état pour durcir la politique par défaut (cf. §8) |
| Durcissement de la redirection d'intents | API 36 | Aucun `Intent` reçu n'est relancé tel quel ; composants non exportés |
| Quotas JobScheduler révisés | API 36 | Le watchdog `WorkManager` peut être différé : il est complémentaire, jamais la seule garde |
| Protection de l'accès au réseau local | Opt-in API 36, renforcement attendu ensuite | Tester l'impact sur les sockets `protect()` vers le LAN ; **à revalider à chaque version majeure** |

## 1. Synthèse exécutive

aKeeper est réalisable sans root via `VpnService` en **full-tunnel local**, sans serveur distant. Moteur hybride :

1. **Résolveur DNS local filtrant** ;
2. **Filtrage IP/port/SNI par flux**, attribué à l'UID ;
3. **Détection et neutralisation de l'évasion** (DoT, DoH, QUIC, ECH).

**L'inspection TLS par MITM est exclue** : CA utilisateur ignorées par les apps depuis Android 7, pinning généralisé, incompatibilité avec la politique Play et la vie privée.

## 2. Matrice de faisabilité et alignement sécurité

| Capacité | Faisabilité | Fiabilité | Risque principal | Décision |
|---|---|---|---|---|
| Filtrage DNS (UDP/TCP 53) | ✅ Élevée | Élevée | DoT strict, DoH applicatif | **Socle** |
| Neutralisation DoT (853) | ✅ Élevée | Élevée (mode auto) | Mode strict = DNS opaque | RST + alerte UI |
| Blocage DoH applicatif | ⚠️ Moyenne | Moyenne (fraîcheur de liste) | Nouveaux endpoints | Blocklist IP/SNI signée |
| Neutralisation ECH | ✅ Élevée | Élevée | ECH hors DNS (rare) | NODATA type 65 |
| QUIC / HTTP/3 | ✅ Élevée | Élevée | — | Blocage UDP/443 ⇒ repli TCP |
| Filtrage SNI (TLS + QUIC Initial) | ✅ Élevée | Élevée sans ECH | ECH, domain fronting | **Socle** |
| Attribution flux → app | ✅ Élevée | Bonne (TCP/UDP), faible (DNS) | UID partagés | Cache LRU 5-tuple |
| Pare-feu par app | ✅ Élevée | Élevée | Profils séparés | **Socle** |
| Fail-closed | ⚠️ Dépend OS | Élevée si lockdown | Lockdown non activé | Détection + onboarding bloquant |
| Exclusion LAN | ✅ Élevée | Élevée | Exfiltration vers LAN | `excludeRoute()` opt-in, désactivé par défaut |
| Inspection TLS (MITM) | ❌ Non viable | — | Play, pinning, vie privée | **Exclu** |
| Couverture profil pro / Private Space | ❌ Hors périmètre | — | Fausse impression de protection | Documenter + afficher |
| Survie OEM agressifs | ⚠️ Moyenne | Variable | Kill silencieux | Lockdown + watchdog + guide OEM |

**Risques projet**

| ID | Risque | Impact | Mitigation |
|---|---|---|---|
| R-01 | minSdk 36 ⇒ base installée réduite en 2026 | Commercial | Décision assumée (sécurité homogène) ; réévaluer un plancher API 35 si l'adoption l'exige |
| R-02 | Refus Play (politique VpnService) | Bloquant | Déclaration anticipée, divulgation in-app, aucune collecte distante par défaut |
| R-03 | Lockdown non activé par l'utilisateur | Fuite au crash | Onboarding bloquant + bannière persistante |
| R-04 | Évolution des restrictions réseau local | Régression fonctionnelle | Tests sur chaque bêta Android |

## 3. Modèle de menace (STRIDE résumé)

| Attaquant | Vecteur | Contre-mesure |
|---|---|---|
| App locale malveillante | DoH/DoT, QUIC, IP en dur, ECH | §6 + filtrage IP par UID |
| App locale malveillante | Lecture des données aKeeper | Sandbox, chiffrement Keystore/Tink, aucun composant exporté hors service VPN protégé |
| App locale malveillante | Redirection d'intent / abus de composant | Composants non exportés, `PendingIntent.FLAG_IMMUTABLE`, receivers `RECEIVER_NOT_EXPORTED` |
| Réseau hostile (Wi-Fi) | Falsification des mises à jour de règles | Signature Ed25519 + version monotone + TLS 1.3 |
| Backend compromis | Push de règles malveillantes | Clé de signature hors ligne (HSM), double validation, anti-rollback |
| Accès physique | Extraction de données | Chiffrement au repos, pas de backup, rétention ≤ 7 jours |
| Paquets hostiles | Exploitation du parseur natif | Rust, fuzzing, limites de taille strictes, pas de `unsafe` hors FFI |
| Utilisateur / OEM | Kill du service ⇒ fuite | Lockdown OS, watchdog, alerte persistante |

## 4. Architecture

```
TUN (10.111.0.1/32, fd00:6d73::1/128, routes 0.0.0.0/0 et ::/0)
 └─ PacketEngine (Rust, JNI, .so alignées 16 KB)
     ├─ Parser L3/L4 (IPv4/IPv6/TCP/UDP/ICMP) ── fuzzé en continu
     ├─ DnsResolverLocal (10.111.0.53 / fd00:6d73::53) ── blocklists, NODATA type 65, canari DoH
     ├─ FlowTable (5-tuple → UID, verdict) ── LRU borné
     ├─ SniExtractor (TLS ClientHello + QUIC Initial)
     └─ Forwarder (sockets protect(), proxy TCP userspace, NAT UDP)
Java (Android)
 ├─ ShieldVpnService (cycle de vie, FGS systemExempted, onRevoke)
 ├─ FlowOwnerResolver (getConnectionOwnerUid + cache)
 ├─ RuleRepository (Room + SQLCipher, clé enveloppée Keystore)
 └─ RuleUpdater (WorkManager, vérification de signature avant activation atomique)
```

## 5. Spécification d'implémentation

### `app/build.gradle.kts`

```kotlin
android {
    namespace = "com.aKeeper"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.aKeeper"
        minSdk = 36
        targetSdk = 36
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        // Les .so non compressées et alignées 16 KB sont exigées par Play.
        jniLibs { useLegacyPackaging = false }
    }

    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation("org.mockito:mockito-junit-jupiter:5.14.2")
    testImplementation("org.assertj:assertj-core:3.27.3")
}
```

> Côté Rust : `-C link-arg=-Wl,-z,max-page-size=16384` ; vérification CI via `zipalign -c -P 16 -v 4` et `llvm-readelf -l` (alignement des segments `LOAD` ≥ 0x4000).

### `AndroidManifest.xml`

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.QUERY_ADVANCED_PROTECTION_MODE" />

    <application
        android:allowBackup="false"
        android:fullBackupContent="false"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="@string/app_name">

        <service
            android:name=".vpn.ShieldVpnService"
            android:exported="false"
            android:foregroundServiceType="systemExempted"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
            <meta-data
                android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON"
                android:value="true" />
        </service>
    </application>
</manifest>
```

> Aucun receiver `BOOT_COMPLETED` : sur Android 15+ le démarrage de FGS au boot est restreint ; c'est Always-on VPN qui relance le service.

### `res/xml/data_extraction_rules.xml`

```xml
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" />
        <exclude domain="file" />
        <exclude domain="database" />
        <exclude domain="sharedpref" />
        <exclude domain="external" />
    </device-transfer>
</data-extraction-rules>
```

### `res/xml/network_security_config.xml`

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">rules.aKeeper.example</domain>
        <pin-set expiration="2027-10-01">
            <!-- Clé publique de l'intermédiaire + clé de secours ; l'intégrité des règles repose sur Ed25519, pas sur ce pin. -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### `vpn/ShieldVpnService.java`

```java
package com.aKeeper.vpn;

import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.atomic.AtomicReference;

public final class ShieldVpnService extends VpnService {

    private static final int NOTIFICATION_ID = 1;
    private static final int FLOW_CACHE_SIZE = 4096;

    private final AtomicReference<ParcelFileDescriptor> tun = new AtomicReference<>();
    private final AtomicReference<PacketEngine> engine = new AtomicReference<>();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // systemExempted exige que le consentement VpnService.prepare() soit déjà accordé, sinon SecurityException.
        startForeground(NOTIFICATION_ID, ShieldNotifications.persistent(this),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        if (tun.get() == null) {
            establishTunnel(PolicyStore.current(this));
        }
        LockdownStatusBus.publish(new LockdownStatus(isAlwaysOn(), isLockdownEnabled()));
        return START_STICKY;
    }

    private void establishTunnel(ShieldPolicy policy) {
        // allowBypass() et allowFamily() sont proscrits : ils ouvrent un canal de fuite hors tunnel.
        var builder = new Builder()
                .setSession("aKeeper")
                .setMtu(1500)
                .addAddress("10.111.0.1", 32)
                .addAddress("fd00:6d73::1", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("10.111.0.53")
                .addDnsServer("fd00:6d73::53")
                .setBlocking(true)
                .setMetered(false)
                .setUnderlyingNetworks(null);

        // Exclusion LAN désactivée par défaut : le trafic LAN échapperait au filtrage (exfiltration possible).
        if (policy.allowLanBypass()) {
            policy.lanRoutes().forEach(builder::excludeRoute);
        }

        var fd = builder.establish();
        if (fd == null) {
            stopSelf();
            return;
        }
        tun.set(fd);
        var resolver = new FlowOwnerResolver(getSystemService(ConnectivityManager.class), FLOW_CACHE_SIZE);
        var newEngine = new PacketEngine(fd, this::protect, resolver, policy);
        engine.set(newEngine);
        newEngine.start();
    }

    @Override
    public void onRevoke() {
        // Un autre VPN a pris la main : sans lockdown, le trafic sort en clair immédiatement.
        LockdownStatusBus.publish(LockdownStatus.REVOKED);
        shutdown();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    private void shutdown() {
        var currentEngine = engine.getAndSet(null);
        if (currentEngine != null) {
            currentEngine.stop();
        }
        var fd = tun.getAndSet(null);
        if (fd != null) {
            try {
                fd.close();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
```

### `vpn/ShieldPolicy.java`

```java
package com.aKeeper.vpn;

import android.net.IpPrefix;

import java.util.List;

public record ShieldPolicy(boolean allowLanBypass, List<IpPrefix> lanRoutes, boolean strictMode) {

    public ShieldPolicy {
        lanRoutes = List.copyOf(lanRoutes);
    }

    public static ShieldPolicy hardened() {
        return new ShieldPolicy(false, List.of(), true);
    }
}
```

### `vpn/LockdownStatus.java`

```java
package com.aKeeper.vpn;

public record LockdownStatus(boolean alwaysOn, boolean lockdown, boolean revoked) {

    public static final LockdownStatus REVOKED = new LockdownStatus(false, false, true);

    public LockdownStatus(boolean alwaysOn, boolean lockdown) {
        this(alwaysOn, lockdown, false);
    }

    public boolean failClosed() {
        return alwaysOn && lockdown && !revoked;
    }
}
```

### `vpn/FlowOwnerResolver.java`

```java
package com.aKeeper.vpn;

import android.net.ConnectivityManager;

import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;

public final class FlowOwnerResolver {

    static final int INVALID_UID = -1;

    public record FlowKey(int protocol, InetSocketAddress local, InetSocketAddress remote) {
        public FlowKey {
            Objects.requireNonNull(local);
            Objects.requireNonNull(remote);
        }
    }

    private final ConnectivityManager connectivityManager;
    private final Map<FlowKey, Integer> cache;

    public FlowOwnerResolver(ConnectivityManager connectivityManager, int maxEntries) {
        this.connectivityManager = connectivityManager;
        this.cache = new LinkedHashMap<>(maxEntries, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<FlowKey, Integer> eldest) {
                return size() > maxEntries;
            }
        };
    }

    // LinkedHashMap en ordre d'accès n'est pas thread-safe ; l'appel Binder reste hors verrou pour ne pas sérialiser les nouveaux flux.
    public OptionalInt resolve(FlowKey key) {
        synchronized (cache) {
            var cached = cache.get(key);
            if (cached != null) {
                return OptionalInt.of(cached);
            }
        }
        int uid;
        try {
            uid = connectivityManager.getConnectionOwnerUid(key.protocol(), key.local(), key.remote());
        } catch (SecurityException notActiveVpn) {
            return OptionalInt.empty();
        }
        if (uid == INVALID_UID) {
            return OptionalInt.empty();
        }
        synchronized (cache) {
            cache.put(key, uid);
        }
        return OptionalInt.of(uid);
    }

    public void evict(FlowKey key) {
        synchronized (cache) {
            cache.remove(key);
        }
    }
}
```

### `security/AdvancedProtectionPolicy.java`

```java
package com.aKeeper.security;

import android.content.Context;
import android.security.advancedprotection.AdvancedProtectionManager;

import com.aKeeper.vpn.ShieldPolicy;

public final class AdvancedProtectionPolicy {

    private final AdvancedProtectionManager manager;

    public AdvancedProtectionPolicy(Context context) {
        this.manager = context.getSystemService(AdvancedProtectionManager.class);
    }

    // Si l'utilisateur a activé Advanced Protection (Android 16), aucune option de relâchement n'est proposée.
    public ShieldPolicy effective(ShieldPolicy userPolicy) {
        if (manager != null && manager.isAdvancedProtectionEnabled()) {
            return ShieldPolicy.hardened();
        }
        return userPolicy;
    }
}
```

### `test/.../FlowOwnerResolverTest.java`

```java
package com.aKeeper.vpn;

import android.net.ConnectivityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FlowOwnerResolverTest {

    private static final int TCP = 6;

    @Mock
    private ConnectivityManager connectivityManager;

    private FlowOwnerResolver resolver;

    private final FlowOwnerResolver.FlowKey key = new FlowOwnerResolver.FlowKey(
            TCP,
            InetSocketAddress.createUnresolved("10.111.0.1", 40000),
            InetSocketAddress.createUnresolved("93.184.216.34", 443));

    @BeforeEach
    void setUp() {
        resolver = new FlowOwnerResolver(connectivityManager, 2);
    }

    @Test
    void resolvesOnceThenServesFromCache() {
        when(connectivityManager.getConnectionOwnerUid(TCP, key.local(), key.remote())).thenReturn(10123);

        assertThat(resolver.resolve(key)).hasValue(10123);
        assertThat(resolver.resolve(key)).hasValue(10123);

        verify(connectivityManager, times(1)).getConnectionOwnerUid(anyInt(), any(), any());
    }

    @Test
    void invalidUidIsNotCached() {
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenReturn(FlowOwnerResolver.INVALID_UID);

        assertThat(resolver.resolve(key)).isEmpty();
        assertThat(resolver.resolve(key)).isEmpty();

        verify(connectivityManager, times(2)).getConnectionOwnerUid(anyInt(), any(), any());
    }

    @Test
    void securityExceptionWhenNotActiveVpnYieldsEmpty() {
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenThrow(new SecurityException());

        assertThat(resolver.resolve(key)).isEmpty();
    }

    @Test
    void evictsLeastRecentlyUsedBeyondCapacity() {
        var k2 = new FlowOwnerResolver.FlowKey(TCP, key.local(), InetSocketAddress.createUnresolved("1.1.1.1", 443));
        var k3 = new FlowOwnerResolver.FlowKey(TCP, key.local(), InetSocketAddress.createUnresolved("8.8.8.8", 443));
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenReturn(10001);

        resolver.resolve(key);
        resolver.resolve(k2);
        resolver.resolve(k3);
        resolver.resolve(key);

        verify(connectivityManager, times(4)).getConnectionOwnerUid(anyInt(), any(), any());
    }
}
```

### `test/.../LockdownStatusTest.java`

```java
package com.aKeeper.vpn;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LockdownStatusTest {

    @Test
    void failClosedOnlyWithAlwaysOnAndLockdown() {
        assertThat(new LockdownStatus(true, true).failClosed()).isTrue();
        assertThat(new LockdownStatus(true, false).failClosed()).isFalse();
        assertThat(new LockdownStatus(false, true).failClosed()).isFalse();
    }

    @Test
    void revokedIsNeverFailClosed() {
        assertThat(LockdownStatus.REVOKED.failClosed()).isFalse();
    }
}
```

## 6. Politique anti-évasion (moteur)

| Trafic | Action | Justification |
|---|---|---|
| UDP/TCP 53 → `10.111.0.53` | Résolution locale filtrée | Socle |
| UDP/TCP 53 → autre IP | DNAT vers le résolveur local | DNS codé en dur |
| TCP/853 → IP DNS virtuelle | RST | Repli Private DNS auto vers 53 |
| TCP/853 → autre IP | Blocage + événement « Private DNS strict » | DNS opaque |
| DNS type 65 (HTTPS/SVCB) | NODATA | Supprime ECH et l'indice h3 |
| `use-application-dns.net` | NXDOMAIN | Désactive le DoH par défaut de Firefox |
| TCP/443 → IP blocklist DoH (signée) | Blocage | Chrome Secure DNS, apps DoH |
| UDP/443 | ICMP port unreachable | Repli QUIC → TCP, SNI visible |
| LAN (RFC 1918 / ULA) | Filtré par défaut ; `excludeRoute()` uniquement si opt-in hors Advanced Protection | Anti-exfiltration |
| UDP autre, UID non autorisé | Politique par app | Pare-feu |

## 7. Stockage et cryptographie

- **Room + SQLCipher** : clé 256 bits aléatoire, **enveloppée** par une clé AES-GCM Keystore (`setIsStrongBoxBacked(true)` avec repli TEE) ; jamais persistée en clair.
- **Préférences** : DataStore + Tink `Aead`, keyset protégé par Keystore (EncryptedSharedPreferences déprécié).
- **Règles** : bundle protobuf signé **Ed25519**, deux clés publiques embarquées (rotation), `version` monotone persistée (anti-rollback), activation atomique (temporaire → vérification → `rename`).
- **Journaux** : métadonnées de flux ≤ 7 jours, UID plutôt que nom de paquet, aucun contenu ; purge `WorkManager`.
- **Backend** : TLS 1.3, pas de CA utilisateur, pinning intermédiaire + secours ; Play Integrity API vérifiée côté serveur.
- **Attestation de clé** : vérification côté serveur de l'attestation Keystore avant tout enrôlement MDM.

## 8. Résilience et fail-closed

1. **Onboarding bloquant** vers `Settings.ACTION_VPN_SETTINGS` (Always-on + Lockdown), vérifié par `isLockdownEnabled()`.
2. **Flotte MDM** : Device Owner / profil géré, `setAlwaysOnVpnPackage(admin, pkg, true, allowlist)`.
3. **Advanced Protection Mode** (Android 16) actif ⇒ `ShieldPolicy.hardened()` forcée, options de relâchement masquées.
4. **Watchdog `WorkManager`** (15 min, soumis aux quotas JobScheduler d'Android 16 ⇒ garde secondaire) : VPN inactif sans révocation ⇒ notification haute priorité.
5. **Guide OEM** (Xiaomi, Samsung, Oppo/OnePlus, Vivo, Honor) : autostart, exclusion *Deep sleeping apps*. `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` uniquement avec justification Play.
6. **Moteur natif** : erreurs en `Result`, jamais de `panic` sur le chemin réseau ; crash JNI ⇒ redémarrage + alerte. `ApplicationStartInfo` / `ApplicationExitInfo` exploités pour diagnostiquer les kills OEM.

## 9. Conformité Google Play et vie privée

- Formulaire **VpnService** (catégorie *device security / firewall*), aucun serveur distant, divulgation in-app avant `prepare()`.
- Déclaration FGS `systemExempted` dans la Play Console.
- targetSdk 36 (exigence Play en vigueur), `.so` alignées 16 KB.
- **Data Safety** : historique de navigation déclaré dès qu'un journal de domaines existe, même local.
- **RGPD** : traitement local par défaut ; télémétrie opt-in, agrégée, inscrite au registre.

## 10. Limites assumées (affichées dans l'app)

- Non couverts : profil professionnel, Private Space, tethering, apps système à UID partagé.
- Private DNS strict ⇒ filtrage DNS impossible, utilisateur alerté.
- Sans lockdown, la protection n'est pas garantie si le service s'arrête.
- Aucun déchiffrement de contenu TLS.
- Appareils < Android 16 non supportés.

## 11. Plan de validation

| Test | Outil / méthode | Critère |
|---|---|---|
| Fuite au kill (lockdown on / off) | `adb shell am force-stop` + tcpdump passerelle | 0 paquet hors tunnel avec lockdown |
| DoT auto / strict | Réglages Private DNS + capture | Repli 53 / alerte « strict » |
| ECH | `chrome://net-internals`, sites de test ECH | ECH non négocié |
| QUIC | Chrome + YouTube, capture UDP/443 | 0 flux QUIC établi |
| IPv6-only (464XLAT) | Réseau opérateur v6-only / émulateur | Connectivité OK, 0 fuite v6 |
| `onRevoke` | Activation d'un second VPN | État « révoqué » affiché |
| Advanced Protection Mode | Activation sur Pixel Android 16 | Politique durcie forcée |
| Exclusion LAN | Opt-in on/off, trafic vers `192.168.x.x` | Filtré par défaut |
| Alignement 16 KB | `zipalign -c -P 16`, émulateur 16 KB | Démarrage OK |
| Robustesse parseur | cargo-fuzz 24 h en CI nightly | 0 crash |
| OEM | Firebase Test Lab + appareils Xiaomi/Samsung | Survie > 72 h sous Doze |
| Rollback de règles | Bundle N-1 signé injecté | Rejeté |
| Bêta Android suivante | Programme bêta Android | Pas de régression (accès réseau local, FGS) |

---

*Points à revalider sur la documentation officielle avant diffusion : conditions d'éligibilité `systemExempted`, API `AdvancedProtectionManager` (permission et signature exactes), statut des restrictions d'accès au réseau local, exigences Play en vigueur (target SDK, 16 KB, formulaire VpnService).*
