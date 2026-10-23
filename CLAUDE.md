# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

aKeeper is a no-root Android firewall / DNS filter built on `VpnService` (local full-tunnel, no remote server). The repo currently contains **only the design spec**: `etude_technique_cybersecurite_android_mobileshield_2026-v2.md` (French). No Gradle project, sources or Rust crate exist yet. That spec is the source of truth. Part I corrects earlier assumptions, Part II is the implementation spec with reference code for `build.gradle.kts`, the manifest, XML configs, the `vpn/` and `security/` classes and their tests. Scaffold from it rather than inventing structure, and update the spec when a design decision changes. `docs/preconisation-initialisation.md` refines the spec for the bootstrap: module split, Gradle/Cargo setup, CI, milestones, and the deviations from the spec still to approve (the Rust `FlowTable` as the single flow cache, a fixed binary rule envelope with an FST payload). Package is `com.akeeper` (lowercase, approved).

License: GPL-3.0. `.gitignore` is the standard Android Studio one (keystores and `google-services.json` are ignored).

## Planned build and test commands (once scaffolded)

From the spec: Gradle Kotlin DSL, a single `app` module, namespace/applicationId `com.akeeper`, Java 21, and JUnit 5 (`useJUnitPlatform()`) with Mockito and AssertJ.

```bash
./gradlew assembleDebug
./gradlew :app:testDebugUnitTest
./gradlew :app:testDebugUnitTest --tests 'com.akeeper.vpn.FlowOwnerResolverTest'
```

The native engine (Rust, through JNI) must be linked with `-C link-arg=-Wl,-z,max-page-size=16384`. CI checks 16 KB alignment with `zipalign -c -P 16 -v 4 <apk>` and `llvm-readelf -l` (every `LOAD` segment aligned ≥ 0x4000). Parser fuzzing uses `cargo-fuzz` in a nightly CI job.

## Architecture (Part II §4)

```
TUN (10.111.0.1/32, fd00:6d73::1/128, routes 0.0.0.0/0 + ::/0)
 └─ PacketEngine (Rust/JNI): L3/L4 parser · DnsResolverLocal (10.111.0.53 / fd00:6d73::53)
    · FlowTable (5-tuple → UID, verdict, bounded LRU) · SniExtractor (TLS ClientHello + QUIC Initial)
    · Forwarder (protect()'d sockets, userspace TCP proxy, UDP NAT)
Java: ShieldVpnService · FlowOwnerResolver · RuleRepository (Room+SQLCipher) · RuleUpdater (WorkManager)
```

Java packages: `com.akeeper.vpn` (`ShieldVpnService`, `ShieldPolicy` record, `LockdownStatus` record, `FlowOwnerResolver`) and `com.akeeper.security` (`AdvancedProtectionPolicy`).

## Non-negotiable design constraints

These come from the spec. Breaking any of them is a security regression.

- **minSdk = targetSdk = 36 (Android 16).** Do not add version guards or compatibility branches.
- **FGS type is `systemExempted`.** No `vpn` FGS type exists. Do not add a `BOOT_COMPLETED` receiver: Always-on VPN restarts the service.
- **Fail-closed is the OS's job** (Always-on + Lockdown, or MDM `setAlwaysOnVpnPackage(..., true, ...)`). The app only detects it (`isAlwaysOn()` / `isLockdownEnabled()`) and alerts. Do not claim app-side fail-closed.
- **Never** call `allowBypass()` or `allowFamily()`, and never exclude the app itself via `addDisallowedApplication`. Use `protect()` on outgoing sockets. Always route `::/0` explicitly.
- LAN `excludeRoute()` is opt-in, off by default, and forbidden while Advanced Protection Mode is on (`ShieldPolicy.hardened()` is forced then).
- **No TLS MITM.** Evasion handling (§6): DNAT stray port-53 traffic to the local resolver, RST TCP/853 to the virtual DNS IP, NODATA for DNS type 65 (kills ECH), NXDOMAIN for `use-application-dns.net`, ICMP unreachable for UDP/443 (forces QUIC to fall back to TCP), a signed DoH IP/SNI blocklist.
- `getConnectionOwnerUid()` needs no permission, only the active VPN role. Cache results per 5-tuple. Keep the Binder call **outside** the cache lock (see `FlowOwnerResolver`).
- Components are non-exported, `PendingIntent.FLAG_IMMUTABLE`, receivers `RECEIVER_NOT_EXPORTED`, and a received `Intent` is never re-launched as-is.
- Storage (§7): Room + SQLCipher with a key wrapped by Keystore AES-GCM (StrongBox first, TEE fallback). Preferences use DataStore + Tink AEAD. **Do not use `EncryptedSharedPreferences`** (deprecated).
- Rule bundles are protobuf signed with **Ed25519** (two embedded public keys for rotation), carry a monotonic version (anti-rollback) and are activated atomically (temp file → verify → rename). Never use HMAC.
- `allowBackup="false"` and `dataExtractionRules` exclude every domain. Flow logs keep metadata only, use UIDs, and are retained ≤ 7 days.
- Native engine: Rust, no `unsafe` outside FFI, errors as `Result`, never `panic` on the network path, strict size limits.

## Code conventions (from the spec's reference code)

- Java 21 idioms: `record` for value types (`ShieldPolicy`, `LockdownStatus`, `FlowKey`), `final` classes, `var`, constructor injection of system services so classes stay unit-testable with Mockito.
- Tests use JUnit 5, `@ExtendWith(MockitoExtension.class)` and AssertJ `assertThat`.
- Code comments are short, in French, and only state why something is done (concurrency, Play or security rationale).

The spec closes with points to recheck against official docs before release: `systemExempted` eligibility, the exact `AdvancedProtectionManager` API and permission, local-network-access restrictions, and current Play requirements.
