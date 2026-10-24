# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

aKeeper is a no-root Android firewall / DNS filter built on `VpnService` (local full-tunnel, no remote server). Milestones J0 (build chain), J1 (DNS filtering), J2 (full tunnel) J3 (per-app firewall), J4 (SNI filtering, strict Private DNS alert) and J5 part 1 (signed rule bundles and updates) are in place. All milestones are listed in `docs/preconisation-initialisation.md` §5, and its "Avancement" section tracks what each delivered and deferred.

- `etude_technique_cybersecurite_android_mobileshield_2026-v2.md` (French) is the source of truth. Part I corrects earlier assumptions; Part II is the implementation spec. Update it when a design decision changes.
- `docs/preconisation-initialisation.md` refines it for the bootstrap. Approved deviations: the Rust flow tables (`TcpStack`, `UdpNat`) are the single attribution cache, and `FlowOwnerResolver` is a plain uncached call; rule bundles use a fixed binary envelope with FST payloads instead of protobuf (`docs/bundle-regles.md`).
- `docs/listes-de-blocage.md` evaluates the blocklist sources. Defaults: HaGeZi LIGHT + Phishing Army + URLhaus (abuse.ch agreement reported by the project owner). StevenBlack is excluded. The URLhaus Auth-Key is a server-side pipeline secret only. The plan is one prebuilt FST per category in the signed bundle.
- `docs/ui-ecrans.md` specifies the screens. Green/amber/red (`akeeper_state_*` in `app/src/main/res/values*/colors.xml`) are reserved for the protection status; never use them for errors, "blocked" verdicts or destructive actions.
- Package is `com.akeeper` (lowercase, approved).

Layout:
- `app/`: `ui.MainActivity`, the only Activity. It shows onboarding O1–O4, then the Home (A1) and Apps (A2) tabs and the Settings screen (R1), with no Fragments.
  - `AppsScreen` loads apps through `AppCatalog` on a worker thread. The list comes from `QUERY_ALL_PACKAGES` (approved, needs a Play declaration), filtered to apps requesting INTERNET.
  - Toggling an app writes `AppRules`; apps that share a UID are toggled together, because the engine blocks by UID.
  - `SettingsScreen` (R1) shows the rules version/date with an update-now button (only when `akeeper.rulesUrl` is set), the lockdown state, the battery guide for the OEMs in `OemGuide`, and R3 and Licences as dialogs. The Licences dialog shows the `NOTICE` of the verified active bundle. Settings with nothing behind them (LAN, logs, categories) are not shown yet.
  - The onboarding step is derived from system state by `OnboardingFlow` (VPN consent, notification permission, `LockdownStatus`); nothing is persisted except a `noBackupFilesDir/onboarding_done` marker.
  - The home state comes from `HomeState.of(ShieldStatus.Snapshot)`.
- `vpn/`:
  - `ShieldVpnService`: FGS `systemExempted`. It routes everything (`0.0.0.0/0` and `::/0`). There is no LAN exclusion yet, because the R1 opt-in doesn't exist.
  - `UpstreamDns`: follows the best non-VPN network and hands the engine one protected, connected UDP socket per DNS server (max 4).
  - `ShieldStatus`: lock-free state and counter holder observed by the UI.
  - `AppRules`: blocked package names in `noBackupFilesDir/app_rules.bin`, written atomically (temp file, fsync, rename) and encrypted with Tink AEAD. The keyset is wrapped by an Android Keystore key, and associated data binds the file to its purpose. This is the approved alternative to DataStore.
    - The service observes it and pushes UIDs to the engine via `setBlockedUids`.
    - An unreadable or tampered file yields no rules.
  - Also: the spec's `ShieldPolicy`, `LockdownStatus`, `FlowOwnerResolver` and `com.akeeper.security.AdvancedProtectionPolicy`.
- `rules/`: signed rule bundles (`docs/bundle-regles.md`).
  - `BundleVerifier` checks the envelope and the Ed25519 signature, with the key chosen by `key_id` among the keys of the `akeeper.rulePublicKeys` Gradle property. With no key, no bundle is accepted.
  - `RuleStore` keeps `noBackupFilesDir/rules/bundle.akrb` and a persistent anti-rollback floor, never below `akeeper.minRuleVersion`. Activation is atomic and requires a strictly newer version. `openActive()` re-verifies the file and hands the same descriptor to the engine.
  - `RuleUpdateWorker` runs every 12 h through WorkManager with a conditional GET on `akeeper.rulesUrl`; nothing is scheduled without a URL. The service schedules it and calls `NativeEngine.setRules` after each activation.
- `engine/`: `NativeEngine` (JNI). The `cargoNdk<Variant>` task builds `rust/` and feeds the `.so` to the variant's `jniLibs`.
- `rust/`:
  - `akeeper-proto`: pure bounded parsers and builders for IP, UDP, TCP, ICMP port-unreachable, DNS and the TLS ClientHello SNI.
  - `akeeper-engine`: mio loop, FST `Blocklist`, DNS `Resolver`, `UdpNat`, and `TcpStack` (smoltcp with `any_ip`, terminating app connections and relaying them over protected sockets; no MITM).
  - `akeeper-ffi`: the only crate allowed `unsafe`. `rust/fuzz/` is a separate nightly-only workspace with targets `packet`, `dns`, `transport`, `tls` and `bundle`.
  - `akeeper-bundle`: an off-device pipeline tool (`keygen`, `build`, `verify`), never shipped in the app. Its test and the Java tests check the same signed fixture, `rules/src/test/resources/com/akeeper/rules/fixture-v5.akrb`; regenerate it with `AKEEPER_WRITE_FIXTURE=1 cargo test -p akeeper-bundle`.
- `build-logic/`: convention plugins `akeeper.android-library` / `akeeper.android-application` (compileSdk/minSdk 36, Java 21, JUnit 5, pinned NDK) and the `CargoNdkBuild` task.

Engine verdicts (spec §6). Anything not listed is dropped (ICMP echo included):
- **UDP/53 to any IP**: answered by the local resolver, from that IP (DNAT).
  - NXDOMAIN for blocklisted names (subdomains included) and for `use-application-dns.net`;
  - NODATA for type 65 (HTTPS/SVCB);
  - SERVFAIL when there is no upstream;
  - everything else is forwarded with a random ID, and only answers whose ID **and** question match are relayed.
- **UDP/443 and UDP/853**: ICMP port unreachable, so QUIC and DoQ fall back to TCP.
- **Other UDP**: relayed by `UdpNat` over one protected, connected socket per (client, destination), with a 60 s idle timeout and a 1024-flow cap.
- **TCP to the resolver IPs and TCP/853 to any IP**: RST.
- **Names matched by `Filter`**: the personal blocklist, every domain category of the active bundle, and the bundle's DoH list. Without a bundle DoH list, the embedded fallback list of public DoH endpoints applies.
  - over DNS, answered NXDOMAIN;
  - in a TLS ClientHello SNI, the TCP flow is reset **before any byte is forwarded**: `TcpStack` holds the app's first bytes until `inspect` reaches a verdict.
  - A non-TLS stream, an unreadable ClientHello or one split across TLS records passes.
- **TCP/443 to a DoH resolver address from the bundle**: RST on the SYN, before any owner lookup or upstream socket (counted as `IpBlocked`).
- **TCP/853 to a third-party server** is counted as `DotBlocked`, a strict Private DNS signal. Detection itself comes from `LinkProperties.getPrivateDnsServerName()` in `UpstreamDns`, which raises `Snapshot.privateDnsStrict`, the amber home state and an alert notification.
- **Other TCP**: terminated by `TcpStack` and relayed over a protected socket. Caps: 512 flows, 64 KiB buffers. The upstream connect starts on the SYN; if it fails, the app gets a RST.
- **Per-app firewall**: a new flow from a blocked UID is refused: RST for TCP, ICMP port unreachable for UDP. `setBlockedUids` also cuts that UID's open flows. An unknown UID (-1) is allowed.
- **Never send through an unprotected socket**: if `protect()` returns false, the flow is refused (counted as `UdpNatFailures` / `TcpFailures`).
- **IPv4 fragments are dropped.**

The personal blocklist is `filesDir/blocklist.txt`, one domain per line, read at start and on each bundle activation; there is no UI for it yet.

JNI contract:
- `nativeStart(tunFd, blocklistFd, bundleFd, host)`, `nativeSetRules(handle, blocklistFd, bundleFd)`, `nativeSetUpstream(handle, slot, fd)`, `nativeSetBlockedUids(handle, int[])`, `nativeCounter(handle, index)`, `nativeStop(handle)`. The engine owns and closes every fd it is given (-1 means absent).
- An unreadable personal blocklist makes `nativeStart` fail. An unreadable bundle is skipped at start, because the anti-rollback floor would otherwise keep protection off until the next bundle; `nativeSetRules` returns -1 and keeps the current rules. The bundle fd must come from `RuleStore.openActive()`, because the engine does not check signatures.
- `host` is a `NativeEngine.Host` held as a global ref. The engine thread stays attached to the JVM and calls it: `protect(int)` per socket, and `ownerUid(...)` once per new flow (`FlowOwnerResolver`, uncached).
- Every callback runs inside a JNI local frame, because that thread never returns to Java and local refs would leak.
- The R8 keep rules are in `engine/consumer-rules.pro`.
- `NativeEngine` methods are `synchronized` so a call can't race `nativeStop` into a use-after-free.
- Keep `NativeEngine.Counter` and `akeeper_engine::Counter` in the same order (17 counters), and `NativeEngine.MAX_UPSTREAMS` equal to `akeeper_engine::MAX_UPSTREAMS`.

License: GPL-3.0.

## Commands

Prerequisites: JDK 21, Android SDK (platform 36) with `local.properties` or `ANDROID_HOME`, NDK `30.0.16248370` (the `ndk` version in `gradle/libs.versions.toml`), Rust stable with targets `aarch64-linux-android` and `x86_64-linux-android`, and `cargo install cargo-ndk`. Set `ANDROID_NDK_HOME` to that NDK.

```bash
./gradlew check :app:assembleRelease          # what CI runs: lint + JVM unit tests + release APK
./gradlew :vpn:testDebugUnitTest --tests 'com.akeeper.vpn.FlowOwnerResolverTest'
scripts/check-16kb.sh app/build/outputs/apk/release/app-release-unsigned.apk

cd rust
cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p akeeper-proto ip::tests::parses_ipv4_udp
cargo run -p akeeper-bundle -- verify bundle.akrb <key0 hex> [<key1 hex>]
cargo +nightly fuzz run packet -- -max_total_time=60
```

- **No emulator here**: this container has no KVM, so VPN behaviour is only covered by JVM and Rust tests. Validate on a device.
- **Lint `ForegroundServicePermission`**: it is suppressed on the service on purpose. Lint doesn't know the VPN runtime prerequisite of `systemExempted` and asks for exact-alarm permissions; don't add those.
- **AGP 9 Kotlin**: built-in Kotlin is disabled (`android.builtInKotlin=false`) because all modules are Java. Re-enable it only if Kotlin sources are added.
- **Rust lints**: `unwrap`, `expect`, `panic` and indexing/slicing are `deny`; use `get()` and `Result`. Tests opt out with `#[allow]`.
- **16 KB alignment**: the native `.so` files are linked with `-z max-page-size=16384` (`rust/.cargo/config.toml`). AGP strips them because `ndkVersion` is pinned.

## Architecture (Part II §4)

```
TUN (10.111.0.1/32, fd00:6d73::1/128, routes 0.0.0.0/0 + ::/0)
 └─ PacketEngine (Rust/JNI): L3/L4 parser · DnsResolverLocal (10.111.0.53 / fd00:6d73::53)
    · FlowTable (5-tuple → UID, verdict, bounded LRU) · SniExtractor (TLS ClientHello + QUIC Initial)
    · Forwarder (protect()'d sockets, userspace TCP proxy, UDP NAT)
Java: ShieldVpnService · FlowOwnerResolver · RuleRepository (Room+SQLCipher) · RuleUpdater (WorkManager)
```

Java packages: `com.akeeper.vpn` (`ShieldVpnService`, `ShieldPolicy` record, `LockdownStatus` record, `FlowOwnerResolver`), `com.akeeper.rules` (`BundleVerifier`, `RuleStore`, `RuleUpdateWorker`) and `com.akeeper.security` (`AdvancedProtectionPolicy`).

## Non-negotiable design constraints

These come from the spec. Breaking any of them is a security regression.

- **minSdk = targetSdk = 36 (Android 16).** Do not add version guards or compatibility branches.
- **FGS type is `systemExempted`.** No `vpn` FGS type exists. Do not add a `BOOT_COMPLETED` receiver: Always-on VPN restarts the service.
- **Fail-closed is the OS's job** (Always-on + Lockdown, or MDM `setAlwaysOnVpnPackage(..., true, ...)`). The app only detects it (`isAlwaysOn()` / `isLockdownEnabled()`) and alerts. Do not claim app-side fail-closed.
- **Never** call `allowBypass()` or `allowFamily()`, and never exclude the app itself via `addDisallowedApplication`. Use `protect()` on outgoing sockets. Always route `::/0` explicitly.
- LAN `excludeRoute()` is opt-in, off by default, and forbidden while Advanced Protection Mode is on (`ShieldPolicy.hardened()` is forced then).
- **No TLS MITM.** Evasion handling (§6): DNAT stray port-53 traffic to the local resolver, RST TCP/853 to the virtual DNS IP, NODATA for DNS type 65 (kills ECH), NXDOMAIN for `use-application-dns.net`, ICMP unreachable for UDP/443 (forces QUIC to fall back to TCP), a signed DoH IP/SNI blocklist.
- `getConnectionOwnerUid()` needs no permission, only the active VPN role. It is called once per new flow, from the engine thread; the UID is kept in the flow entry (approved deviation from the spec's Java LRU).
- Components are non-exported, `PendingIntent.FLAG_IMMUTABLE`, receivers `RECEIVER_NOT_EXPORTED`, and a received `Intent` is never re-launched as-is.
- Storage (§7): Room + SQLCipher with a key wrapped by Keystore AES-GCM (StrongBox first, TEE fallback). Preferences use an atomically written file + Tink AEAD (approved alternative to DataStore, see `AppRules`). **Do not use `EncryptedSharedPreferences`** (deprecated).
- Rule bundles use the fixed binary envelope (approved instead of protobuf), signed with **Ed25519** (two embedded public keys for rotation). They carry a monotonic version (anti-rollback, persistent floor) and are activated atomically (temp file → verify → rename). Never use HMAC, and never put a private key in the repository or the app.
- `allowBackup="false"` and `dataExtractionRules` exclude every domain. Flow logs keep metadata only, use UIDs, and are retained ≤ 7 days.
- Native engine: Rust, no `unsafe` outside FFI, errors as `Result`, never `panic` on the network path, strict size limits.

## Code conventions (from the spec's reference code)

- Java 21 idioms: `record` for value types (`ShieldPolicy`, `LockdownStatus`, `FlowKey`), `final` classes, `var`, constructor injection of system services so classes stay unit-testable with Mockito.
- Tests use JUnit 5, `@ExtendWith(MockitoExtension.class)` and AssertJ `assertThat`.
- Code comments are short, in French, and only state why something is done (concurrency, Play or security rationale).

The spec closes with points to recheck against official docs before release: `systemExempted` eligibility, the exact `AdvancedProtectionManager` API and permission, local-network-access restrictions, and current Play requirements.
