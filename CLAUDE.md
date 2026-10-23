# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

aKeeper is a no-root Android firewall / DNS filter built on `VpnService` (local full-tunnel, no remote server). Milestones J0 (build chain) and J1 (DNS-only VPN) are in place. All milestones are listed in `docs/preconisation-initialisation.md` §5, and its "Avancement" section tracks what each delivered and deferred.

- `etude_technique_cybersecurite_android_mobileshield_2026-v2.md` (French) is the source of truth. Part I corrects earlier assumptions; Part II is the implementation spec. Update it when a design decision changes.
- `docs/preconisation-initialisation.md` refines it for the bootstrap. Deviations still to approve: the Rust `FlowTable` as the single flow cache, and a fixed binary rule envelope with an FST payload instead of protobuf.
- `docs/ui-ecrans.md` specifies the screens. Green/amber/red (`akeeper_state_*` in `app/src/main/res/values*/colors.xml`) are reserved for the protection status; never use them for errors, "blocked" verdicts or destructive actions.
- Package is `com.akeeper` (lowercase, approved).

Layout:
- `app/`: `ui.MainActivity`, the only Activity. It shows onboarding O1–O4, then home A1, with no Fragments.
  - The onboarding step is derived from system state by `OnboardingFlow` (VPN consent, notification permission, `LockdownStatus`); nothing is persisted except a `noBackupFilesDir/onboarding_done` marker.
  - The home state comes from `HomeState.of(ShieldStatus.Snapshot)`.
- `vpn/`:
  - `ShieldVpnService`: FGS `systemExempted`. It routes **only** the resolver IPs (`10.111.0.53/32`, `fd00:6d73::53/128`) in J1; full tunnel arrives in J2.
  - `UpstreamDns`: follows the best non-VPN network and hands the engine one protected, connected UDP socket per DNS server (max 4).
  - `ShieldStatus`: lock-free state and counter holder observed by the UI.
  - Also: the spec's `ShieldPolicy`, `LockdownStatus`, `FlowOwnerResolver` and `com.akeeper.security.AdvancedProtectionPolicy`.
- `engine/`: `NativeEngine` (JNI). The `cargoNdk<Variant>` task builds `rust/` and feeds the `.so` to the variant's `jniLibs`.
- `rust/`: workspace `akeeper-proto` (pure bounded parsers and builders: IP, UDP, TCP RST, DNS), `akeeper-engine` (mio loop, FST `Blocklist`, DNS `Resolver`), `akeeper-ffi` (the only crate allowed `unsafe`). `rust/fuzz/` is a separate nightly-only workspace with targets `packet`, `dns` and `transport`.
- `build-logic/`: convention plugins `akeeper.android-library` / `akeeper.android-application` (compileSdk/minSdk 36, Java 21, JUnit 5, pinned NDK) and the `CargoNdkBuild` task.

Engine behaviour (J1) for traffic addressed to the resolver IPs:
- **UDP/53**:
  - NXDOMAIN for blocklisted names (subdomains included) and for `use-application-dns.net`;
  - NODATA for type 65 (HTTPS/SVCB);
  - SERVFAIL when there is no upstream;
  - everything else is forwarded with a random ID, and only answers whose ID **and** question match are relayed.
- **TCP**: RST, so Private DNS in "automatic" mode falls back to UDP/53 at once.
- **Everything else** is dropped.

The blocklist is `filesDir/blocklist.txt`, one domain per line, read once at start; there is no UI or default list yet.

JNI contract (scalars only, no Java objects cross):
- `nativeStart(tunFd, blocklistFd)`, `nativeSetUpstream(handle, slot, fd)`, `nativeCounter(handle, index)`, `nativeStop(handle)`. The engine owns and closes every fd it is given.
- `NativeEngine` methods are `synchronized` so a call can't race `nativeStop` into a use-after-free.
- Keep `NativeEngine.Counter` and `akeeper_engine::Counter` in the same order, and `NativeEngine.MAX_UPSTREAMS` equal to `akeeper_engine::MAX_UPSTREAMS`.

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
