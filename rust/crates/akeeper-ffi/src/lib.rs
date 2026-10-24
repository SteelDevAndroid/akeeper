//! Points d'entrée JNI de `com.akeeper.engine.NativeEngine`.
//! Hors `nativeStart` (qui reçoit l'hôte Java), seuls des scalaires traversent la frontière.

use std::ffi::c_void;
use std::io::Read;
use std::net::UdpSocket;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

use akeeper_engine::{
    Blocklist, BundleRules, CategoryMask, Config, Counter, Engine, Filter, Host, SharedHost,
};
use jni::objects::{GlobalRef, JClass as JniClass, JIntArray, JObject, JValue};
use jni::{JNIEnv, JavaVM};

type JniEnv = c_void;
type JClass = c_void;
type JInt = i32;
type JLong = i64;

/// Prend possession de `tun_fd`, `blocklist_fd` et `bundle_fd` (détachés côté Java ; -1 = absent) et renvoie un
/// handle opaque, ou 0 en cas d'échec (liste personnelle illisible comprise ; un bundle illisible est ignoré).
/// Les fd sont fermés dans tous les cas. `categories` : un bit par catégorie du bundle laissée active.
/// `host` implémente `NativeEngine.Host` ; une référence globale est conservée jusqu'à `nativeStop`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JniClass<'local>,
    tun_fd: JInt,
    blocklist_fd: JInt,
    bundle_fd: JInt,
    categories: JInt,
    host: JObject<'local>,
) -> JLong {
    let tun = owned(tun_fd);
    let rules = RuleSources::new(blocklist_fd, bundle_fd, categories);
    let (Some(tun), Some(host)) = (tun, JavaHost::new(&mut env, &host)) else {
        return 0;
    };
    catch_unwind(AssertUnwindSafe(|| start(tun, rules, Arc::new(host)))).unwrap_or(0)
}

/// `NativeEngine.Host` rappelé depuis le thread moteur, attaché une fois pour toutes à la JVM.
struct JavaHost {
    vm: JavaVM,
    host: GlobalRef,
}

impl JavaHost {
    fn new(env: &mut JNIEnv<'_>, host: &JObject<'_>) -> Option<Self> {
        if host.is_null() {
            return None;
        }
        Some(Self {
            vm: env.get_java_vm().ok()?,
            host: env.new_global_ref(host).ok()?,
        })
    }

    /// Le thread moteur ne revient jamais en Java : sans cadre local, chaque référence locale fuirait.
    fn call<T>(&self, default: T, f: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>) -> T {
        // Attachement permanent : un attach/detach par appel coûterait plus cher que l'appel lui-même.
        let Ok(mut env) = self.vm.attach_current_thread_permanently() else {
            return default;
        };
        let result = env.with_local_frame(8, |env| f(env));
        // Une exception Java laissée pendante ferait échouer tout appel JNI suivant sur ce thread.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result.unwrap_or(default)
    }
}

impl Host for JavaHost {
    fn protect(&self, fd: RawFd) -> bool {
        self.call(false, |env| {
            env.call_method(&self.host, "protect", "(I)Z", &[JValue::Int(fd)])?
                .z()
        })
    }

    fn owner_uid(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        let uid = self.call(-1, |env| {
            let local_ip = env.byte_array_from_slice(&ip_bytes(local.ip()))?;
            let remote_ip = env.byte_array_from_slice(&ip_bytes(remote.ip()))?;
            env.call_method(
                &self.host,
                "ownerUid",
                "(I[BI[BI)I",
                &[
                    JValue::Int(JInt::from(protocol)),
                    JValue::Object(&local_ip),
                    JValue::Int(JInt::from(local.port())),
                    JValue::Object(&remote_ip),
                    JValue::Int(JInt::from(remote.port())),
                ],
            )?
            .i()
        });
        u32::try_from(uid).ok()
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Remplace la liste des UID privés d'Internet. Renvoie 0 si accepté, -1 sinon.
///
/// # Safety
/// `handle` vient de `nativeStart` et n'a pas encore été passé à `nativeStop` (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeSetBlockedUids<'local>(
    env: JNIEnv<'local>,
    _class: JniClass<'local>,
    handle: JLong,
    uids: JIntArray<'local>,
) -> JInt {
    // SAFETY: contrat de la fonction ; lecture seule via &Engine.
    let Some(engine) = (unsafe { (handle as *const Engine).as_ref() }) else {
        return -1;
    };
    let Ok(len) = env.get_array_length(&uids) else {
        return -1;
    };
    let mut values = vec![0; usize::try_from(len).unwrap_or(0)];
    if env.get_int_array_region(&uids, 0, &mut values).is_err() {
        return -1;
    }
    let uids = values.into_iter().filter_map(|u| u32::try_from(u).ok());
    match catch_unwind(AssertUnwindSafe(|| engine.set_blocked_uids(uids))) {
        Ok(Ok(())) => 0,
        _ => -1,
    }
}

/// Remplace les règles (liste personnelle et bundle signé, -1 = absent). Le filtre est construit sur le thread
/// appelant. Renvoie 0 si accepté, -1 sinon : les règles en place restent alors actives. Les fd sont fermés.
///
/// # Safety
/// `handle` vient de `nativeStart` et n'a pas encore été passé à `nativeStop` (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeSetRules(
    _env: *mut JniEnv,
    _class: *mut JClass,
    handle: JLong,
    blocklist_fd: JInt,
    bundle_fd: JInt,
    categories: JInt,
) -> JInt {
    let rules = RuleSources::new(blocklist_fd, bundle_fd, categories);
    // SAFETY: contrat de la fonction ; lecture seule via &Engine.
    let Some(engine) = (unsafe { (handle as *const Engine).as_ref() }) else {
        return -1;
    };
    let applied = catch_unwind(AssertUnwindSafe(|| {
        let filter = load_filter(rules)?;
        engine.set_filter(filter)
    }));
    match applied {
        Ok(Ok(())) => 0,
        _ => -1,
    }
}

/// Suspend les blocages pour `millis` (plafonné par le moteur) ; `millis` <= 0 les rétablit aussitôt.
/// Renvoie 0 si accepté, -1 sinon.
///
/// # Safety
/// `handle` vient de `nativeStart` et n'a pas encore été passé à `nativeStop` (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativePause(
    _env: *mut JniEnv,
    _class: *mut JClass,
    handle: JLong,
    millis: JLong,
) -> JInt {
    // SAFETY: contrat de la fonction ; lecture seule via &Engine.
    let Some(engine) = (unsafe { (handle as *const Engine).as_ref() }) else {
        return -1;
    };
    let result = catch_unwind(AssertUnwindSafe(|| match u64::try_from(millis) {
        Ok(ms) if ms > 0 => engine.pause(Duration::from_millis(ms)),
        _ => engine.resume(),
    }));
    match result {
        Ok(Ok(())) => 0,
        _ => -1,
    }
}

fn owned(fd: JInt) -> Option<OwnedFd> {
    // SAFETY: Java a appelé ParcelFileDescriptor.detachFd() : un fd positif est ouvert et n'a plus d'autre propriétaire.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Règles à charger : liste personnelle, bundle, et catégories du bundle laissées actives.
struct RuleSources {
    personal: Option<OwnedFd>,
    bundle: Option<OwnedFd>,
    categories: CategoryMask,
}

impl RuleSources {
    fn new(personal_fd: JInt, bundle_fd: JInt, categories: JInt) -> Self {
        Self {
            personal: owned(personal_fd),
            bundle: owned(bundle_fd),
            // Les bits d'un entier signé Java : -1 active tout.
            categories: CategoryMask::from_bits(categories as u32),
        }
    }
}

fn start(tun: OwnedFd, rules: RuleSources, host: SharedHost) -> JLong {
    if set_nonblocking(&tun).is_err() {
        return 0;
    }
    let Ok(personal) = read_personal(rules.personal) else {
        return 0;
    };
    // Bundle signé mais illisible (défaut du pipeline) : le plancher anti-rollback empêche d'en revenir, donc
    // refuser de démarrer couperait la protection jusqu'au bundle suivant. Le moteur démarre sans lui.
    let bundle = read_bundle(rules.bundle, rules.categories).unwrap_or(None);
    let filter = Filter::new(personal.0, bundle).with_allowed(personal.1);
    match Engine::start(tun, Config { filter, host }) {
        Ok(engine) => Box::into_raw(Box::new(engine)) as JLong,
        Err(_) => 0,
    }
}

fn load_filter(rules: RuleSources) -> std::io::Result<Filter> {
    // Les deux fd sont lus avant tout échec : chacun est fermé quoi qu'il arrive.
    let (personal, bundle) = (
        read_personal(rules.personal),
        read_bundle(rules.bundle, rules.categories),
    );
    let (blocked, allowed) = personal?;
    Ok(Filter::new(blocked, bundle?).with_allowed(allowed))
}

/// `(bloqués, exceptions)` de la liste personnelle.
fn read_personal(fd: Option<OwnedFd>) -> std::io::Result<(Blocklist, Blocklist)> {
    let Some(fd) = fd else {
        return Ok((Blocklist::empty(), Blocklist::empty()));
    };
    let text = read_bounded(fd, MAX_BLOCKLIST_BYTES)?;
    Ok(Blocklist::personal(&String::from_utf8_lossy(&text)))
}

fn read_bundle(
    fd: Option<OwnedFd>,
    categories: CategoryMask,
) -> std::io::Result<Option<BundleRules>> {
    let Some(fd) = fd else {
        return Ok(None);
    };
    let bytes = read_bounded(fd, MAX_BUNDLE_BYTES)?;
    BundleRules::parse(&bytes, categories)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
}

// Bornes mémoire : un fichier au-delà est refusé plutôt que tronqué silencieusement.
const MAX_BLOCKLIST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = akeeper_engine::MAX_BUNDLE as u64;

fn read_bounded(fd: OwnedFd, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
    }
    Ok(bytes)
}

fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` appartient à `fd`, emprunté pendant tout l'appel ; F_GETFL/F_SETFL n'ont pas d'autre effet.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: idem ci-dessus.
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Renvoie -1 pour un handle nul ou un compteur inconnu.
///
/// # Safety
/// `handle` vient de `nativeStart` et n'a pas encore été passé à `nativeStop` (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeCounter(
    _env: *mut JniEnv,
    _class: *mut JClass,
    handle: JLong,
    counter: JInt,
) -> JLong {
    // SAFETY: contrat de la fonction ; lecture seule via &Engine.
    let Some(engine) = (unsafe { (handle as *const Engine).as_ref() }) else {
        return -1;
    };
    Counter::from_index(counter).map_or(-1, |c| {
        JLong::try_from(engine.stats().get(c)).unwrap_or(JLong::MAX)
    })
}

/// Confie au moteur un socket UDP connecté au DNS amont et protégé ; `fd` = -1 vide le slot.
/// Renvoie 0 si accepté, -1 sinon (le fd est fermé dans tous les cas).
///
/// # Safety
/// `handle` vient de `nativeStart` et n'a pas encore été passé à `nativeStop` (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeSetUpstream(
    _env: *mut JniEnv,
    _class: *mut JClass,
    handle: JLong,
    slot: JInt,
    fd: JInt,
) -> JInt {
    let socket = owned(fd).map(UdpSocket::from);
    // SAFETY: contrat de la fonction ; lecture seule via &Engine.
    let Some(engine) = (unsafe { (handle as *const Engine).as_ref() }) else {
        return -1;
    };
    let Ok(slot) = usize::try_from(slot) else {
        return -1;
    };
    match catch_unwind(AssertUnwindSafe(|| engine.set_upstream(slot, socket))) {
        Ok(Ok(())) => 0,
        _ => -1,
    }
}

/// # Safety
/// `handle` vient de `nativeStart` et n'est passé qu'une fois ici (garanti par le verrou Java).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeStop(
    _env: *mut JniEnv,
    _class: *mut JClass,
    handle: JLong,
) {
    let ptr = handle as *mut Engine;
    if ptr.is_null() {
        return;
    }
    // SAFETY: contrat de la fonction ; la Box est reprise une seule fois puis détruite.
    let engine = unsafe { Box::from_raw(ptr) };
    // Un échec d'arrêt n'a pas de traitement côté Java : le fd est fermé quoi qu'il arrive.
    let _ = catch_unwind(AssertUnwindSafe(|| engine.stop()));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::ptr::null_mut;
    use std::time::{Duration, Instant};

    struct AllowAll;

    impl Host for AllowAll {
        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn owner_uid(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }
    }

    fn start_with(tun: OwnedFd, blocklist: Option<OwnedFd>) -> JLong {
        super::start(tun, sources(blocklist, None), Arc::new(AllowAll))
    }

    fn sources(personal: Option<OwnedFd>, bundle: Option<OwnedFd>) -> RuleSources {
        RuleSources {
            personal,
            bundle,
            categories: CategoryMask::ALL,
        }
    }

    fn pipe_with(bytes: &[u8]) -> OwnedFd {
        let (reader, mut writer) = std::io::pipe().unwrap();
        std::io::Write::write_all(&mut writer, bytes).unwrap();
        OwnedFd::from(reader)
    }

    fn bundle(version: u64) -> Vec<u8> {
        use akeeper_proto::bundle::{self, Section, category, kind};
        let ads = Blocklist::from_domains("tracker.example");
        let sections = [Section {
            kind: kind::DOMAINS,
            category: category::ADS,
            data: ads.as_bytes(),
        }];
        let mut bytes = bundle::signed_message(0, version, 0, &sections).unwrap();
        bytes.extend_from_slice(&[0; bundle::SIGNATURE_LEN]);
        bytes
    }

    fn set_rules(handle: JLong, blocklist: JInt, bundle: JInt) -> JInt {
        // SAFETY: les tests n'appellent set_rules qu'avec 0 ou un handle pas encore arrêté.
        unsafe {
            Java_com_akeeper_engine_NativeEngine_nativeSetRules(
                null_mut(),
                null_mut(),
                handle,
                blocklist,
                bundle,
                -1,
            )
        }
    }

    fn set_upstream(handle: JLong, slot: JInt, fd: JInt) -> JInt {
        // SAFETY: les tests n'appellent set_upstream qu'avec 0 ou un handle pas encore arrêté.
        unsafe {
            Java_com_akeeper_engine_NativeEngine_nativeSetUpstream(
                null_mut(),
                null_mut(),
                handle,
                slot,
                fd,
            )
        }
    }

    fn counter(handle: JLong, index: JInt) -> JLong {
        // SAFETY: les tests n'appellent counter qu'avec 0 ou un handle pas encore arrêté.
        unsafe {
            Java_com_akeeper_engine_NativeEngine_nativeCounter(
                null_mut(),
                null_mut(),
                handle,
                index,
            )
        }
    }

    fn stop(handle: JLong) {
        // SAFETY: les tests arrêtent chaque handle une seule fois (0 est accepté).
        unsafe { Java_com_akeeper_engine_NativeEngine_nativeStop(null_mut(), null_mut(), handle) }
    }

    #[test]
    fn start_count_stop_round_trip() {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        let handle = start_with(OwnedFd::from(engine_side), None);
        assert_ne!(handle, 0);

        app.send(&[0x45]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while counter(handle, Counter::Malformed as JInt) < 1 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(counter(handle, 99), -1);

        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(set_upstream(handle, 0, upstream.into_raw_fd()), 0);
        let rejected = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(set_upstream(handle, 4, rejected.into_raw_fd()), -1);
        assert_eq!(set_upstream(handle, -1, -1), -1);
        stop(handle);
    }

    #[test]
    fn loads_blocklist_from_fd() {
        let (app, engine_side) = UnixDatagram::pair().unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        std::io::Write::write_all(&mut writer, b"ads.example.net\n").unwrap();
        drop(writer);
        let handle = start_with(OwnedFd::from(engine_side), Some(OwnedFd::from(reader)));
        assert_ne!(handle, 0);
        drop(app);
        stop(handle);
    }

    #[test]
    fn loads_bundle_and_replaces_rules() {
        let (_app, engine_side) = UnixDatagram::pair().unwrap();
        let handle = super::start(
            OwnedFd::from(engine_side),
            sources(None, Some(pipe_with(&bundle(3)))),
            Arc::new(AllowAll),
        );
        assert_ne!(handle, 0);
        assert_eq!(
            set_rules(
                handle,
                pipe_with(b"ads.example.net\n").into_raw_fd(),
                pipe_with(&bundle(4)).into_raw_fd()
            ),
            0
        );
        assert_eq!(
            set_rules(handle, -1, pipe_with(b"AKRB garbage").into_raw_fd()),
            -1
        );
        assert_eq!(set_rules(handle, -1, -1), 0);
        stop(handle);
    }

    #[test]
    fn starts_without_an_unreadable_bundle() {
        let (_app, engine_side) = UnixDatagram::pair().unwrap();
        let handle = super::start(
            OwnedFd::from(engine_side),
            sources(None, Some(pipe_with(b"AKRB garbage"))),
            Arc::new(AllowAll),
        );
        assert_ne!(handle, 0);
        stop(handle);
    }

    #[test]
    fn pauses_and_resumes() {
        let (_app, engine_side) = UnixDatagram::pair().unwrap();
        let handle = start_with(OwnedFd::from(engine_side), None);
        let pause = |millis| {
            // SAFETY: les tests n'appellent pause qu'avec 0 ou un handle pas encore arrêté.
            unsafe {
                Java_com_akeeper_engine_NativeEngine_nativePause(
                    null_mut(),
                    null_mut(),
                    handle,
                    millis,
                )
            }
        };
        assert_eq!(pause(60_000), 0);
        assert_eq!(pause(0), 0);
        assert_eq!(pause(-5), 0);
        stop(handle);
    }

    #[test]
    fn rejects_null_handle() {
        assert_eq!(counter(0, 0), -1);
        assert_eq!(set_upstream(0, 0, -1), -1);
        assert_eq!(set_rules(0, -1, -1), -1);
        // SAFETY: un handle nul est refusé avant tout accès.
        let paused = unsafe {
            Java_com_akeeper_engine_NativeEngine_nativePause(null_mut(), null_mut(), 0, 1)
        };
        assert_eq!(paused, -1);
        stop(0);
    }
}
