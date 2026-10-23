//! Points d'entrée JNI de `com.akeeper.engine.NativeEngine`.
//! Seuls des scalaires traversent la frontière : aucun objet Java n'est manipulé côté natif.

use std::ffi::c_void;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};

use std::io::Read;
use std::net::UdpSocket;

use akeeper_engine::{Blocklist, Counter, Engine};

type JniEnv = c_void;
type JClass = c_void;
type JInt = i32;
type JLong = i64;

/// Prend possession de `tun_fd` et de `blocklist_fd` (détachés côté Java ; -1 = liste vide)
/// et renvoie un handle opaque, ou 0 en cas d'échec. Les deux fd sont fermés dans tous les cas.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeStart(
    _env: *mut JniEnv,
    _class: *mut JClass,
    tun_fd: JInt,
    blocklist_fd: JInt,
) -> JLong {
    let tun = owned(tun_fd);
    let blocklist = owned(blocklist_fd);
    let Some(tun) = tun else {
        return 0;
    };
    catch_unwind(AssertUnwindSafe(|| start(tun, blocklist))).unwrap_or(0)
}

fn owned(fd: JInt) -> Option<OwnedFd> {
    // SAFETY: Java a appelé ParcelFileDescriptor.detachFd() : un fd positif est ouvert et n'a plus d'autre propriétaire.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn start(tun: OwnedFd, blocklist: Option<OwnedFd>) -> JLong {
    if set_nonblocking(&tun).is_err() {
        return 0;
    }
    let blocklist = match blocklist.map(read_blocklist).transpose() {
        Ok(list) => list.unwrap_or_else(Blocklist::empty),
        Err(_) => return 0,
    };
    match Engine::start(tun, blocklist) {
        Ok(engine) => Box::into_raw(Box::new(engine)) as JLong,
        Err(_) => 0,
    }
}

// Borne mémoire : une liste au-delà est refusée plutôt que tronquée silencieusement.
const MAX_BLOCKLIST_BYTES: u64 = 64 * 1024 * 1024;

fn read_blocklist(fd: OwnedFd) -> std::io::Result<Blocklist> {
    let mut text = String::new();
    std::fs::File::from(fd)
        .take(MAX_BLOCKLIST_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_BLOCKLIST_BYTES {
        return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
    }
    Ok(Blocklist::from_domains(&text))
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

    fn start(fd: JInt) -> JLong {
        Java_com_akeeper_engine_NativeEngine_nativeStart(null_mut(), null_mut(), fd, -1)
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
        let handle = start(engine_side.into_raw_fd());
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
        let handle = Java_com_akeeper_engine_NativeEngine_nativeStart(
            null_mut(),
            null_mut(),
            engine_side.into_raw_fd(),
            OwnedFd::from(reader).into_raw_fd(),
        );
        assert_ne!(handle, 0);
        drop(app);
        stop(handle);
    }

    #[test]
    fn rejects_invalid_fd_and_null_handle() {
        assert_eq!(start(-1), 0);
        assert_eq!(counter(0, 0), -1);
        assert_eq!(set_upstream(0, 0, -1), -1);
        stop(0);
    }
}
