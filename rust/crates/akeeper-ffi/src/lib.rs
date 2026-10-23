//! Points d'entrée JNI de `com.akeeper.engine.NativeEngine`.
//! Seuls des scalaires traversent la frontière : aucun objet Java n'est manipulé côté natif.

use std::ffi::c_void;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};

use akeeper_engine::{Counter, Engine};

type JniEnv = c_void;
type JClass = c_void;
type JInt = i32;
type JLong = i64;

/// Prend possession de `tun_fd` (détaché côté Java) et renvoie un handle opaque, ou 0 en cas d'échec.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_akeeper_engine_NativeEngine_nativeStart(
    _env: *mut JniEnv,
    _class: *mut JClass,
    tun_fd: JInt,
) -> JLong {
    if tun_fd < 0 {
        return 0;
    }
    // SAFETY: Java a appelé ParcelFileDescriptor.detachFd() : ce fd est ouvert et n'a plus d'autre propriétaire.
    let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    catch_unwind(AssertUnwindSafe(|| start(tun))).unwrap_or(0)
}

fn start(tun: OwnedFd) -> JLong {
    if set_nonblocking(&tun).is_err() {
        return 0;
    }
    match Engine::start(tun) {
        Ok(engine) => Box::into_raw(Box::new(engine)) as JLong,
        Err(_) => 0,
    }
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
        Java_com_akeeper_engine_NativeEngine_nativeStart(null_mut(), null_mut(), fd)
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
        stop(handle);
    }

    #[test]
    fn rejects_invalid_fd_and_null_handle() {
        assert_eq!(start(-1), 0);
        assert_eq!(counter(0, 0), -1);
        stop(0);
    }
}
