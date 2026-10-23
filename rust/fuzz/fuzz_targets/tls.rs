#![no_main]

use akeeper_proto::tls::{self, Sni};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Sni::Host(host)) = tls::client_hello_sni(data) {
        // Le nom extrait reste ASCII imprimable, borné et en minuscules.
        assert!(host.len() <= 253 && host.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
    }
});
