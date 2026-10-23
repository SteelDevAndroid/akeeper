#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = akeeper_proto::ip::parse(data) {
        // La charge utile doit toujours rester une sous-tranche de l'entrée.
        assert!(packet.payload.len() <= data.len());
        let _ = packet.is_fragment();
    }
});
