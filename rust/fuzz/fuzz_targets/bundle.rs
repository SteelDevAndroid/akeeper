#![no_main]

use akeeper_proto::bundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = bundle::parse(data) {
        // Les sections et la signature restent dans les bornes de l'entrée.
        assert_eq!(envelope.signed.len() + envelope.signature.len(), data.len());
        for section in &envelope.sections {
            let _ = bundle::cidrs(section.data);
        }
    }
});
