#![no_main]

use akeeper_proto::dns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(query) = dns::parse_query(data) {
        let mut out = Vec::new();
        dns::negative_response(&query, dns::Rcode::NxDomain, &mut out);
        // La réponse construite doit être relisible et porter la même question.
        let (id, question) = dns::parse_response_key(&out).expect("réponse construite illisible");
        assert_eq!((id, question), (query.id, query.question));
    }
    let _ = dns::parse_response_key(data);
});
