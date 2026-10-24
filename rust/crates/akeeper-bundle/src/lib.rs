//! Construction et signature des bundles de règles, côté pipeline (jamais embarqué dans l'app).
//! La clé privée ne quitte pas la machine de signature : l'app ne contient que les clés publiques.

pub mod sources;

use std::net::IpAddr;

use akeeper_engine::{Blocklist, BundleRules, RulesError};
use akeeper_proto::bundle::{self, BundleError, Section, category, kind};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const SEED_LEN: usize = 32;

#[derive(Debug)]
pub enum Error {
    Bundle(BundleError),
    InvalidCidr(String),
    BadSignature,
    Rules(RulesError),
}

impl From<BundleError> for Error {
    fn from(e: BundleError) -> Self {
        Self::Bundle(e)
    }
}

/// Listes sources d'un bundle, en texte (un domaine ou une plage par ligne, `#` commente).
#[derive(Default)]
pub struct Sources {
    pub ads: Option<String>,
    pub malware: Option<String>,
    pub phishing: Option<String>,
    pub doh: Option<String>,
    pub doh_ips: Option<String>,
    pub notice: Option<String>,
}

pub fn signing_key(seed: &[u8; SEED_LEN]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn public_key_hex(key: &SigningKey) -> String {
    hex(key.verifying_key().as_bytes())
}

/// Construit et signe un bundle. Déterministe : mêmes entrées, mêmes octets (Ed25519 est déterministe).
pub fn build(
    key: &SigningKey,
    key_id: u8,
    version: u64,
    created_at: u64,
    sources: &Sources,
) -> Result<Vec<u8>, Error> {
    let mut bytes = message(key_id, version, created_at, sources)?;
    let signature = key.sign(&bytes);
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Bundle sans signature (64 octets nuls), pour la liste intégrée à l'APK : son authenticité vient de la signature
/// de l'APK. L'app ne l'active jamais comme une mise à jour : `verify` le refuse, la version 0 n'avance pas le plancher.
pub fn build_unsigned(created_at: u64, sources: &Sources) -> Result<Vec<u8>, Error> {
    let mut bytes = message(0, 0, created_at, sources)?;
    bytes.extend_from_slice(&[0; bundle::SIGNATURE_LEN]);
    Ok(bytes)
}

fn message(key_id: u8, version: u64, created_at: u64, sources: &Sources) -> Result<Vec<u8>, Error> {
    let lists: Vec<(u8, Blocklist)> = [
        (category::ADS, &sources.ads),
        (category::MALWARE, &sources.malware),
        (category::PHISHING, &sources.phishing),
        (category::DOH, &sources.doh),
    ]
    .into_iter()
    .filter_map(|(cat, text)| text.as_deref().map(|t| (cat, Blocklist::from_domains(t))))
    .collect();
    let cidrs = sources.doh_ips.as_deref().map(cidr_records).transpose()?;

    let mut sections: Vec<Section<'_>> = lists
        .iter()
        .map(|(cat, list)| Section {
            kind: kind::DOMAINS,
            category: *cat,
            data: list.as_bytes(),
        })
        .collect();
    if let Some(records) = &cidrs {
        sections.push(Section {
            kind: kind::CIDRS,
            category: category::DOH,
            data: records,
        });
    }
    if let Some(notice) = &sources.notice {
        sections.push(Section {
            kind: kind::NOTICE,
            category: 0,
            data: notice.as_bytes(),
        });
    }
    Ok(bundle::signed_message(
        key_id, version, created_at, &sections,
    )?)
}

/// Contrôle du pipeline avant publication : signature par la clé désignée par `key_id`, comme dans l'app, puis
/// chargement par le moteur. Un bundle signé que le moteur refuse ne doit jamais être publié : le plancher
/// anti-rollback interdirait d'en revenir.
pub fn verify(bytes: &[u8], public_keys: &[VerifyingKey]) -> Result<u64, Error> {
    let envelope = bundle::parse(bytes)?;
    let key = public_keys
        .get(usize::from(envelope.key_id))
        .ok_or(Error::BadSignature)?;
    let signature = Signature::from_slice(envelope.signature).map_err(|_| Error::BadSignature)?;
    key.verify(envelope.signed, &signature)
        .map_err(|_| Error::BadSignature)?;
    BundleRules::parse(bytes).map_err(Error::Rules)?;
    Ok(envelope.version)
}

/// `1.1.1.0/24`, `2606:4700::/32` ou une adresse seule ; IPv4 stockée en adresse IPv6 mappée.
fn cidr_records(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter_map(|l| l.split('#').next())
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let invalid = || Error::InvalidCidr(line.to_owned());
        let (addr, prefix) = match line.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().map_err(|_| invalid())?)),
            None => (line, None),
        };
        let (prefix, octets) = match addr.parse::<IpAddr>().map_err(|_| invalid())? {
            IpAddr::V4(v4) => {
                let p = prefix.unwrap_or(32);
                if p > 32 {
                    return Err(invalid());
                }
                (p + 96, v4.to_ipv6_mapped().octets())
            }
            IpAddr::V6(v6) => {
                let p = prefix.unwrap_or(128);
                if p > 128 {
                    return Err(invalid());
                }
                (p, v6.octets())
            }
        };
        out.push(prefix);
        out.extend_from_slice(&octets);
    }
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_key(text: &str) -> Option<VerifyingKey> {
    let text = text.trim();
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    VerifyingKey::from_bytes(&key).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Clé de test publique et connue : sert aussi au test Java du même fixture, jamais à la production.
    const TEST_SEED: [u8; SEED_LEN] = [1; SEED_LEN];

    fn fixture_sources() -> Sources {
        Sources {
            ads: Some("tracker.example\nads.example.net\n".into()),
            phishing: Some("login-bank.example\n".into()),
            doh: Some("doh.example.org\n".into()),
            doh_ips: Some("192.0.2.0/24\n2001:db8::1\n".into()),
            notice: Some("Listes de test, domaine public.".into()),
            ..Sources::default()
        }
    }

    #[test]
    fn builds_a_bundle_the_engine_loads_and_the_signature_covers() {
        let key = signing_key(&TEST_SEED);
        let bytes = build(&key, 1, 5, 1_761_220_000, &fixture_sources()).unwrap();
        let other = signing_key(&[2; SEED_LEN]).verifying_key();
        assert_eq!(verify(&bytes, &[other, key.verifying_key()]).unwrap(), 5);
        assert!(
            verify(&bytes, &[key.verifying_key(), other]).is_err(),
            "key_id 1 désigne la seconde clé"
        );

        assert_eq!(BundleRules::parse(&bytes).unwrap().version(), 5);

        let mut tampered = bytes.clone();
        tampered[20] ^= 1;
        assert!(verify(&tampered, &[other, key.verifying_key()]).is_err());
    }

    #[test]
    fn an_unsigned_bundle_loads_in_the_engine_but_never_verifies() {
        let bytes = build_unsigned(1_761_220_000, &fixture_sources()).unwrap();
        assert_eq!(BundleRules::parse(&bytes).unwrap().version(), 0);
        let key = signing_key(&TEST_SEED).verifying_key();
        assert!(matches!(
            verify(&bytes, &[key, key]),
            Err(Error::BadSignature)
        ));
        assert_eq!(
            &bytes[bytes.len() - bundle::SIGNATURE_LEN..],
            &[0; bundle::SIGNATURE_LEN]
        );
    }

    #[test]
    fn rejects_invalid_ranges() {
        assert!(cidr_records("10.0.0.0/33").is_err());
        assert!(cidr_records("2001:db8::/129").is_err());
        assert!(cidr_records("not-an-ip").is_err());
        assert_eq!(cidr_records("# vide\n\n").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parses_hex_public_keys() {
        let key = signing_key(&TEST_SEED);
        let parsed = parse_hex_key(&public_key_hex(&key)).unwrap();
        assert_eq!(parsed, key.verifying_key());
        assert!(parse_hex_key("zz").is_none());
    }

    /// Le fixture partagé avec les tests Java (`rules/`) : un changement de format le casse des deux côtés.
    #[test]
    fn matches_the_fixture_shared_with_java() {
        let key = signing_key(&TEST_SEED);
        let bytes = build(&key, 0, 5, 1_761_220_000, &fixture_sources()).unwrap();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../rules/src/test/resources/com/akeeper/rules/fixture-v5.akrb"
        );
        if std::env::var_os("AKEEPER_WRITE_FIXTURE").is_some() {
            std::fs::write(path, &bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "régénérer avec AKEEPER_WRITE_FIXTURE=1"
        );
        assert_eq!(
            public_key_hex(&key),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
    }
}
