//! Enveloppe binaire des bundles de règles signés (format décrit dans `docs/bundle-regles.md`).
//!
//! ```text
//! 0   4  magic "AKRB"          16  8  created_at (s Unix)
//! 4   2  format = 1            24  4  payload_len
//! 6   1  key_id (0 ou 1)       28  …  payload : sections [kind u8, category u8, 0u16, len u32, data]
//! 7   1  réservé = 0           fin 64 signature Ed25519 de tout ce qui précède
//! 8   8  version (monotone)
//! ```
//! Entiers en gros-boutiste. La signature est vérifiée côté Java avant toute activation ; ce parseur ne fait
//! que borner et découper, il est exposé au fuzzing.

pub const MAGIC: [u8; 4] = *b"AKRB";
pub const FORMAT: u16 = 1;
pub const HEADER_LEN: usize = 28;
pub const SIGNATURE_LEN: usize = 64;
/// Borne mémoire : le moteur charge le bundle entier, une enveloppe plus grande est refusée.
pub const MAX_BUNDLE: usize = 32 * 1024 * 1024;
pub const MAX_SECTIONS: usize = 64;
const SECTION_HEADER: usize = 8;
/// Une plage d'adresses : longueur de préfixe sur l'espace IPv6 (IPv4 en `::ffff:0:0/96`), puis l'adresse.
pub const CIDR_RECORD: usize = 17;

pub mod kind {
    /// FST de domaines en labels inversés (format de `akeeper_engine::Blocklist`).
    pub const DOMAINS: u8 = 1;
    /// Plages d'adresses de `CIDR_RECORD` octets.
    pub const CIDRS: u8 = 2;
    /// Texte UTF-8 : sources et licences, affiché par l'écran « Licences ».
    pub const NOTICE: u8 = 3;
}

pub mod category {
    pub const ADS: u8 = 1;
    pub const MALWARE: u8 = 2;
    pub const PHISHING: u8 = 3;
    /// Résolveurs DNS-over-HTTPS publics : noms (SNI, DNS) et adresses.
    pub const DOH: u8 = 4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    TooLarge,
    BadMagic,
    UnsupportedFormat,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section<'a> {
    pub kind: u8,
    pub category: u8,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub key_id: u8,
    pub version: u64,
    pub created_at: u64,
    /// Octets couverts par la signature : en-tête et payload.
    pub signed: &'a [u8],
    pub signature: &'a [u8],
    pub sections: Vec<Section<'a>>,
}

pub fn parse(bytes: &[u8]) -> Result<Envelope<'_>, BundleError> {
    if bytes.len() > MAX_BUNDLE {
        return Err(BundleError::TooLarge);
    }
    let header = bytes.get(..HEADER_LEN).ok_or(BundleError::Malformed)?;
    if header.get(..4) != Some(&MAGIC[..]) {
        return Err(BundleError::BadMagic);
    }
    if be(header, 4, 2)? != u64::from(FORMAT) {
        return Err(BundleError::UnsupportedFormat);
    }
    let key_id = u8::try_from(be(header, 6, 1)?).map_err(|_| BundleError::Malformed)?;
    if key_id > 1 || be(header, 7, 1)? != 0 {
        return Err(BundleError::Malformed);
    }
    let payload_len = usize::try_from(be(header, 24, 4)?).map_err(|_| BundleError::Malformed)?;
    // Taille exacte : aucun octet hors signature ne peut être ajouté à la fin.
    if bytes.len() != HEADER_LEN + payload_len + SIGNATURE_LEN {
        return Err(BundleError::Malformed);
    }
    let (signed, signature) = bytes.split_at(HEADER_LEN + payload_len);
    let payload = signed.get(HEADER_LEN..).ok_or(BundleError::Malformed)?;
    Ok(Envelope {
        key_id,
        version: be(header, 8, 8)?,
        created_at: be(header, 16, 8)?,
        signed,
        signature,
        sections: sections(payload)?,
    })
}

/// Les sections doivent couvrir exactement le payload ; un type inconnu est conservé pour que l'appelant l'ignore.
fn sections(mut payload: &[u8]) -> Result<Vec<Section<'_>>, BundleError> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        if out.len() == MAX_SECTIONS {
            return Err(BundleError::Malformed);
        }
        let header = payload
            .get(..SECTION_HEADER)
            .ok_or(BundleError::Malformed)?;
        if be(header, 2, 2)? != 0 {
            return Err(BundleError::Malformed);
        }
        let len = usize::try_from(be(header, 4, 4)?).map_err(|_| BundleError::Malformed)?;
        let rest = payload
            .get(SECTION_HEADER..)
            .ok_or(BundleError::Malformed)?;
        if len > rest.len() {
            return Err(BundleError::Malformed);
        }
        let (data, tail) = rest.split_at(len);
        out.push(Section {
            kind: header.first().copied().ok_or(BundleError::Malformed)?,
            category: header.get(1).copied().ok_or(BundleError::Malformed)?,
            data,
        });
        payload = tail;
    }
    Ok(out)
}

/// Plages `(préfixe, adresse IPv6)` d'une section `CIDRS`. Un préfixe > 128 rend la section invalide.
pub fn cidrs(data: &[u8]) -> Result<Vec<(u8, [u8; 16])>, BundleError> {
    let (records, rest) = data.as_chunks::<CIDR_RECORD>();
    if !rest.is_empty() {
        return Err(BundleError::Malformed);
    }
    records
        .iter()
        .map(|[prefix, addr @ ..]| {
            if *prefix > 128 {
                return Err(BundleError::Malformed);
            }
            Ok((*prefix, *addr))
        })
        .collect()
}

/// Octets à signer pour un bundle : en-tête puis sections. Le bundle final est ce message suivi de la signature.
pub fn signed_message(
    key_id: u8,
    version: u64,
    created_at: u64,
    sections: &[Section<'_>],
) -> Result<Vec<u8>, BundleError> {
    if key_id > 1 || sections.len() > MAX_SECTIONS {
        return Err(BundleError::Malformed);
    }
    let mut payload = Vec::new();
    for section in sections {
        let len = u32::try_from(section.data.len()).map_err(|_| BundleError::TooLarge)?;
        payload.extend_from_slice(&[section.kind, section.category, 0, 0]);
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(section.data);
    }
    if HEADER_LEN + payload.len() + SIGNATURE_LEN > MAX_BUNDLE {
        return Err(BundleError::TooLarge);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| BundleError::TooLarge)?;
    let mut message = Vec::with_capacity(HEADER_LEN + payload.len());
    message.extend_from_slice(&MAGIC);
    message.extend_from_slice(&FORMAT.to_be_bytes());
    message.extend_from_slice(&[key_id, 0]);
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(&created_at.to_be_bytes());
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

/// Entier gros-boutiste de `len` octets (≤ 8) à `offset`.
fn be(bytes: &[u8], offset: usize, len: usize) -> Result<u64, BundleError> {
    let field = bytes
        .get(offset..offset + len)
        .ok_or(BundleError::Malformed)?;
    Ok(field.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn bundle(sections: &[Section<'_>]) -> Vec<u8> {
        let mut bytes = signed_message(1, 42, 1_761_000_000, sections).unwrap();
        bytes.extend_from_slice(&[0xaa; SIGNATURE_LEN]);
        bytes
    }

    #[test]
    fn round_trips_header_and_sections() {
        let cidr = [[24u8].as_slice(), &[0; 16]].concat();
        let bytes = bundle(&[
            Section {
                kind: kind::DOMAINS,
                category: category::ADS,
                data: b"fst",
            },
            Section {
                kind: kind::CIDRS,
                category: category::DOH,
                data: &cidr,
            },
            Section {
                kind: 99,
                category: 0,
                data: b"",
            },
        ]);
        let envelope = parse(&bytes).unwrap();
        assert_eq!(
            (envelope.key_id, envelope.version, envelope.created_at),
            (1, 42, 1_761_000_000)
        );
        assert_eq!(envelope.signed.len(), bytes.len() - SIGNATURE_LEN);
        assert_eq!(envelope.signature, &[0xaa; SIGNATURE_LEN]);
        assert_eq!(envelope.sections.len(), 3);
        assert_eq!(envelope.sections[0].data, b"fst");
        assert_eq!(
            cidrs(envelope.sections[1].data).unwrap(),
            vec![(24, [0; 16])]
        );
    }

    #[test]
    fn rejects_bad_headers_and_trailing_bytes() {
        let good = bundle(&[Section {
            kind: kind::NOTICE,
            category: 0,
            data: b"GPL",
        }]);
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(parse(&bad), Err(BundleError::BadMagic));
        bad = good.clone();
        bad[5] = 2;
        assert_eq!(parse(&bad), Err(BundleError::UnsupportedFormat));
        bad = good.clone();
        bad[6] = 2;
        assert_eq!(parse(&bad), Err(BundleError::Malformed));
        bad = good.clone();
        bad.push(0);
        assert_eq!(parse(&bad), Err(BundleError::Malformed));
        // Section qui déborde du payload.
        bad = good.clone();
        bad[HEADER_LEN + 7] = 200;
        assert_eq!(parse(&bad), Err(BundleError::Malformed));
    }

    #[test]
    fn rejects_invalid_cidrs() {
        assert!(cidrs(&[0; 16]).is_err());
        assert!(cidrs(&[[129u8].as_slice(), &[0; 16]].concat()).is_err());
        assert_eq!(cidrs(&[]).unwrap(), vec![]);
    }

    #[test]
    fn never_panics_on_any_prefix() {
        let bytes = bundle(&[Section {
            kind: kind::DOMAINS,
            category: category::ADS,
            data: b"abc",
        }]);
        for len in 0..bytes.len() {
            assert!(parse(&bytes[..len]).is_err());
        }
    }
}
