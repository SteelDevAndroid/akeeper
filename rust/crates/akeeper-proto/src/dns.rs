//! Messages DNS (RFC 1035) : juste ce qu'il faut pour filtrer une question et relayer la réponse.

const HEADER: usize = 12;
const MAX_NAME: usize = 255;
const MAX_LABEL: usize = 63;

const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const OPCODE_MASK: u16 = 0x7800;

pub const TYPE_HTTPS: u16 = 65;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    ServFail = 2,
    NxDomain = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    NotAQuery,
    NotAResponse,
    UnsupportedOpcode,
    UnsupportedCounts,
    CompressedQuestion,
    BadLabel,
    NameTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query<'a> {
    pub id: u16,
    flags: u16,
    /// Nom en minuscules, sans point final ; vide pour la racine.
    pub name: String,
    pub qtype: u16,
    /// Section question telle que reçue (nom + type + classe), pour l'écho et l'anti-usurpation.
    pub question: &'a [u8],
}

pub fn parse_query(msg: &[u8]) -> Result<Query<'_>, DnsError> {
    let flags = u16_at(msg, 2)?;
    if flags & FLAG_QR != 0 {
        return Err(DnsError::NotAQuery);
    }
    if flags & OPCODE_MASK != 0 {
        return Err(DnsError::UnsupportedOpcode);
    }
    // Une seule question, aucune réponse ni autorité : tout le reste est hors protocole pour un client stub.
    if u16_at(msg, 4)? != 1 || u16_at(msg, 6)? != 0 || u16_at(msg, 8)? != 0 {
        return Err(DnsError::UnsupportedCounts);
    }
    let (name, end) = read_question_name(msg, HEADER)?;
    Ok(Query {
        id: u16_at(msg, 0)?,
        flags,
        name,
        qtype: u16_at(msg, end)?,
        question: msg.get(HEADER..end + 4).ok_or(DnsError::Truncated)?,
    })
}

/// Réponse sans enregistrement (NXDOMAIN, NODATA, SERVFAIL) : en-tête + question en écho.
pub fn negative_response(query: &Query<'_>, rcode: Rcode, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&query.id.to_be_bytes());
    let flags = FLAG_QR | (query.flags & FLAG_RD) | FLAG_RA | rcode as u16;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(query.question);
}

/// En-tête d'une réponse amont : identifiant et section question, à comparer à la requête en attente.
pub fn parse_response_key(msg: &[u8]) -> Result<(u16, &[u8]), DnsError> {
    if u16_at(msg, 2)? & FLAG_QR == 0 {
        return Err(DnsError::NotAResponse);
    }
    if u16_at(msg, 4)? != 1 {
        return Err(DnsError::UnsupportedCounts);
    }
    let (_, end) = read_question_name(msg, HEADER)?;
    let question = msg.get(HEADER..end + 4).ok_or(DnsError::Truncated)?;
    Ok((u16_at(msg, 0)?, question))
}

/// Remplace l'identifiant d'un message déjà validé.
pub fn set_id(msg: &mut [u8], id: u16) {
    if let Some(slot) = msg.get_mut(0..2) {
        slot.copy_from_slice(&id.to_be_bytes());
    }
}

fn read_question_name(msg: &[u8], mut at: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut wire_len = 0usize;
    loop {
        let len = usize::from(*msg.get(at).ok_or(DnsError::Truncated)?);
        at += 1;
        if len == 0 {
            return Ok((name, at));
        }
        // Les pointeurs de compression n'ont rien à faire dans une question : refusés plutôt que suivis.
        if len & 0xc0 != 0 {
            return Err(DnsError::CompressedQuestion);
        }
        if len > MAX_LABEL {
            return Err(DnsError::BadLabel);
        }
        wire_len += len + 1;
        if wire_len > MAX_NAME {
            return Err(DnsError::NameTooLong);
        }
        let label = msg.get(at..at + len).ok_or(DnsError::Truncated)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            // ASCII imprimable hors '.' : un point dans un label tromperait la correspondance par suffixe.
            if !b.is_ascii_graphic() || b == b'.' {
                return Err(DnsError::BadLabel);
            }
            name.push(char::from(b.to_ascii_lowercase()));
        }
        at += len;
    }
}

fn u16_at(msg: &[u8], at: usize) -> Result<u16, DnsError> {
    msg.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(DnsError::Truncated)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m
    }

    #[test]
    fn parses_and_lowercases_name() {
        let msg = query(0x1234, "Ads.Example.NET", 1);
        let q = parse_query(&msg).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "ads.example.net");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.question, &msg[12..]);
    }

    #[test]
    fn builds_nxdomain_echoing_question_and_rd() {
        let msg = query(7, "tracker.example", 1);
        let q = parse_query(&msg).unwrap();
        let mut out = Vec::new();
        negative_response(&q, Rcode::NxDomain, &mut out);
        assert_eq!(&out[..2], &[0, 7]);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0x8183);
        assert_eq!(&out[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&out[12..], q.question);
        let (id, question) = parse_response_key(&out).unwrap();
        assert_eq!((id, question), (7, q.question));
    }

    #[test]
    fn rejects_hostile_names() {
        let mut msg = query(1, "a.example", 1);
        msg[12] = 0xc0;
        assert_eq!(parse_query(&msg), Err(DnsError::CompressedQuestion));

        let mut msg = query(1, "a.example", 1);
        msg[13] = b'.';
        assert_eq!(parse_query(&msg), Err(DnsError::BadLabel));

        let long = vec!["a".repeat(60); 5].join(".");
        assert_eq!(parse_query(&query(1, &long, 1)), Err(DnsError::NameTooLong));
    }

    #[test]
    fn rejects_responses_and_multi_question_queries() {
        let mut msg = query(1, "example", 1);
        msg[2] |= 0x80;
        assert_eq!(parse_query(&msg), Err(DnsError::NotAQuery));
        let mut msg = query(1, "example", 1);
        msg[5] = 2;
        assert_eq!(parse_query(&msg), Err(DnsError::UnsupportedCounts));
        let mut msg = query(1, "example", 1);
        msg[2] |= 0x28;
        assert_eq!(parse_query(&msg), Err(DnsError::UnsupportedOpcode));
    }

    #[test]
    fn never_panics_on_any_prefix() {
        let msg = query(9, "www.example.org", TYPE_HTTPS);
        for len in 0..=msg.len() {
            let _ = parse_query(&msg[..len]);
            let _ = parse_response_key(&msg[..len]);
        }
    }
}
