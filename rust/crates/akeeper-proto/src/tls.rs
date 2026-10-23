//! Lecture du SNI d'un ClientHello TLS (RFC 8446 §4.1.2, RFC 6066 §3), sans déchiffrer quoi que ce soit.

const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;
/// Un enregistrement TLS ne dépasse jamais 2^14 octets de clair (RFC 8446 §5.1), plus l'en-tête.
pub const MAX_RECORD: usize = RECORD_HEADER + (1 << 14);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// Nom d'hôte demandé, en minuscules.
    Host(String),
    /// ClientHello complet sans extension server_name (connexion par IP, rare).
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// Le début du flux ressemble à TLS mais l'enregistrement n'est pas encore complet.
    Incomplete,
    NotTls,
    Malformed,
}

/// Analyse le premier enregistrement d'un flux client. Un ClientHello fragmenté sur plusieurs
/// enregistrements (quasi inexistant en pratique) est traité comme `Malformed`.
pub fn client_hello_sni(stream: &[u8]) -> Result<Sni, TlsError> {
    let header = stream
        .get(..RECORD_HEADER)
        .ok_or_else(|| incomplete_or_not_tls(stream))?;
    let mut r = Reader(header);
    if r.u8()? != CONTENT_HANDSHAKE || r.u8()? != 3 {
        return Err(TlsError::NotTls);
    }
    r.u8()?;
    let len = usize::from(r.u16()?);
    let record = stream
        .get(RECORD_HEADER..RECORD_HEADER + len)
        .ok_or(TlsError::Incomplete)?;

    let mut r = Reader(record);
    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsError::NotTls);
    }
    let body_len = r.u24()?;
    let mut hello = Reader(r.take(body_len)?);
    hello.take(2 + 32)?; // legacy_version + random
    let session = usize::from(hello.u8()?);
    hello.take(session)?;
    let suites = usize::from(hello.u16()?);
    hello.take(suites)?;
    let compression = usize::from(hello.u8()?);
    hello.take(compression)?;
    if hello.0.is_empty() {
        return Ok(Sni::Absent);
    }
    let ext_len = usize::from(hello.u16()?);
    let mut extensions = Reader(hello.take(ext_len)?);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let len = usize::from(extensions.u16()?);
        let body = extensions.take(len)?;
        if kind == EXT_SERVER_NAME {
            return server_name(body);
        }
    }
    Ok(Sni::Absent)
}

fn incomplete_or_not_tls(stream: &[u8]) -> TlsError {
    match stream.first() {
        None | Some(&CONTENT_HANDSHAKE) => TlsError::Incomplete,
        Some(_) => TlsError::NotTls,
    }
}

fn server_name(body: &[u8]) -> Result<Sni, TlsError> {
    let mut r = Reader(body);
    let list_len = usize::from(r.u16()?);
    let mut list = Reader(r.take(list_len)?);
    while !list.0.is_empty() {
        let kind = list.u8()?;
        let len = usize::from(list.u16()?);
        let name = list.take(len)?;
        if kind == NAME_TYPE_HOST {
            // Nom d'hôte DNS ASCII (RFC 6066) : tout autre octet signale un ClientHello forgé.
            if name.is_empty() || name.len() > 253 || !name.iter().all(|b| b.is_ascii_graphic()) {
                return Err(TlsError::Malformed);
            }
            let host: String = name
                .iter()
                .map(|&b| char::from(b.to_ascii_lowercase()))
                .collect();
            return Ok(Sni::Host(host.trim_end_matches('.').to_owned()));
        }
    }
    Ok(Sni::Absent)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if n > self.0.len() {
            return Err(TlsError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        self.take(1)?.first().copied().ok_or(TlsError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| TlsError::Malformed)?,
        ))
    }

    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.take(3)?;
        Ok(b.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// ClientHello TLS 1.3 minimal avec les extensions données (type, contenu).
    pub(crate) fn client_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (kind, body) in extensions {
            ext.extend_from_slice(&kind.to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(body);
        }
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(32);
        hello.extend_from_slice(&[0x22; 32]);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    pub(crate) fn sni_extension(host: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![NAME_TYPE_HOST];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host.as_bytes());
        let mut body = (entry.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&entry);
        (EXT_SERVER_NAME, body)
    }

    #[test]
    fn extracts_lowercased_sni_after_other_extensions() {
        let record = client_hello(&[
            (0x002b, vec![2, 3, 4]),
            sni_extension("Tracker.Example.NET."),
        ]);
        assert_eq!(
            client_hello_sni(&record),
            Ok(Sni::Host("tracker.example.net".into()))
        );
    }

    #[test]
    fn reports_absent_sni() {
        assert_eq!(
            client_hello_sni(&client_hello(&[(0x002b, vec![2, 3, 4])])),
            Ok(Sni::Absent)
        );
    }

    #[test]
    fn waits_for_the_rest_of_the_record() {
        let record = client_hello(&[sni_extension("example.org")]);
        assert_eq!(client_hello_sni(&record[..3]), Err(TlsError::Incomplete));
        assert_eq!(
            client_hello_sni(&record[..record.len() - 1]),
            Err(TlsError::Incomplete)
        );
        assert_eq!(client_hello_sni(&[]), Err(TlsError::Incomplete));
    }

    #[test]
    fn recognises_non_tls_streams() {
        assert_eq!(
            client_hello_sni(b"GET / HTTP/1.1\r\n"),
            Err(TlsError::NotTls)
        );
        assert_eq!(client_hello_sni(b"G"), Err(TlsError::NotTls));
    }

    #[test]
    fn rejects_forged_names_and_lengths() {
        let mut record = client_hello(&[sni_extension("bad\u{1}name")]);
        assert_eq!(client_hello_sni(&record), Err(TlsError::Malformed));
        record = client_hello(&[sni_extension("example.org")]);
        let last = record.len() - 1;
        record[last - 12] = 0xff;
        assert!(client_hello_sni(&record).is_err());
    }

    #[test]
    fn never_panics_on_any_prefix() {
        let record = client_hello(&[
            (0x0010, vec![0, 3, 2, b'h', b'2']),
            sni_extension("www.example.org"),
        ]);
        for len in 0..=record.len() {
            let _ = client_hello_sni(&record[..len]);
        }
    }
}
