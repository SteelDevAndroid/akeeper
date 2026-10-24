use fst::Set;

/// Domaines bloqués, sous-domaines compris. Clés stockées en labels inversés (`net.example.ads`)
/// pour que chaque suffixe du nom testé soit une seule recherche dans le FST.
pub struct Blocklist(Set<Vec<u8>>);

impl Blocklist {
    pub fn empty() -> Self {
        Self(Set::default())
    }

    /// Une entrée par ligne ; `#` commente, la casse est ignorée, les lignes invalides sont écartées.
    pub fn from_domains(text: &str) -> Self {
        let mut keys: Vec<String> = text
            .lines()
            .filter_map(|line| line.split('#').next())
            .map(str::trim)
            .filter(|d| is_valid_domain(d))
            .map(|d| reversed(&d.to_ascii_lowercase()))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        // Clés triées et uniques : la construction ne peut pas échouer.
        Self(Set::from_iter(keys).unwrap_or_default())
    }

    /// Liste personnelle : une règle par ligne, `#` commente. Un nom préfixé de `@@` est une exception (toujours
    /// autorisé), les autres sont bloqués. Renvoie `(bloqués, exceptions)`.
    pub fn personal(text: &str) -> (Self, Self) {
        let (mut blocked, mut allowed) = (String::new(), String::new());
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            let (target, name) = match line.strip_prefix("@@") {
                Some(name) => (&mut allowed, name),
                None => (&mut blocked, line),
            };
            target.push_str(name.trim());
            target.push('\n');
        }
        (Self::from_domains(&blocked), Self::from_domains(&allowed))
    }

    /// FST déjà construit (bundle signé) : sa somme de contrôle est vérifiée, car une recherche dans un FST
    /// corrompu peut paniquer.
    pub fn from_fst(bytes: Vec<u8>) -> Result<Self, fst::Error> {
        let set = Set::new(bytes)?;
        set.as_fst().verify()?;
        Ok(Self(set))
    }

    /// Octets du FST, tels que `from_fst` les relit.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_fst().as_bytes()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `name` est déjà en minuscules (normalisé par le parseur DNS).
    pub fn blocks(&self, name: &str) -> bool {
        let mut key = String::with_capacity(name.len());
        name.rsplit('.').any(|label| {
            if !key.is_empty() {
                key.push('.');
            }
            key.push_str(label);
            self.0.contains(&key)
        })
    }
}

fn reversed(domain: &str) -> String {
    domain.rsplit('.').collect::<Vec<_>>().join(".")
}

fn is_valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn blocks_listed_domain_and_its_subdomains_only() {
        let list = Blocklist::from_domains(
            "ads.example.net\n# commentaire\nTracker.Example  # fin\n\nbad domain\n",
        );
        assert_eq!(list.len(), 2);
        assert!(list.blocks("ads.example.net"));
        assert!(list.blocks("cdn.ads.example.net"));
        assert!(list.blocks("tracker.example"));
        assert!(!list.blocks("example.net"));
        assert!(!list.blocks("notads.example.net"));
        assert!(!list.blocks(""));
    }

    #[test]
    fn round_trips_through_fst_bytes() {
        let list = Blocklist::from_domains("ads.example.net");
        let copy = Blocklist::from_fst(list.as_bytes().to_vec()).unwrap();
        assert!(copy.blocks("cdn.ads.example.net"));
        let mut corrupted = list.as_bytes().to_vec();
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 0xff;
        assert!(Blocklist::from_fst(corrupted).is_err());
        assert!(Blocklist::from_fst(b"not an fst".to_vec()).is_err());
    }

    #[test]
    fn splits_personal_rules_into_blocks_and_exceptions() {
        let (blocked, allowed) = Blocklist::personal(
            "# mes règles\nads.example.net\n@@ok.example.net  # toujours permis\n@@\nbad domain\n",
        );
        assert!(blocked.blocks("ads.example.net") && !blocked.blocks("ok.example.net"));
        assert!(allowed.blocks("cdn.ok.example.net") && !allowed.blocks("ads.example.net"));
        assert_eq!((blocked.len(), allowed.len()), (1, 1));
    }

    #[test]
    fn empty_list_blocks_nothing() {
        assert!(!Blocklist::empty().blocks("ads.example.net"));
        assert!(Blocklist::from_domains("").is_empty());
    }
}
