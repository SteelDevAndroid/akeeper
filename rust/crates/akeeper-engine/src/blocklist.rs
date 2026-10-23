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
    fn empty_list_blocks_nothing() {
        assert!(!Blocklist::empty().blocks("ads.example.net"));
        assert!(Blocklist::from_domains("").is_empty());
    }
}
