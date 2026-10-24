use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use akeeper_proto::bundle::{self, BundleError, category, kind};

use crate::Blocklist;

/// Points d'accès DoH publics, repli utilisé tant qu'aucun bundle ne fournit sa propre liste DoH. Même fichier que
/// celui que publie le pipeline de règles (`rules/sources/doh-hosts.txt`).
const DOH_HOSTS: &str = include_str!("../../../../rules/sources/doh-hosts.txt");

#[derive(Debug)]
pub enum RulesError {
    Envelope(BundleError),
    Fst(fst::Error),
}

impl From<BundleError> for RulesError {
    fn from(e: BundleError) -> Self {
        Self::Envelope(e)
    }
}

impl From<fst::Error> for RulesError {
    fn from(e: fst::Error) -> Self {
        Self::Fst(e)
    }
}

/// Pourquoi un nom ou une adresse est refusé. Les codes sont exposés à Java (`NativeEngine.Reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Domaine bloqué par l'utilisateur.
    Personal,
    /// Contournement du filtrage par DNS chiffré (DoH) : jamais autorisable.
    Evasion,
    /// Catégorie du bundle, désignée par son identifiant (`akeeper_proto::bundle::category`).
    Category(u8),
}

impl Reason {
    pub fn code(self) -> u8 {
        match self {
            Self::Personal => 1,
            Self::Evasion => 2,
            Self::Category(id) => 16u8.saturating_add(id),
        }
    }
}

/// Catégories de domaines du bundle que l'utilisateur laisse actives, un bit par identifiant. Les listes DoH ne
/// dépendent pas de ce masque : le contournement DNS n'a pas d'interrupteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoryMask(u32);

impl CategoryMask {
    pub const ALL: Self = Self(u32::MAX);

    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    fn allows(self, id: u8) -> bool {
        1u32.checked_shl(u32::from(id))
            .is_some_and(|bit| self.0 & bit != 0)
    }
}

/// Contenu d'un bundle de règles. La signature a déjà été vérifiée côté Java (`BundleVerifier`) sur ce même fichier.
pub struct BundleRules {
    version: u64,
    domains: Vec<(u8, Blocklist)>,
    doh_domains: Option<Blocklist>,
    doh_ips: Vec<Cidr>,
}

impl BundleRules {
    /// Les catégories hors de `enabled` ne sont pas chargées ; les listes DoH le sont toujours.
    pub fn parse(bytes: &[u8], enabled: CategoryMask) -> Result<Self, RulesError> {
        let envelope = bundle::parse(bytes)?;
        let mut rules = Self {
            version: envelope.version,
            domains: Vec::new(),
            doh_domains: None,
            doh_ips: Vec::new(),
        };
        for section in &envelope.sections {
            match (section.kind, section.category) {
                (kind::DOMAINS, category::DOH) => {
                    rules.doh_domains = Some(Blocklist::from_fst(section.data.to_vec())?);
                }
                (kind::DOMAINS, id) if enabled.allows(id) => rules
                    .domains
                    .push((id, Blocklist::from_fst(section.data.to_vec())?)),
                (kind::CIDRS, category::DOH) => rules.doh_ips.extend(
                    bundle::cidrs(section.data)?
                        .into_iter()
                        .map(|(prefix, addr)| Cidr::new(prefix, u128::from_be_bytes(addr))),
                ),
                // Type ou catégorie inconnus (bundle plus récent que l'app) et NOTICE : sans effet sur le filtrage.
                _ => {}
            }
        }
        Ok(rules)
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    net: u128,
    mask: u128,
}

impl Cidr {
    fn new(prefix: u8, addr: u128) -> Self {
        let mask = u128::MAX
            .checked_shl(u32::from(128 - prefix.min(128)))
            .unwrap_or(0);
        Self {
            net: addr & mask,
            mask,
        }
    }

    fn contains(&self, addr: u128) -> bool {
        addr & self.mask == self.net
    }
}

/// Noms et adresses bloqués, partagés par le résolveur DNS et l'inspection TCP. Construit hors du thread moteur
/// puis remplacé d'un bloc (`Engine::set_filter`).
pub struct Filter {
    user: Blocklist,
    allowed: Blocklist,
    domains: Vec<(u8, Blocklist)>,
    doh: Blocklist,
    doh_ips: Vec<Cidr>,
    /// Pause demandée par l'utilisateur : plus aucun nom ni adresse n'est bloqué. Partagé avec le moteur, qui le
    /// conserve d'un filtre au suivant quand les règles sont remplacées.
    paused: Arc<AtomicBool>,
}

impl Filter {
    pub fn new(user: Blocklist, bundle: Option<BundleRules>) -> Self {
        match bundle {
            Some(b) => Self {
                user,
                allowed: Blocklist::empty(),
                domains: b.domains,
                doh: b
                    .doh_domains
                    .unwrap_or_else(|| Blocklist::from_domains(DOH_HOSTS)),
                doh_ips: b.doh_ips,
                paused: Arc::default(),
            },
            None => Self {
                user,
                allowed: Blocklist::empty(),
                domains: Vec::new(),
                doh: Blocklist::from_domains(DOH_HOSTS),
                doh_ips: Vec::new(),
                paused: Arc::default(),
            },
        }
    }

    /// Exceptions personnelles : elles l'emportent sur la liste personnelle et sur les catégories, mais jamais sur
    /// le contournement DNS.
    pub fn with_allowed(mut self, allowed: Blocklist) -> Self {
        self.allowed = allowed;
        self
    }

    pub(crate) fn share_pause(&mut self, paused: Arc<AtomicBool>) {
        self.paused = paused;
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Raison du refus d'un nom, `None` s'il est autorisé. `name` est déjà en minuscules (normalisé par le parseur
    /// DNS ou TLS). Ordre : contournement DNS, exceptions, liste personnelle, catégories actives.
    pub(crate) fn verdict(&self, name: &str) -> Option<Reason> {
        if self.is_paused() {
            return None;
        }
        if self.doh.blocks(name) {
            return Some(Reason::Evasion);
        }
        if self.allowed.blocks(name) {
            return None;
        }
        if self.user.blocks(name) {
            return Some(Reason::Personal);
        }
        self.domains
            .iter()
            .find(|(_, list)| list.blocks(name))
            .map(|&(id, _)| Reason::Category(id))
    }

    pub(crate) fn blocks(&self, name: &str) -> bool {
        self.verdict(name).is_some()
    }

    /// Adresse d'un résolveur DoH connu. Parcours linéaire : quelques centaines de plages, une fois par flux.
    pub(crate) fn blocks_ip(&self, ip: IpAddr) -> bool {
        if self.is_paused() {
            return false;
        }
        let addr = match ip {
            IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
            IpAddr::V6(v6) => u128::from(v6),
        };
        self.doh_ips.iter().any(|cidr| cidr.contains(addr))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use akeeper_proto::bundle::{SIGNATURE_LEN, Section};
    use std::net::Ipv4Addr;

    /// Bundle de test (signature factice : la vérification est faite côté Java).
    pub(crate) fn bundle_bytes(
        ads: &str,
        doh: Option<&str>,
        doh_cidrs: &[(u8, IpAddr)],
    ) -> Vec<u8> {
        let ads = Blocklist::from_domains(ads);
        let doh = doh.map(Blocklist::from_domains);
        let cidrs: Vec<u8> = doh_cidrs
            .iter()
            .flat_map(|&(prefix, ip)| {
                let (prefix, addr) = match ip {
                    IpAddr::V4(v4) => (prefix + 96, v4.to_ipv6_mapped().octets()),
                    IpAddr::V6(v6) => (prefix, v6.octets()),
                };
                std::iter::once(prefix).chain(addr)
            })
            .collect();
        let mut sections = vec![
            Section {
                kind: kind::DOMAINS,
                category: category::ADS,
                data: ads.as_bytes(),
            },
            Section {
                kind: kind::CIDRS,
                category: category::DOH,
                data: &cidrs,
            },
            Section {
                kind: kind::NOTICE,
                category: 0,
                data: b"HaGeZi GPL-3.0",
            },
        ];
        if let Some(doh) = &doh {
            sections.push(Section {
                kind: kind::DOMAINS,
                category: category::DOH,
                data: doh.as_bytes(),
            });
        }
        let mut bytes = bundle::signed_message(0, 7, 0, &sections).unwrap();
        bytes.extend_from_slice(&[0; SIGNATURE_LEN]);
        bytes
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn blocks_user_list_and_embedded_doh_without_bundle() {
        let filter = Filter::new(Blocklist::from_domains("ads.example.net"), None);
        assert!(filter.blocks("cdn.ads.example.net"));
        assert!(filter.blocks("dns.google"));
        assert!(filter.blocks("mozilla.cloudflare-dns.com"));
        assert!(!filter.blocks("www.google.com"));
        assert!(!filter.blocks_ip(v4(1, 1, 1, 1)));
    }

    #[test]
    fn bundle_adds_categories_doh_names_and_addresses() {
        let bytes = bundle_bytes(
            "tracker.example",
            Some("doh.example.org"),
            &[
                (24, v4(1, 1, 1, 0)),
                (128, "2606:4700:4700::1111".parse().unwrap()),
            ],
        );
        let rules = BundleRules::parse(&bytes, CategoryMask::ALL).unwrap();
        assert_eq!(rules.version(), 7);
        let filter = Filter::new(Blocklist::from_domains("mine.example"), Some(rules));
        assert!(filter.blocks("mine.example"));
        assert!(filter.blocks("a.tracker.example"));
        assert!(filter.blocks("doh.example.org"));
        // La liste DoH du bundle remplace le repli embarqué.
        assert!(!filter.blocks("dns.google"));
        assert!(filter.blocks_ip(v4(1, 1, 1, 1)));
        assert!(!filter.blocks_ip(v4(1, 1, 2, 1)));
        assert!(filter.blocks_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!filter.blocks_ip("2606:4700:4700::1001".parse().unwrap()));
    }

    #[test]
    fn bundle_without_doh_names_keeps_embedded_fallback() {
        let rules = BundleRules::parse(
            &bundle_bytes("tracker.example", None, &[]),
            CategoryMask::ALL,
        )
        .unwrap();
        assert!(Filter::new(Blocklist::empty(), Some(rules)).blocks("dns.google"));
    }

    #[test]
    fn rejects_corrupted_fst_section() {
        let mut bytes = bundle_bytes("tracker.example", None, &[]);
        // Premier octet de données de la première section (FST) : la somme de contrôle ne correspond plus.
        let fst_start = bundle::HEADER_LEN + 8 + 10;
        bytes[fst_start] ^= 0xff;
        assert!(BundleRules::parse(&bytes, CategoryMask::ALL).is_err());
    }

    #[test]
    fn a_pause_lifts_every_block_and_a_resume_restores_it() {
        let bytes = bundle_bytes("tracker.example", None, &[(32, v4(192, 0, 2, 1))]);
        let mut filter = Filter::new(
            Blocklist::from_domains("mine.example"),
            Some(BundleRules::parse(&bytes, CategoryMask::ALL).unwrap()),
        );
        let paused = Arc::new(AtomicBool::new(false));
        filter.share_pause(Arc::clone(&paused));
        assert!(
            filter.blocks("mine.example")
                && filter.blocks("a.tracker.example")
                && filter.blocks("dns.google")
        );
        assert!(filter.blocks_ip(v4(192, 0, 2, 1)));

        paused.store(true, Ordering::Relaxed);
        assert!(
            !filter.blocks("mine.example")
                && !filter.blocks("a.tracker.example")
                && !filter.blocks("dns.google")
        );
        assert!(!filter.blocks_ip(v4(192, 0, 2, 1)));

        paused.store(false, Ordering::Relaxed);
        assert!(filter.blocks("mine.example"));
    }

    /// La liste livrée dans l'APK : elle doit se charger et bloquer sans fausse alerte sur les sites courants.
    #[test]
    fn the_shipped_default_list_blocks_ad_domains_and_spares_common_sites() {
        let bytes = include_bytes!("../../../../rules/src/main/assets/default-rules.akrb");
        let rules = BundleRules::parse(bytes, CategoryMask::ALL).unwrap();
        assert_eq!(rules.version(), 0);
        let filter = Filter::new(Blocklist::empty(), Some(rules));
        assert!(filter.blocks("googlesyndication.com"));
        assert!(filter.blocks("pagead2.googlesyndication.com"));
        // La liste intégrée porte aussi les points d'accès et les adresses DoH du fichier partagé.
        assert!(filter.blocks("dns.google") && filter.blocks_ip(v4(8, 8, 8, 8)));
        assert!(!filter.blocks_ip(v4(93, 184, 216, 34)));
        for site in [
            "example.org",
            "wikipedia.org",
            "github.com",
            "www.google.com",
            "mozilla.org",
            "lemonde.fr",
        ] {
            assert!(!filter.blocks(site), "{site} ne doit pas être bloqué");
        }
    }

    /// Bundle de test à trois catégories : publicité, malware et hameçonnage, plus la liste DoH.
    fn three_categories() -> Vec<u8> {
        use akeeper_proto::bundle::SIGNATURE_LEN;
        let lists = [
            (category::ADS, Blocklist::from_domains("ads.example")),
            (
                category::MALWARE,
                Blocklist::from_domains("malware.example"),
            ),
            (category::PHISHING, Blocklist::from_domains("phish.example")),
        ];
        let sections: Vec<_> = lists
            .iter()
            .map(|(cat, list)| akeeper_proto::bundle::Section {
                kind: kind::DOMAINS,
                category: *cat,
                data: list.as_bytes(),
            })
            .collect();
        let mut bytes = bundle::signed_message(0, 1, 0, &sections).unwrap();
        bytes.extend_from_slice(&[0; SIGNATURE_LEN]);
        bytes
    }

    fn mask_without(id: u8) -> CategoryMask {
        CategoryMask::from_bits(!(1u32 << id))
    }

    #[test]
    fn only_the_enabled_categories_are_loaded_and_each_names_itself() {
        let bytes = three_categories();
        let all = Filter::new(
            Blocklist::empty(),
            Some(BundleRules::parse(&bytes, CategoryMask::ALL).unwrap()),
        );
        assert_eq!(
            all.verdict("a.ads.example"),
            Some(Reason::Category(category::ADS))
        );
        assert_eq!(
            all.verdict("malware.example"),
            Some(Reason::Category(category::MALWARE))
        );
        assert_eq!(
            all.verdict("phish.example"),
            Some(Reason::Category(category::PHISHING))
        );

        let no_ads = Filter::new(
            Blocklist::empty(),
            Some(BundleRules::parse(&bytes, mask_without(category::ADS)).unwrap()),
        );
        assert_eq!(no_ads.verdict("ads.example"), None);
        assert!(no_ads.blocks("malware.example") && no_ads.blocks("phish.example"));

        let none = Filter::new(
            Blocklist::empty(),
            Some(BundleRules::parse(&bytes, CategoryMask::from_bits(0)).unwrap()),
        );
        assert!(!none.blocks("malware.example"));
        assert!(
            none.blocks("dns.google"),
            "le contournement DNS n'a pas d'interrupteur"
        );
    }

    #[test]
    fn exceptions_beat_personal_blocks_and_categories_but_never_the_dns_bypass() {
        let bytes = three_categories();
        let (blocked, allowed) = Blocklist::personal(
            "mine.example\n@@ads.example\n@@dns.google\n@@mine.example\nother.example\n",
        );
        let filter = Filter::new(
            blocked,
            Some(BundleRules::parse(&bytes, CategoryMask::ALL).unwrap()),
        )
        .with_allowed(allowed);

        assert_eq!(
            filter.verdict("x.ads.example"),
            None,
            "exception contre catégorie"
        );
        assert_eq!(
            filter.verdict("mine.example"),
            None,
            "exception contre liste personnelle"
        );
        assert_eq!(filter.verdict("other.example"), Some(Reason::Personal));
        assert_eq!(filter.verdict("dns.google"), Some(Reason::Evasion));
        assert_eq!(
            filter.verdict("malware.example"),
            Some(Reason::Category(category::MALWARE))
        );
    }

    #[test]
    fn reasons_have_stable_codes() {
        assert_eq!(Reason::Personal.code(), 1);
        assert_eq!(Reason::Evasion.code(), 2);
        assert_eq!(Reason::Category(category::ADS).code(), 17);
        assert_eq!(Reason::Category(category::PHISHING).code(), 19);
        assert_eq!(Reason::Category(250).code(), 255);
    }

    #[test]
    fn prefix_zero_matches_everything() {
        assert!(Cidr::new(0, 0).contains(u128::MAX));
        assert!(Cidr::new(128, 5).contains(5));
        assert!(!Cidr::new(128, 5).contains(4));
    }
}
