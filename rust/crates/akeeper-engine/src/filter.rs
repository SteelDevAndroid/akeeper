use crate::Blocklist;

/// Points d'accès DoH publics les plus répandus. Liste provisoire embarquée : elle passera dans le
/// bundle de règles signé (J5), avec les adresses IP des résolveurs (spec §6).
const DOH_HOSTS: &str = "
cloudflare-dns.com
one.one.one.one
dns.google
dns.quad9.net
dns9.quad9.net
dns10.quad9.net
dns11.quad9.net
doh.opendns.com
doh.familyshield.opendns.com
dns.adguard-dns.com
dns.adguard.com
dns.nextdns.io
doh.cleanbrowsing.org
doh.mullvad.net
dns.mullvad.net
freedns.controld.com
dns.controld.com
doh.dns.sb
dns.alidns.com
doh.pub
";

/// Noms bloqués, partagés par le résolveur DNS et l'inspection SNI.
pub(crate) struct Filter {
    blocklist: Blocklist,
    doh: Blocklist,
}

impl Filter {
    pub(crate) fn new(blocklist: Blocklist) -> Self {
        Self {
            blocklist,
            doh: Blocklist::from_domains(DOH_HOSTS),
        }
    }

    /// `name` est déjà en minuscules (normalisé par le parseur DNS ou TLS).
    pub(crate) fn blocks(&self, name: &str) -> bool {
        self.blocklist.blocks(name) || self.doh.blocks(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_user_list_and_known_doh_endpoints() {
        let filter = Filter::new(Blocklist::from_domains("ads.example.net"));
        assert!(filter.blocks("cdn.ads.example.net"));
        assert!(filter.blocks("dns.google"));
        assert!(filter.blocks("mozilla.cloudflare-dns.com"));
        assert!(!filter.blocks("www.google.com"));
    }
}
