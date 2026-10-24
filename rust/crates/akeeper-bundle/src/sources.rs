//! Extraction de listes de domaines depuis les sources externes. Le pipeline de règles s'en sert avant de construire
//! les bundles ; rien de ce module n'est embarqué dans l'app.

use std::collections::HashSet;
use std::net::IpAddr;

/// Domaines des `top` premiers rangs d'un export Tranco (`rang,domaine`).
pub fn popular_domains(csv: &str, top: usize) -> HashSet<String> {
    csv.lines()
        .filter_map(|line| line.split_once(','))
        .filter(|(rank, _)| rank.trim().parse::<usize>().is_ok_and(|r| r <= top))
        .map(|(_, domain)| domain.trim().to_ascii_lowercase())
        .collect()
}

/// Noms d'hôte des URL malveillantes d'URLhaus encore en ligne, un par ligne.
///
/// Les adresses IP sont écartées, qu'un filtre DNS ne peut pas bloquer. Un hôte dont un domaine parent figure parmi
/// les `popular` est écarté aussi : une URL malveillante hébergée chez une plateforme légitime (forge de code,
/// stockage cloud, raccourcisseur) ne doit pas faire bloquer toute la plateforme.
pub fn urlhaus_hosts(csv: &str, popular: &HashSet<String>) -> String {
    let mut columns = (2, 3);
    let mut hosts: Vec<String> = Vec::new();
    for line in csv.lines() {
        if let Some(header) = line.strip_prefix('#') {
            // L'en-tête commenté donne l'ordre des colonnes ; sans lui, l'ordre documenté est supposé.
            let names = split_csv(header.trim_start());
            if let (Some(url), Some(status)) =
                (position(&names, "url"), position(&names, "url_status"))
            {
                columns = (url, status);
            }
            continue;
        }
        let fields = split_csv(line);
        let (Some(url), Some(status)) = (fields.get(columns.0), fields.get(columns.1)) else {
            continue;
        };
        if !status.eq_ignore_ascii_case("online") {
            continue;
        }
        if let Some(host) = host_of(url)
            && !has_popular_suffix(&host, popular)
        {
            hosts.push(host);
        }
    }
    hosts.sort_unstable();
    hosts.dedup();
    hosts.join("\n")
}

fn position(names: &[String], wanted: &str) -> Option<usize> {
    names.iter().position(|n| n.eq_ignore_ascii_case(wanted))
}

/// Découpe une ligne CSV : champs séparés par des virgules, éventuellement entre guillemets (`""` pour un guillemet).
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.starts_with('[') {
        return None;
    }
    let host = host
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let valid = host.contains('.')
        && host.len() <= 253
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then_some(host)
}

/// Vrai si l'hôte, ou l'un de ses domaines parents, est dans l'ensemble.
fn has_popular_suffix(host: &str, popular: &HashSet<String>) -> bool {
    let mut candidate = host;
    loop {
        if popular.contains(candidate) {
            return true;
        }
        match candidate.split_once('.') {
            Some((_, parent)) => candidate = parent,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = r##"################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-24 08:00:00","http://Evil.Example.com:8080/a.exe","online","2026-10-24 08:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/1/","bot"
"2","2026-10-24 08:01:00","https://user:pw@evil.example.com/b.sh","online","2026-10-24 08:01:00","malware_download","sh","https://urlhaus.abuse.ch/url/2/","bot"
"3","2026-10-24 08:02:00","http://203.0.113.9/c.bin","online","2026-10-24 08:02:00","malware_download","bin","https://urlhaus.abuse.ch/url/3/","bot"
"4","2026-10-24 08:03:00","http://[2001:db8::1]/d","online","2026-10-24 08:03:00","malware_download","","https://urlhaus.abuse.ch/url/4/","bot"
"5","2026-10-24 08:04:00","https://raw.githubusercontent.com/x/y/z.exe","online","2026-10-24 08:04:00","malware_download","","https://urlhaus.abuse.ch/url/5/","bot"
"6","2026-10-24 08:05:00","http://gone.example.net/e","offline","2026-10-24 08:05:00","malware_download","","https://urlhaus.abuse.ch/url/6/","bot"
"7","2026-10-24 08:06:00","http://localhost/f","online","2026-10-24 08:06:00","malware_download","","https://urlhaus.abuse.ch/url/7/","bot"
"8","2026-10-24 08:07:00","http://bad host.example.org/g","online","2026-10-24 08:07:00","malware_download","","https://urlhaus.abuse.ch/url/8/","bot"
"##;

    fn popular() -> HashSet<String> {
        popular_domains(
            "1,google.com\n2,githubusercontent.com\n300000,rare.example\nnot,a row\n",
            100_000,
        )
    }

    #[test]
    fn keeps_only_the_top_ranks_of_the_popularity_list() {
        let set = popular();
        assert!(set.contains("google.com") && set.contains("githubusercontent.com"));
        assert!(!set.contains("rare.example"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn extracts_online_hosts_without_ips_popular_domains_or_garbage() {
        let hosts = urlhaus_hosts(CSV, &popular());
        assert_eq!(hosts, "evil.example.com");
    }

    #[test]
    fn follows_the_column_order_given_by_the_header() {
        let csv = "# url_status,url\n\"online\",\"http://a.example.net/x\"\n\"offline\",\"http://b.example.net/x\"\n";
        assert_eq!(urlhaus_hosts(csv, &HashSet::new()), "a.example.net");
    }

    #[test]
    fn splits_quoted_fields_with_commas_and_quotes() {
        assert_eq!(split_csv(r#""a,b","c""d",e"#), vec!["a,b", "c\"d", "e"]);
        assert_eq!(split_csv(""), vec![""]);
    }

    #[test]
    fn matches_a_host_against_every_parent_domain() {
        let set: HashSet<String> = ["example.com".to_string()].into();
        assert!(has_popular_suffix("a.b.example.com", &set));
        assert!(has_popular_suffix("example.com", &set));
        assert!(!has_popular_suffix("notexample.com", &set));
    }
}
