#!/usr/bin/env bash
# Construit, signe et vérifie le bundle de règles publié (docs/bundle-regles.md) dans <dossier de sortie>/bundle.akrb.
#
# Variables :
#   RULES_SEED_B64      graine Ed25519 en base64 (secret) ; jamais affichée
#   RULES_KEY_ID        0 ou 1, index de la clé publique embarquée dans l'app (défaut 0)
#   RULES_PUBLIC_KEYS   clés publiques hex, séparées par une virgule : le bundle est revérifié avec elles avant publication
#   URLHAUS_AUTH_KEY    clé abuse.ch (secret, facultative) ; sans elle, la catégorie « malware » est omise
#   LIST_DIR            dossier de listes déjà téléchargées (light.txt, phishing.txt, urlhaus.csv, tranco.csv) : saute le réseau
#   RULES_VERSION       version monotone du bundle (défaut : l'heure Unix)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:?usage : build-rules.sh <dossier de sortie>}"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
umask 077

: "${RULES_SEED_B64:?RULES_SEED_B64 est requis}"
: "${RULES_PUBLIC_KEYS:?RULES_PUBLIC_KEYS est requis}"
key_id="${RULES_KEY_ID:-0}"
version="${RULES_VERSION:-$(date -u +%s)}"
lists="${LIST_DIR:-$tmp}"

fetch() { # <url> <fichier>
    if [ ! -s "$2" ]; then
        curl -fsSL --retry 3 --retry-delay 5 --max-time 180 -o "$2" "$1"
    fi
}

fetch https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt "$lists/light.txt"
fetch https://phishing.army/download/phishing_army_blocklist.txt "$lists/phishing.txt"

count() { grep -cvE '^\s*(#|$)' "$1" || true; }
# Une source vide ou tronquée ne doit jamais être publiée : les appareils perdraient leur protection sans le savoir.
[ "$(count "$lists/light.txt")" -ge 30000 ] || { echo "HaGeZi LIGHT : liste trop courte" >&2; exit 1; }
[ "$(count "$lists/phishing.txt")" -ge 10000 ] || { echo "Phishing Army : liste trop courte" >&2; exit 1; }

args=(--ads "$lists/light.txt" --phishing "$lists/phishing.txt"
      --doh "$root/rules/sources/doh-hosts.txt" --doh-ips "$root/rules/sources/doh-ips.txt")
# Exclusions : fichier versionné, puis liste facultative (ALLOW_LIST_URL, par exemple une liste blanche française).
cp "$root/rules/sources/default-allow.txt" "$tmp/allow.txt"
allow_extra=no
if [ -n "${ALLOW_LIST_URL:-}" ]; then
    if curl -fsSL --retry 3 --retry-delay 5 --max-time 120 -o "$lists/allow-extra.txt" "$ALLOW_LIST_URL" \
        && [ "$(count "$lists/allow-extra.txt")" -ge 1 ]; then
        printf '\n' >> "$tmp/allow.txt"
        cat "$lists/allow-extra.txt" >> "$tmp/allow.txt"
        allow_extra=yes
    else
        # Une liste blanche en panne ne doit pas empêcher de publier les règles de blocage.
        echo "ALLOW_LIST_URL illisible : exclusions du dépôt seules" >&2
    fi
fi
args+=(--allow "$tmp/allow.txt")
malware=no
if [ -n "${URLHAUS_AUTH_KEY:-}" ]; then
    # La clé fait partie de l'URL : -s sans -v, et --fail pour que curl n'affiche pas l'URL en cas d'erreur.
    if [ ! -s "$lists/urlhaus.csv" ]; then
        curl -fsS --retry 3 --max-time 180 -o "$lists/urlhaus.csv" \
            "https://urlhaus-api.abuse.ch/v2/files/exports/${URLHAUS_AUTH_KEY}/recent.csv" || rm -f "$lists/urlhaus.csv"
    fi
    fetch "https://tranco-list.eu/top-1m.csv.zip" "$tmp/tranco.zip" || true
    if [ -s "$lists/urlhaus.csv" ] && { [ -s "$lists/tranco.csv" ] || { [ -s "$tmp/tranco.zip" ] && unzip -p "$tmp/tranco.zip" > "$lists/tranco.csv"; }; }; then
        (cd "$root/rust" && cargo run -q --locked -p akeeper-bundle -- urlhaus \
            --csv "$lists/urlhaus.csv" --tranco "$lists/tranco.csv" --top 100000 --out "$tmp/malware.txt")
        if [ -s "$tmp/malware.txt" ]; then
            args+=(--malware "$tmp/malware.txt")
            malware=yes
        fi
    fi
fi

{
    echo "HaGeZi's Multi LIGHT : licence GPL-3.0, https://github.com/hagezi/dns-blocklists"
    echo "Phishing Army : https://phishing.army/ (données de PhishTank, OpenPhish, CERT.PL, Phishunt, urlscan.io, PhishStats, StalkPhish, URLAbuse et AntiPhish.org)"
    [ "$malware" = yes ] && echo "URLhaus (abuse.ch) : https://urlhaus.abuse.ch/, usage soumis à l'accord d'abuse.ch"
    [ "$allow_extra" = yes ] && echo "Exclusions : ${ALLOW_LIST_NOTICE:-$ALLOW_LIST_URL}"
    echo "Construit le $(date -u +%F) à $(date -u +%H:%M) UTC, version $version."
} > "$tmp/notice.txt"

retrieved_at="$(date -u +%s)"
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
{
    printf '1\tHaGeZi Multi LIGHT\tGPL-3.0\thttps://github.com/hagezi/dns-blocklists\t%s\t%s\t%s\n' \
        "$retrieved_at" "$((retrieved_at + 28800))" "$(sha256_file "$lists/light.txt")"
    printf '3\tPhishing Army\tSee upstream terms\thttps://phishing.army/\t%s\t%s\t%s\n' \
        "$retrieved_at" "$((retrieved_at + 14400))" "$(sha256_file "$lists/phishing.txt")"
    [ "$malware" = yes ] && printf '2\tURLhaus\tabuse.ch agreement\thttps://urlhaus.abuse.ch/\t%s\t%s\t%s\n' \
        "$retrieved_at" "$((retrieved_at + 43200))" "$(sha256_file "$tmp/malware.txt")"
    printf '5\taKeeper default allow\tGPL-3.0\trepository:rules/sources/default-allow.txt\t%s\t0\t%s\n' \
        "$retrieved_at" "$(sha256_file "$root/rules/sources/default-allow.txt")"
    printf '4\taKeeper DoH hosts\tGPL-3.0\trepository:rules/sources/doh-hosts.txt\t%s\t0\t%s\n' \
        "$retrieved_at" "$(sha256_file "$root/rules/sources/doh-hosts.txt")"
    printf '4\taKeeper DoH IPs\tGPL-3.0\trepository:rules/sources/doh-ips.txt\t%s\t0\t%s\n' \
        "$retrieved_at" "$(sha256_file "$root/rules/sources/doh-ips.txt")"
    [ "$allow_extra" = yes ] && printf '5\tExternal allow list\t%s\t%s\t%s\t0\t%s\n' \
        "${ALLOW_LIST_NOTICE:-unspecified}" "$ALLOW_LIST_URL" "$retrieved_at" \
        "$(sha256_file "$lists/allow-extra.txt")"
} > "$tmp/provenance.txt"
args+=(--provenance "$tmp/provenance.txt")

seed="$tmp/seed"
printf '%s' "$RULES_SEED_B64" | base64 -d > "$seed"

cd "$root/rust"
cargo run -q --locked -p akeeper-bundle -- build --seed "$seed" --key-id "$key_id" --version "$version" \
    "${args[@]}" --notice "$tmp/notice.txt" --out "$out/bundle.akrb"
# Revérification avec les clés publiques que l'app embarque : un bundle que l'app refuserait n'est pas publié.
IFS=',' read -r -a keys <<< "$RULES_PUBLIC_KEYS"
cargo run -q --locked -p akeeper-bundle -- verify "$out/bundle.akrb" "${keys[@]}"
echo "catégories : ads phishing doh allow$([ "$malware" = yes ] && echo ' malware')"
