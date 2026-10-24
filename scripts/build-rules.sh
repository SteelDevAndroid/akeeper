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
    echo "Construit le $(date -u +%F) à $(date -u +%H:%M) UTC, version $version."
} > "$tmp/notice.txt"

seed="$tmp/seed"
printf '%s' "$RULES_SEED_B64" | base64 -d > "$seed"

cd "$root/rust"
cargo run -q --locked -p akeeper-bundle -- build --seed "$seed" --key-id "$key_id" --version "$version" \
    "${args[@]}" --notice "$tmp/notice.txt" --out "$out/bundle.akrb"
# Revérification avec les clés publiques que l'app embarque : un bundle que l'app refuserait n'est pas publié.
IFS=',' read -r -a keys <<< "$RULES_PUBLIC_KEYS"
cargo run -q --locked -p akeeper-bundle -- verify "$out/bundle.akrb" "${keys[@]}"
echo "catégories : ads phishing doh$([ "$malware" = yes ] && echo ' malware')"
