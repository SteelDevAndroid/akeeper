#!/usr/bin/env bash
# Empreintes SHA-256 (base64) des clés publiques de la chaîne du serveur de règles, pour akeeper.rulesPins.
# À lancer depuis un réseau sans proxy TLS : un proxy d'inspection fausserait la chaîne.
# Le certificat feuille est ignoré (il change à chaque renouvellement) ; la racine est cherchée dans le magasin système.
set -euo pipefail

host="${1:?usage : rules-pins.sh <hôte> [magasin de CA, défaut /etc/ssl/certs]}"
store="${2:-/etc/ssl/certs}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl s_client -connect "$host:443" -servername "$host" -showcerts </dev/null 2>/dev/null \
    | awk -v dir="$tmp" '/BEGIN CERTIFICATE/ { n++ } /BEGIN CERTIFICATE/,/END CERTIFICATE/ { print > (dir "/cert" n ".pem") }'
[ -f "$tmp/cert1.pem" ] || { echo "Aucun certificat reçu de $host" >&2; exit 1; }

spki() {
    openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
}

last=""
for cert in $(ls "$tmp"/cert*.pem | sort -V | tail -n +2); do
    echo "$(spki "$cert")  intermédiaire : $(openssl x509 -in "$cert" -noout -subject)"
    last="$cert"
done
last="${last:-$tmp/cert1.pem}"

root="$store/$(openssl x509 -in "$last" -noout -issuer_hash).0"
if [ -f "$root" ]; then
    echo "$(spki "$root")  racine : $(openssl x509 -in "$root" -noout -subject)"
else
    echo "Racine introuvable dans $store : $(openssl x509 -in "$last" -noout -issuer)" >&2
fi
