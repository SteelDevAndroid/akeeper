#!/usr/bin/env bash
# Régénère la liste intégrée à l'APK (rules/src/main/assets/default-rules.akrb) depuis HaGeZi LIGHT.
# Elle n'est pas signée Ed25519 : son authenticité est celle de l'APK qui la contient. Les mises à jour, elles,
# sont toujours signées (docs/bundle-regles.md). LIGHT_LIST=<fichier> évite le téléchargement.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

list="${LIGHT_LIST:-$tmp/light.txt}"
if [ -z "${LIGHT_LIST:-}" ]; then
    curl -fsSL -o "$list" https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt
fi

cat > "$tmp/notice.txt" <<NOTICE
HaGeZi's Multi LIGHT, liste intégrée : licence GPL-3.0, https://github.com/hagezi/dns-blocklists
Téléchargée le $(date -u +%F).
NOTICE

out="$root/rules/src/main/assets/default-rules.akrb"
mkdir -p "$(dirname "$out")"
cd "$root/rust"
cargo run -q --locked -p akeeper-bundle -- build-unsigned \
    --ads "$list" --notice "$tmp/notice.txt" --created "$(date -u +%s)" --out "$out"
