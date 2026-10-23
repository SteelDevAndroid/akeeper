#!/usr/bin/env bash
set -euo pipefail

apk="$1"
build_tools="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
"$build_tools/zipalign" -c -P 16 -v 4 "$apk" > /dev/null

readelf="$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$apk" 'lib/*' -d "$tmp"

status=0
while IFS= read -r so; do
    while IFS= read -r align; do
        if (( align < 16384 )); then
            echo "Segment LOAD non aligné 16 KB ($align) : ${so#"$tmp"/}"
            status=1
        fi
    done < <("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }')
done < <(find "$tmp/lib" -name '*.so')
exit "$status"
