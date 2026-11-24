#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

binary=$(realpath "${1:?usage: packaging/build.sh BINARY OUTPUT_DIR}")
mkdir -p "${2:?usage: packaging/build.sh BINARY OUTPUT_DIR}"
out=$(realpath "$2")
cd -- "$(dirname -- "$0")/.."

version_line=$("$binary" --version)
if [[ ! $version_line =~ ^exordos-link\ ([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    echo "Unexpected binary version: $version_line" >&2
    exit 1
fi
version=${BASH_REMATCH[1]}
arch=$(dpkg --print-architecture)
name="exordos-link_${version}_linux_${arch}"
work=$(mktemp -d)
trap 'rm -r -- "$work"' EXIT

install -Dm755 "$binary" "$work/$name/exordos-link"
install -Dm644 README.md "$work/$name/README.md"
install -Dm644 LICENSE "$work/$name/LICENSE"
install -Dm644 examples/*.json -t "$work/$name/examples"
tar -czf "$out/$name.tar.gz" -C "$work" "$name"

deb="$work/debian/exordos-link"
install -Dm755 "$binary" "$deb/usr/bin/exordos-link"
install -Dm644 README.md "$deb/usr/share/doc/exordos-link/README.md"
install -Dm644 LICENSE "$deb/usr/share/doc/exordos-link/copyright"
install -Dm644 examples/*.json -t "$deb/usr/share/doc/exordos-link/examples"

mkdir "$deb/DEBIAN"
cat > "$work/debian/control" <<'EOF'
Source: exordos-link
Section: net
Priority: optional
Maintainer: Exordos <exordos@users.noreply.github.com>

Package: exordos-link
Architecture: any
Description: SPIFFE-authenticated TCP proxy
EOF
dependencies=$(cd "$work" && dpkg-shlibdeps -O -edebian/exordos-link/usr/bin/exordos-link)
cat > "$deb/DEBIAN/control" <<EOF
Package: exordos-link
Version: $version
Architecture: $arch
Section: net
Priority: optional
Maintainer: Exordos <exordos@users.noreply.github.com>
Depends: ${dependencies#shlibs:Depends=}
Homepage: https://github.com/exordos/exordos_link
Description: SPIFFE-authenticated TCP proxy for private service-to-service links
EOF
dpkg-deb --root-owner-group --build "$deb" "$out/exordos-link_${version}_${arch}.deb"
