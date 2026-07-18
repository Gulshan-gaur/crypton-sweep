#!/usr/bin/env sh
set -eu

repo="Gulshan-gaur/crypton-sweep"
version="${CRYPTON_SWEEP_VERSION:-latest}"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) target="x86_64-unknown-linux-gnu" ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Darwin:arm64) target="aarch64-apple-darwin" ;;
  *) echo "Unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
archive="crypton-sweep-${target}.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  "$base/$archive" --output "$tmp/$archive"
tar -xzf "$tmp/$archive" -C "$tmp"

bin_dir="${CRYPTON_SWEEP_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$bin_dir"
install "$tmp/crypton-sweep" "$bin_dir/crypton-sweep"
echo "Installed crypton-sweep to $bin_dir/crypton-sweep"
case ":${PATH}:" in
  *":$bin_dir:"*) ;;
  *) echo "Add $bin_dir to PATH to run crypton-sweep" ;;
esac
