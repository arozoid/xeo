#!/usr/bin/env bash
# Install the `xeo` interpreter from source.
#
# Detects and checks the host architecture, builds a release binary with
# cargo, and installs it to ~/.local/bin (or --prefix). If the `xeon` package
# manager is present, the interpreter is also registered with it (xeon
# bootstrap) so scripts installed through xeon can find it.
#
# Usage:
#   ./install.sh [--prefix DIR]
set -euo pipefail

#-------------- host detection / arch check --------------#
case "$(uname -s)" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  CYGWIN*|MINGW*|MSYS*) PLATFORM="windows" ;;
  *)      PLATFORM="unknown" ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)             ARCH="$(uname -m)" ;;
esac

echo "==> host: ${ARCH}-${PLATFORM}"

case "$ARCH" in
  x86_64|arm64) ;; # supported — continue
  *)
    echo "!! arch '${ARCH}' is not a supported build target" >&2
    echo "   supported arches: x86_64, arm64" >&2
    exit 1
    ;;
esac

#-------------- options --------------#
PREFIX="${PREFIX:-$HOME/.local}"
for arg in "$@"; do
  case "$arg" in
    --prefix=*) PREFIX="${arg#--prefix=}" ;;
  esac
done

#-------------- locate rust --------------#
if ! command -v cargo >/dev/null 2>&1; then
  echo "!! rust/cargo not found" >&2
  echo "   install it with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
  exit 1
fi

#-------------- build --------------#
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "==> building xeo from $REPO_DIR"
( cd "$REPO_DIR" && cargo build --release )

BIN_SRC="$REPO_DIR/target/release/xeo"
if [ ! -f "$BIN_SRC" ]; then
  echo "!! build did not produce $BIN_SRC" >&2
  exit 1
fi

#-------------- install --------------#
mkdir -p "$PREFIX/bin"
if [ -w "$PREFIX/bin" ]; then
  cp "$BIN_SRC" "$PREFIX/bin/xeo"
elif [ "${EUID:-$(id -u)}" -eq 0 ]; then
  cp "$BIN_SRC" "$PREFIX/bin/xeo"
else
  echo "!! no write permission for $PREFIX/bin (elsewhere xeo would need sudo)" >&2
  echo "   rerun as root, or pass --prefix=<dir>:" >&2
  echo "     ./install.sh --prefix=~/.local" >&2
  exit 1
fi
chmod +x "$PREFIX/bin/xeo"

VER="$("$REPO_DIR/target/release/xeo" --version 2>/dev/null | head -n1 || true)"
echo "==> installed $VER"
echo "   binary: $PREFIX/bin/xeo"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "   note: add $PREFIX/bin to your PATH to use xeo" ;;
esac

#-------------- register with xeon (if present) --------------#
if command -v xeon >/dev/null 2>&1; then
  echo "==> registering xeo with xeon"
  xeon bootstrap "$PREFIX/bin/xeo" 2>/dev/null \
    && echo "   xeo registered with xeon" \
    || echo "   (could not register with xeon — you can run \`xeon bootstrap $PREFIX/bin/xeo\`)"
fi
