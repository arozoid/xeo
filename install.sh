#!/bin/bash

# configuration
xeon_dir="$HOME/.xeon"
xeon_bin="$xeon_dir/bin"
local_bin="$HOME/.local/bin"
binary_name="xeo"
REPO="arozoid/xeo"
BASE_URL="https://github.com/$REPO/releases/latest/download"

echo "--- installing xeo ---"

# 1. create directories
mkdir -p "$xeon_bin"
mkdir -p "$local_bin"

# 2. architecture & OS detection (The logic bridge)
OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"

if [ "$OS_TYPE" == "Linux" ]; then
    if [[ "$ARCH_TYPE" == "aarch64" || "$ARCH_TYPE" == "arm64" ]]; then
        ARTIFACT="xeo-arm64"
    else
        ARTIFACT="xeo-linux"
    fi
elif [ "$OS_TYPE" == "Darwin" ]; then
    ARTIFACT="xeo-macos"
else
    echo "Unsupported OS: $OS_TYPE"
    exit 1
fi

# 3. handle binary installation
if [ -f "./target/release/$binary_name" ]; then
    echo "found local build, installing..."
    cp "./target/release/$binary_name" "$xeon_bin/$binary_name"
elif [ -f "./$binary_name" ]; then
    echo "found binary in current folder, installing..."
    cp "./$binary_name" "$xeon_bin/$binary_name"
else
    echo "Downloading $ARTIFACT for $OS_TYPE ($ARCH_TYPE)..."
    DOWNLOAD_URL="$BASE_URL/$ARTIFACT"
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "$xeon_bin/$binary_name"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$xeon_bin/$binary_name" "$DOWNLOAD_URL"
    else
        echo "error: neither curl nor wget found."
        exit 1
    fi
fi

# 4. set permissions & symlink
chmod +x "$xeon_bin/$binary_name"
ln -sf "$xeon_bin/$binary_name" "$local_bin/$binary_name"

# 5. update path (fixed to handle path more safely)
if [[ ":$PATH:" != *":$local_bin:"* ]]; then
    SHELL_PROFILE=""
    case "$SHELL" in
        */zsh)  SHELL_PROFILE="$HOME/.zshrc" ;;
        */bash) SHELL_PROFILE="$HOME/.bashrc" ;;
        *)      SHELL_PROFILE="$HOME/.profile" ;;
    esac
    
    echo "adding $local_bin to PATH in $SHELL_PROFILE"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_PROFILE"
    echo "Run 'source $SHELL_PROFILE' to start using xeo."
fi

echo "--- success: xeo installed to $local_bin ---"