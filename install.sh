#!/bin/bash

# configuration
xeon_dir="$HOME/.xeon"
xeon_bin="$xeon_dir/bin"
local_bin="$HOME/.local/bin"
binary_name="xeo"
download_url="https://github.com/arozoid/xeo/releases/latest/download/xeo"

echo "--- installing xeo ---"

# 1. create directories
mkdir -p "$xeon_bin"
mkdir -p "$local_bin"

# 2. handle binary installation
if [ -f "./target/release/$binary_name" ]; then
    echo "found local build, installing..."
    cp "./target/release/$binary_name" "$xeon_bin/$binary_name"
elif [ -f "./$binary_name" ]; then
    echo "found binary in current folder, installing..."
    cp "./$binary_name" "$xeon_bin/$binary_name"
else
    echo "local binary not found. attempting to download..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$xeon_bin/$binary_name"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$xeon_bin/$binary_name" "$download_url"
    else
        echo "error: neither curl nor wget found. please install one or build xeo from source."
        exit 1
    fi
fi

# 3. set permissions
chmod +x "$xeon_bin/$binary_name"

# 4. create symlink
ln -sf "$xeon_bin/$binary_name" "$local_bin/$binary_name"

# 5. update path for mac/linux shells
shell_type=$(basename "$SHELL")
if [[ ":$PATH:" != *":$local_bin:"* ]]; then
    if [ "$shell_type" == "zsh" ]; then
        config_file="$HOME/.zshrc"
    else
        config_file="$HOME/.bashrc"
    fi
    
    echo "adding $local_bin to path in $config_file"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$config_file"
    echo "please run 'source $config_file' to start using xeo."
fi

echo "--- success: xeo installed to $xeon_bin ---"