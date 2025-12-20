#!/bin/bash

# Configuration
XEON_DIR="$HOME/.xeon"
LOCAL_BIN="$HOME/.local/bin/xeo"

echo "--- uninstalling xeo ---"

# 1. Remove the symlink from local bin
if [ -L "$LOCAL_BIN" ] || [ -f "$LOCAL_BIN" ]; then
    rm "$LOCAL_BIN"
    echo "removed: $LOCAL_BIN"
else
    echo "info: no binary found in ~/.local/bin"
fi

# 2. Remove the hidden .xeon directory (contains /bin and plugins)
if [ -d "$XEON_DIR" ]; then
    rm -rf "$XEON_DIR"
    echo "removed: $XEON_DIR"
else
    echo "info: ~/.xeon directory not found"
fi

echo "--- success: xeo has been removed from your system ---"