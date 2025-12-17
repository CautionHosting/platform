#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

BINARY_NAME="caution"
SOURCE="out/caution"
INSTALL_DIR="${HOME}/.local/bin"

# Check if source binary exists
if [ ! -f "$SOURCE" ]; then
    echo "Error: $SOURCE not found"
    echo "Run 'make cli' first to build the CLI"
    exit 1
fi

# Create install directory if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Copy and rename binary
cp "$SOURCE" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

echo "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"

# Check if install dir is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Note: $INSTALL_DIR is not in your PATH"
    echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi