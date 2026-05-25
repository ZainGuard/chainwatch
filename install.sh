#!/bin/sh
set -e

# chainwatch installer
# Usage: curl -fsSL https://raw.githubusercontent.com/zainguard/chainwatch/main/install.sh | bash

REPO="zainguard/chainwatch"
BINARY="chainwatch"
INSTALL_DIR="/usr/local/bin"

# Resolve latest version from GitHub API if not set
if [ -z "$CHAINWATCH_VERSION" ]; then
  CHAINWATCH_VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
fi

if [ -z "$CHAINWATCH_VERSION" ]; then
  echo "error: could not determine latest version" >&2
  exit 1
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "error: unsupported OS: $OS (use go install on Windows)" >&2
    exit 1
    ;;
esac

VERSION_NUM="${CHAINWATCH_VERSION#v}"
ARCHIVE="${BINARY}_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${CHAINWATCH_VERSION}/${ARCHIVE}"

echo "Installing chainwatch ${CHAINWATCH_VERSION} (${OS}/${ARCH})..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$ARCHIVE"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

# Install — try /usr/local/bin, fall back to ~/.local/bin
if [ -w "$INSTALL_DIR" ]; then
  install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
  echo "Installed to $INSTALL_DIR/$BINARY"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
  echo "Installed to $INSTALL_DIR/$BINARY"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo ""
      echo "Add to your shell profile:"
      echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
      ;;
  esac
fi

echo ""
chainwatch --version
