#!/bin/sh
set -e

BINARY="chainwatch"
CACHE_DIR="$HOME/.chainwatch"

# Find the installed binary
INSTALL_PATH=$(command -v "$BINARY" 2>/dev/null || true)

if [ -z "$INSTALL_PATH" ]; then
  # Not in PATH — check common locations
  for loc in "/usr/local/bin/$BINARY" "$HOME/.local/bin/$BINARY" "$(go env GOPATH 2>/dev/null)/bin/$BINARY"; do
    if [ -f "$loc" ]; then
      INSTALL_PATH="$loc"
      break
    fi
  done
fi

if [ -z "$INSTALL_PATH" ]; then
  echo "chainwatch not found. Nothing to remove."
  exit 0
fi

echo "Removing $INSTALL_PATH..."
rm -f "$INSTALL_PATH"
echo "Done."

# Offer to remove cache
if [ -d "$CACHE_DIR" ]; then
  printf "Remove cached scan data at %s? [y/N] " "$CACHE_DIR"
  read -r answer
  case "$answer" in
    [yY]*)
      rm -rf "$CACHE_DIR"
      echo "Cache removed."
      ;;
    *)
      echo "Cache kept."
      ;;
  esac
fi
