#!/usr/bin/env bash
# Serve this folder over http, for browsers that dislike file:// URLs.
#   ./serve.sh [port]
set -euo pipefail
PORT="${1:-8099}"
cd "$(dirname "${BASH_SOURCE[0]}")"
echo "Open http://127.0.0.1:${PORT}/index.html  (ctrl-c to stop)"
exec python3 -m http.server "${PORT}"
