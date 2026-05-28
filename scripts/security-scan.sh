#!/usr/bin/env bash
set -euo pipefail

if command -v gosec >/dev/null 2>&1; then
  gosec_bin=(gosec)
else
  gosec_bin=(go run github.com/securego/gosec/v2/cmd/gosec@latest)
fi

"${gosec_bin[@]}" \
  -quiet \
  -exclude=G104 \
  -exclude-dir=scripts/vulnerable-fixture \
  ./...
