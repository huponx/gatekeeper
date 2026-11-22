#!/usr/bin/env bash
# Prints the routes.yaml the chart ships (routes.yaml) with a local upstream
# for identity, for local runs and the web e2e. Usage: scripts/routes.sh [identity gRPC target]
set -euo pipefail
dir=$(cd "$(dirname "$0")/.." && pwd)
printf 'upstreams:\n  identity: {target: "%s"}\n' "${1:-localhost:9090}"
cat "$dir/routes.yaml"
