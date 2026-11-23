#!/usr/bin/env bash
# Prints the routes.yaml the chart ships (routes.yaml) with a local upstream for identity and the
# descriptor set (descriptors.binpb, identity does not serve gRPC reflection), for local runs and the
# e2e scripts. Usage: scripts/routes.sh [identity gRPC target]
set -euo pipefail
dir=$(cd "$(dirname "$0")/.." && pwd)
printf 'descriptors: %s/descriptors.binpb\nupstreams:\n  identity: {target: "%s"}\n' "$dir" "${1:-localhost:9090}"
cat "$dir/routes.yaml"
