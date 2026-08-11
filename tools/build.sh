#!/bin/bash
# Build the template bundle locally; run the generated scripts on Proxmox.
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

exec python3 "$script_dir/build.py" "$@"
