#!/bin/bash
set -euo pipefail
umask 077
# Parse and apply in an isolated disposable netns before touching live configuration.
amneziawg-go awgcheck
trap 'ip link del awgcheck 2>/dev/null || true' EXIT
awg-quick strip "$1" >/tmp/awgcheck.conf
awg setconf awgcheck /tmp/awgcheck.conf
