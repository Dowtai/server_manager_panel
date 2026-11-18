#!/bin/bash
set -euo pipefail
umask 077
awg-quick strip /data/awg0.conf > /data/awg0.stripped
trap 'rm -f /data/awg0.stripped' EXIT
awg syncconf awg0 /data/awg0.stripped
