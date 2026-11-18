#!/bin/bash
set -euo pipefail
umask 077
mkdir -p /tmp/probe
cat > /tmp/probe/awgp.conf
amneziawg-go awgp
trap 'ip link del awgp 2>/dev/null || true' EXIT
awg-quick strip /tmp/probe/awgp.conf >/tmp/probe/awgp.stripped
awg setconf awgp /tmp/probe/awgp.stripped
address=$(awk '$1=="Address" {print $3}' /tmp/probe/awgp.conf)
mtu=$(awk '$1=="MTU" {print $3}' /tmp/probe/awgp.conf)
ip address add "$address" dev awgp
ip link set mtu "$mtu" up dev awgp
ip route add "$1/32" dev awgp
ip route add 1.1.1.1/32 dev awgp
ping -c 1 -W 10 "$1" >/dev/null
curl --fail --silent --max-time 20 https://1.1.1.1/cdn-cgi/trace >/dev/null
awk '{ if ($2 > 0) found=1 } END { exit !found }' < <(awg show awgp latest-handshakes)
