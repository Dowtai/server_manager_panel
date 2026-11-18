#!/bin/bash
set -euo pipefail
umask 077
amneziawg-go awg0
awg-quick strip /data/awg0.conf >/tmp/awg0.stripped
awg setconf awg0 /tmp/awg0.stripped
rm /tmp/awg0.stripped
address=$(awk '$1=="Address" {print $3}' /data/awg0.conf)
mtu=$(awk '$1=="MTU" {print $3}' /data/awg0.conf)
ip address add "$address" dev awg0
ip link set mtu "$mtu" up dev awg0
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
trap 'ip link del awg0 2>/dev/null || true' EXIT
trap 'exit 0' TERM INT
while sleep 5 & wait $!; do awg show awg0 public-key >/dev/null; done
