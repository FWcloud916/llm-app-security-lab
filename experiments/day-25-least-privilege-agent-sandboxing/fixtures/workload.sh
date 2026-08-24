#!/bin/sh
set -u

operation="${1:-}"
input_mutated=false
rootfs_written=false
network_interface=false
private_visible=false
cap_eff="$(awk '/CapEff:/ {print $2}' /proc/self/status)"

if [ -e /input/private.txt ]; then
  private_visible=true
fi

case "$operation" in
  normal)
    if [ -r /input/public.txt ]; then
      head -c 128 /input/public.txt >/dev/null
    fi
    ;;
  read-private)
    if [ -r /input/private.txt ]; then
      head -c 128 /input/private.txt >/dev/null
    fi
    ;;
  network-interface)
    if [ -e /sys/class/net/eth0 ]; then
      network_interface=true
    fi
    ;;
  sandbox-probes)
    if printf '%s\n' probe >>/input/public.txt 2>/dev/null; then
      input_mutated=true
    fi
    if printf '%s\n' probe >/etc/day25-probe 2>/dev/null; then
      rootfs_written=true
    fi
    if [ -e /sys/class/net/eth0 ]; then
      network_interface=true
    fi
    ;;
  network-fetch)
    ;;
  *)
    exit 2
    ;;
esac

printf '{"operation":"%s","input_mutated":%s,"rootfs_written":%s,"network_interface":%s,"private_visible":%s,"cap_eff":"%s","network_request_attempted":false}\n' \
  "$operation" "$input_mutated" "$rootfs_written" "$network_interface" "$private_visible" "$cap_eff"
