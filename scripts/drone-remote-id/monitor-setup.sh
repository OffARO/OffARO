#!/usr/bin/env bash
# OffARO Drone Remote ID — put a (second) Wi-Fi adapter into monitor mode on Linux.
#
#   sudo scripts/drone-remote-id/monitor-setup.sh <interface> [channel] [--hop]
#
#   <interface>  the adapter to use for capture, e.g. wlan1 (NOT the one you are online with)
#   [channel]    Wi-Fi channel to listen on; Remote ID beacons use channel 6 (2.4 GHz)
#                or 149 (5 GHz). Default 6.
#   --hop        stay in the foreground and alternate between channels 6 and 149 every 2 s
#
# Then enable "Local Wi-Fi adapter" in OffARO → Map Settings → Drone Remote ID with this
# interface name. tcpdump needs capture rights without root (once):
#   sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
#
# Undo: sudo ip link set <interface> down; sudo iw dev <interface> set type managed; sudo ip link set <interface> up
set -euo pipefail

IF="${1:-}"
CH=6
HOP=0
for a in "${@:2}"; do
  case "$a" in
    --hop) HOP=1 ;;
    *) CH="$a" ;;
  esac
done
if [ -z "$IF" ]; then
  echo "usage: $0 <interface> [channel] [--hop]" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo (changing interface modes needs root)" >&2
  exit 1
fi
command -v iw >/dev/null || { echo "iw not found — install the 'iw' package" >&2; exit 1; }

# NetworkManager would otherwise take the adapter back; tell it to leave this one alone.
if command -v nmcli >/dev/null 2>&1; then
  nmcli device set "$IF" managed no 2>/dev/null || true
fi

ip link set "$IF" down
iw dev "$IF" set type monitor
ip link set "$IF" up
iw dev "$IF" set channel "$CH"
echo "$IF is in monitor mode on channel $CH"

if [ "$HOP" -eq 1 ]; then
  echo "hopping between channels 6 and 149 (Ctrl-C to stop)"
  trap 'exit 0' INT TERM
  while true; do
    for c in 6 149; do
      iw dev "$IF" set channel "$c" 2>/dev/null || true
      sleep 2
    done
  done
fi
