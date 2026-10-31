#!/usr/bin/env bash
# OffARO Drone Remote ID — remote receiver (Raspberry Pi / any Linux box with a
# monitor-mode Wi-Fi adapter and, ideally, an external antenna).
#
#   sudo scripts/drone-remote-id/pi-receiver.sh <interface> [port] [channel]
#
# Puts <interface> into monitor mode (see monitor-setup.sh), then streams every
# beacon / probe-response frame as a pcap stream to the first TCP client that
# connects on [port] (default 5003). In OffARO enable "Remote receiver" under
# Map Settings → Drone Remote ID with this machine's address and port.
#
# Needs: iw, tcpdump, socat   (apt install iw tcpdump socat)
#
# As a service: copy this file to /usr/local/bin, then
#   [Unit] Description=OffARO Remote ID receiver  After=network.target
#   [Service] ExecStart=/usr/local/bin/pi-receiver.sh wlan1 5003  Restart=always
#   [Install] WantedBy=multi-user.target
# in /etc/systemd/system/remoteid-receiver.service, `systemctl enable --now remoteid-receiver`.
set -euo pipefail

IF="${1:-}"
PORT="${2:-5003}"
CH="${3:-6}"
if [ -z "$IF" ]; then
  echo "usage: $0 <interface> [port] [channel]" >&2
  exit 1
fi
for t in iw tcpdump socat; do
  command -v "$t" >/dev/null || { echo "$t not found — apt install iw tcpdump socat" >&2; exit 1; }
done

HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$HERE/monitor-setup.sh" ]; then
  "$HERE/monitor-setup.sh" "$IF" "$CH"
else
  ip link set "$IF" down; iw dev "$IF" set type monitor; ip link set "$IF" up; iw dev "$IF" set channel "$CH"
fi

FILTER='type mgt and (subtype beacon or subtype probe-resp)'
echo "streaming pcap from $IF on TCP port $PORT (Ctrl-C to stop)"
trap 'exit 0' INT TERM
while true; do
  # One client at a time; tcpdump restarts for every new connection so the
  # client always receives a fresh pcap header.
  socat -u "EXEC:tcpdump -i $IF -U -w - -s 0 -n '$FILTER'" "TCP-LISTEN:$PORT,reuseaddr" || true
  sleep 1
done
