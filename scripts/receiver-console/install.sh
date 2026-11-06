#!/usr/bin/env bash
# Install the OffARO receiver console on a Raspberry Pi whose console (tty1) auto-logs
# in a user and runs a viewer — the usual dump1090 "view1090 on the attached screen" setup.
#
#   sudo bash install.sh [--user pi] [--lat 69.70 --lon 18.88] [extra receiver_console.py options]
#
# What it does
#   * copies receiver_console.py to /usr/local/bin
#   * writes ~<user>/view.sh so it starts the console (the previous view.sh is kept as view.sh.bak);
#     if ~<user>/.bashrc does not already run view.sh on tty1, a line is appended that does
#   * does NOT restart the running console; log out of tty1 (or `pkill -t tty1 -u <user>`) and
#     the autologin brings the new console up
#
# Your AIS software must send NMEA to UDP 127.0.0.1:2222 (AIS Dispatcher: add a UDP
# destination; rtl_ais: -h 127.0.0.1 -P 2222; AIS-catcher: -u 127.0.0.1 2222).
set -euo pipefail

USER_NAME=pi
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_NAME="$2"; shift 2 ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
[ -n "$HOME_DIR" ] || { echo "no such user: $USER_NAME" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

install -m 755 "$HERE/receiver_console.py" /usr/local/bin/receiver_console.py
python3 -m py_compile /usr/local/bin/receiver_console.py

VIEW="$HOME_DIR/view.sh"
if [ -f "$VIEW" ] && ! grep -q receiver_console "$VIEW"; then
  cp -p "$VIEW" "$VIEW.bak"
  echo "kept the previous $VIEW as $VIEW.bak"
fi
{
  echo '#!/bin/sh'
  echo '# OffARO receiver console (ADS-B + AIS + addresses) on the attached screen.'
  echo '# Restarts itself if it ever exits; edit the options below to taste.'
  echo 'while true; do'
  printf '  /usr/bin/python3 /usr/local/bin/receiver_console.py --log /tmp/receiver_console.log'
  for a in "${EXTRA[@]}"; do printf ' %q' "$a"; done
  echo
  echo '  sleep 2'
  echo 'done'
} > "$VIEW"
chmod 755 "$VIEW"; chown "$USER_NAME:" "$VIEW"

BASHRC="$HOME_DIR/.bashrc"
if ! grep -qE '^[^#]*view\.sh' "$BASHRC" 2>/dev/null; then
  cat >> "$BASHRC" <<EOF

# OffARO receiver console on the attached screen (tty1 autologin)
if [ "\$(tty)" = /dev/tty1 ]; then exec $VIEW; fi
EOF
  echo "added the tty1 start to $BASHRC"
fi
echo "installed. Start it now with:  pkill -t tty1 -u $USER_NAME   (the autologin restarts the console)"
