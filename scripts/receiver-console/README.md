# Receiver console — ADS-B and AIS on the receiver box's own screen

A full-screen text display for a Raspberry Pi (or any Linux box) that runs **dump1090-fa**
and an **AIS receiver**, replacing `view1090` on the attached screen. One screen, two panes,
plus the box's IP address and the ports to point OffARO at — so the box can be used on a
field LAN with no internet and no SSH tunnel.

```
 aisadsb  wlan0 192.168.1.50  rx 69.7020N 18.8850E                     09:06:06
 ADS-B  3 aircraft  ·  dump1090 ok · 386 msg/min
 ICAO   FLIGHT   SQWK   ALT ft  SPD kt  TRK  DIST km  BRG    V/S  AGE   RSSI
 47878c NOZ1480  0734     7975     267  208     28.5  197  +1344   0s  -23.3
 …
 AIS  2 vessels  ·  rx ttyACM0 · 42 msg/min
 MMSI      NAME                  SOG kt  COG  DIST km  BRG  STATUS          AGE
 257123000 FJORDKONGEN             12.3  045     23.4  180  Under way        3s
 …
 OffARO → 192.168.1.50  AIS :10111  ADS-B :30003  Remote ID :5003     sort:dist
```

## What it reads

* **ADS-B:** dump1090's `aircraft.json` (default `/run/dump1090-fa/aircraft.json`).
* **AIS:** NMEA `!AIVDM` sentences on a local UDP port (default `127.0.0.1:2222`). Add a UDP
  destination to your AIS software: AIS Dispatcher → *Destinations* → `127.0.0.1` port `2222`;
  `rtl_ais -h 127.0.0.1 -P 2222`; `AIS-catcher -u 127.0.0.1 2222`. Message types 1–5, 9, 18,
  19, 21 and 24 are decoded (position, name, call sign, navigation status).
* The header shows every IPv4 address of the box; the footer shows the ports OffARO uses
  (`--ais-port`, `--adsb-port`, `--remoteid-port`, 0 hides one). The pane titles show the
  health of each feed (no `aircraft.json`, stale file, no USB receiver, no data for N minutes).

Only Python 3 and its standard library are needed. Press `s` to sort by age instead of distance.

## Vessel names across restarts

A ship's name, call sign and type arrive only every six minutes (AIS message 5 / 24), so
with `--cache FILE` the console keeps them in a small JSON file and shows the name the moment
the first position report comes in. The file is written at most once a minute and only when
something changed; put it on persistent storage when the root file system is an overlay
(`install.sh` uses `data/vessels.json` next to itself). Entries unseen for five years are
dropped and the file is capped at 100 000 vessels.

**Seed it from OffARO:** OffARO already has the same information for every vessel it has
ever shown (`ais-static.db` in its user-data folder). On the machine that runs OffARO:

```
python3 export_offaro_cache.py --into vessels.json
scp vessels.json pi@<box>:/path/to/receiver-console/data/vessels.json
```

On the box, `export_offaro_cache.py --from-json other.json --into data/vessels.json` merges a
second file (newer "last seen" wins, missing fields are filled in). User-data folders:
macOS `~/Library/Application Support/Offaro`, Windows `%APPDATA%\Offaro`, Linux `~/.config/Offaro`.

## Install on the console (tty1 autologin)

```
sudo bash install.sh --user pi --lat 69.70 --lon 18.88
pkill -t tty1 -u pi        # the autologin restarts the console with the new program
```

`install.sh` copies `receiver_console.py` to `/usr/local/bin`, writes `~pi/view.sh` to start it
(the previous `view.sh` is kept as `view.sh.bak`) and, if `.bashrc` does not already run
`view.sh` on tty1, adds that. Extra arguments are passed on to the program; see
`receiver_console.py --help`. To go back, restore `view.sh.bak`.

## Serving OffARO on the LAN

OffARO's receivers connect directly to the box: AIS as a TCP NMEA stream (for example a
`socat UDP-RECV:10110 TCP-LISTEN:10111,fork` bridge from another AIS Dispatcher destination),
ADS-B on dump1090's port 30003 (SBS) and Remote ID on the filtering proxy's port 5003 with
`--bind 0.0.0.0` (see [`../drone-remote-id`](../drone-remote-id)). These streams have no
authentication, so only do this on a LAN you trust.

## Tests

```
python3 -m unittest test_receiver_console.py
```
