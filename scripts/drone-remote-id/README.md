# Drone Remote ID receiver

Lets OffARO show drones that broadcast **Remote ID** (ASTM F3411 / ASD-STAN, the "licence plate" every drone over 250 g transmits in the EU and the US). The drone sends its position, operator ID and operator position as Wi-Fi beacons on channel 6 (sometimes 149). A Wi-Fi adapter in **monitor mode** hears them; OffARO decodes them and draws the drones on the map.

OffARO itself can run tcpdump on a local adapter (Linux). The programs here are for the better setup: a **Raspberry Pi with the adapter and an external antenna**, placed high, which any OffARO on Windows, macOS or Linux connects to.

| File | Purpose |
| --- | --- |
| `remoteid_filter.py` | **Use this.** Puts the adapter into monitor mode, keeps tcpdump running and serves the capture to OffARO as a pcap stream on TCP port 5003. Forwards **only the frames that carry Remote ID**; everything else (ten beacons a second from every access point around) is dropped on the Pi. About 1 kB/s per drone in the air, nothing when the sky is empty, so it works over 4G. Several OffARO clients may connect at once. Python 3 standard library only. |
| `remoteid-filter.service` | systemd unit that starts the filter at boot, with the capabilities tcpdump needs and nothing else. |
| `monitor-setup.sh` | Puts an adapter into monitor mode on a channel, once (`--hop` alternates between channels 6 and 149). Used when OffARO runs tcpdump itself on a local adapter. |
| `pi-receiver.sh` | The older, simpler receiver: tcpdump piped through socat. Sends the **unfiltered** capture to one client at a time. Fine on a LAN, too much data over 4G. |
| `test_remoteid_filter.py` | Unit tests for the filter (`python3 -m unittest -q test_remoteid_filter.py`). |

## Quick start on a Raspberry Pi

```
sudo apt install iw tcpdump
ip link                                   # find the adapter's name, e.g. wlan1
sudo ./remoteid_filter.py --interface wlan1 --monitor-channel 6 --listen 5003
```

The filter listens on `127.0.0.1` only, for use through an SSH tunnel. Add `--bind 0.0.0.0` to reach it directly over the LAN; the stream has no authentication, so anyone who can connect sees the drone positions.

From the laptop:

```
ssh -L 5003:localhost:5003 pi@<the-pi>
```

In OffARO: **Map Settings → Drone Remote ID → Remote receiver**, address `127.0.0.1`, port `5003`. The card's status line shows when the stream is connected; with the filter in place the frame counter only moves when a drone is heard.

## Run it as a service

```
sudo install -m 755 remoteid_filter.py /usr/local/bin/
sudo install -m 644 remoteid-filter.service /etc/systemd/system/
sudo nano /etc/systemd/system/remoteid-filter.service   # set the interface name
sudo systemctl daemon-reload
sudo systemctl enable --now remoteid-filter
journalctl -u remoteid-filter -f
```

The log prints a statistics line every minute: frames seen, Remote ID frames forwarded, clients connected.

## Adapters

The adapter must support monitor mode under Linux. Known to work: Ralink RT5370 (2.4 GHz only), Atheros AR9271, MediaTek MT7612U (2.4 + 5 GHz). The Pi's built-in Wi-Fi does not. Use a second adapter for the capture so the Pi's own network connection is untouched.
