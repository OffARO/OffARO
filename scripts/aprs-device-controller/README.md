# APRS device controller (remote station)

The remote end of OffARO's **Device Control Panel**. It runs on a small Linux box at a cabin, a repeater site or a boat, listens for signed APRS messages from your OffARO, switches **Shelly** relays (heaters, pumps, lights, radios) and answers with the state of every device. The panel in OffARO then shows the toggles in the right position.

It was written for a real cabin station with fourteen relays and has run there since 2025. Callsigns, the signing key and the addresses have been replaced with placeholders; everything else is the production code.

| File | Purpose |
| --- | --- |
| `aprs_device_controller.py` | The controller. KISS client to Direwolf, APRS-IS client as a second path, HMAC-MD5 message signing per the ARETF APRS Authentication draft, retries, de-duplication and reverse-path replies. |
| `aprs_is.py` | APRS-IS login/parse helpers used by the controller. |
| `shelly_control.py` | Switch a Shelly Gen 2/3 relay on or off over its HTTP RPC API (also a small command-line tool). Needs the Python `requests` package. |
| `shelly_status.py` | Prints the state of every device in `shelly.txt`. |
| `shelly.txt` | The device list: one line per relay, in the **same order** as the devices in the OffARO template. Example included. |
| `aprs-device-controller.service` | systemd unit. |

## Protocol (must match the OffARO contact)

| Setting | Here | In OffARO |
| --- | --- | --- |
| `MY_CALLSIGN` | the remote station's callsign | the contact's callsign |
| `AUTHORIZED_SENDER` | your OffARO callsign | *Settings → Station → Callsign* |
| `SIGNING_KEY` | shared secret | the contact's **Signing Key**, with **Sign outgoing messages** ticked |
| `STATUS_PREFIX` / `CONTROL_PREFIX` / `STATUS_COMMAND` | `S:` / `C:` / `status` | the template's Status Prefix, Control Prefix and Status Command |
| Protocol | three states `0`/`1`/`2` | template protocol **Custom** |
| Device order | lines of `shelly.txt` | the template's Groups & Devices, in the same order |

On the air: `status` → `S:0010201001020100` (one digit per device: `0` off, `1` on, `2` no answer), and `C:12002210…` sets devices (`2` = leave unchanged) and is answered with a fresh `S:` line. Unsigned messages, messages from anyone but `AUTHORIZED_SENDER`, and bad signatures are ignored. See *Chat & Messaging → Device Control* in the OffARO manual for the panel side.

## Install

1. Install Direwolf and a KISS-capable radio setup; Direwolf must accept KISS clients on TCP port 8001 (`KISSPORT 8001` in `direwolf.conf`).
2. `sudo apt install python3-requests`
3. Copy this folder to `/opt/aprs-device-controller` and edit the **Configuration** block at the top of `aprs_device_controller.py`: callsigns, `SIGNING_KEY`, and `APRS_IS_HOST` (pick a server near you, or set `APRS_IS_ENABLED = False` for RF only). **Choose your own, unique signing key.** The published value `CHANGE-ME` is known to everyone, and the controller refuses to start until the callsigns and the key have been changed.
4. Fill in `shelly.txt`. Columns: id, IP, backup IP (may be empty), name, channel (empty for single-relay devices, `0`/`1`/… for multi-channel ones).
5. `sudo cp aprs-device-controller.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now aprs-device-controller`
6. `journalctl -u aprs-device-controller -f` and press **Request Status** in OffARO.

## Notes from running it

- Log in to APRS-IS under a **different SSID** than the one the messages are addressed to (`APRS_IS_LOGIN_CALLSIGN`). aprsc drops upstream packets whose source equals a verified client's login, so logging in as the station's own callsign hides its RF beacons from every other APRS-IS client.
- Replies go back on the path the request arrived on, and over RF when APRS-IS is down. Acknowledgements over RF wait a few seconds so the digipeater chain has finished repeating the request.
- The log file rotates at 10 MiB, five generations.
