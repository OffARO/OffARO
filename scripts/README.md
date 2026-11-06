# Helper scripts for OffARO

Programs that run next to OffARO rather than inside it: on a Raspberry Pi in the field, on a remote station, or on the machine that holds a USB receiver. They are not part of the installers because they belong on other machines. Each folder is self-contained and has its own README.

| Folder | Runs on | Purpose |
| --- | --- | --- |
| [`drone-remote-id/`](drone-remote-id) | Raspberry Pi / Linux with a monitor-mode Wi-Fi adapter | Receives drone **Remote ID** beacons and serves them to OffARO over TCP. The filtering proxy only forwards the frames that carry Remote ID, so it works over a 4G link. Manual: *Drone Remote ID → Receiver setup*. |
| [`aprs-device-controller/`](aprs-device-controller) | A small Linux box at the remote site, with Direwolf and Shelly relays | The remote end of OffARO's **Device Control Panel**: receives signed APRS messages, switches Shelly relays and reports their state back. Manual: *Chat & Messaging → Device Control*. |
| [`receiver-console/`](receiver-console) | Raspberry Pi with dump1090-fa and an AIS receiver, with a screen attached | Full-screen **ADS-B + AIS** display on the box's own screen, with its IP address and the ports to point OffARO at — for a field LAN without internet. Replaces `view1090`. |
| `ant-plus-dog-tracker/` | Machine with an ANT+ USB stick | *Wanted.* A bridge that decodes Garmin ANT+ dog-collar positions and sends them to OffARO's **Local Position Injection** (UDP). If you have written one, open an issue in [OffARO-Feedback](https://github.com/OffARO/OffARO-Feedback) and we will add it here. |

## Getting a script onto a Pi

Either clone this repository on the Pi:

```
git clone --depth 1 https://github.com/OffARO/OffARO.git
cd OffARO/scripts/drone-remote-id
```

or fetch single files with the **Raw** button on GitHub, for example:

```
curl -LO https://raw.githubusercontent.com/OffARO/OffARO/main/scripts/drone-remote-id/remoteid_filter.py
```

## Contributing

Scripts written by OffARO users are welcome. Open an issue or a pull request with the script, a short README (what it needs, how to start it, how OffARO is configured to use it) and a licence note. Keep secrets out: callsigns, signing keys and LAN addresses belong in a configuration file or in placeholders such as `N0CALL`.
