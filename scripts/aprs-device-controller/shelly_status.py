#!/usr/bin/env python3
"""Hent status fra alle Shelly-enheter listet i shelly.txt."""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import requests

DEFAULT_TIMEOUT = 5
DEVICE_FILE = Path(__file__).parent / "shelly.txt"


def load_devices(path: Path) -> list[tuple[int, str, str | None, str, int | None]]:
    """Les enheter fra CSV-fil. Returnerer liste av (id, ip, backup_ip, navn, kanal)."""
    text = path.read_text()
    reader = csv.reader(io.StringIO(text))
    next(reader)  # hopp over header
    devices = []
    for row in reader:
        if len(row) >= 4 and row[0].strip():
            device_id = int(row[0].strip())
            ip = row[1].strip()
            backup_ip = row[2].strip() or None
            name = row[3].strip()
            channel = int(row[4].strip()) if len(row) >= 5 and row[4].strip() else None
            devices.append((device_id, ip, backup_ip, name, channel))
    return devices


def get_full_status(host: str) -> dict:
    """Hent full status via Shelly.GetStatus."""
    url = f"http://{host}/rpc/Shelly.GetStatus"
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def format_switch(status: dict, channel: int) -> str:
    """Formater status for én spesifikk switch-kanal."""
    key = f"switch:{channel}"
    sw = status.get(key, {})
    if not sw:
        return "ingen data"
    state = "PÅ" if sw.get("output") else "AV"
    power = sw.get("apower")
    if power is not None:
        return f"{state}, {power:.1f}W"
    return state


def format_status(status: dict, channel: int | None = None) -> str:
    """Tolk status-respons og returner lesbar tekst.

    Hvis channel er satt, vis kun den spesifikke switch-kanalen.
    """
    parts = []

    if channel is not None:
        # Flerkanals enhet — vis kun angitt kanal
        parts.append(format_switch(status, channel))
    else:
        # Switch-komponenter (plugger, releer)
        for key in sorted(status):
            if key.startswith("switch:"):
                sw = status[key]
                state = "PÅ" if sw.get("output") else "AV"
                power = sw.get("apower")
                if power is not None:
                    parts.append(f"{state}, {power:.1f}W")
                else:
                    parts.append(state)

    # Temperatur-komponenter
    for key in sorted(status):
        if key.startswith("temperature:"):
            temp = status[key]
            tc = temp.get("tC")
            if tc is not None:
                parts.append(f"{tc:.1f}°C")

    # Fuktighet
    for key in sorted(status):
        if key.startswith("humidity:"):
            hum = status[key]
            rh = hum.get("rh")
            if rh is not None:
                parts.append(f"{rh:.0f}% RF")

    # Røykvarsler
    for key in sorted(status):
        if key.startswith("smoke:"):
            smoke = status[key]
            alarm = smoke.get("alarm")
            if alarm is not None:
                parts.append("ALARM!" if alarm else "OK (ingen røyk)")

    if not parts:
        parts.append("online")

    return ", ".join(parts)


def fetch_status(ip: str, backup_ip: str | None, cache: dict) -> tuple[dict | Exception, str]:
    """Hent status med fallback til backup-IP. Returnerer (resultat, brukt_ip)."""
    for host in [ip] + ([backup_ip] if backup_ip else []):
        if host in cache:
            return cache[host], host
        try:
            cache[host] = get_full_status(host)
            return cache[host], host
        except (requests.ConnectionError, requests.Timeout):
            continue
        except Exception as e:
            cache[host] = Exception(f"feil: {e}")
            return cache[host], host
    result = Exception("ikke tilgjengelig")
    cache[ip] = result
    return result, ip


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEVICE_FILE
    devices = load_devices(path)

    name_width = max(len(name) for _, _, _, name, _ in devices)
    status_cache: dict[str, dict | Exception] = {}

    print(f"{'ID':>3}  {'Enhet':<{name_width}}  {'IP':<16} Status")
    print("-" * (name_width + 45))

    for device_id, ip, backup_ip, name, channel in devices:
        cached, used_ip = fetch_status(ip, backup_ip, status_cache)
        if isinstance(cached, Exception):
            info = str(cached)
        else:
            info = format_status(cached, channel)
            if used_ip != ip:
                info += f" (via {used_ip})"
        print(f"{device_id:>3}  {name:<{name_width}}  {ip:<16} {info}")


if __name__ == "__main__":
    main()
