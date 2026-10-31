#!/usr/bin/env python3
"""Enkel styring av Shelly Gen 2/3-enheter via HTTP RPC API."""

from __future__ import annotations

import sys
import requests

DEFAULT_TIMEOUT = 5  # sekunder


def switch_set(host: str, on: bool, switch_id: int = 0) -> dict:
    """Slå en Shelly-switch på eller av."""
    url = f"http://{host}/rpc/Switch.Set"
    payload = {"id": switch_id, "on": on}
    resp = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def get_status(host: str, switch_id: int = 0) -> dict:
    """Hent status for en switch."""
    url = f"http://{host}/rpc/Switch.GetStatus"
    payload = {"id": switch_id}
    resp = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def get_device_info(host: str) -> dict:
    """Hent enhetsinformasjon."""
    url = f"http://{host}/rpc/Shelly.GetDeviceInfo"
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.50"
    action = sys.argv[2] if len(sys.argv) > 2 else "on"

    try:
        info = get_device_info(host)
        print(f"Enhet: {info.get('name', 'ukjent')} ({info.get('model', '?')})")
    except Exception as e:
        print(f"Kunne ikke hente enhetsinfo: {e}")

    try:
        if action == "on":
            result = switch_set(host, on=True)
            print(f"Slått PÅ: {result}")
        elif action == "off":
            result = switch_set(host, on=False)
            print(f"Slått AV: {result}")
        elif action == "status":
            status = get_status(host)
            print(f"Status: output={status.get('output')}, "
                  f"strøm={status.get('apower', 0)}W")
        else:
            print(f"Ukjent handling: {action}. Bruk: on, off, status")
    except requests.ConnectionError:
        print(f"Kunne ikke koble til {host}. Sjekk at enheten er på "
              "samme nettverk og er tilgjengelig.")
    except Exception as e:
        print(f"Feil: {e}")
