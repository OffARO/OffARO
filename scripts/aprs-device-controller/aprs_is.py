#!/usr/bin/env python3
"""APRS-IS client for the Hjulroa controller.

Pure helpers (passcode, login line, line parser) plus AprsIsClient, a
reconnecting TCP client that reads packets as text lines and hands them to a
callback. No dependency on aprs_device_controller.py.
"""
from __future__ import annotations

import logging
import socket
import threading
import time

log = logging.getLogger("aprs-ctrl")


def aprs_passcode(callsign: str) -> int:
    """Standard APRS-IS passcode: computed over the callsign without SSID."""
    call = callsign.split("-")[0].upper()
    h = 0x73E2
    for i in range(0, len(call), 2):
        h ^= ord(call[i]) << 8
        if i + 1 < len(call):
            h ^= ord(call[i + 1])
    return h & 0x7FFF


def login_line(callsign: str, version: str, message_calls: list[str] | None = None) -> str:
    """Login line. The server always delivers messages addressed to the login
    callsign; when we log in under a different SSID than the one we answer
    for, `message_calls` adds a `g/CALL` filter so those messages still arrive.

    Why a different SSID: aprsc drops any packet arriving from upstream whose
    source callsign equals a verified client's login on that server (loop
    protection). Logging in as N0CALL-12 — the tracker's RF callsign — made
    LA8HQ (aprs-is.nrrl.no) discard every RF beacon of N0CALL-12 gated by
    other iGates, so no NRRL client (OffARO included) ever saw them, while
    aprs.fi did. Hence N0CALL-13 for the link, N0CALL-12 for the messages."""
    line = f"user {callsign} pass {aprs_passcode(callsign)} vers Hjulroa {version}"
    calls = [c for c in (message_calls or []) if c and c.upper() != callsign.upper()]
    if calls:
        line += " filter " + " ".join(f"g/{c}" for c in calls)
    return line


def parse_is_line(line: str) -> dict | None:
    """Split an APRS-IS line 'SRC>DEST,PATH:info' into its parts.

    Returns None for server comments ('#...'), blank lines and anything that
    does not look like a packet. The path list may contain q-constructs such
    as 'qAC', 'LA9HQ'; callers do not need them.
    """
    line = line.rstrip("\r\n")
    if not line or line.startswith("#"):
        return None
    header, sep, info = line.partition(":")
    if not sep:
        return None
    source, sep, rest = header.partition(">")
    if not sep or not source or not rest:
        return None
    parts = rest.split(",")
    return {
        "source": source.strip(),
        "destination": parts[0].strip(),
        "path": [p.strip() for p in parts[1:]],
        "info": info,
    }


class AprsIsClient:
    """Reconnecting APRS-IS client.

    Runs its reader on a daemon thread. Every non-comment line is passed to
    `on_line(line)`. `is_up()` is true only after the server confirmed a
    verified login, because an unverified login can receive but the server
    silently drops what it sends.
    """
    name = "APRS-IS"

    def __init__(self, host: str, port: int, callsign: str, version: str,
                 on_line, idle_timeout: float = 120, reconnect_delay: float = 10,
                 login_callsign: str | None = None) -> None:
        self._host = host
        self._port = port
        # `callsign` is the station we answer for (messages addressed to it are
        # requested with a g/ filter); `login_callsign` is what we log in as —
        # must NOT be the RF beacon callsign, see login_line().
        self._message_callsign = callsign
        self._callsign = login_callsign or callsign
        self._version = version
        self._on_line = on_line
        self._idle_timeout = idle_timeout
        self._reconnect_delay = reconnect_delay
        self._sock = None
        self._connected = False
        self._verified = False
        self._last_rx = 0.0
        # Reason of the last failed connect attempt, or None when the last
        # attempt succeeded. Used to keep the reconnect loop from flooding the
        # log with the same WARNING every reconnect_delay seconds.
        self._last_failure: str | None = None
        self._lock = threading.Lock()

    # ── Transport interface ─────────────────────────────────────────
    def is_up(self) -> bool:
        return self._connected and self._verified

    def send(self, source: str, dest: str, path: list[str], info: str) -> None:
        # The path on an APRS-IS send is always TCPIP*. Messages that arrived
        # over APRS-IS carry reverse_path=[], and an empty path here produced
        # "N0CALL-12>APZOFA,::N0CALL-4  :ack021" — an empty via-call that aprsc
        # silently drops. Defaulted here so no caller can get it wrong.
        line = f"{source}>{dest},{','.join(path or ['TCPIP*'])}:{info}\r\n"
        with self._lock:
            if self._sock is None or not self._connected:
                raise ConnectionError("APRS-IS not connected")
            if not self._verified:
                raise ConnectionError("APRS-IS not verified")
            self._sock.sendall(line.encode("utf-8", errors="replace"))

    # ── Lifecycle ───────────────────────────────────────────────────
    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="aprs-is").start()

    def _run(self) -> None:
        while True:
            try:
                self._connect_and_read()
            except Exception as e:
                if self._connected:
                    # An established connection dropped: always worth a warning.
                    log.warning(f"🌐 APRS-IS lost: {e}")
                else:
                    self._log_connect_failure(str(e) or e.__class__.__name__)
            finally:
                self._close()
            time.sleep(self._reconnect_delay)

    # ── Reconnect logging ───────────────────────────────────────────
    # While the cabin internet is down this loop runs every reconnect_delay
    # seconds, forever. Say it loudly once, then keep repeats out of the log.
    def _log_connect_failure(self, reason: str) -> None:
        if reason == self._last_failure:
            log.debug(f"🌐 APRS-IS still unreachable: {reason}")
            return
        log.warning(f"🌐 APRS-IS connect failed: {reason}")
        self._last_failure = reason

    def _log_connect_success(self) -> None:
        log.info(f"🌐 APRS-IS TCP connection to {self._host}:{self._port} established, "
                 f"logging in as {self._callsign}")
        self._last_failure = None

    def _close(self) -> None:
        with self._lock:
            sock, self._sock = self._sock, None
            self._connected = False
            self._verified = False
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _connect_and_read(self) -> None:
        # Attempt logged at DEBUG: with the internet down this runs every
        # reconnect_delay seconds. The outcome is what gets logged (once).
        log.debug(f"🌐 Connecting to APRS-IS {self._host}:{self._port} as {self._callsign}...")
        sock = socket.create_connection((self._host, self._port), timeout=15)
        self._log_connect_success()
        sock.settimeout(5.0)
        sock.sendall((login_line(self._callsign, self._version, [self._message_callsign]) + "\r\n").encode())
        with self._lock:
            self._sock = sock
            self._connected = True
        self._last_rx = time.time()
        buf = b""
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                if time.time() - self._last_rx > self._idle_timeout:
                    raise ConnectionError(f"no data for {self._idle_timeout:.0f}s")
                continue
            if not data:
                raise ConnectionError("server closed connection")
            self._last_rx = time.time()
            buf += data
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                try:
                    self.handle_line(raw.decode("utf-8", errors="replace"))
                except Exception:
                    log.exception("🌐 APRS-IS line handler failed — line dropped")

    # ── Line handling (unit-tested without a socket) ────────────────
    def handle_line(self, line: str) -> None:
        line = line.rstrip("\r\n")
        if not line:
            return
        if line.startswith("#"):
            if "logresp" in line:
                if " unverified" in line or " verified" not in line:
                    self._verified = False
                    log.error(f"🌐 APRS-IS login NOT verified — receiving only, "
                              f"replies will go over RF ({line})")
                else:
                    self._verified = True
                    log.info(f"🌐 APRS-IS connected as {self._callsign} (verified)")
            return
        self._on_line(line)
