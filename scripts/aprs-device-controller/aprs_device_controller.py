#!/usr/bin/env python3
"""
APRS Device Controller — Remote Station Script

Connects to Direwolf via KISS TCP, listens for signed APRS messages,
and controls Shelly devices. Counterpart to OffARO's Device Control Panel.

Protocol:
  - "status"          → query all devices, respond with S:NNNNNNNNNNNN
  - "C:NNNNNNNNNNNN"  → set devices (0=off, 1=on), respond with status
  - "S:NNNNNNNNNNNN"  → status response (outgoing only)

Each digit: 0=off, 1=on, 2=no answer (status only)

All messages signed with HMAC-MD5 per ARETF APRS Authentication draft.
Only accepts messages from AUTHORIZED_SENDER with valid signature.
Responses use reverse digipeater path from the incoming message.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import Protocol
import hmac
import hashlib
import io
import logging
import logging.handlers
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import aprs_is

# ── Configuration ──────────────────────────────────────────────────────
MY_CALLSIGN = "N0CALL-12"
AUTHORIZED_SENDER = "N0CALL-4"
SIGNING_KEY = "CHANGE-ME"   # Must match the Signing Key of the OffARO contact
DIREWOLF_HOST = "localhost"
DIREWOLF_PORT = 8001
DEVICE_FILE = Path(__file__).parent / "shelly.txt"
LOG_FILE = Path(__file__).parent / "aprs-controller.log"
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MiB per file
LOG_BACKUPS = 5                    # keep 5 rotated files → ~50 MiB ceiling
STATUS_PREFIX = "S:"
CONTROL_PREFIX = "C:"
STATUS_COMMAND = "status"
RECONNECT_DELAY = 10  # seconds between reconnection attempts
APRS_IS_ENABLED = True            # False → RF only, no code change needed
APRS_IS_HOST = "rotate.aprs2.net"
APRS_IS_PORT = 14580
# Log in under a DIFFERENT SSID than MY_CALLSIGN. aprsc discards upstream packets
# whose source equals a verified client's login (loop protection): logged in as
# N0CALL-12, the server dropped every RF beacon of N0CALL-12 gated by other iGates,
# so NRRL clients (OffARO!) never saw the tracker move. Messages to MY_CALLSIGN
# are still delivered — aprs_is adds a g/ filter for them.
APRS_IS_LOGIN_CALLSIGN = "N0CALL-13"
IS_IDLE_TIMEOUT = 120             # seconds without any server line → reconnect
IS_FALLBACK_PATH = ["WIDE1-1", "WIDE2-1"]  # RF path used when APRS-IS is down
# When a request reaches us over APRS-IS but originated on RF (q-construct
# qAR/qAO: an iGate uploaded it), the APRS-IS server only routes our ACK to
# TX-iGates that have already uploaded a copy from the sender. The fastest
# uploader is often a receive-only iGate, so an instant ACK gets routed
# nowhere useful (seen 2026-09-04 16:19). Wait a few seconds first.
IS_ACK_DELAY_RF_ORIGIN = 5
# After OffARO has ACKed our reply, a duplicate of its request arriving over
# APRS-IS is only worth a re-ACK if it can be OffARO's own retransmission,
# which fires 30 s after the original. Anything older is a late echo that a
# slow iGate uploaded (2026-09-06 00:06: a 50 s old copy) and gets nothing.
IS_REACK_WINDOW = 45
# ACKs going out over RF wait this long so the digipeater chain that is still
# repeating the incoming request has finished; an ACK sent 0.4 s after the
# request was never heard by the local digis (2026-09-04 16:25).
RF_ACK_DELAY = 3
VERSION = "1.2"
# Refuse to run with the published placeholders: the key is public, so anyone
# could sign commands to your relays. Edit the Configuration block first.
if SIGNING_KEY in ("", "CHANGE-ME") or MY_CALLSIGN.startswith("N0CALL") or AUTHORIZED_SENDER.startswith("N0CALL"):
    sys.exit("aprs_device_controller: set MY_CALLSIGN, AUTHORIZED_SENDER and a unique SIGNING_KEY in the Configuration block before starting")
# ───────────────────────────────────────────────────────────────────────

# Logging: send to BOTH stdout (captured by journalctl when running under
# systemd) and a rotating file in the working directory. The file gives
# the user a tail-able log that survives journal-rate-limiting / vacuum,
# and the per-message envelope below keeps the level-of-detail consistent
# whether the message ends up accepted or rejected.
_log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("aprs-ctrl")
log.setLevel(logging.INFO)
# Avoid duplicates if module is reloaded.
log.handlers.clear()
_stdout_handler = logging.StreamHandler(sys.stdout)
_stdout_handler.setFormatter(_log_formatter)
log.addHandler(_stdout_handler)
try:
    _file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"
    )
    _file_handler.setFormatter(_log_formatter)
    log.addHandler(_file_handler)
except Exception as _e:
    # Fall through silently — stdout/journal still works.
    print(f"WARNING: could not open log file {LOG_FILE}: {_e}", file=sys.stderr)
# Suppress propagation to root logger so we don't get double-prints.
log.propagate = False

# Import Shelly control functions
try:
    from shelly_control import switch_set, get_status
except ImportError:
    log.error("Cannot import shelly_control.py — must be in same directory")
    sys.exit(1)


# ── Device list ────────────────────────────────────────────────────────

def load_devices(path: Path) -> list[tuple[int, str, str | None, str, int | None]]:
    """Load devices from shelly.txt. Returns [(id, ip, backup_ip, name, channel), ...]"""
    text = path.read_text()
    reader = csv.reader(io.StringIO(text))
    next(reader)  # skip header
    devices = []
    for row in reader:
        if len(row) >= 4 and row[0].strip():
            try:
                device_id = int(row[0].strip())
            except ValueError:
                continue
            ip = row[1].strip()
            backup_ip = row[2].strip() or None
            name = row[3].strip()
            channel = int(row[4].strip()) if len(row) >= 5 and row[4].strip() else None
            devices.append((device_id, ip, backup_ip, name, channel))
    return devices


def try_host(func, ip: str, backup_ip: str | None, *args, **kwargs):
    """Try func on primary IP, fall back to backup_ip on connection failure."""
    for host in [ip] + ([backup_ip] if backup_ip else []):
        try:
            return func(host, *args, **kwargs)
        except (ConnectionError, OSError):
            continue
    raise ConnectionError(f"Neither {ip} nor {backup_ip} reachable")


# ── ASCII-85 codec ─────────────────────────────────────────────────────

def encode_ascii85(data: bytes) -> str:
    """Encode bytes to ASCII-85 string (chars 33-117)."""
    result = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        remaining = len(chunk)
        value = 0
        for j in range(4):
            value = value * 256 + (chunk[j] if j < remaining else 0)
        chars = []
        for _ in range(5):
            chars.append(chr(33 + value % 85))
            value //= 85
        chars.reverse()
        result.extend(chars[:remaining + 1] if remaining < 4 else chars)
    return "".join(result)


def decode_ascii85(s: str) -> bytes:
    """Decode ASCII-85 string to bytes. Strict: only the characters '!'..'u'
    and only group values below 2^32, so every digest has exactly one
    spelling — otherwise a replayed signature could be re-spelled to dodge
    the replay guard."""
    result = []
    for i in range(0, len(s), 5):
        chunk = s[i:i + 5]
        remaining = len(chunk)
        value = 0
        for j in range(5):
            if j < remaining:
                c = ord(chunk[j]) - 33
                if not 0 <= c <= 84:
                    raise ValueError(f"character {chunk[j]!r} is not Ascii85")
            else:
                c = 84
            value = value * 85 + c
        if value >= 1 << 32:
            raise ValueError("non-canonical Ascii85 group")
        count = remaining - 1 if remaining < 5 else 4
        for j in range(3, 3 - count, -1):
            result.append((value >> (j * 8)) & 0xFF)
    return bytes(result)


# ── HMAC-MD5 signing ───────────────────────────────────────────────────

def compute_hmac(sender: str, addressee: str, body: str,
                 key: str, minutes: int) -> bytes:
    """Compute HMAC-MD5 per ARETF APRS Authentication draft."""
    timestamp_buf = struct.pack(">I", minutes & 0xFFFFFFFF)
    h = hmac.new(key.encode(), digestmod=hashlib.md5)
    h.update(timestamp_buf)
    h.update(sender.encode())
    h.update(b">")
    h.update(addressee.strip().encode())
    h.update(b":")
    h.update(body.encode())
    return h.digest()


def sign_message(sender: str, addressee: str, body: str, key: str) -> str:
    """Sign a message body, returns body + \\S + signature."""
    minutes = int(time.time() / 60)
    digest = compute_hmac(sender, addressee, body, key, minutes)
    return body + "\\S" + encode_ascii85(digest)


def verify_signature(sender: str, addressee: str, body: str,
                     signature_ascii85: str, key: str) -> bool:
    """Verify HMAC-MD5 signature with 1-minute propagation tolerance."""
    try:
        expected = decode_ascii85(signature_ascii85)
    except Exception:
        return False
    current_minutes = int(time.time() / 60)
    # Check current, -1, and -2 minutes (3-minute tolerance for digipeater delays)
    for minutes in (current_minutes, current_minutes - 1, current_minutes - 2):
        computed = compute_hmac(sender, addressee, body, key, minutes)
        if computed == expected:
            return True
    return False


def extract_signature(full_body: str) -> tuple[str, str] | None:
    """Extract body and signature from message. Returns (body, sig) or None."""
    # Strip trailing {seq} if present (sequence number may not have been removed)
    import re
    # On the wire an APRS message id is "{00F" — no closing brace; accept both forms
    stripped = re.sub(r'\{\w{1,5}\}?$', '', full_body)

    # The signature is ALWAYS the last 22 characters: "\S" + 20 Ascii85 chars.
    # Find it by position, never by searching for "\S": both "\" and "S" are
    # valid Ascii85 characters, so about 1 signature in 7 000 contains "\S"
    # itself — rfind() then split inside it, saw 8 chars instead of 20 and the
    # command was REJECTED as unsigned (OffARO field case 2026-10-08:
    # "test 9\Sr5[j$h\"1CA\S!Acf5D&=").
    if len(stripped) < 22 or stripped[-22:-20] != "\\S":
        return None
    sig = stripped[-20:]
    # Verify all chars are in ASCII-85 range (33-117)
    if not all(33 <= ord(c) <= 117 for c in sig):
        return None
    return stripped[:-22], sig


# ── AX.25 / KISS framing ──────────────────────────────────────────────

KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD


def encode_callsign(callsign: str, last: bool = False,
                    h_bit: bool = False) -> bytes:
    """Encode a callsign into 7-byte AX.25 format."""
    parts = callsign.split("-")
    call = parts[0].upper().ljust(6)
    ssid = int(parts[1]) if len(parts) > 1 else 0
    encoded = bytes(c << 1 for c in call[:6].encode())
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if last:
        ssid_byte |= 0x01  # end-of-address bit
    if h_bit:
        ssid_byte |= 0x80  # has-been-repeated bit
    return encoded + bytes([ssid_byte])


def decode_callsign(data: bytes) -> tuple[str, int, bool, bool]:
    """Decode 7-byte AX.25 callsign. Returns (call, ssid, last, h_bit)."""
    call = "".join(chr(b >> 1) for b in data[:6]).rstrip()
    ssid_byte = data[6]
    ssid = (ssid_byte >> 1) & 0x0F
    last = bool(ssid_byte & 0x01)
    h_bit = bool(ssid_byte & 0x80)
    callsign = f"{call}-{ssid}" if ssid else call
    return callsign, ssid, last, h_bit


def kiss_unescape(data: bytes) -> bytes:
    """Remove KISS escape sequences."""
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == KISS_FESC:
            i += 1
            if i < len(data):
                if data[i] == KISS_TFEND:
                    result.append(KISS_FEND)
                elif data[i] == KISS_TFESC:
                    result.append(KISS_FESC)
                else:
                    result.append(data[i])
        else:
            result.append(data[i])
        i += 1
    return bytes(result)


def kiss_escape(data: bytes) -> bytes:
    """Add KISS escape sequences."""
    result = bytearray()
    for b in data:
        if b == KISS_FEND:
            result.extend([KISS_FESC, KISS_TFEND])
        elif b == KISS_FESC:
            result.extend([KISS_FESC, KISS_TFESC])
        else:
            result.append(b)
    return bytes(result)


def parse_ax25_frame(frame: bytes) -> dict | None:
    """Parse AX.25 frame into components."""
    if len(frame) < 16:
        return None

    # Destination (7 bytes)
    dest_call, dest_ssid, dest_last, _ = decode_callsign(frame[0:7])
    # Source (7 bytes)
    src_call, src_ssid, src_last, _ = decode_callsign(frame[7:14])

    # Digipeaters
    digipeaters = []
    offset = 14
    last = src_last
    while not last and offset + 7 <= len(frame):
        digi_call, digi_ssid, last, h_bit = decode_callsign(frame[offset:offset + 7])
        digipeaters.append({"callsign": digi_call, "h_bit": h_bit})
        offset += 7

    # Control + PID
    if offset + 2 > len(frame):
        return None
    control = frame[offset]
    pid = frame[offset + 1]
    info = frame[offset + 2:]

    return {
        "destination": dest_call,
        "source": src_call,
        "digipeaters": digipeaters,
        "control": control,
        "pid": pid,
        "info": info.decode("utf-8", errors="replace"),
    }


def build_ax25_frame(source: str, destination: str, digipeaters: list[str],
                     info: str) -> bytes:
    """Build an AX.25 UI frame."""
    no_digis = len(digipeaters) == 0
    frame = bytearray()
    frame.extend(encode_callsign(destination))
    frame.extend(encode_callsign(source, last=no_digis))
    for i, digi in enumerate(digipeaters):
        is_last = i == len(digipeaters) - 1
        frame.extend(encode_callsign(digi, last=is_last))
    frame.append(0x03)  # UI control
    frame.append(0xF0)  # No layer 3
    frame.extend(info.encode("utf-8"))
    return bytes(frame)


def build_kiss_frame(ax25_frame: bytes) -> bytes:
    """Wrap AX.25 frame in KISS framing."""
    return bytes([KISS_FEND, 0x00]) + kiss_escape(ax25_frame) + bytes([KISS_FEND])


def extract_reverse_path(digipeaters: list[dict], via_igate: bool = False) -> list[str]:
    """Build a WIDE return path based on how many hops the incoming packet used.

    Using explicit callsigns in the return path doesn't work reliably because
    most digipeaters only respond to WIDE aliases, not their own callsign.
    Instead, count the number of used hops and build a standard WIDE path.

    via_igate: the message arrived as a third-party packet ("}...") gated from
    APRS-IS to RF by an iGate. The outer frame then typically shows zero used
    hops, but the real sender is somewhere behind the internet and cannot hear
    a direct reply — so never answer "direct"; use at least WIDE1-1,WIDE2-1.
    """
    used_hops = sum(1 for d in digipeaters if d["h_bit"])
    if via_igate and used_hops < 2:
        return ["WIDE1-1", "WIDE2-1"]
    if used_hops == 0:
        return []  # Direct, no digipeaters needed
    elif used_hops == 1:
        return ["WIDE1-1"]
    elif used_hops == 2:
        return ["WIDE1-1", "WIDE2-1"]
    else:
        # 3+ hops: use WIDE1-1,WIDE2-2 (don't exceed 3 total)
        return ["WIDE1-1", "WIDE2-2"]


# ── Transports ─────────────────────────────────────────────────────────
# A transport is where a message came from and where its reply goes back.
# Two implementations: KissTransport (Direwolf/RF, below) and
# aprs_is.AprsIsClient (internet). Both expose the same three members.

class Transport(Protocol):
    name: str

    def is_up(self) -> bool: ...

    def send(self, source: str, dest: str, path: list[str], info: str) -> None:
        """Transmit one APRS packet. Raise on failure."""
        ...


@dataclass
class Message:
    """One APRS message after transport-specific parsing."""
    source: str                 # real sender (after third-party unwrap on RF)
    addressee: str
    body: str                   # includes trailing \S signature, excludes {seq}
    sequence: str | None
    reverse_path: list[str]     # RF: from extract_reverse_path(); APRS-IS: []
    transport: Transport
    rx_path: str = "direct"     # human-readable path for the RX log line
                                # (iGate hop included; see process_kiss_data)


class KissTransport:
    """Direwolf over KISS/TCP. main() attaches the live socket."""
    name = "RF"

    def __init__(self) -> None:
        self._sock: socket.socket | None = None

    def attach(self, sock: socket.socket) -> None:
        with _sock_lock:
            self._sock = sock

    def detach(self) -> None:
        """Drop and close the socket. Taking _sock_lock means no worker thread
        is inside sendall() on it, so the fd cannot be closed and reused under
        a blocked writer."""
        with _sock_lock:
            sock, self._sock = self._sock, None
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def is_up(self) -> bool:
        return self._sock is not None

    def send(self, source: str, dest: str, path: list[str], info: str) -> None:
        frame = build_kiss_frame(build_ax25_frame(source, dest, path, info))
        with _sock_lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError("Direwolf not connected")
            sock.sendall(frame)


# Set by main(); used by the retry queue to fall back to RF.
_rf_transport: KissTransport | None = None
# Set by main() when APRS-IS is enabled; lets RF replies retry over the internet.
_is_transport: Transport | None = None


# ── APRS message parsing ──────────────────────────────────────────────

def parse_aprs_message(info: str) -> dict | None:
    """Parse APRS message format :ADDRESSEE:message{seq}"""
    if not info.startswith(":"):
        return None
    if len(info) < 11:
        return None
    addressee = info[1:10].rstrip()
    if info[10:11] != ":":
        return None
    body = info[11:]
    # Extract sequence number
    seq = None
    seq_idx = body.rfind("{")
    if seq_idx >= 0:
        seq = body[seq_idx + 1:].rstrip("}")
        body = body[:seq_idx]
    return {"addressee": addressee, "body": body, "sequence": seq}


def format_aprs_message(source: str, addressee: str, body: str,
                        seq: str | None = None) -> str:
    """Format APRS message: :ADDRESSEE :body{seq}"""
    padded = addressee.ljust(9)
    msg = f":{padded}:{body}"
    if seq:
        msg += "{" + seq + "}"
    return msg


# ── Device control ─────────────────────────────────────────────────────

def query_all_devices(devices: list) -> str:
    """Query all devices, return state string (0=off, 1=on, 2=no answer)."""
    states = []
    for device_id, ip, backup_ip, name, channel in devices:
        try:
            status = try_host(get_status, ip, backup_ip,
                              channel if channel is not None else 0)
            is_on = status.get("output", False)
            states.append("1" if is_on else "0")
            log.info(f"  Device {device_id} ({name}): {'ON' if is_on else 'OFF'}")
        except Exception as e:
            states.append("2")
            log.warning(f"  Device {device_id} ({name}): no answer ({e})")
    return "".join(states)


def apply_control(devices: list, command: str) -> str:
    """Apply control command to devices. 0=off, 1=on, 2=skip. Returns status string after."""
    for i, digit in enumerate(command):
        if i >= len(devices):
            break
        if digit == "2":
            device_id, _, _, name, _ = devices[i]
            log.info(f"  Device {device_id} ({name}): skipped (unchanged)")
            continue
        device_id, ip, backup_ip, name, channel = devices[i]
        target = digit == "1"
        try:
            try_host(switch_set, ip, backup_ip,
                     on=target, switch_id=channel if channel is not None else 0)
            log.info(f"  Device {device_id} ({name}): set {'ON' if target else 'OFF'}")
        except Exception as e:
            log.warning(f"  Device {device_id} ({name}): control failed ({e})")

    # Small delay to let devices settle, then query status
    time.sleep(1)
    return query_all_devices(devices)


# ── Sequence number generator (persisted to disk) ─────────────────────
SEQ_FILE = Path(__file__).parent / ".aprs_seq"
SEQ_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SEQ_MAX = 62 * 62 * 62  # 238328

def _load_seq() -> int:
    try:
        return int(SEQ_FILE.read_text().strip())
    except Exception:
        return 0

def _save_seq(n: int) -> None:
    try:
        SEQ_FILE.write_text(str(n))
    except Exception as e:
        log.warning(f"Failed to save sequence number: {e}")

_seq_counter = _load_seq()

def next_sequence() -> str:
    """Generate next base-62 sequence number (3 chars), persisted to disk."""
    global _seq_counter
    _seq_counter += 1
    if _seq_counter >= SEQ_MAX:
        _seq_counter = 1
    _save_seq(_seq_counter)
    n = _seq_counter
    result = []
    for _ in range(3):
        result.append(SEQ_CHARS[n % 62])
        n //= 62
    return "".join(reversed(result))


# ── Deduplication ──────────────────────────────────────────────────────
_recent_messages: dict[str, float] = {}  # key -> timestamp
DEDUP_WINDOW = 600  # 10 minutes — ignore duplicate within this window


def _dedup_key(source: str, body: str, sequence: str | None = None) -> str:
    return f"{source}:{body}:{sequence or ''}"


def request_age(source: str, body: str, sequence: str | None = None,
                now: float | None = None) -> float | None:
    """Seconds since the first copy of this request arrived, or None."""
    t = _recent_messages.get(_dedup_key(source, body, sequence))
    if t is None:
        return None
    return (time.time() if now is None else now) - t


def is_duplicate(source: str, body: str, sequence: str | None = None) -> bool:
    """Check if this message was already processed recently."""
    key = _dedup_key(source, body, sequence)
    now = time.time()
    # Clean old entries
    expired = [k for k, t in _recent_messages.items() if now - t > DEDUP_WINDOW]
    for k in expired:
        del _recent_messages[k]
    # Check
    if key in _recent_messages:
        log.debug(f"🔄 Duplicate message from {source} (within {DEDUP_WINDOW}s window)")
        return True
    _recent_messages[key] = now
    return False


# ── Replayed signatures ────────────────────────────────────────────────
# The signature covers sender, addressee, body and the minute — not the {seq}.
# A captured control command could therefore be re-sent with a fresh {seq}
# inside the three-minute validity window and would pass is_duplicate(). The
# protocol cannot tell such a replay from the owner sending the same command
# twice in one minute (identical signature, new {seq}), so a repeated signature
# is not rejected: a control command is downgraded to a status query. The
# owner still gets an ACK and the current state; a replayer changes nothing.
# Status requests are read-only and are left alone.
_seen_signatures: dict[str, tuple[str | None, float]] = {}  # key -> (seq, ts)


def is_replayed_signature(source: str, body: str, signature: str,
                          sequence: str | None, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    for k in [k for k, (_, t) in _seen_signatures.items() if now - t > DEDUP_WINDOW]:
        del _seen_signatures[k]
    # Key on the digest, not its spelling (decode_ascii85 is strict, so this
    # is belt and braces; the caller has already verified the signature).
    key = f"{source.upper()}:{body}:{decode_ascii85(signature).hex()}"
    seen = _seen_signatures.get(key)
    if seen is None:
        _seen_signatures[key] = (sequence, now)
        return False
    return seen[0] != sequence


def effective_body(source: str, body: str, signature: str,
                   sequence: str | None, now: float | None = None) -> str:
    """The body to act on: a control command whose signature was already
    accepted under another sequence number becomes a status query."""
    if not body.startswith(CONTROL_PREFIX):
        return body
    if is_replayed_signature(source, body, signature, sequence, now):
        log.warning("   ⚠️ control command repeats a signature already accepted under "
                    f"another sequence number (now seq={sequence or '—'}) — "
                    "answering with status only, nothing switched")
        return STATUS_COMMAND
    return body


# ── Completed exchanges ────────────────────────────────────────────────
# Once OffARO has ACKed our status response, the exchange is over. Late
# copies of the same request (RF digipeater / iGate echoes can trail by
# minutes) must not trigger further re-ACKs — there is nobody waiting.
_completed_requests: dict[str, float] = {}  # "source|request-seq" -> timestamp


def _request_key(source: str, seq: str) -> str:
    return f"{source.upper()}|{seq}"


def mark_request_completed(source: str, seq: str, now: float | None = None) -> None:
    if now is None:
        now = time.time()
    _completed_requests[_request_key(source, seq)] = now
    for k in [k for k, t in _completed_requests.items() if now - t > DEDUP_WINDOW]:
        del _completed_requests[k]


def is_request_completed(source: str, seq: str, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    t = _completed_requests.get(_request_key(source, seq))
    return t is not None and now - t <= DEDUP_WINDOW


# ── RF-origin detection on APRS-IS lines ───────────────────────────────
# qAR/qAr = uploaded by an iGate that heard it on RF; qAO/qAo = uploaded by a
# receive-only (client-only) iGate. qAC/qAS/qAU mean it came straight from a
# client or server on the internet.
RF_ORIGIN_Q = ("qAR", "qAr", "qAO", "qAo")


def is_rf_originated(rx_path: str) -> bool:
    return any(elem in RF_ORIGIN_Q for elem in rx_path.split(","))


def _delayed_call(delay: float, fn) -> None:
    """Run fn on a daemon timer thread after delay seconds (patchable in tests)."""
    t = threading.Timer(delay, fn)
    t.daemon = True
    t.start()


_delayed_call_real = _delayed_call  # tests patch _delayed_call and restore from this


def _ack_delay_for(msg: Message) -> tuple[float, str]:
    """How long to hold an ACK for this message, and why."""
    if msg.transport.name == "APRS-IS" and is_rf_originated(msg.rx_path):
        return IS_ACK_DELAY_RF_ORIGIN, "request originated on RF — letting TX-iGates near the sender upload first"
    if msg.transport.name == "RF":
        return RF_ACK_DELAY, "letting the digipeater burst finish"
    return 0, ""


def _send_ack_now_or_later(msg: Message, verb: str) -> None:
    """Send the ACK for msg on its transport (with fallback), after the delay
    _ack_delay_for() prescribes. verb is "sent" or "re-sent" for the log."""

    def send_ack() -> None:
        try:
            used = _send_ack_with_fallback(msg)
            log.info(f"   📨 ACK {verb} for seq {msg.sequence} via {used} "
                     f"{_sent_path_str(msg, used)}")
        except Exception as e:
            log.error(f"   ❌ Failed to send ACK for seq {msg.sequence}: {e}")

    delay, reason = _ack_delay_for(msg)
    if delay > 0:
        log.info(f"   ⏳ ACK for seq {msg.sequence} in {delay:g}s ({reason})")
        _delayed_call(delay, send_ack)
    else:
        send_ack()


# ── Duplicate-ACK throttling ───────────────────────────────────────────
# The same request typically reaches us many times: several TX-iGates gate
# it from APRS-IS to RF and each copy is digipeated again. Re-sending an ACK
# for every copy turned one request into eight ACKs on 2026-09-04. Answer
# each (sender, seq) with at most one ACK per DUP_ACK_INTERVAL seconds.
DUP_ACK_INTERVAL = 20
_last_ack_sent: dict[str, float] = {}  # "source|seq" -> timestamp


def may_send_ack(source: str, seq: str, now: float | None = None) -> bool:
    """Return True (and record the send) unless an ACK for this (source, seq)
    went out less than DUP_ACK_INTERVAL seconds ago."""
    if now is None:
        now = time.time()
    key = f"{source}|{seq}"
    last = _last_ack_sent.get(key)
    if last is not None and now - last < DUP_ACK_INTERVAL:
        return False
    _last_ack_sent[key] = now
    # Keep the table from growing forever.
    for k in [k for k, t in _last_ack_sent.items() if now - t > DEDUP_WINDOW]:
        del _last_ack_sent[k]
    return True


# ── Outgoing message retry (ACK tracking) ─────────────────────────────
MAX_RETRIES = 3
# Seconds between retries. When OffARO and Hjulroa have no direct RF path
# every packet detours via APRS-IS and a TX-iGate; measured 2026-09-04 that
# took 37 s for an ACK and 68 s for a status response. Retrying faster than
# that only floods the channel with copies that were already on their way.
RETRY_INTERVAL = 90

# Pending outgoing messages: seq -> entry dict, see queue_outgoing().
_pending_acks: dict[str, dict] = {}

# _sock_lock serialises writes to the Direwolf socket (KissTransport.send).
# _queue_lock protects _pending_acks. Never hold _queue_lock while sending.
_sock_lock = threading.Lock()
_queue_lock = threading.Lock()


def _send_via(preferred: Transport, source: str, dest: str, path: list[str],
              info: str, what: str) -> str:
    """Send one packet on `preferred`, falling back to RF when that transport
    is down *or* its send fails. Returns the name of the transport used, and
    raises if nothing usable is left — callers decide whether to queue or drop.

    A send can fail while is_up() still says yes: a write timeout, or a
    half-open APRS-IS socket after the cabin internet flapped. Treat that
    exactly like a transport that is down, or the packet is simply lost.

    This is the single fallback implementation; both the retry queue
    (_send_with_fallback) and the immediate ACK (_send_ack_with_fallback)
    go through it.
    """
    reason = "down"
    if preferred.is_up():
        try:
            preferred.send(source, dest, path, info)
            return preferred.name
        except Exception as e:
            log.warning(f"   ↩ {preferred.name} send failed ({e}) — falling back to RF")
            reason = "send failed"
    rf = _rf_transport
    if rf is not None and preferred is not rf and rf.is_up():
        log.info(f"   ↩ {preferred.name} {reason} — sending {what} over RF "
                 f"via {','.join(IS_FALLBACK_PATH)}")
        rf.send(source, dest, IS_FALLBACK_PATH, info)
        return rf.name
    raise ConnectionError(f"{preferred.name} down and no RF fallback available")


def _wire_info(entry: dict) -> str:
    """The info field to put on the air for this entry, right now.

    A signed entry (entry['resign'] set) is RE-SIGNED with the current
    timestamp on every send. The HMAC signature is time-windowed, so a reply
    delayed by the 90 s retry interval (up to ~4.5 min over three retries) or a
    slow multi-hop path used to arrive with an already-expired signature —
    OffARO then showed it "Unverified". Re-signing per send keeps the timestamp
    fresh no matter how many retries or how slow the path. Unsigned entries
    retransmit their original info unchanged."""
    rs = entry.get('resign')
    if rs is None:
        return entry['info']
    signed_body = sign_message(rs['sender'], rs['addressee'], rs['body'], SIGNING_KEY)
    return format_aprs_message(rs['sender'], rs['addressee'], signed_body, entry['seq'])


def _send_with_fallback(entry: dict) -> str:
    """Send a queued entry on its preferred transport, or over RF. Raises if
    nothing usable is up, in which case the entry stays queued for the next
    interval."""
    return _send_via(entry['transport'], entry['source'], entry['dest'],
                     entry['path'], _wire_info(entry), f"seq {entry['seq']}")


def _send_on_both(entry: dict) -> str:
    """Transmit a response on BOTH transports when both are up, so a peer that
    listens on only one still receives it. A request often reaches Hjulroa
    through an RF→APRS-IS iGate, so replying only on the arriving transport
    (APRS-IS) is a dead end for an RF-only OffARO — most iGates do not gate
    APRS-IS back to RF. Sends on the arriving transport (with its reverse path)
    plus the other one; one signature (re-signed fresh via _wire_info), the
    same frame on both. Returns the transports used; raises if neither is up so
    the caller keeps the entry queued."""
    info = _wire_info(entry)
    arrived = entry['transport']
    used: list[str] = []
    # 1. The transport the request arrived on, with its computed reverse path.
    if arrived.is_up():
        try:
            arrived.send(entry['source'], entry['dest'], entry['path'], info)
            used.append(arrived.name)
        except Exception as e:
            log.warning(f"   ↩ {arrived.name} copy of seq {entry['seq']} failed ({e})")
    # 2. The OTHER transport. An APRS-IS-arrived request has a 'direct' reverse
    #    path, so its RF copy needs a WIDE digipeater path to propagate.
    if arrived.name == "APRS-IS":
        other, other_path = _rf_transport, (entry['path'] if entry['path'] else IS_FALLBACK_PATH)
    else:
        other, other_path = _is_transport, []   # client fills TCPIP*
    if other is not None and other is not arrived and other.is_up():
        try:
            other.send(entry['source'], entry['dest'], other_path, info)
            used.append(other.name)
        except Exception as e:
            log.warning(f"   ↩ {other.name} copy of seq {entry['seq']} failed ({e})")
    if not used:
        # Neither send worked — reuse the single-transport fallback, which
        # raises if nothing is usable (entry then stays queued).
        return _send_with_fallback(entry)
    return "+".join(used)


def _retry_target(entry: dict) -> tuple[Transport, list[str]]:
    """Which transport (and path) a retry should use.

    Odd retries go on the *other* transport when it is up, even retries on
    the original one. A reply that keeps dying on one path (2026-09-05: four
    identical APRS-IS sends, none reached OffARO) then gets a real second
    chance instead of the same failure again.
    """
    preferred = entry['transport']
    if entry['retries'] % 2 == 1:
        if preferred.name == "APRS-IS" and _rf_transport is not None and _rf_transport.is_up():
            return _rf_transport, IS_FALLBACK_PATH
        if preferred.name == "RF" and _is_transport is not None and _is_transport.is_up():
            return _is_transport, []   # the client fills in TCPIP*
    return preferred, entry['path']


def _send_ack_with_fallback(msg: Message) -> str:
    """Send the ACK for `msg` on the transport it arrived on, or over RF.
    Returns the transport name used; raises if neither is usable."""
    info = format_aprs_message(MY_CALLSIGN, msg.source, f"ack{msg.sequence}")
    return _send_via(msg.transport, MY_CALLSIGN, "APZOFA", msg.reverse_path, info,
                     f"ACK for seq {msg.sequence}")


def _sent_path_str(msg: Message, used: str) -> str:
    """The path an ACK for `msg` actually went out with, for the log line."""
    if used != msg.transport.name:
        return ','.join(IS_FALLBACK_PATH)
    return ','.join(msg.reverse_path) if msg.reverse_path else 'direct'


def queue_outgoing(seq: str, source: str, dest: str, path: list[str], info: str,
                   description: str, transport: Transport,
                   request: tuple[str, str] | None = None,
                   resign: dict | None = None,
                   broadcast: bool = False) -> None:
    """Send a message and queue it for retry until an ACK arrives.

    `request` is (sender, request-seq) of the message this one answers; when
    the ACK for this message arrives, that request is marked completed.

    `resign` (sender, addressee, body) makes every (re)send re-sign the body
    with a fresh HMAC timestamp instead of reusing `info`, so a reply delayed
    by retries or a slow path never arrives with an expired signature.

    `broadcast` sends every attempt on BOTH transports (RF + APRS-IS) at once
    instead of one-with-fallback, maximising the chance a peer on either
    transport receives it."""
    entry = {
        'seq': seq, 'source': source, 'dest': dest, 'path': list(path),
        'info': info, 'transport': transport, 'description': description,
        'sent_at': time.time(), 'retries': 0, 'request': request,
        'resign': resign, 'broadcast': broadcast,
    }
    with _queue_lock:
        _pending_acks[seq] = entry
    try:
        used = _send_on_both(entry) if broadcast else _send_with_fallback(entry)
        log.info(f"📤 {description} via {used} (seq {seq}, awaiting ACK)")
    except Exception as e:
        log.error(f"Failed to send {description}: {e} — will retry in {RETRY_INTERVAL}s")


def handle_incoming_ack(seq: str) -> None:
    """Remove message from retry queue when ACK is received."""
    with _queue_lock:
        info = _pending_acks.pop(seq, None)
    if info is not None:
        log.info(f"✅ ACK received for seq {seq} ({info['description']})")
        if info.get('request'):
            mark_request_completed(*info['request'])
    else:
        log.debug(f"ACK for unknown seq {seq}")


def accept_incoming_ack(source: str, seq: str) -> bool:
    """ACKs are unsigned, so at least insist that they come from the station we
    talk to; anyone else could otherwise silence our retries."""
    if source.upper() != AUTHORIZED_SENDER.upper():
        log.warning(f"   ⛔ ACK for seq {seq} from {source} ignored (not {AUTHORIZED_SENDER})")
        return False
    handle_incoming_ack(seq)
    return True


def process_retries() -> None:
    """Retransmit pending messages whose retry interval has elapsed."""
    now = time.time()
    with _queue_lock:
        due = [(seq, e) for seq, e in _pending_acks.items()
               if now - e['sent_at'] >= RETRY_INTERVAL]
    for seq, entry in due:
        if entry['retries'] >= MAX_RETRIES:
            log.warning(f"⏰ Gave up on seq {seq} ({entry['description']}) after {MAX_RETRIES} retries")
            with _queue_lock:
                _pending_acks.pop(seq, None)
            continue
        with _queue_lock:
            if seq not in _pending_acks:
                # ACKed between the snapshot above and this retry — skip it.
                continue
            # entry is the same dict object stored in _pending_acks, so this
            # mutation is visible there too.
            entry['retries'] += 1
            entry['sent_at'] = now
        try:
            # _wire_info (inside both send paths) re-signs a signed response
            # with a fresh timestamp so the retry never carries a stale one.
            if entry.get('broadcast'):
                used = _send_on_both(entry)   # both transports every attempt
                note = ""
            else:
                transport, path = _retry_target(entry)
                used = _send_via(transport, entry['source'], entry['dest'], path,
                                 _wire_info(entry), f"seq {seq}")
                note = "" if transport is entry['transport'] else " (alternating)"
            log.info(f"🔄 Retry {entry['retries']}/{MAX_RETRIES} for seq {seq} "
                     f"({entry['description']}) via {used}{note}")
        except Exception as e:
            log.error(f"Retry {entry['retries']}/{MAX_RETRIES} for seq {seq} failed: {e}")


# ── Main loop ──────────────────────────────────────────────────────────

def handle_message(msg: Message, body: str, devices: list) -> None:
    """Process a verified, non-duplicate message: ACK now, respond later."""
    if msg.sequence:
        may_send_ack(msg.source, msg.sequence)  # first ACK always goes; records the time
        _send_ack_now_or_later(msg, "sent")
    else:
        log.info(f"   ⚠️  no ACK requested by sender (message had no sequence number)")

    if body != STATUS_COMMAND and not body.startswith(CONTROL_PREFIX):
        log.warning(f"   ❓ unknown command body: {body!r} — no response will be sent")
        return

    # Device work can take minutes (Shelly HTTP timeouts); keep it off the
    # receiving thread so the early ACK keeps its head start.
    threading.Thread(
        target=_run_command_and_respond,
        args=(msg, body, devices),
        daemon=True,
        name=f"cmd-{msg.source}-{msg.sequence or '-'}",
    ).start()


def _run_command_and_respond(msg: Message, body: str, devices: list) -> None:
    """Worker: do the slow device work, then queue the signed response."""
    if body == STATUS_COMMAND:
        log.info(f"   📊 STATUS request — querying {len(devices)} devices...")
        states = query_all_devices(devices)
    else:
        command = body[len(CONTROL_PREFIX):]
        log.info(f"   🎮 CONTROL command: {command}")
        states = apply_control(devices, command)

    response_body = STATUS_PREFIX + states
    seq = next_sequence()
    path_str = ",".join(msg.reverse_path) if msg.reverse_path else "direct"
    log.info(f"   📤 TX response → {msg.source}: {response_body} "
             f"[seq={seq}, via {msg.transport.name} {path_str}]")

    # Sign at each (re)send, not once here — a retry 90 s+ later must carry a
    # fresh timestamp or OffARO rejects the signature as stale. resign holds the
    # unsigned body so _wire_info can re-sign on every transmission.
    signed_body = sign_message(MY_CALLSIGN, msg.source, response_body, SIGNING_KEY)
    response_info = format_aprs_message(MY_CALLSIGN, msg.source, signed_body, seq)
    # broadcast=True: send the response on RF *and* APRS-IS at once. The request
    # commonly arrives via an RF→APRS-IS iGate, so replying only on the arriving
    # transport can never reach an RF-only OffARO (iGates rarely gate IS→RF).
    queue_outgoing(seq, MY_CALLSIGN, "APZOFA", msg.reverse_path, response_info,
                   f"Status response to {msg.source}", msg.transport,
                   request=(msg.source, msg.sequence) if msg.sequence else None,
                   resign={'sender': MY_CALLSIGN, 'addressee': msg.source,
                           'body': response_body},
                   broadcast=True)


_handler_lock = threading.Lock()


def handle_incoming(msg: Message, devices: list) -> None:
    """Transport-independent handling of one parsed APRS message.

    Called from the KISS main loop and from the APRS-IS reader thread, so the
    shared tables (dedup, ACK throttle, retry queue) are used under one lock.
    The slow device work runs on its own worker thread, but the immediate ACK
    is written to the socket while the lock is held, so it can be held for as
    long as that write takes — up to the socket timeout (1 s for Direwolf,
    5 s for APRS-IS).
    """
    if msg.addressee.upper().rstrip() != MY_CALLSIGN.upper():
        log.debug(f"Not for us: '{msg.addressee}' != '{MY_CALLSIGN}'")
        return
    with _handler_lock:
        _handle_incoming_locked(msg, devices)


def _handle_incoming_locked(msg: Message, devices: list) -> None:
    source = msg.source

    # Incoming ACK (before signature check — ACKs are not signed).
    if msg.body.startswith("ack"):
        ack_seq = msg.body[3:]
        log.info(f"📥 ACK from {source} via {msg.transport.name}: ack{ack_seq}")
        accept_incoming_ack(source, ack_seq)
        return

    # ── Per-message envelope log ─────────────────────────────────
    seq_label = msg.sequence or '—'
    log.info(f"📥 RX from {source} → {msg.addressee} via {msg.transport.name}  "
             f"[seq={seq_label}, path={msg.rx_path}]")
    log.info(f"   body: {msg.body}")

    if source.upper() != AUTHORIZED_SENDER.upper():
        log.warning(f"   ⛔ REJECTED: unauthorized sender (expected {AUTHORIZED_SENDER})")
        log.info(f"   ❌ no ACK sent (sender not on whitelist)")
        return

    sig_result = extract_signature(msg.body)
    if not sig_result:
        log.warning(f"   ⛔ REJECTED: no signature found (\\S marker missing or wrong length)")
        log.info(f"   ❌ no ACK sent (unsigned messages are not authenticated)")
        return

    body, signature = sig_result
    if not verify_signature(source, MY_CALLSIGN, body, signature, SIGNING_KEY):
        log.warning(
            f"   ⛔ REJECTED: signature verification FAILED "
            f"(body={body!r}, sig={signature!r})"
        )
        log.info(f"   ❌ no ACK sent (signature did not verify)")
        return

    log.info("   ✅ signature OK (HMAC-MD5)")
    body = effective_body(source, body, signature, msg.sequence)
    reverse_str = ','.join(msg.reverse_path) if msg.reverse_path else 'direct'

    # Duplicate (same message via several digis / iGates / transports)
    if is_duplicate(source, body, msg.sequence):
        log.info(f"   🔄 DUPLICATE within {DEDUP_WINDOW}s window — re-sending ACK only")
        # RF echoes of a completed exchange get no re-ACK (nobody is waiting,
        # and airtime is precious). A duplicate arriving over APRS-IS is a real
        # retransmission by the sender — echoes never re-enter the server — so
        # it evidently missed our ACK; re-ACKing there costs nothing.
        age = request_age(source, body, msg.sequence)
        late = age is not None and age > IS_REACK_WINDOW
        if (msg.sequence and is_request_completed(source, msg.sequence)
                and (msg.transport.name == "RF" or late)):
            why = "RF echo" if msg.transport.name == "RF" else f"{age:.0f}s old echo via APRS-IS"
            log.info(f"   ✔ exchange for seq {msg.sequence} already acknowledged by "
                     f"{source} — no re-ACK ({why})")
        elif msg.sequence and not may_send_ack(source, msg.sequence):
            log.info(f"   💤 ACK for seq {msg.sequence} already sent within "
                     f"{DUP_ACK_INTERVAL}s — not re-sending")
        elif msg.sequence:
            _send_ack_now_or_later(msg, "re-sent")
        else:
            log.info(f"   ⚠️  no ACK to re-send (original had no sequence number)")
        return

    log.info(f"   📋 ACCEPTED: body={body!r}, reverse path={reverse_str}")
    handle_message(msg, body, devices)


def process_kiss_data(buffer: bytearray, devices: list,
                      transport: KissTransport) -> bytearray:
    """Extract complete KISS frames, parse them, hand messages to handle_incoming."""
    while True:
        start = buffer.find(bytes([KISS_FEND]))
        if start < 0:
            break
        end = buffer.find(bytes([KISS_FEND]), start + 1)
        if end < 0:
            break

        frame_data = buffer[start + 1:end]
        buffer = buffer[end + 1:]

        if len(frame_data) < 2:
            continue
        if frame_data[0] != 0x00:  # KISS data frame on port 0 only
            continue

        ax25_data = kiss_unescape(frame_data[1:])
        parsed = parse_ax25_frame(ax25_data)
        if not parsed:
            log.debug(f"Failed to parse AX.25 frame ({len(ax25_data)} bytes)")
            continue

        info = parsed["info"]
        actual_source = parsed["source"]
        via_igate = False

        # Third-party packets (iGate forwarded): }SENDER>DEST,PATH::ADDR :msg
        if info.startswith("}"):
            tp_match = info[1:].split("::", 1)
            if len(tp_match) == 2:
                header = tp_match[0]                 # "N0CALL-4>APZOFA,TCPIP,LD9HO*"
                info = ":" + tp_match[1]             # ":N0CALL-12 :status\S..."
                actual_source = header.split(">")[0].strip()
                via_igate = True
                log.debug(f"📡 Third-party packet from {actual_source} via {parsed['source']}")

        msg = parse_aprs_message(info)
        if not msg:
            log.debug(f"Not an APRS message: {parsed['info'][:40]}")
            continue

        if parsed['digipeaters']:
            rx_path = ','.join(
                d['callsign'] + ('*' if d['h_bit'] else '')
                for d in parsed['digipeaters']
            )
        else:
            rx_path = 'direct'
        if via_igate:
            rx_path = f"{rx_path} (via iGate {parsed['source']})"

        handle_incoming(Message(
            source=actual_source,
            addressee=msg["addressee"],
            body=msg["body"],
            sequence=msg["sequence"],
            reverse_path=extract_reverse_path(parsed["digipeaters"], via_igate=via_igate),
            transport=transport,
            rx_path=rx_path,
        ), devices)

    return buffer


def message_from_is_line(line: str, transport: Transport) -> Message | None:
    """Turn one APRS-IS text line into a Message, or None if it is not a message."""
    parts = aprs_is.parse_is_line(line)
    if not parts:
        return None
    msg = parse_aprs_message(parts["info"])
    if not msg:
        return None
    return Message(
        source=parts["source"],
        addressee=msg["addressee"],
        body=msg["body"],
        sequence=msg["sequence"],
        reverse_path=[],
        transport=transport,
        rx_path=",".join(parts["path"]) or "TCPIP",
    )


def _retry_loop() -> None:
    """Run process_retries() once a second, forever, on its own thread.

    It used to be called from the KISS recv-loop timeout, which meant retries
    stopped entirely while Direwolf was down — exactly when APRS-IS may still
    be able to deliver them. process_retries() takes _queue_lock only around
    the dict work and never sends under it, so it is safe off the main thread.
    """
    while True:
        try:
            process_retries()
        except Exception as e:
            log.error(f"❌ retry loop error: {e}")
        time.sleep(1)


def _on_is_line(line: str, transport: Transport, devices: list) -> None:
    """Callback for the APRS-IS reader thread."""
    try:
        msg = message_from_is_line(line, transport)
        # With no filter the server should only ever send us messages for
        # N0CALL-12, so anything else is worth a line in the log: it shows
        # whether a request reached the server at all (2026-09-04, seq 025).
        if msg is None:
            log.info(f"🌐 APRS-IS: not a message for us, ignored: {line[:120]}")
            return
        if msg.addressee.upper().rstrip() != MY_CALLSIGN.upper():
            log.info(f"🌐 APRS-IS: message for {msg.addressee.strip()} (not us) "
                     f"from {msg.source}: {msg.body[:60]}")
            return
        handle_incoming(msg, devices)
    except Exception as e:
        log.error(f"🌐 error handling APRS-IS line {line[:60]!r}: {e}")


def main():
    log.info(f"🚀 APRS Device Controller starting")
    log.info(f"   Callsign: {MY_CALLSIGN}")
    log.info(f"   Authorized sender: {AUTHORIZED_SENDER}")
    log.info(f"   Direwolf: {DIREWOLF_HOST}:{DIREWOLF_PORT}")
    log.info(f"   APRS-IS: {APRS_IS_HOST}:{APRS_IS_PORT} "
             f"({'enabled' if APRS_IS_ENABLED else 'disabled'})")

    # Load devices
    devices = load_devices(DEVICE_FILE)
    log.info(f"📋 Loaded {len(devices)} devices from {DEVICE_FILE}")
    for did, ip, backup_ip, name, ch in devices:
        ch_str = f" ch{ch}" if ch is not None else ""
        bk_str = f", backup {backup_ip}" if backup_ip else ""
        log.info(f"   {did:>2}. {name} ({ip}{bk_str}{ch_str})")

    global _rf_transport
    rf = KissTransport()
    _rf_transport = rf

    if APRS_IS_ENABLED:
        is_client = aprs_is.AprsIsClient(
            APRS_IS_HOST, APRS_IS_PORT, MY_CALLSIGN, VERSION,
            on_line=lambda line: _on_is_line(line, is_client, devices),
            idle_timeout=IS_IDLE_TIMEOUT, reconnect_delay=RECONNECT_DELAY,
            login_callsign=APRS_IS_LOGIN_CALLSIGN,
        )
        is_client.start()
        global _is_transport
        _is_transport = is_client
    else:
        log.info("🌐 APRS-IS disabled (APRS_IS_ENABLED = False) — RF only")

    threading.Thread(target=_retry_loop, daemon=True, name="retries").start()

    while True:
        try:
            log.info(f"🔌 Connecting to Direwolf at {DIREWOLF_HOST}:{DIREWOLF_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DIREWOLF_HOST, DIREWOLF_PORT))
            # Disable Nagle so the small ACK KISS frame flushes to Direwolf
            # immediately instead of being coalesced with the much-later response.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(1.0)  # 1 second timeout for non-blocking reads
            log.info("✅ Connected to Direwolf")
            rf.attach(sock)

            buffer = bytearray()
            while True:
                try:
                    data = sock.recv(1024)
                    if not data:
                        log.warning("🔌 Connection closed by Direwolf")
                        break
                    log.debug(f"📥 Received {len(data)} bytes: {data[:40].hex()}...")
                    buffer.extend(data)
                    buffer = process_kiss_data(buffer, devices, rf)
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    raise

        except ConnectionRefusedError:
            log.warning(f"🔌 Connection refused — is Direwolf running?")
        except ConnectionResetError:
            log.warning(f"🔌 Connection reset by Direwolf")
        except KeyboardInterrupt:
            log.info("👋 Shutting down")
            break
        except Exception as e:
            log.error(f"❌ Error: {e}")
        finally:
            # detach() nulls and closes the socket under _sock_lock, so a
            # worker cannot be inside sendall() on the fd we are closing.
            rf.detach()

        log.info(f"⏳ Reconnecting in {RECONNECT_DELAY} seconds...")
        try:
            time.sleep(RECONNECT_DELAY)
        except KeyboardInterrupt:
            log.info("👋 Shutting down")
            break


if __name__ == "__main__":
    main()
