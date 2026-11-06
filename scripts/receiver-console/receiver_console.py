#!/usr/bin/env python3
"""OffARO receiver console — ADS-B + AIS on the local screen of a receiver box.

Replaces `view1090` on the console of a Raspberry Pi that runs dump1090-fa and an
AIS receiver (AIS Dispatcher, rtl_ais, AIS-catcher …). One screen, two panes:

  * ADS-B: read from dump1090's aircraft.json (default /run/dump1090-fa/aircraft.json)
  * AIS:   NMEA AIVDM sentences received on a local UDP port (default 2222); the AIS
           software just needs one UDP destination pointing at 127.0.0.1:<port>.

The header shows the box's IP addresses and the footer tells you where to point
OffARO (AIS / ADS-B / Remote ID host:port), so the box can be used on a LAN with
no internet and no SSH tunnel. Only the standard library (plus curses) is needed.

  python3 receiver_console.py --lat 69.70 --lon 18.88
  python3 receiver_console.py --dump --dump-wait 5     # one frame as plain text (for tests / ssh)

Keys: s = toggle sort (distance / age).  See install.sh for the console autostart.
"""
import argparse
import collections
import glob
import json
import os
import math
import select
import socket
import subprocess
import sys
import time

VERSION = '1.0'

# ─── AIS decoding ──────────────────────────────────────────────────────────

NAV_STATUS = {
    0: 'Under way', 1: 'At anchor', 2: 'Not under cmd', 3: 'Restricted', 4: 'Constr. draught',
    5: 'Moored', 6: 'Aground', 7: 'Fishing', 8: 'Sailing', 11: 'Towing astern', 12: 'Pushing',
    14: 'AIS-SART', 15: '',
}


def nmea_checksum_ok(sentence):
    """True when the `*hh` checksum of an NMEA sentence matches (or there is none)."""
    if '*' not in sentence:
        return True
    body, _, given = sentence.rpartition('*')
    if not body.startswith(('!', '$')):
        return False
    calc = 0
    for ch in body[1:]:
        calc ^= ord(ch)
    try:
        return calc == int(given.strip()[:2], 16)
    except ValueError:
        return False


class Bits:
    """Six-bit ASCII payload of an AIVDM sentence as a bit field."""

    def __init__(self, payload, fill_bits=0):
        value = 0
        for ch in payload:
            c = ord(ch) - 48
            if c > 40:
                c -= 8
            if c < 0 or c > 63:
                raise ValueError('bad sixbit character %r' % ch)
            value = (value << 6) | c
        self.length = len(payload) * 6 - fill_bits
        self.value = value >> fill_bits if fill_bits else value

    def u(self, start, length):
        if start + length > self.length:
            raise ValueError('field beyond payload')
        shift = self.length - start - length
        return (self.value >> shift) & ((1 << length) - 1)

    def s(self, start, length):
        v = self.u(start, length)
        if v & (1 << (length - 1)):
            v -= 1 << length
        return v

    def text(self, start, length):
        out = []
        for i in range(start, min(start + length, self.length - 5), 6):
            c = self.u(i, 6)
            out.append(chr(c + 64) if c < 32 else chr(c))
        return ''.join(out).split('@', 1)[0].strip()


def _lonlat(bits, lon_at, lat_at):
    lon = bits.s(lon_at, 28) / 600000.0
    lat = bits.s(lat_at, 27) / 600000.0
    if abs(lon) > 180 or abs(lat) > 90:
        return None, None
    return lon, lat


def decode_ais(payload, fill_bits=0):
    """Decode one (reassembled) AIVDM payload to a dict, or None for unsupported types."""
    b = Bits(payload, fill_bits)
    if b.length < 38:
        return None
    t = b.u(0, 6)
    mmsi = b.u(8, 30)
    out = {'type': t, 'mmsi': mmsi}
    if t in (1, 2, 3) and b.length >= 137:
        out['status'] = b.u(38, 4)
        sog = b.u(50, 10)
        out['sog'] = None if sog == 1023 else sog / 10.0
        out['lon'], out['lat'] = _lonlat(b, 61, 89)
        cog = b.u(116, 12)
        out['cog'] = None if cog == 3600 else cog / 10.0
        hdg = b.u(128, 9)
        out['hdg'] = None if hdg == 511 else hdg
        out['kind'] = 'A'
    elif t == 4 and b.length >= 134:
        out['lon'], out['lat'] = _lonlat(b, 79, 107)
        out['kind'] = 'Base'
    elif t == 5 and b.length >= 422:
        out['callsign'] = b.text(70, 42)
        out['name'] = b.text(112, 120)
        out['shiptype'] = b.u(232, 8)
        out['destination'] = b.text(302, 120)
        out['kind'] = 'A'
    elif t == 9 and b.length >= 128:
        alt = b.u(38, 12)
        out['alt'] = None if alt == 4095 else alt
        sog = b.u(50, 10)
        out['sog'] = None if sog == 1023 else float(sog)
        out['lon'], out['lat'] = _lonlat(b, 61, 89)
        cog = b.u(116, 12)
        out['cog'] = None if cog == 3600 else cog / 10.0
        out['kind'] = 'SAR'
    elif t in (18, 19) and b.length >= 133:
        sog = b.u(46, 10)
        out['sog'] = None if sog == 1023 else sog / 10.0
        out['lon'], out['lat'] = _lonlat(b, 57, 85)
        cog = b.u(112, 12)
        out['cog'] = None if cog == 3600 else cog / 10.0
        hdg = b.u(124, 9)
        out['hdg'] = None if hdg == 511 else hdg
        out['kind'] = 'B'
        if t == 19 and b.length >= 271:
            out['name'] = b.text(143, 120)
            out['shiptype'] = b.u(263, 8)
    elif t == 21 and b.length >= 219:
        out['name'] = b.text(43, 120)
        out['lon'], out['lat'] = _lonlat(b, 164, 192)
        out['kind'] = 'AtoN'
    elif t == 24 and b.length >= 40:
        part = b.u(38, 2)
        out['kind'] = 'B'
        if part == 0 and b.length >= 160:
            out['name'] = b.text(40, 120)
        elif part == 1 and b.length >= 132:
            out['shiptype'] = b.u(40, 8)
            out['callsign'] = b.text(90, 42)
    else:
        return None
    return out


class AisAssembler:
    """Feeds NMEA lines, reassembles multi-sentence messages, yields decoded dicts."""

    def __init__(self):
        self.parts = {}           # (channel, seq) -> {count, got:{idx: payload}, fill, t}
        self.sentences = 0
        self.bad = 0

    def feed(self, line):
        line = line.strip()
        if not line.startswith(('!AIVDM', '!AIVDO', '!BSVDM', '!ABVDM')):
            return None
        if not nmea_checksum_ok(line):
            self.bad += 1
            return None
        fields = line.split('*', 1)[0].split(',')
        if len(fields) < 7:
            self.bad += 1
            return None
        try:
            count, index = int(fields[1]), int(fields[2])
            fill = int(fields[6] or 0)
        except ValueError:
            self.bad += 1
            return None
        self.sentences += 1
        payload = fields[5]
        if count == 1:
            return self._decode(payload, fill)
        key = (fields[4], fields[3])
        entry = self.parts.get(key)
        if entry is None or entry['count'] != count or time.time() - entry['t'] > 30:
            entry = self.parts[key] = {'count': count, 'got': {}, 'fill': 0, 't': time.time()}
        entry['got'][index] = payload
        if index == count:
            entry['fill'] = fill
        if len(entry['got']) == count:
            del self.parts[key]
            joined = ''.join(entry['got'][i] for i in range(1, count + 1))
            return self._decode(joined, entry['fill'])
        return None

    def _decode(self, payload, fill):
        try:
            return decode_ais(payload, fill)
        except ValueError:
            self.bad += 1
            return None


class VesselTable:
    def __init__(self, max_age):
        self.max_age = max_age
        self.vessels = {}          # mmsi -> dict

    def apply(self, msg, now):
        if not msg:
            return
        v = self.vessels.setdefault(msg['mmsi'], {'mmsi': msg['mmsi'], 'last': now})
        for k in ('lat', 'lon', 'sog', 'cog', 'hdg', 'status', 'name', 'callsign', 'shiptype', 'alt'):
            if msg.get(k) is not None:
                v[k] = msg[k]
        if 'kind' in msg and (msg['kind'] != 'A' or 'kind' not in v):
            v['kind'] = msg['kind']
        v['last'] = now

    def prune(self, now):
        for mmsi in [m for m, v in self.vessels.items() if now - v['last'] > self.max_age]:
            del self.vessels[mmsi]

    def rows(self):
        return list(self.vessels.values())


# ─── ADS-B (dump1090 aircraft.json) ────────────────────────────────────────

def read_aircraft_json(path):
    with open(path) as f:
        return json.load(f)


# ─── Geometry / formatting ────────────────────────────────────────────────

def distance_bearing(lat1, lon1, lat2, lon2):
    """Great-circle distance in km and initial bearing in degrees from point 1 to 2."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    d = 2 * r * math.asin(min(1.0, math.sqrt(a)))
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    brg = (math.degrees(math.atan2(y, x)) + 360) % 360
    return d, brg


def fmt_age(seconds):
    if seconds is None:
        return '-'
    seconds = int(seconds)
    if seconds < 60:
        return '%ds' % seconds
    if seconds < 3600:
        return '%dm' % (seconds // 60)
    return '%dh' % (seconds // 3600)


def fmt_num(v, fmt='%.1f'):
    return '-' if v is None else fmt % v


def fit(text, width):
    text = str(text)
    return text[:width].ljust(width)


def fmt_coord(lat, lon):
    return '%.4f%s %.4f%s' % (abs(lat), 'N' if lat >= 0 else 'S', abs(lon), 'E' if lon >= 0 else 'W')


def split_rows(avail, n_a, n_b, ratio=0.55):
    """Rows for pane A and pane B out of `avail` rows.

    The split line stays at `ratio` while both panes fit, so the screen does not jump
    around; a pane that needs more pushes the line, a pane that needs less gives up rows.
    Each pane keeps at least one row.
    """
    avail = max(avail, 2)
    need_a, need_b = max(n_a, 1), max(n_b, 1)
    share = int(round(avail * ratio))
    if need_a + need_b <= avail:
        a = min(max(share, need_a), avail - need_b)
    else:
        a = max(share, avail - need_b)      # B only gets what it needs
        a = min(a, need_a, avail - 1)       # A likewise, and B keeps a row
    return a, avail - a


def local_ips():
    """[(ifname, ip)] for every non-loopback IPv4 address, wired first."""
    out = []
    try:
        data = json.loads(subprocess.run(['ip', '-j', '-4', 'addr'], capture_output=True, text=True, timeout=3).stdout)
        for link in data:
            name = link.get('ifname', '?')
            for a in link.get('addr_info', []):
                if a.get('family') == 'inet' and a.get('scope') != 'host':
                    out.append((name, a['local']))
    except Exception:
        try:
            ips = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=3).stdout.split()
            out = [('', ip) for ip in ips if ':' not in ip and not ip.startswith('127.')]
        except Exception:
            out = []
    out.sort(key=lambda t: (not t[0].startswith('eth'), t[0]))
    return out


# ─── Model + frame rendering (pure, testable) ──────────────────────────────

class Model:
    """Everything the renderer needs; the collectors fill it in."""

    def __init__(self, args):
        self.args = args
        self.hostname = socket.gethostname()
        self.ips = []
        self.aircraft = []            # dicts from aircraft.json
        self.adsb_age = None          # seconds since aircraft.json was written
        self.adsb_total = None        # dump1090 total message counter
        self.adsb_rate = collections.deque()   # (t, total)
        self.ais_events = collections.deque()  # timestamps of AIS sentences
        self.ais_last = None          # time of the last datagram
        self.ais_device = None        # path of the USB receiver, if found
        self.vessels = VesselTable(args.max_age)
        self.assembler = AisAssembler()
        self.sort_by_distance = True
        self.started = time.time()

    @property
    def position(self):
        if self.args.lat is None or self.args.lon is None:
            return None
        return (self.args.lat, self.args.lon)

    def adsb_msg_per_min(self, now):
        while self.adsb_rate and now - self.adsb_rate[0][0] > 60:
            self.adsb_rate.popleft()
        if len(self.adsb_rate) < 2:
            return None
        (t0, c0), (t1, c1) = self.adsb_rate[0], self.adsb_rate[-1]
        if t1 - t0 < 5:
            return None
        return (c1 - c0) * 60.0 / (t1 - t0)

    def ais_msg_per_min(self, now):
        while self.ais_events and now - self.ais_events[0] > 60:
            self.ais_events.popleft()
        if now - self.started < 60:
            return len(self.ais_events) * 60.0 / max(now - self.started, 1)
        return float(len(self.ais_events))


def aircraft_rows(model, now):
    rows = []
    pos = model.position
    for a in model.aircraft:
        seen = a.get('seen')
        if seen is None or seen > model.args.max_age:
            continue
        lat, lon = a.get('lat'), a.get('lon')
        dist = brg = None
        if pos and lat is not None and lon is not None:
            dist, brg = distance_bearing(pos[0], pos[1], lat, lon)
        rows.append({'hex': a.get('hex', '?'), 'flight': (a.get('flight') or '').strip(),
                     'squawk': a.get('squawk', ''), 'alt': a.get('alt_baro', a.get('alt_geom')),
                     'gs': a.get('gs'), 'track': a.get('track', a.get('true_heading')),
                     'vs': a.get('baro_rate', a.get('geom_rate')), 'dist': dist, 'brg': brg,
                     'age': seen, 'rssi': a.get('rssi'),
                     'emergency': a.get('emergency') not in (None, 'none'),
                     'has_pos': lat is not None})
    return sort_rows(rows, model.sort_by_distance)


def vessel_rows(model, now):
    rows = []
    pos = model.position
    for v in model.vessels.rows():
        lat, lon = v.get('lat'), v.get('lon')
        dist = brg = None
        if pos and lat is not None and lon is not None:
            dist, brg = distance_bearing(pos[0], pos[1], lat, lon)
        kind = v.get('kind', 'A')
        if kind == 'A':
            status = NAV_STATUS.get(v.get('status', 15), 'Status %s' % v.get('status'))
        else:
            status = {'B': 'Class B', 'AtoN': 'AtoN', 'Base': 'Base station', 'SAR': 'SAR aircraft'}.get(kind, kind)
        rows.append({'mmsi': v['mmsi'], 'name': v.get('name') or v.get('callsign') or '',
                     'sog': v.get('sog'), 'cog': v.get('cog'), 'dist': dist, 'brg': brg,
                     'status': status, 'age': now - v['last'], 'has_pos': lat is not None,
                     'emergency': v.get('status') == 14})
    return sort_rows(rows, model.sort_by_distance)


def sort_rows(rows, by_distance):
    if by_distance:
        rows.sort(key=lambda r: (r['dist'] is None, r['dist'] if r['dist'] is not None else 0, r['age']))
    else:
        rows.sort(key=lambda r: r['age'])
    return rows


ADSB_HEAD = ' ICAO   FLIGHT   SQWK   ALT ft  SPD kt  TRK  DIST km  BRG    V/S  AGE   RSSI'
AIS_HEAD = ' MMSI      NAME                  SOG kt  COG  DIST km  BRG  STATUS          AGE'


def adsb_line(r):
    alt = r['alt']
    alt_s = 'GND' if alt == 'ground' else ('-' if alt is None else '%d' % alt)
    return ' %-6s %-8s %-4s %8s %7s %4s %8s %4s %6s %4s %6s' % (
        r['hex'][:6], r['flight'][:8], (r['squawk'] or '')[:4], alt_s,
        fmt_num(r['gs'], '%.0f'), fmt_num(r['track'], '%03.0f'), fmt_num(r['dist']),
        fmt_num(r['brg'], '%03.0f'), fmt_num(r['vs'], '%+d'), fmt_age(r['age']), fmt_num(r['rssi']))


def ais_line(r):
    return ' %-9s %-20s %7s %4s %8s %4s  %-14s %4s' % (
        r['mmsi'], r['name'][:20], fmt_num(r['sog']), fmt_num(r['cog'], '%03.0f'),
        fmt_num(r['dist']), fmt_num(r['brg'], '%03.0f'), r['status'][:14], fmt_age(r['age']))


def health_adsb(model, now):
    if model.adsb_age is None:
        return 'dump1090: no aircraft.json'
    if model.adsb_age > 15:
        return 'dump1090: stale (%s)' % fmt_age(model.adsb_age)
    rate = model.adsb_msg_per_min(now)
    return 'dump1090 ok' + ('' if rate is None else ' · %.0f msg/min' % rate)


def health_ais(model, now):
    bits = []
    if model.args.ais_device_glob and not model.ais_device:
        bits.append('no USB receiver')
    elif model.ais_device:
        bits.append('rx %s' % os.path.basename(os.path.realpath(model.ais_device)))
    if model.ais_last is None:
        bits.append('no data yet (udp %d)' % model.args.ais_udp)
    elif now - model.ais_last > 120:
        bits.append('no data for %s' % fmt_age(now - model.ais_last))
    else:
        bits.append('%.0f msg/min' % model.ais_msg_per_min(now))
    return ' · '.join(bits)


def render_frame(model, width, height, now=None):
    """Return (lines, attrs): `height` strings of exactly `width` chars and a style tag per line."""
    now = time.time() if now is None else now
    width = max(width, 40)
    height = max(height, 8)
    air = aircraft_rows(model, now)
    sea = vessel_rows(model, now)
    lines, attrs = [], []

    def put(text, attr='normal'):
        lines.append(fit(text, width))
        attrs.append(attr)

    ipinfo = '  '.join(('%s %s' % (n, ip)).strip() for n, ip in model.ips) or 'no IP address'
    clock = time.strftime('%H:%M:%S', time.localtime(now))
    pos = model.position
    left = ' %s  %s  rx %s' % (model.hostname, ipinfo, fmt_coord(*pos) if pos else 'position unknown')
    put(left[:width - len(clock) - 2].ljust(width - len(clock) - 1) + clock, 'header')

    avail = height - 6
    n_air, n_sea = split_rows(avail, len(air), len(sea))

    put(' ADS-B  %d aircraft  ·  %s' % (len(air), health_adsb(model, now)), 'title')
    put(ADSB_HEAD, 'colhead')
    body(put, air, n_air, adsb_line, 'no aircraft', model.args.max_age)

    put(' AIS  %d vessels  ·  %s' % (len(sea), health_ais(model, now)), 'title')
    put(AIS_HEAD, 'colhead')
    body(put, sea, n_sea, ais_line, 'no vessels', model.args.max_age)

    put(footer_text(model, width - 1), 'footer')   # curses cannot write the very last cell
    return lines, attrs


def body(put, rows, n, fmt, empty_text, max_age):
    if not rows:
        put('   (%s)' % empty_text, 'dim')
        for _ in range(n - 1):
            put('')
        return
    shown = rows[:n] if len(rows) <= n else rows[:max(n - 1, 0)]
    for r in shown:
        attr = 'alert' if r.get('emergency') else ('dim' if r['age'] > max_age / 2 else 'normal')
        put(fmt(r), attr)
    if len(rows) > n:
        put('   … %d more' % (len(rows) - len(shown)), 'dim')
    for _ in range(n - len(shown) - (1 if len(rows) > n else 0)):
        put('')


def footer_text(model, width=80):
    """Where to point OffARO: the box's first IP once, then one port per feed."""
    ip = model.ips[0][1] if model.ips else '<ip>'
    a = model.args
    parts = []
    if a.ais_port:
        parts.append('AIS :%d' % a.ais_port)
    if a.adsb_port:
        parts.append('ADS-B :%d' % a.adsb_port)
    if a.remoteid_port:
        parts.append('Remote ID :%d' % a.remoteid_port)
    where = (' OffARO → %s  %s' % (ip, '  '.join(parts))) if parts else ''
    tag = 'sort:%s' % ('dist' if model.sort_by_distance else 'age')
    if len(where) + len(tag) + 2 <= width:
        return where.ljust(width - len(tag)) + tag
    return where


# ─── Collectors ───────────────────────────────────────────────────────────

class Collector:
    def __init__(self, model):
        self.model = model
        self.sock = None
        self.buf = b''
        self.last_json = 0
        self.last_ips = 0
        self.last_prune = 0

    def open_udp(self):
        a = self.model.args
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.ais_bind, a.ais_udp))
        s.setblocking(False)
        self.sock = s

    def poll(self, timeout):
        """Wait up to `timeout` s for AIS datagrams, then refresh the periodic sources."""
        m = self.model
        if self.sock:
            r, _, _ = select.select([self.sock], [], [], timeout)
            while r:
                try:
                    data, _ = self.sock.recvfrom(65535)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                now = time.time()
                m.ais_last = now
                for line in data.decode('ascii', 'replace').splitlines():
                    msg = m.assembler.feed(line)
                    if line.startswith('!'):
                        m.ais_events.append(now)
                    m.vessels.apply(msg, now)
                r, _, _ = select.select([self.sock], [], [], 0)
        else:
            time.sleep(timeout)
        now = time.time()
        if now - self.last_json >= 1:
            self.last_json = now
            self.refresh_adsb(now)
        if now - self.last_ips >= 10:
            self.last_ips = now
            m.ips = local_ips()
            if m.args.ais_device_glob:
                found = sorted(glob.glob(m.args.ais_device_glob))
                m.ais_device = found[0] if found else None
        if now - self.last_prune >= 5:
            self.last_prune = now
            m.vessels.prune(now)

    def refresh_adsb(self, now):
        m = self.model
        try:
            st = os.stat(m.args.aircraft_json)
            d = read_aircraft_json(m.args.aircraft_json)
        except (OSError, ValueError):
            m.adsb_age = None
            m.aircraft = []
            return
        m.adsb_age = max(0.0, now - st.st_mtime)
        m.aircraft = d.get('aircraft', [])
        total = d.get('messages')
        if isinstance(total, (int, float)):
            m.adsb_rate.append((now, total))


# ─── curses front end ─────────────────────────────────────────────────────

def run_curses(stdscr, model, collector):
    import curses
    curses.curs_set(0)
    stdscr.nodelay(True)
    styles = {'normal': 0, 'dim': curses.A_DIM, 'title': curses.A_BOLD, 'colhead': curses.A_UNDERLINE,
              'header': curses.A_REVERSE, 'footer': curses.A_REVERSE, 'alert': curses.A_BOLD}
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
        styles['title'] |= curses.color_pair(1)
        styles['alert'] |= curses.color_pair(2)
        styles['header'] = curses.color_pair(3) | curses.A_BOLD
        styles['footer'] = curses.color_pair(3) | curses.A_BOLD
    except curses.error:
        pass
    while True:
        collector.poll(0.5)
        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1
        if ch in (ord('s'), ord('S')):
            model.sort_by_distance = not model.sort_by_distance
        elif ch == curses.KEY_RESIZE:
            stdscr.clear()
        h, w = stdscr.getmaxyx()
        lines, attrs = render_frame(model, w, h)
        for y, (text, tag) in enumerate(zip(lines, attrs)):
            if y >= h:
                break
            try:
                stdscr.addnstr(y, 0, text, w - 1 if y == h - 1 else w, styles.get(tag, 0))
            except curses.error:
                pass
        stdscr.refresh()


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--aircraft-json', default='/run/dump1090-fa/aircraft.json', help='dump1090 JSON (default /run/dump1090-fa/aircraft.json)')
    p.add_argument('--ais-udp', type=int, default=2222, help='UDP port to receive AIVDM sentences on (default 2222)')
    p.add_argument('--ais-bind', default='127.0.0.1', help='address to bind the AIS UDP socket to (default 127.0.0.1)')
    p.add_argument('--ais-device-glob', default='/dev/serial/by-id/*', help='glob that matches the USB AIS receiver, shown as health ("" to disable)')
    p.add_argument('--lat', type=float, help='receiver latitude (for distance / bearing)')
    p.add_argument('--lon', type=float, help='receiver longitude')
    p.add_argument('--max-age', type=int, default=120, help='hide targets not heard for this many seconds (default 120)')
    p.add_argument('--ais-port', type=int, default=10111, help='TCP port OffARO should use for AIS on this box, shown in the footer (0 = hide)')
    p.add_argument('--adsb-port', type=int, default=30003, help='port OffARO should use for ADS-B (SBS/BaseStation, default 30003; 0 = hide)')
    p.add_argument('--remoteid-port', type=int, default=5003, help='port OffARO should use for Remote ID (default 5003; 0 = hide)')
    p.add_argument('--dump', action='store_true', help='print one frame as text and exit (no curses)')
    p.add_argument('--dump-wait', type=float, default=3, help='seconds to collect data before --dump (default 3)')
    p.add_argument('--width', type=int, default=80, help='frame width for --dump')
    p.add_argument('--height', type=int, default=26, help='frame height for --dump')
    p.add_argument('--log', help='append errors to this file')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    model = Model(args)
    model.ips = local_ips()
    collector = Collector(model)
    try:
        collector.open_udp()
    except OSError as e:
        sys.stderr.write('AIS UDP %s:%d: %s (AIS pane will stay empty)\n' % (args.ais_bind, args.ais_udp, e))
    if args.dump:
        end = time.time() + args.dump_wait
        while time.time() < end:
            collector.poll(0.5)
        lines, _ = render_frame(model, args.width, args.height)
        print('\n'.join(lines))
        return 0
    import curses
    while True:
        try:
            curses.wrapper(run_curses, model, collector)
            return 0
        except KeyboardInterrupt:
            return 0
        except Exception as e:  # keep the kiosk alive, log and restart the UI
            if args.log:
                with open(args.log, 'a') as f:
                    f.write('%s %r\n' % (time.strftime('%Y-%m-%dT%H:%M:%S'), e))
            time.sleep(2)


if __name__ == '__main__':
    sys.exit(main())
