#!/usr/bin/env python3
"""OffARO Drone Remote ID — filtering pcap proxy for a remote receiver.

Sits between tcpdump and OffARO on a Raspberry Pi (or any Linux box) with a
monitor-mode Wi-Fi adapter. tcpdump captures every beacon / probe response on
the channel; this program keeps only the frames that carry a Remote ID vendor
element (ASD-STAN OUI FA-0B-BC or Parrot 90-3A-E6, type 0x0D) and serves them,
still as a pcap stream, on a TCP port. OffARO's "Remote receiver" source reads
it unchanged, so the decoder stays in OffARO and the Pi never needs updating
when it changes. Over a 4G link this cuts the traffic from every access point
on the channel down to roughly a kilobyte per second per drone in the air.

Compared with the plain `tcpdump | socat` receiver it also accepts several
OffARO clients at once, and tcpdump keeps running while clients come and go.

    sudo remoteid_filter.py --interface wlan1 --monitor-channel 6 --listen 5003
    # listens on 127.0.0.1 only (use through `ssh -L 5003:localhost:5003 pi`);
    # add --bind 0.0.0.0 to serve the LAN directly

    tcpdump -i wlan1 -U -w - -s 0 -n 'type mgt and (subtype beacon or subtype probe-resp)' \
        | remoteid_filter.py --stdin --listen 5003

Needs Python 3.7+ (standard library only), tcpdump and, for --monitor-channel, iw.
See the systemd unit next to this file for running it at boot.
"""
import argparse
import os
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

ASD_STAN_OUI = b'\xfa\x0b\xbc'
PARROT_OUI = b'\x90\x3a\xe6'
ODID_OUI_TYPE = 0x0D
ODID_MESSAGE_SIZE = 25

MGMT_HEADER = 24
BEACON_FIXED = 12
IE_VENDOR = 0xDD
SUBTYPE_PROBE_RESP = 5
SUBTYPE_BEACON = 8

LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

GLOBAL_HEADER = 24
RECORD_HEADER = 16
MAX_RECORD = 262144

BPF_FILTER = 'type mgt and (subtype beacon or subtype probe-resp)'
RESTART_DELAYS_S = [2, 5, 10, 30]
MAX_CLIENT_BACKLOG = 4 * 1024 * 1024   # bytes queued for one slow client before it is dropped
MAX_CLIENTS = 16


# ---------------------------------------------------------------- frame check

def is_remote_id_frame(frame):
    """True for a beacon or probe response that carries a Remote ID element with at
    least one full ODID message. Mirrors extractRemoteId() in OffARO's odidWifi.ts."""
    if len(frame) < MGMT_HEADER + BEACON_FIXED:
        return False
    fc = frame[0]
    ftype = (fc >> 2) & 0x03
    subtype = fc >> 4
    if ftype != 0 or subtype not in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP):
        return False
    i = MGMT_HEADER + BEACON_FIXED
    n = len(frame)
    while i + 2 <= n:
        ie_id = frame[i]
        ie_len = frame[i + 1]
        start = i + 2
        end = start + ie_len
        if end > n:
            return False            # truncated element: stop, like OffARO
        if (ie_id == IE_VENDOR and ie_len >= 5 + ODID_MESSAGE_SIZE
                and frame[start + 3] == ODID_OUI_TYPE
                and frame[start:start + 3] in (ASD_STAN_OUI, PARROT_OUI)):
            return True
        i = end
    return False


def dot11_payload(data, link_type):
    """The 802.11 frame inside a pcap record: radiotap (127) is stripped by its length
    field, raw 802.11 (105) passes through, anything else is None."""
    if link_type == LINKTYPE_IEEE802_11:
        return data
    if link_type != LINKTYPE_IEEE802_11_RADIOTAP or len(data) < 8:
        return None
    rt_len = struct.unpack_from('<H', data, 2)[0]
    if rt_len > len(data) or rt_len < 8:
        return None
    return data[rt_len:]


# ---------------------------------------------------------------- pcap stream

class PcapError(Exception):
    pass


class PcapFilter:
    """Incremental pcap stream filter: feed() any split of the byte stream and get back
    the complete records (header + data, verbatim) that contain Remote ID."""

    def __init__(self):
        self.buf = bytearray()
        self.little = True
        self.nanos = False
        self.link_type = None
        self.global_header = None
        self.frames_seen = 0
        self.remote_id_frames = 0

    def feed(self, chunk):
        out = []
        if not chunk:
            return out
        self.buf += chunk
        off = 0
        if self.link_type is None:
            if len(self.buf) < GLOBAL_HEADER:
                return out
            magic_le = struct.unpack_from('<I', self.buf, 0)[0]
            if magic_le == 0xA1B2C3D4:
                self.little, self.nanos = True, False
            elif magic_le == 0xA1B23C4D:
                self.little, self.nanos = True, True
            elif magic_le == 0xD4C3B2A1:
                self.little, self.nanos = False, False
            elif magic_le == 0x4D3CB2A1:
                self.little, self.nanos = False, True
            else:
                raise PcapError('not a pcap stream (magic 0x%08x)' % magic_le)
            self.link_type = struct.unpack_from('<I' if self.little else '>I', self.buf, 20)[0]
            self.global_header = bytes(self.buf[:GLOBAL_HEADER])
            off = GLOBAL_HEADER
        fmt = '<IIII' if self.little else '>IIII'
        while len(self.buf) - off >= RECORD_HEADER:
            _sec, _frac, incl, _orig = struct.unpack_from(fmt, self.buf, off)
            if incl > MAX_RECORD:
                raise PcapError('pcap record too large (%d bytes)' % incl)
            if len(self.buf) - off - RECORD_HEADER < incl:
                break
            record = bytes(self.buf[off:off + RECORD_HEADER + incl])
            off += RECORD_HEADER + incl
            self.frames_seen += 1
            frame = dot11_payload(record[RECORD_HEADER:], self.link_type)
            if frame is not None and is_remote_id_frame(frame):
                self.remote_id_frames += 1
                out.append(record)
        if off:
            del self.buf[:off]
        return out


# ---------------------------------------------------------------- client hub

class Hub:
    """Fan-out of pcap records to TCP clients. A client receives the pcap global header
    first and only records broadcast after it joined; records are dropped for a client
    while the header is still unknown (tcpdump not started yet)."""

    def __init__(self, log=None, on_remove=None):
        self.header = None
        self.clients = {}        # socket -> bytearray backlog
        self.waiting = set()     # connected before the header was known
        self.log = log or (lambda msg: None)
        # Called with the socket, still open, before it is closed: the owner unregisters
        # it from its selector here, so a reused fd number can never hit a stale entry.
        self.on_remove = on_remove or (lambda sock: None)

    def set_header(self, header):
        if header == self.header:
            return
        if self.header is not None:
            # A different pcap header (new link type) cannot be spliced into a running
            # stream: drop everyone, they reconnect and start cleanly.
            self.log('pcap header changed; disconnecting %d client(s)' % len(self.clients))
            for sock in list(self.clients):
                self.remove_client(sock)
        self.header = header
        for sock in list(self.waiting):
            self.clients[sock] += header
        self.waiting.clear()

    def add_client(self, sock):
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        self.clients[sock] = bytearray()
        if self.header is None:
            self.waiting.add(sock)
        else:
            self.clients[sock] += self.header

    def remove_client(self, sock):
        if sock not in self.clients:
            return
        self.clients.pop(sock, None)
        self.waiting.discard(sock)
        try:
            self.on_remove(sock)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def client_count(self):
        return len(self.clients)

    def broadcast(self, record):
        for sock, backlog in self.clients.items():
            if sock in self.waiting:
                continue
            backlog += record

    def flush_all(self):
        for sock in list(self.clients):
            backlog = self.clients.get(sock)
            if backlog is None or not backlog:
                continue
            try:
                sent = sock.send(backlog)
                del backlog[:sent]
            except (BlockingIOError, InterruptedError):
                pass
            except OSError as e:
                self.log('client %s dropped: %s' % (peer_name(sock), e))
                self.remove_client(sock)
                continue
            if len(backlog) > MAX_CLIENT_BACKLOG:
                self.log('client %s too slow (%d bytes queued); dropped' % (peer_name(sock), len(backlog)))
                self.remove_client(sock)


def peer_name(sock):
    try:
        host, port = sock.getpeername()[:2]
        return '%s:%s' % (host, port)
    except OSError:
        return '?'


# ---------------------------------------------------------------- tcpdump / main

def tcpdump_args(iface, tcpdump='tcpdump'):
    """The same capture command OffARO uses for its local tcpdump source. Debian's tcpdump
    drops to its own user after opening the interface; when run from systemd the unit
    must therefore allow CAP_SETUID/CAP_SETGID (see remoteid-filter.service)."""
    return [tcpdump, '-i', iface, '-U', '-w', '-', '-s', '0', '-n', BPF_FILTER]


def setup_monitor(iface, channel, log):
    """Put iface into monitor mode on channel (needs root and iw), like monitor-setup.sh."""
    cmds = [
        ['ip', 'link', 'set', iface, 'down'],
        ['iw', 'dev', iface, 'set', 'type', 'monitor'],
        ['ip', 'link', 'set', iface, 'up'],
        ['iw', 'dev', iface, 'set', 'channel', str(channel)],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise SystemExit('monitor setup failed: %s: %s' % (' '.join(cmd), r.stdout.decode(errors='replace').strip()))
    log('%s in monitor mode on channel %s' % (iface, channel))


class Proxy:
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.sel = selectors.DefaultSelector()
        self.hub = Hub(log, on_remove=self.unregister)
        self.filter = PcapFilter()
        self.child = None
        self.source = None        # file object with a readable fd (tcpdump stdout or stdin)
        self.stderr_tail = ''
        self.attempt = 0
        self.next_start = 0.0
        self.stopping = False
        self.last_stats = time.monotonic()
        self.listener = None

    # -- source
    def start_source(self):
        if self.args.stdin:
            self.source = os.fdopen(os.dup(sys.stdin.fileno()), 'rb', buffering=0)
        else:
            cmd = tcpdump_args(self.args.interface, self.args.tcpdump)
            self.log('starting: %s' % ' '.join(cmd))
            try:
                self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            except OSError as e:
                self.log('cannot start tcpdump: %s' % e)
                self.schedule_restart()
                return
            self.source = self.child.stdout
            os.set_blocking(self.child.stderr.fileno(), False)
            self.sel.register(self.child.stderr, selectors.EVENT_READ, self.on_stderr)
        os.set_blocking(self.source.fileno(), False)
        self.filter = PcapFilter()
        self.sel.register(self.source, selectors.EVENT_READ, self.on_source)

    def stop_source(self):
        if self.source is not None:
            try:
                self.sel.unregister(self.source)
            except (KeyError, ValueError):
                pass
            try:
                self.source.close()
            except OSError:
                pass
            self.source = None
        if self.child is not None:
            try:
                self.sel.unregister(self.child.stderr)
            except (KeyError, ValueError):
                pass
            if self.child.poll() is None:
                try:
                    self.child.terminate()
                    try:
                        self.child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.child.kill()
                except OSError as e:
                    # tcpdump runs as its own user; without CAP_KILL we may not signal it.
                    # Closing its stdout makes it exit on the next write, and systemd
                    # kills the whole cgroup on stop anyway.
                    self.log('could not signal tcpdump (pid %s): %s' % (self.child.pid, e))
            try:
                self.child.stderr.close()
            except OSError:
                pass
            self.child = None

    def schedule_restart(self):
        self.stop_source()
        if self.args.stdin or self.stopping:
            self.stopping = True
            return
        delay = RESTART_DELAYS_S[min(self.attempt, len(RESTART_DELAYS_S) - 1)]
        self.attempt += 1
        self.next_start = time.monotonic() + delay
        self.log('tcpdump exited%s; restart in %ds' % (': ' + self.stderr_tail if self.stderr_tail else '', delay))

    def on_stderr(self, f):
        try:
            data = f.read(4096)
        except (BlockingIOError, InterruptedError):
            return
        if data:
            text = data.decode(errors='replace')
            if self.args.verbose:
                for line in text.rstrip().splitlines():
                    self.log('tcpdump: ' + line)
            lines = text.strip().splitlines()
            if lines:
                self.stderr_tail = lines[-1][:200]

    def on_source(self, f):
        try:
            data = f.read(65536)
        except (BlockingIOError, InterruptedError):
            return
        if not data:
            self.schedule_restart()
            return
        try:
            records = self.filter.feed(data)
        except PcapError as e:
            self.log('source stream dropped: %s' % e)
            self.schedule_restart()
            return
        if self.filter.global_header is not None and self.hub.header != self.filter.global_header:
            self.hub.set_header(self.filter.global_header)
            self.attempt = 0
        for rec in records:
            self.hub.broadcast(rec)
        if records:
            self.hub.flush_all()

    # -- clients
    def on_accept(self, listener):
        try:
            sock, addr = listener.accept()
        except OSError:
            return
        if self.hub.client_count() >= MAX_CLIENTS:
            self.log('refusing %s:%s: %d clients already' % (addr[0], addr[1], MAX_CLIENTS))
            sock.close()
            return
        self.hub.add_client(sock)
        self.sel.register(sock, selectors.EVENT_READ, self.on_client)
        self.log('client %s:%s connected (%d total)' % (addr[0], addr[1], self.hub.client_count()))

    def on_client(self, sock):
        # Clients never send anything useful; readable means closed (or junk to discard).
        try:
            data = sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b''
        if not data:
            self.log('client %s disconnected' % peer_name(sock))
            self.drop_client(sock)

    def drop_client(self, sock):
        self.hub.remove_client(sock)      # runs unregister() first, then closes

    def unregister(self, sock):
        try:
            self.sel.unregister(sock)
        except (KeyError, ValueError):
            pass

    # -- loop
    def run(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.args.bind, self.args.listen))
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.sel.register(self.listener, selectors.EVENT_READ, self.on_accept)
        self.log('listening on %s:%d' % self.listener.getsockname()[:2])
        self.start_source()
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())
        while not self.stopping:
            for key, _ in self.sel.select(timeout=1.0):
                try:
                    key.data(key.fileobj)
                except Exception as e:      # one misbehaving fd must not take the loop down
                    self.log('error handling %r: %s' % (key.fileobj, e))
                    if isinstance(key.fileobj, socket.socket) and key.fileobj is not self.listener:
                        self.drop_client(key.fileobj)
            self.hub.flush_all()
            now = time.monotonic()
            if self.source is None and not self.stopping and now >= self.next_start:
                self.start_source()
            if now - self.last_stats >= self.args.stats_interval:
                self.last_stats = now
                self.log('frames=%d remote_id=%d clients=%d source=%s' % (
                    self.filter.frames_seen, self.filter.remote_id_frames, self.hub.client_count(),
                    'stdin' if self.args.stdin else ('running' if self.child and self.child.poll() is None else 'down')))
        self.stop_source()
        for sock in list(self.hub.clients):
            self.hub.remove_client(sock)
        self.listener.close()
        self.log('stopped')

    def request_stop(self):
        self.stopping = True


def build_parser():
    p = argparse.ArgumentParser(description='Filtering pcap proxy for OffARO Drone Remote ID remote receivers.')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--interface', '-i', help='monitor-mode interface; tcpdump is started and kept running')
    src.add_argument('--stdin', action='store_true', help='read a pcap stream from stdin instead of starting tcpdump')
    p.add_argument('--tcpdump', default='tcpdump', help='tcpdump binary (default: from PATH)')
    p.add_argument('--monitor-channel', type=int, metavar='CH', help='put --interface into monitor mode on this channel first (root, iw)')
    p.add_argument('--listen', '-p', type=int, default=5003, help='TCP port to serve the filtered stream on (default 5003)')
    p.add_argument('--bind', default='127.0.0.1',
                   help='address to listen on (default 127.0.0.1: reachable through an ssh tunnel only; '
                        '--bind 0.0.0.0 to serve the LAN directly — the stream is unauthenticated)')
    p.add_argument('--stats-interval', type=int, default=60, help='seconds between stats lines on stderr (default 60)')
    p.add_argument('--verbose', '-v', action='store_true', help='also log every tcpdump stderr line')
    return p


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)

    def log(msg):
        sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S ') + 'remoteid_filter: ' + msg + '\n')
        sys.stderr.flush()

    if args.monitor_channel is not None:
        if args.stdin:
            p.error('--monitor-channel needs --interface')
        setup_monitor(args.interface, args.monitor_channel, log)
    Proxy(args, log).run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
