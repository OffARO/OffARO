"""Tests for remoteid_filter.py — run with: python3 -m unittest -v scripts/drone-remote-id/test_remoteid_filter.py"""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remoteid_filter as rf  # noqa: E402

ASD = bytes([0xFA, 0x0B, 0xBC])
PARROT = bytes([0x90, 0x3A, 0xE6])


def mgmt_frame(subtype, ies, mac=b'\x02\x11\x22\x33\x44\x55'):
    fc = bytes([subtype << 4, 0x00])
    header = fc + b'\x00\x00' + b'\xff' * 6 + mac + mac + b'\x00\x00'   # 24 bytes
    fixed = b'\x00' * 12
    return header + fixed + ies


def ie(ie_id, body):
    return bytes([ie_id, len(body)]) + body


def rid_ie(oui=ASD, counter=7, payload=None):
    payload = b'\x02' + b'\x00' * 24 if payload is None else payload   # one 25-byte ODID message
    return ie(0xDD, oui + bytes([0x0D, counter]) + payload)


def ssid_ie(name=b'HomeWifi'):
    return ie(0x00, name)


def radiotap(frame, present=0, extra=b''):
    body = struct.pack('<I', present) + extra
    hdr = struct.pack('<BBH', 0, 0, 4 + len(body)) + body
    return hdr + frame


def pcap_header(linktype=127, magic=0xA1B2C3D4, little=True):
    fmt = '<IHHiIII' if little else '>IHHiIII'
    return struct.pack(fmt, magic, 2, 4, 0, 0, 262144, linktype)


def pcap_record(data, sec=1700000000, frac=123, little=True):
    fmt = '<IIII' if little else '>IIII'
    return struct.pack(fmt, sec, frac, len(data), len(data)) + data


class IsRemoteIdFrame(unittest.TestCase):
    def test_beacon_with_asd_stan_element(self):
        self.assertTrue(rf.is_remote_id_frame(mgmt_frame(8, ssid_ie() + rid_ie())))

    def test_probe_response_with_parrot_element(self):
        self.assertTrue(rf.is_remote_id_frame(mgmt_frame(5, rid_ie(oui=PARROT))))

    def test_plain_access_point_beacon_is_not(self):
        self.assertFalse(rf.is_remote_id_frame(mgmt_frame(8, ssid_ie() + ie(0x01, b'\x82\x84\x8b\x96'))))

    def test_other_vendor_element_is_not(self):
        self.assertFalse(rf.is_remote_id_frame(mgmt_frame(8, ie(0xDD, b'\x00\x50\xf2\x01' + b'\x00' * 30))))

    def test_data_frame_and_other_mgmt_subtypes_are_not(self):
        self.assertFalse(rf.is_remote_id_frame(mgmt_frame(4, rid_ie())))        # probe request
        data_fc = bytes([0x08, 0x00])
        self.assertFalse(rf.is_remote_id_frame(data_fc + b'\x00' * 40 + rid_ie()))

    def test_truncated_element_is_not(self):
        frame = mgmt_frame(8, rid_ie())
        self.assertFalse(rf.is_remote_id_frame(frame[:-10]))

    def test_short_frame_is_not(self):
        self.assertFalse(rf.is_remote_id_frame(b'\x80\x00' + b'\x00' * 10))

    def test_element_without_a_full_odid_message_is_not(self):
        self.assertFalse(rf.is_remote_id_frame(mgmt_frame(8, rid_ie(payload=b'\x02' * 10))))


class Dot11Payload(unittest.TestCase):
    def test_strips_radiotap_by_its_length_field(self):
        frame = mgmt_frame(8, rid_ie())
        self.assertEqual(rf.dot11_payload(radiotap(frame, present=0x20, extra=b'\xc0'), 127), frame)

    def test_passes_raw_80211_through(self):
        frame = mgmt_frame(8, rid_ie())
        self.assertEqual(rf.dot11_payload(frame, 105), frame)

    def test_rejects_other_link_types_and_bad_radiotap(self):
        self.assertIsNone(rf.dot11_payload(b'\x00' * 40, 1))
        self.assertIsNone(rf.dot11_payload(b'\x00\x00\xff\xff' + b'\x00' * 10, 127))


class PcapFilterStream(unittest.TestCase):
    def collect(self, stream, chunk=7):
        f = rf.PcapFilter()
        out = []
        for i in range(0, len(stream), chunk):
            out.extend(f.feed(stream[i:i + chunk]))
        return f, out

    def test_passes_only_remote_id_records_with_header_preserved(self):
        drone = pcap_record(radiotap(mgmt_frame(8, rid_ie())))
        ap = pcap_record(radiotap(mgmt_frame(8, ssid_ie())))
        f, out = self.collect(pcap_header() + ap + drone + ap + drone)
        self.assertEqual(f.global_header, pcap_header())
        self.assertEqual(out, [drone, drone])
        self.assertEqual((f.frames_seen, f.remote_id_frames), (4, 2))

    def test_big_endian_and_nanosecond_headers(self):
        drone = pcap_record(radiotap(mgmt_frame(8, rid_ie())), little=False)
        f, out = self.collect(pcap_header(magic=0xA1B23C4D, little=False) + drone, chunk=5)
        self.assertEqual(out, [drone])
        self.assertEqual(f.link_type, 127)

    def test_raw_80211_link_type(self):
        drone = pcap_record(mgmt_frame(8, rid_ie()))
        f, out = self.collect(pcap_header(linktype=105) + drone)
        self.assertEqual(out, [drone])

    def test_not_a_pcap_stream_raises(self):
        with self.assertRaises(rf.PcapError):
            rf.PcapFilter().feed(b'GET / HTTP/1.1\r\n' + b'\x00' * 20)

    def test_oversized_record_raises(self):
        bad = struct.pack('<IIII', 1, 2, 10_000_000, 10_000_000)
        with self.assertRaises(rf.PcapError):
            rf.PcapFilter().feed(pcap_header() + bad)


class HubFanout(unittest.TestCase):
    def test_new_client_gets_header_then_only_what_is_broadcast_after_it_joined(self):
        hub = rf.Hub()
        hub.set_header(pcap_header())
        a_srv, a_cli = socket.socketpair()
        hub.add_client(a_srv)
        rec1 = pcap_record(b'\x01' * 30)
        hub.broadcast(rec1)
        b_srv, b_cli = socket.socketpair()
        hub.add_client(b_srv)
        rec2 = pcap_record(b'\x02' * 30)
        hub.broadcast(rec2)
        hub.flush_all()
        a_cli.settimeout(1); b_cli.settimeout(1)
        self.assertEqual(a_cli.recv(65536), pcap_header() + rec1 + rec2)
        self.assertEqual(b_cli.recv(65536), pcap_header() + rec2)
        self.assertEqual(hub.client_count(), 2)
        for s in (a_srv, a_cli, b_srv, b_cli):
            s.close()

    def test_client_without_header_yet_receives_nothing_until_header_known(self):
        hub = rf.Hub()
        srv, cli = socket.socketpair()
        hub.add_client(srv)
        hub.broadcast(pcap_record(b'\x01' * 30))
        hub.flush_all()
        hub.set_header(pcap_header())
        rec = pcap_record(b'\x02' * 30)
        hub.broadcast(rec)
        hub.flush_all()
        cli.settimeout(1)
        self.assertEqual(cli.recv(65536), pcap_header() + rec)
        srv.close(); cli.close()

    def test_closed_client_is_dropped(self):
        hub = rf.Hub()
        hub.set_header(pcap_header())
        srv, cli = socket.socketpair()
        hub.add_client(srv)
        cli.close()
        for _ in range(3):
            hub.broadcast(pcap_record(b'\x03' * 30000))
            hub.flush_all()
        self.assertEqual(hub.client_count(), 0)


class TcpdumpArgs(unittest.TestCase):
    def test_matches_offaros_own_filter(self):
        self.assertEqual(
            rf.tcpdump_args('wlan1', 'tcpdump'),
            ['tcpdump', '-i', 'wlan1', '-U', '-w', '-', '-s', '0', '-n', 'type mgt and (subtype beacon or subtype probe-resp)'])

class HubRemovalHook(unittest.TestCase):
    def test_on_remove_runs_before_the_socket_is_closed(self):
        seen = []
        hub = rf.Hub(on_remove=lambda sock: seen.append(sock.fileno()))
        hub.set_header(pcap_header())
        srv, cli = socket.socketpair()
        fd = srv.fileno()
        hub.add_client(srv)
        hub.remove_client(srv)
        self.assertEqual(seen, [fd])           # still a valid fd inside the hook
        self.assertEqual(srv.fileno(), -1)     # closed afterwards
        cli.close()

    def test_dropping_a_dead_client_during_flush_also_runs_the_hook(self):
        seen = []
        hub = rf.Hub(on_remove=lambda sock: seen.append(sock.fileno()))
        hub.set_header(pcap_header())
        srv, cli = socket.socketpair()
        fd = srv.fileno()
        hub.add_client(srv)
        cli.close()
        for _ in range(3):
            hub.broadcast(pcap_record(b'\x03' * 30000))
            hub.flush_all()
        self.assertEqual(seen, [fd])


class Defaults(unittest.TestCase):
    def test_listens_on_loopback_unless_told_otherwise(self):
        args = rf.build_parser().parse_args(['--stdin'])
        self.assertEqual((args.bind, args.listen), ('127.0.0.1', 5003))
        self.assertEqual(rf.build_parser().parse_args(['--stdin', '--bind', '0.0.0.0']).bind, '0.0.0.0')

class StopSource(unittest.TestCase):
    def test_tcpdump_that_cannot_be_signalled_does_not_crash_shutdown(self):
        # tcpdump has switched to its own user; without CAP_KILL os.kill() raises
        # PermissionError. Shutdown must still complete (systemd kills the cgroup).
        import types
        class Child:
            pid = 4242
            stderr = types.SimpleNamespace(fileno=lambda: -1, close=lambda: None)
            def poll(self): return None
            def terminate(self): raise PermissionError(1, 'Operation not permitted')
            def kill(self): raise PermissionError(1, 'Operation not permitted')
            def wait(self, timeout=None): return 0
        logs = []
        proxy = rf.Proxy(types.SimpleNamespace(stdin=False, interface='wlan1', tcpdump='tcpdump',
                                               verbose=False, stats_interval=60, listen=0, bind='127.0.0.1'),
                         logs.append)
        proxy.child = Child()
        proxy.source = None
        proxy.stop_source()          # must not raise
        self.assertIsNone(proxy.child)
        self.assertTrue(any('Operation not permitted' in m for m in logs), logs)



class EndToEnd(unittest.TestCase):
    """The real program: pcap on stdin, filtered pcap out of the TCP port."""

    def test_stdin_to_tcp_client(self):
        import subprocess, time, re
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'remoteid_filter.py')
        proc = subprocess.Popen([sys.executable, script, '--stdin', '--listen', '0', '--bind', '127.0.0.1'],
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            line = proc.stderr.readline().decode()
            m = re.search(r'listening on 127\.0\.0\.1:(\d+)', line)
            self.assertIsNotNone(m, line)
            port = int(m.group(1))
            drone = pcap_record(radiotap(mgmt_frame(8, rid_ie())))
            ap = pcap_record(radiotap(mgmt_frame(8, ssid_ie())))
            proc.stdin.write(pcap_header() + ap)          # header + noise before anyone connects
            proc.stdin.flush()
            time.sleep(0.3)
            cli = socket.create_connection(('127.0.0.1', port), timeout=2)
            time.sleep(0.3)
            proc.stdin.write(ap + drone + ap)
            proc.stdin.flush()
            got = b''
            deadline = time.time() + 3
            while len(got) < len(pcap_header()) + len(drone) and time.time() < deadline:
                got += cli.recv(65536)
            self.assertEqual(got, pcap_header() + drone)
            cli.close()
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)
