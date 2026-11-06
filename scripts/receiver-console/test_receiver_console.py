#!/usr/bin/env python3
"""Tests for receiver_console.py:  python3 -m unittest scripts/receiver-console/test_receiver_console.py"""
import argparse
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import receiver_console as rc  # noqa: E402

# Public AIVDM reference sentences (gpsd / AIVDM protocol decoding document).
TYPE1 = '!AIVDM,1,1,,B,177KQJ5000G?tO`K>RA1wUbN0TKH,0*5C'
TYPE5_A = '!AIVDM,2,1,1,A,55?MbV02;H;s<HtKR20EHE:0@T4@Dn2222222216L961O5Gf0NSQEp6ClRp8,0*1C'
TYPE5_B = '!AIVDM,2,2,1,A,88888888880,2*25'
TYPE18 = '!AIVDM,1,1,,A,B52K>;h00Fc>jpUlNV@ikwpUoP06,0*4C'


def args(**kw):
    base = dict(aircraft_json='/nonexistent', ais_udp=2222, ais_bind='127.0.0.1', ais_device_glob='', cache=None,
                lat=69.70, lon=18.88, max_age=120, ais_port=10111, adsb_port=30003, remoteid_port=5003)
    base.update(kw)
    return argparse.Namespace(**base)


class ChecksumAndBits(unittest.TestCase):
    def test_checksum(self):
        self.assertTrue(rc.nmea_checksum_ok(TYPE1))
        self.assertFalse(rc.nmea_checksum_ok(TYPE1[:-1] + 'D'))
        self.assertTrue(rc.nmea_checksum_ok('!AIVDM,1,1,,B,177KQJ5000G?tO`K>RA1wUbN0TKH,0'))  # no checksum → accepted

    def test_sixbit_text_stops_at_padding(self):
        b = rc.Bits('55?MbV02;H;s<HtKR20EHE:0@T4@Dn2222222216L961O5Gf0NSQEp6ClRp888888888880', 2)
        self.assertEqual(b.text(112, 120), 'EVER DIADEM')
        self.assertEqual(b.text(70, 42), '3FOF8')

    def test_bad_character_raises(self):
        with self.assertRaises(ValueError):
            rc.Bits('abc~')


class Decode(unittest.TestCase):
    def test_type1_position_report(self):
        m = rc.decode_ais(TYPE1.split(',')[5])
        self.assertEqual(m['type'], 1)
        self.assertEqual(m['mmsi'], 477553000)
        self.assertEqual(m['status'], 5)
        self.assertEqual(m['sog'], 0.0)
        self.assertAlmostEqual(m['lon'], -122.345832, places=4)
        self.assertAlmostEqual(m['lat'], 47.582833, places=4)
        self.assertEqual(m['cog'], 51.0)
        self.assertEqual(m['hdg'], 181)

    def test_type5_two_fragments(self):
        a = rc.AisAssembler()
        self.assertIsNone(a.feed(TYPE5_A))
        m = a.feed(TYPE5_B)
        self.assertEqual(m['type'], 5)
        self.assertEqual(m['mmsi'], 351759000)
        self.assertEqual(m['name'], 'EVER DIADEM')
        self.assertEqual(m['callsign'], '3FOF8')
        self.assertEqual(m['shiptype'], 70)
        self.assertEqual(m['destination'], 'NEW YORK')
        self.assertEqual(a.parts, {})

    def test_type18_class_b(self):
        m = rc.decode_ais(TYPE18.split(',')[5])
        self.assertEqual(m['type'], 18)
        self.assertEqual(m['mmsi'], 338087471)
        self.assertEqual(m['kind'], 'B')
        self.assertAlmostEqual(m['lon'], -74.0721, places=3)
        self.assertAlmostEqual(m['lat'], 40.6845, places=3)
        self.assertIsNone(m['hdg'])

    def test_assembler_rejects_garbage(self):
        a = rc.AisAssembler()
        self.assertIsNone(a.feed('$GPRMC,1,2,3'))
        self.assertIsNone(a.feed('!AIVDM,1,1,,A,177KQJ5000G?tO`K>RA1wUbN0TKH,0*00'))  # wrong checksum
        self.assertIsNone(a.feed('!AIVDM,x,1,,A,177KQJ5000G?tO`K>RA1wUbN0TKH,0'))
        self.assertIsNone(a.feed('!AIVDM,1,1,,A,17,0'))  # too short
        self.assertEqual(a.bad, 2)

    def test_vessel_table_merges_static_and_position(self):
        t = rc.VesselTable(120)
        a = rc.AisAssembler()
        t.apply(a.feed(TYPE5_A), 10); t.apply(a.feed(TYPE5_B), 10)
        t.apply(rc.decode_ais('177KQJ5000G?tO`K>RA1wUbN0TKH'), 20)
        self.assertEqual(sorted(t.vessels), [351759000, 477553000])
        self.assertEqual(t.vessels[351759000]['name'], 'EVER DIADEM')
        self.assertNotIn('lat', t.vessels[351759000])
        t.prune(200)
        self.assertEqual(t.vessels, {})


class Cache(unittest.TestCase):
    def test_ship_type_labels(self):
        self.assertEqual(rc.ship_type_text(70), 'Cargo')
        self.assertEqual(rc.ship_type_text(79), 'Cargo')
        self.assertEqual(rc.ship_type_text(37), 'Pleasure')
        self.assertEqual(rc.ship_type_text(44), 'HSC')
        self.assertEqual(rc.ship_type_text(0), '')
        self.assertEqual(rc.ship_type_text(None), '')
        self.assertEqual(rc.ship_type_text(12), '')
        self.assertEqual(rc.normalise_type_text('High speed craft (HSC)'), 'HSC')
        self.assertEqual(rc.normalise_type_text('Towing: length exceeds 200m'), 'Towing')
        self.assertEqual(rc.normalise_type_text('Not available'), '')
        self.assertEqual(rc.normalise_type_text('Fishing'), 'Fishing')

    def test_roundtrip_merge_and_prune(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'v.json')
            c = rc.VesselCache(path, save_interval=60)
            self.assertEqual(c.load(), 0)
            a = rc.AisAssembler()
            self.assertFalse(c.remember(rc.decode_ais(TYPE1.split(',')[5]), 1000))   # position only → nothing
            a.feed(TYPE5_A)
            self.assertTrue(c.remember(a.feed(TYPE5_B), 1000))
            self.assertEqual(c.vessels[351759000], {'n': 'EVER DIADEM', 'c': '3FOF8', 'd': 'NEW YORK', 't': 'Cargo', 's': 1000})
            self.assertTrue(c.save_if_due(1010))              # first save happens at once
            c.remember({'mmsi': 351759000, 'name': 'EVER DIADEM II'}, 1020)
            self.assertFalse(c.save_if_due(1030))             # next one not before 60 s have passed
            self.assertTrue(c.save_if_due(1070))
            self.assertFalse(os.path.exists(path + '.tmp'))
            data = json.load(open(path))
            self.assertEqual(data['vessels']['351759000']['n'], 'EVER DIADEM II')
            c2 = rc.VesselCache(path)
            self.assertEqual(c2.load(now=2000), 1)
            self.assertEqual(c2.lookup(351759000)['t'], 'Cargo')
            c3 = rc.VesselCache(path, max_age_days=1)
            self.assertEqual(c3.load(now=1000 + 2 * 86400), 0)   # too old → dropped

    def test_imported_long_labels_and_junk(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'v.json')
            json.dump({'version': 1, 'vessels': {'205545190': {'n': 'QILAK', 't': 'High speed craft (HSC)', 's': 5},
                                                 'abc': {'n': 'x', 's': 5}, '7': 'junk', '8': {'n': '<b>' * 20, 's': 5}}}, open(path, 'w'))
            c = rc.VesselCache(path)
            self.assertEqual(c.load(now=10), 2)
            self.assertEqual(c.vessels[205545190], {'s': 5, 'n': 'QILAK', 't': 'HSC'})
            self.assertEqual(len(c.vessels[8]['n']), 20)

    def test_table_uses_cached_name_before_static_message_arrives(self):
        c = rc.VesselCache('/nonexistent/v.json')
        c.vessels[477553000] = {'n': 'CACHED NAME', 'c': 'ABCD', 't': 'Tanker', 's': 1}
        t = rc.VesselTable(120, c)
        t.apply(rc.decode_ais(TYPE1.split(',')[5]), 10)
        v = t.vessels[477553000]
        self.assertEqual((v['name'], v['callsign'], v['type']), ('CACHED NAME', 'ABCD', 'Tanker'))
        m = rc.Model(args()); m.vessels = t; m.cache = c
        rows = rc.vessel_rows(m, 11)
        self.assertEqual(rc.ais_line(rows[0]), ' 477553000 CACHED NAME           0.0  051  6598.2 331 Tanker    Moored        1s')
        self.assertEqual(len(rc.ais_line(rows[0])), 80)
        self.assertEqual(len(rc.AIS_HEAD), 80)

    def test_cap_keeps_newest(self):
        c = rc.VesselCache('/nonexistent/v.json', max_entries=2)
        c.vessels = {1: {'s': 10}, 2: {'s': 30}, 3: {'s': 20}}
        c._cap()
        self.assertEqual(sorted(c.vessels), [2, 3])

    def test_unwritable_path_is_reported_not_fatal(self):
        c = rc.VesselCache('/nonexistent-dir/v.json')
        c.vessels = {1: {'n': 'X', 's': 1}}; c.dirty = True
        self.assertFalse(c.save_if_due(force=True))
        self.assertIn('cache not saved', c.error)


class ExportTool(unittest.TestCase):
    def test_export_from_offaro_db_and_merge(self):
        import sqlite3
        import export_offaro_cache as ex
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, 'ais-static.db')
            con = sqlite3.connect(db)
            con.execute('CREATE TABLE vessel_static (mmsi TEXT PRIMARY KEY, name TEXT, imo TEXT, callsign TEXT, shipType INTEGER, shipTypeCategory TEXT, shipTypeColor TEXT, dimBow INTEGER, dimStern INTEGER, dimPort INTEGER, dimStarboard INTEGER, draught REAL, lastSeen INTEGER NOT NULL)')
            now_ms = int(time.time() * 1000)
            con.executemany('INSERT INTO vessel_static (mmsi, name, callsign, shipType, shipTypeCategory, lastSeen) VALUES (?,?,?,?,?,?)', [
                ('257123000', 'FJORDKONGEN', 'LABC', 60, 'Passenger', now_ms),
                ('257999000', 'OLD BOAT', None, 30, 'Fishing', now_ms - 6 * 365 * 86400 * 1000),
                ('258000000', None, None, None, 'Cargo', now_ms),
                ('junk', 'X', None, None, None, now_ms),
            ])
            con.commit(); con.close()
            out = os.path.join(d, 'vessels.json')
            json.dump({'version': 1, 'vessels': {'257123000': {'n': 'OLD NAME', 'd': 'TROMSO', 's': int(time.time()) - 1000}}}, open(out, 'w'))
            self.assertEqual(ex.main(['--db', db, '--into', out]), 0)
            data = json.load(open(out))['vessels']
            self.assertEqual(data['257123000']['n'], 'FJORDKONGEN')     # newer wins
            self.assertEqual(data['257123000']['d'], 'TROMSO')          # but keeps what the DB lacks
            self.assertEqual(data['257123000']['t'], 'Passenger')
            self.assertEqual(data['258000000'], {'s': data['258000000']['s'], 't': 'Cargo'})
            self.assertNotIn('257999000', data)                          # older than 5 years
            self.assertNotIn('junk', data)
            # merging a second JSON file
            other = os.path.join(d, 'other.json')
            json.dump({'version': 1, 'vessels': {'111257511': {'n': 'RESCUE 2 TROMS', 's': int(time.time())}}}, open(other, 'w'))
            self.assertEqual(ex.main(['--from-json', other, '--into', out]), 0)
            self.assertIn('111257511', json.load(open(out))['vessels'])


class Geometry(unittest.TestCase):
    def test_distance_bearing_tromso_oslo(self):
        d, b = rc.distance_bearing(69.6496, 18.9560, 59.9139, 10.7522)
        self.assertAlmostEqual(d, 1155, delta=15)
        self.assertAlmostEqual(b, 203, delta=3)

    def test_same_point(self):
        d, b = rc.distance_bearing(60, 10, 60, 10)
        self.assertEqual((round(d, 6), b), (0.0, 0.0))


class Layout(unittest.TestCase):
    def test_split_rows(self):
        self.assertEqual(rc.split_rows(20, 3, 4), (11, 9))      # both fit → stable 55/45 split
        self.assertEqual(rc.split_rows(20, 0, 0), (11, 9))
        self.assertEqual(rc.split_rows(20, 3, 15), (5, 15))     # AIS needs more → line moves up
        self.assertEqual(rc.split_rows(20, 14, 2), (14, 6))     # ADS-B needs more → line moves down
        self.assertEqual(rc.split_rows(20, 30, 30), (11, 9))    # both overflow → 55/45
        self.assertEqual(rc.split_rows(20, 30, 4), (16, 4))     # AIS only takes what it needs
        self.assertEqual(rc.split_rows(20, 5, 30), (5, 15))
        self.assertEqual(rc.split_rows(2, 30, 30), (1, 1))

    def test_fmt(self):
        self.assertEqual(rc.fmt_age(5), '5s')
        self.assertEqual(rc.fmt_age(125), '2m')
        self.assertEqual(rc.fmt_age(7300), '2h')
        self.assertEqual(rc.fmt_age(None), '-')
        self.assertEqual(rc.fmt_coord(69.702, 18.885), '69.7020N 18.8850E')
        self.assertEqual(rc.fmt_coord(-33.9, -70.6), '33.9000S 70.6000W')

    def model(self, **kw):
        m = rc.Model(args(**kw))
        m.hostname = 'aisadsb'
        m.ips = [('wlan0', '172.30.172.127')]
        m.aircraft = [
            {'hex': '47878c', 'flight': 'NOZ1480 ', 'alt_baro': 'ground', 'gs': 0.0, 'true_heading': 281.2,
             'squawk': '0734', 'emergency': 'none', 'messages': 170, 'seen': 0.1, 'rssi': -11.4},
            {'hex': '4ca7b5', 'flight': 'SAS4123', 'alt_baro': 35000, 'gs': 455.3, 'track': 123.4, 'baro_rate': -1216,
             'squawk': '7700', 'emergency': 'general', 'lat': 70.1, 'lon': 19.5, 'seen': 2.0, 'rssi': -20.1},
            {'hex': 'old001', 'seen': 500},
        ]
        m.adsb_age = 1.0
        return m

    def test_frame_shape_and_content(self):
        m = self.model()
        a = rc.AisAssembler()
        for s in (TYPE5_A, TYPE5_B, TYPE1):
            m.vessels.apply(a.feed(s), 1000)
        m.ais_last = 1000
        lines, attrs = rc.render_frame(m, 80, 26, now=1001)
        self.assertEqual(len(lines), 26)
        print('\n'.join(lines)) if os.environ.get('SHOW') else None
        self.assertTrue(all(len(l) == 80 for l in lines))
        self.assertIn('aisadsb  wlan0 172.30.172.127', lines[0])
        self.assertIn('ADS-B  2 aircraft', lines[1])              # the 500 s old one is hidden
        self.assertIn('AIS  2 vessels', lines[14])   # 1 header + 2 title/colhead + 11 rows
        self.assertTrue(lines[25].startswith(' OffARO → 172.30.172.127  AIS :10111  ADS-B :30003  Remote ID :5003'), lines[25])
        self.assertTrue(lines[25].rstrip().endswith('sort:dist'), lines[25])
        self.assertIn('rx 69.7000N 18.8800E', lines[0])
        rows = '\n'.join(lines)
        self.assertIn(' 47878c NOZ1480  0734      GND       0  281        -    -      -   0s  -11.4', rows)
        self.assertIn(' 4ca7b5 SAS4123  7700    35000     455  123     50.4  028  -1216   2s  -20.1', rows)
        self.assertIn(' 477553000                       0.0  051  6598.2 331           Moored        1s', rows)
        self.assertIn(' 351759000 EVER DIADEM', rows)
        self.assertEqual(attrs[0], 'header')
        self.assertEqual(attrs[3], 'alert')      # SAS4123 squawking 7700 sorts first (has a distance)

    def test_frame_overflow_marker_and_small_screen(self):
        m = self.model()
        m.aircraft = [{'hex': '%06x' % i, 'seen': i, 'lat': 69.7, 'lon': 18.88 + i / 100} for i in range(40)]
        lines, _ = rc.render_frame(m, 80, 26, now=0)
        self.assertTrue(any('… ' in l and ' more' in l for l in lines))
        lines, _ = rc.render_frame(m, 60, 10, now=0)
        self.assertEqual(len(lines), 10)
        self.assertTrue(all(len(l) == 60 for l in lines))

    def test_health_strings(self):
        m = self.model(ais_device_glob='/dev/serial/by-id/*')
        self.assertEqual(rc.health_ais(m, 100), 'no USB receiver · no data yet (udp 2222)')
        m.ais_device = '/dev/null'   # a real path, so realpath() keeps the short name
        self.assertEqual(rc.health_ais(m, 100), 'rx null · no data yet (udp 2222)')
        m.ais_last = 100; m.ais_events.extend([100] * 10); m.started = 40
        self.assertEqual(rc.health_ais(m, 100), 'rx null · 10 msg/min')
        self.assertEqual(rc.health_ais(m, 400), 'rx null · no data for 5m')
        m.cache = rc.VesselCache('/nonexistent/x.json'); m.cache.vessels = {1: {}, 2: {}}
        self.assertEqual(rc.health_ais(m, 100), 'rx null · 10 msg/min · 2 names cached')
        m.adsb_age = None
        self.assertEqual(rc.health_adsb(m, 100), 'dump1090: no aircraft.json')
        m.adsb_age = 30
        self.assertEqual(rc.health_adsb(m, 100), 'dump1090: stale (30s)')
        m.adsb_age = 1; m.adsb_rate.extend([(40, 1000), (100, 1600)])
        self.assertEqual(rc.health_adsb(m, 100), 'dump1090 ok · 600 msg/min')

    def test_footer_without_position_or_ip(self):
        m = self.model(lat=None, lon=None, remoteid_port=0)
        m.ips = []
        text = rc.footer_text(m, 80)
        self.assertTrue(text.startswith(' OffARO → <ip>  AIS :10111  ADS-B :30003'), text)
        self.assertNotIn('Remote ID', text)
        self.assertEqual(len(text), 80)
        self.assertTrue(text.endswith('sort:dist'))
        lines, _ = rc.render_frame(m, 80, 26, now=0)
        self.assertIn('rx position unknown', lines[0])
        self.assertEqual(len(rc.footer_text(m, 40)), 40)


if __name__ == '__main__':
    unittest.main()
