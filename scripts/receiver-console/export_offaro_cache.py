#!/usr/bin/env python3
"""Seed the receiver console's vessel cache from OffARO's own AIS static database.

OffARO keeps the names, call signs and types of every vessel it has seen in
`ais-static.db` (SQLite) in its user-data folder. This exports them into the JSON
cache that `receiver_console.py --cache FILE` uses, merging with whatever the file
already holds (the newer "last seen" wins, missing fields are filled in).

  python3 export_offaro_cache.py --into vessels.json                 # OffARO DB of this machine
  python3 export_offaro_cache.py --db /path/to/ais-static.db --into vessels.json
  python3 export_offaro_cache.py --from-json other.json --into vessels.json   # merge two caches

Copy the result to the receiver box (for example to the folder that holds
receiver_console.py on persistent storage) and start the console with --cache.
OffARO's user-data folder: macOS ~/Library/Application Support/Offaro, Windows
%APPDATA%\\Offaro, Linux ~/.config/Offaro.
"""
import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from receiver_console import VesselCache, ship_type_text, normalise_type_text  # noqa: E402


def default_db():
    if sys.platform == 'darwin':
        base = os.path.expanduser('~/Library/Application Support/Offaro')
    elif sys.platform.startswith('win'):
        base = os.path.join(os.environ.get('APPDATA', ''), 'Offaro')
    else:
        base = os.path.expanduser('~/.config/Offaro')
    return os.path.join(base, 'ais-static.db')


def read_offaro_db(path):
    """{mmsi(int): entry} from OffARO's vessel_static table; works on a copy so a running OffARO is never disturbed."""
    tmp = tempfile.mkdtemp(prefix='offaro-ais-')
    try:
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, os.path.join(tmp, 'ais-static.db' + suffix))
        con = sqlite3.connect('file:%s?mode=ro' % os.path.join(tmp, 'ais-static.db'), uri=True)
        out = {}
        for mmsi, name, callsign, ship_type, category, last_seen in con.execute(
                'SELECT mmsi, name, callsign, shipType, shipTypeCategory, lastSeen FROM vessel_static'):
            if not str(mmsi).isdigit():
                continue
            e = {'s': int(last_seen / 1000) if last_seen and last_seen > 10 ** 11 else int(last_seen or 0)}
            if name:
                e['n'] = str(name).strip()[:20]
            if callsign:
                e['c'] = str(callsign).strip()[:20]
            t = ship_type_text(ship_type) or normalise_type_text(category)
            if t:
                e['t'] = t
            if len(e) > 1:
                out[int(mmsi)] = e
        con.close()
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def merge(cache, entries):
    """Merge {mmsi: entry} into a VesselCache; returns (added, updated)."""
    added = updated = 0
    for mmsi, e in entries.items():
        cur = cache.vessels.get(mmsi)
        if cur is None:
            cache.vessels[mmsi] = dict(e)
            added += 1
            continue
        newer = e.get('s', 0) >= cur.get('s', 0)
        changed = False
        for k in ('n', 'c', 'd', 't'):
            if e.get(k) and (newer or not cur.get(k)) and cur.get(k) != e[k]:
                cur[k] = e[k]
                changed = True
        if e.get('s', 0) > cur.get('s', 0):
            cur['s'] = e['s']
            changed = True
        updated += changed
    cache.dirty = cache.dirty or bool(added or updated)
    return added, updated


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--db', default=default_db(), help='OffARO ais-static.db (default: this machine\'s OffARO)')
    p.add_argument('--from-json', metavar='FILE', help='merge another receiver-console cache file instead of a database')
    p.add_argument('--into', required=True, metavar='FILE', help='cache file to create or merge into')
    p.add_argument('--max-age-days', type=int, default=5 * 365, help='skip vessels not seen for this long (default 5 years)')
    args = p.parse_args(argv)

    cache = VesselCache(args.into, max_age_days=args.max_age_days)
    before = cache.load()
    if args.from_json:
        other = VesselCache(args.from_json, max_age_days=args.max_age_days)
        other.load()
        entries = other.vessels
        source = args.from_json
    else:
        if not os.path.exists(args.db):
            sys.exit('no OffARO database at %s (use --db)' % args.db)
        entries = read_offaro_db(args.db)
        source = args.db
    cutoff = time.time() - args.max_age_days * 86400
    entries = {m: e for m, e in entries.items() if e.get('s', 0) >= cutoff}
    added, updated = merge(cache, entries)
    if not cache.save_if_due(force=True) and cache.dirty:
        sys.exit(cache.error or 'could not write %s' % args.into)
    print('%s: %d vessels read; %s: %d before, %d added, %d updated, %d now' % (
        source, len(entries), args.into, before, added, updated, len(cache.vessels)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
