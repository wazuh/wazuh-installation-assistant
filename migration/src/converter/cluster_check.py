#!/usr/bin/env python3
"""Cross-node check of candidate wazuh-manager.conf files before any is staged.
Usage: cluster_check.py <candidate-dir-or-file>...   Exit 0 when every rule holds, 1 otherwise.
Rules: one cluster name and one key on every node; node names unique; exactly one master; every node's <nodes> lists
the master's address and only addresses; the master listens beyond loopback when there are workers. The key is never
printed, only whether it is equal."""
import sys, ipaddress, re
import xml.etree.ElementTree as ET
from pathlib import Path
def load(p):
    p = Path(p); p = p / 'wazuh-manager.conf' if p.is_dir() else p
    c = ET.parse(p).getroot().find('cluster')
    return p, {k: (c.findtext(k) or '').strip() for k in ('name', 'node_name', 'node_type', 'key', 'bind_addr', 'port')}, [n.text.strip() for n in c.findall('nodes/node')]
nodes = [load(a) for a in sys.argv[1:]]
fails = []
def check(ok, msg):
    print(('PASS ' if ok else 'FAIL ') + msg); ok or fails.append(msg)
check(len({v['name'] for _, v, _ in nodes}) == 1, 'one cluster name: %s' % sorted({v['name'] for _, v, _ in nodes}))
check(len({v['key'] for _, v, _ in nodes}) == 1 and all(re.fullmatch('[A-Za-z0-9]{32}', v['key']) for _, v, _ in nodes), 'one 32-character key on every node (not printed)')
names = [v['node_name'] for _, v, _ in nodes]
check(len(names) == len(set(names)), 'node names unique: %s' % names)
masters = [(p, v, n) for p, v, n in nodes if v['node_type'] == 'master']
check(len(masters) == 1, 'exactly one master: %s' % [v['node_name'] for _, v, _ in masters])
if masters:
    mp, mv, mn = masters[0]
    maddr = mn[0] if mn else ''
    def addr(x):
        try: ipaddress.ip_address(x); return True
        except ValueError: return bool(re.fullmatch(r'[A-Za-z0-9.-]+', x))
    for p, v, n in nodes:
        check(bool(n) and all(addr(x) for x in n) and maddr in n, '%s: <nodes> %s are addresses and include the master %s' % (v['node_name'], n, maddr))
    if len(nodes) > 1:
        loop = mv['bind_addr'] in ('127.0.0.1', '::1', 'localhost')
        check(not loop, 'master bind_addr %s reachable by workers' % mv['bind_addr'])
sys.exit(1 if fails else 0)
