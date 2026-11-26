#!/usr/bin/env python3
"""Add evidence-backed 5.0 fields without replacing any original JSON value.

Usage: python3 apply_map.py INPUT.ndjson[.gz] OUTPUT.ndjson[.gz] [--map field-map.json]
Accepts search hits with _source, or bare alert objects. No network or third-party packages.
"""
import argparse
import copy
import datetime as dt
import gzip
import ipaddress
import json
import math
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def open_text(path, mode='rt'):
    return gzip.open(path, mode, encoding='utf-8') if str(path).endswith('.gz') else open(path, mode, encoding='utf-8')


def documents(path):
    with open_text(path) as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def source(doc):
    return doc.get('_source', doc)


def get(d, path):
    """Walk objects and arrays, including literal keys containing dots. Same result as before, as a loop."""
    while True:
        if not path:
            return d
        if isinstance(d, list):
            out = []
            for v in d:
                x = get(v, path)
                if isinstance(x, list):
                    out.extend(x)
                elif x is not None:
                    out.append(x)
            return out or None
        if not isinstance(d, dict):
            return None
        if path in d:
            return d[path]
        head, sep, tail = path.partition('.')
        if head in d:
            if not sep:
                return d[head]
            d = d[head]
            path = tail
            continue
        # A literal dotted key can also be an intermediate object; only keys that contain a dot can match here.
        for key in sorted([k for k in d if '.' in k], key=len, reverse=True):
            if path.startswith(key + '.'):
                d = d[key]
                path = path[len(key)+1:]
                break
        else:
            return None


def nonempty(v):
    if v is None or v == '':
        return False
    if isinstance(v, (list, dict)):
        return any(nonempty(x) for x in (v.values() if isinstance(v, dict) else v))
    return True  # false and zero are data


def values(v):
    return v if isinstance(v, list) else [v]


def matches(d, q):
    if not q or 'match_all' in q:
        return True
    if 'term' in q or 'terms' in q or 'match_phrase' in q or 'match' in q:
        op = next(k for k in ('term', 'terms', 'match_phrase', 'match') if k in q)
        path, expected = next(iter(q[op].items()))
        if isinstance(expected, dict):
            expected = expected.get('query', expected.get('value'))
        return any(v in values(expected) for v in values(get(d, path)))
    if 'exists' in q:
        return nonempty(get(d, q['exists']['field']))
    if 'wildcard' in q:
        import fnmatch
        path, pat = next(iter(q['wildcard'].items()))
        if isinstance(pat, dict):
            pat = pat['value']
        return any(fnmatch.fnmatchcase(str(v), pat) for v in values(get(d, path)) if v is not None)
    if 'range' in q:
        path, ranges = next(iter(q['range'].items()))
        for v in values(get(d, path)):
            try:
                v = float(v)
                if all({'gte':v >= z, 'gt':v > z, 'lte':v <= z, 'lt':v < z}[k] for k,z in ranges.items()):
                    return True
            except (ValueError, TypeError):
                pass
        return False
    if 'bool' in q:
        b = q['bool']
        def clauses(key):
            x = b.get(key, [])
            return x if isinstance(x, list) else [x]
        if not all(matches(d,x) for x in clauses('must') + clauses('filter')):
            return False
        if any(matches(d,x) for x in clauses('must_not')):
            return False
        should = clauses('should')
        minimum = b.get('minimum_should_match', 0 if b.get('must') or b.get('filter') else int(bool(should)))
        return sum(matches(d,x) for x in should) >= int(minimum)
    raise ValueError('Unsupported query: ' + repr(q))


def put_added(d, path, value):
    """Never overwrite an existing value or scalar parent, including empty values."""
    keys = path.split('.')
    cur = d
    for k in keys[:-1]:
        if k in cur and not isinstance(cur[k], dict):
            return False
        cur = cur.setdefault(k, {})
    if keys[-1] in cur:
        return False
    cur[keys[-1]] = value
    return True


_H5_FRAC = re.compile(r'(T\d{2}:\d{2}:\d{2})\.(\d+)')
_H5_OFF = re.compile(r'([+-]\d{2})(\d{2})$')


def date_norm(v):
    """The date as it is written to the indexer, or None when it is not a date.
    Python before 3.11 refuses in datetime.fromisoformat an offset written +0000 (every 4.x `timestamp`, and
    `@timestamp` of the 4.x sample alerts) and fractions of other than 3 or 6 digits (cloud logs carry 7 and 9), so on
    RHEL 9's python3.9 those dates were dropped while 3.12 kept them (S5: 57,706 of 100,006 alerts). The check
    normalises both before parsing (H5: offset and fraction; S5 had the offset only) and returns the ORIGINAL value, as
    3.12 always did and as H5 loaded it on 3.9 (S5 rewrote +0000 to +00:00; the indexer accepted both)."""
    if not isinstance(v, str):
        return None
    s = _H5_OFF.sub(r'\1:\2', v.replace('Z', '+00:00'))
    s = _H5_FRAC.sub(lambda m: m.group(1) + '.' + (m.group(2) + '000000')[:6], s)
    try:
        dt.datetime.fromisoformat(s)
        return v
    except ValueError:
        return None


def date_ok(v):
    return date_norm(v) is not None


def conform(v, schema):
    """Conservative indexable-value check; no silent numeric coercion."""
    if isinstance(v, list):
        xs = [conform(x, schema) for x in v]
        xs = [x for x in xs if x is not None]
        return xs or None
    if not nonempty(v):
        return None
    typ = schema['type']
    if typ in ('keyword', 'match_only_text', 'text'):
        if isinstance(v, (str, int, float, bool)):
            s = str(v)
            return s if len(s) <= schema.get('ignore_above', 2147483647) else None
    elif typ == 'ip':
        if not isinstance(v, str) or '%' in v or v != v.strip():
            return None
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    elif typ in ('byte', 'short', 'integer', 'long'):
        if isinstance(v, bool) or not re.fullmatch(r'[+-]?[0-9]+', str(v)):
            return None
        n = int(v)
        bits = {'byte':8, 'short':16, 'integer':32, 'long':64}[typ]
        return n if -(2**(bits-1)) <= n < 2**(bits-1) else None
    elif typ in ('float', 'double', 'scaled_float'):
        try:
            x = float(v)
            return x if math.isfinite(x) else None
        except (ValueError, TypeError, OverflowError):
            return None
    elif typ in ('date', 'date_nanos'):
        return date_norm(v)
    elif typ == 'boolean':
        if v in (True, 'true', 'True', '1'):
            return True
        if v in (False, 'false', 'False', '0'):
            return False
    elif typ == 'geo_point':
        if isinstance(v, dict) and 'lat' in v and 'lon' in v:
            try:
                a,b = float(v['lat']),float(v['lon'])
                if -90 <= a <= 90 and -180 <= b <= 180:
                    return {'lat':a, 'lon':b}
            except (ValueError,TypeError):
                pass
    return None


def integer_key(v):
    if isinstance(v, bool) or not re.fullmatch(r'[+-]?[0-9]+', str(v)):
        raise ValueError('Not an integer')
    return int(v)


class Mapper:
    def __init__(self, spec):
        self.spec = spec
        self.rules = spec['rules']
        self.stats = Counter()
        self.rule_evidence = {r['id']:Counter() for r in self.rules}
        self.schema = spec['target_schema']
        self.groups = {}
        for r in self.rules:
            key=json.dumps(r.get('when',{}),sort_keys=True)
            self.groups.setdefault(key, (r.get('when',{}), []))[1].append(r)
        for r in self.rules:
            if r['target'] not in self.schema:
                raise ValueError('Target not in disk schema: ' + r['target'])

    def evaluate(self, r, d):
        op = r['operation']
        if op == 'constant':
            v = r['value']
            return (v if v is None or isinstance(v, (str, int, float, bool)) else copy.deepcopy(v)), []
        if op == 'integration':
            if nonempty(get(d,'syscheck.event')):
                return ('wazuh-fim' if r['part']=='name' else 'system-activity'), ['syscheck.event']
            keys = set(values(get(d,'rule.groups')) + values(get(d,'decoder.name')))
            for row in self.spec['lookups']['integrations']['rows']:
                if keys.intersection(row['keys']):
                    return row[r['part']], [p for p in ('rule.groups','decoder.name') if keys.intersection(values(get(d,p)))]
            return None, []
        # Only present[0] is ever used: look at the sources in order and stop at the first usable one.
        skip = r.get('skip_values', [])
        first_valid = r.get('first_valid')
        present = []
        for sp in r.get('sources', []):
            v = get(d, sp)
            if nonempty(v) and v not in skip:
                if first_valid:
                    v = conform(v, self.schema[r['target']])
                    if v is None:
                        continue
                present.append((sp, v))
                break
        if op == 'status_outcome':
            if not present:
                return r.get('missing'), []
            try:
                n = integer_key(present[0][1])
                return ('success' if n == 0 else 'failure'), [present[0][0]]
            except ValueError:
                return None, []
        if not present:
            return None, []
        p,v = present[0]
        if op in ('copy','cast','array'):
            out = values(v) if op == 'array' else (v if v is None or isinstance(v, (str, int, float, bool)) else copy.deepcopy(v))
            if r.get('trim'):  # 4.x group lists keep the blank after a comma ("windows, WEF" gives " WEF")
                out = [x.strip() if isinstance(x, str) else x for x in out] if isinstance(out, list) else (out.strip() if isinstance(out, str) else out)
        elif op == 'lookup':
            table = self.spec['lookups'][r['table']]['rows']
            def key(x):
                mode = r.get('key_mode')
                if mode in ('integer', 'signin'):
                    try:
                        n = integer_key(x)
                    except ValueError:
                        return None
                    return str(n) if mode == 'integer' else ('errorCode 0' if n == 0 else 'errorCode != 0')
                return str(x).lower() if mode == 'lowercase' else str(x)
            out = [table.get(key(x)) for x in values(v)]
            out = [x for x in out if x is not None]
            if r.get('part'):
                out = [x[r['part']] for x in out]
            if r.get('split'):
                out = [x for y in out for x in values(y)]
            if not r.get('preserve_duplicates'):
                out = list(dict.fromkeys(out))
            if not r.get('array'):
                out = out[0] if out else None
        elif op == 'last_segment':
            s = str(v)
            if r.get('unquote'):  # GCP logName ends in 'cloudaudit.googleapis.com%2Factivity'
                import urllib.parse
                s = urllib.parse.unquote(s)
            out = s.rsplit('/', 1)[-1]
        elif op == 'strip_prefix':  # 4.x 'Package less than X' -> native 'Fixed in X'; docker 'sha256:'
            s = str(v)
            out = r.get('replacement', '') + s[len(r['prefix']):] if s.startswith(r['prefix']) else s
        elif op == 'basename':
            out = re.split(r'[/\\]', str(v))[-1]
        elif op == 'dirname':
            s = str(v);i = max(s.rfind('/'),s.rfind('\\'));out=s[:i] if i>0 else s[:i+1]
        elif op == 'github_url':
            s = str(v)
            out = 'https://github.com/' + s if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', s) else None
        elif op == 'split_csv':
            out = list(dict.fromkeys(x.strip() for x in str(v).split(',') if x.strip()))
            if r.get('table'):
                table=self.spec['lookups'][r['table']]['rows']
                if r.get('reverse'):
                    table={z['id']:z for z in table.values()}
                out=[table[x][r['part']] for x in out if x in table]
        elif op == 'port':
            out = conform(v, {'type':'long'})
            if out is not None and not 0 <= out <= 65535:
                out = None
        else:
            raise ValueError('Unknown operation '+op)
        return out, [p]

    def apply(self, doc, track=False):
        original=source(doc)
        result=copy.deepcopy(doc)
        dest=source(result)
        changed={}
        sample = original.get('@sampledata') is True or str(original.get('id')) == '1580123327.49031'
        active = [r for q,rs in self.groups.values() if matches(original,q) for r in rs]
        active.sort(key=lambda r:r['id'])
        for r in active:
            v,used=self.evaluate(r,original)
            if nonempty(v):
                converted=conform(v,self.schema[r['target']])
                if converted is None:
                    if track:self.stats['rejected:'+r['id']]+=1
                    continue
                v=converted
                if track:
                    self.rule_evidence[r['id']]['sample' if sample else 'real']+=1
                if get(dest,r['target']) is not None:
                    if track and get(dest,r['target']) != v:self.stats['collision:'+r['id']]+=1
                elif put_added(dest,r['target'],v):
                    changed[r['target']]={'rule':r['id'],'sources':used,'semantic':r['semantic']}
                    if track:self.stats['added:'+r['id']]+=1
        return result,changed


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input');ap.add_argument('output');ap.add_argument('--map',default=str(HERE/'field-map-v2.json'))
    args=ap.parse_args()
    if Path(args.input).resolve()==Path(args.output).resolve():
        ap.error('input and output must differ')
    mapper=Mapper(json.load(open(args.map)))
    n=0
    with open_text(args.output,'wt') as f:
        for doc in documents(args.input):
            mapped,_=mapper.apply(doc,track=True)
            f.write(json.dumps(mapped,ensure_ascii=False,separators=(',',':'))+'\n');n+=1
    print(json.dumps({'documents':n,'output':args.output,'stats':dict(mapper.stats)},indent=2))


if __name__=='__main__':
    main()
