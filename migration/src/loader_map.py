"""The H1 loader's corrected, schema-checked Python shaping step.

Like S3's Converter, evaluate the shared rules into a fresh WCS object.
The original alert stays intact under legacy.alert. No network calls here.
"""
import copy
import hashlib
import json
from pathlib import Path

from apply_map import Mapper, conform, get, matches, nonempty, put_added, values

MAP_PATH = Path(__file__).with_name('history-loader-map.json')
MAP_SHA256 = hashlib.sha256(MAP_PATH.read_bytes()).hexdigest()


def compile_query(q):
    """The common queries (match_all, exists, term/terms/match/match_phrase) as closures with the path and the expected
    values worked out once; anything else goes through apply_map.matches. Same answers as matches()."""
    if not q or 'match_all' in q:
        return lambda d: True
    if 'exists' in q:
        field = q['exists']['field']
        return lambda d: nonempty(get(d, field))
    if 'term' in q or 'terms' in q or 'match_phrase' in q or 'match' in q:
        op = next(k for k in ('term', 'terms', 'match_phrase', 'match') if k in q)
        path, expected = next(iter(q[op].items()))
        if isinstance(expected, dict):
            expected = expected.get('query', expected.get('value'))
        want = values(expected)
        return lambda d: any(v in want for v in values(get(d, path)))
    return lambda d: matches(d, q)


class LoaderMapper:
    def __init__(self, cluster='wazuh', agent_ids=True, registry=None, spec=None):
        self.spec = spec if spec is not None else json.loads(MAP_PATH.read_text())
        self.mapper = Mapper(self.spec)
        self.cluster = cluster
        self.agent_ids = agent_ids
        self.registry = registry or {}
        self._groups = [(compile_query(query), rules) for query, rules in self.mapper.groups.values()]
        self._active_cache = {}

    def convert(self, alert, index='', doc_id=''):
        out = {}
        key = tuple([test(alert) for test, _ in self._groups])
        active = self._active_cache.get(key)
        if active is None:
            active = [r for (test, rules), hit in zip(self._groups, key) if hit for r in rules]
            active.sort(key=lambda r: r['id'])
            self._active_cache[key] = active
        for r in active:
            if r['target'] == 'wazuh.agent.id' and not self.agent_ids:
                continue
            value, _ = self.mapper.evaluate(r, alert)
            if r['target'] == 'wazuh.cluster.name':
                value = self.cluster
            converted = conform(value, self.mapper.schema[r['target']]) if nonempty(value) else None
            if converted is not None:
                put_added(out, r['target'], converted)
        if get(out, '@timestamp') is None:
            ts = conform(alert.get('timestamp'), self.mapper.schema['@timestamp'])
            if ts is not None:
                put_added(out, '@timestamp', ts)
        put_added(out, 'event.kind', 'alert')
        put_added(out, 'tags', ['v4-legacy'])
        if nonempty(alert.get('full_log')):
            value = conform(alert['full_log'], self.spec['target_schema']['message'])
            if value is not None:
                put_added(out, 'message', value)
        if get(out, 'wazuh.integration.name') is None:
            put_added(out, 'wazuh.integration.name', 'legacy-4x')
            put_added(out, 'wazuh.integration.category', 'unclassified')
        agent = alert.get('agent') or {}
        entry = self.registry.get(str(agent.get('id')))
        if entry and entry.get('name') == agent.get('name') and entry.get('groups'):
            put_added(out, 'wazuh.agent.groups', copy.deepcopy(entry['groups']))
        # the loader serializes and drops the alert right after this call and nothing mutates it, so it is not copied
        out['legacy'] = {'index': index, 'id': doc_id, 'alert': alert}
        return out

    def targets(self):
        return {r['target'] for r in self.mapper.rules} | {
            'message', 'tags', 'event.kind', 'wazuh.agent.groups'}


def field_hiding_map(spec=None):
    """Merged (H1 tool gap 2, S5-D1): the 4.x field -> every 5.0 field the loader fills from it, GENERATED from the very
    rules convert() evaluates, plus convert()'s own copies (full_log -> message, timestamp -> @timestamp). The indexer
    stage hides all of them wherever a 4.x role hid the 4.x field (field-level security, masking), so FLS covers exactly
    what the history holds. Never hand-made: a hand-made copy missed 7 fields (S5)."""
    spec = spec if spec is not None else json.loads(MAP_PATH.read_text())
    out = {}
    for r in spec['rules']:
        for src in r.get('sources') or []:
            out.setdefault(src, set()).add(r['target'])
    out.setdefault('full_log', set()).add('message')
    out.setdefault('timestamp', set()).add('@timestamp')
    return {k: sorted(v) for k, v in sorted(out.items())}
