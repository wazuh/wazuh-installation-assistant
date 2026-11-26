"""Additions to the settings converter: the installed 5.0 base, the 5.0 schema, the stock 4.x files and the 5.0
internal-option range table. Python 3.9+, standard library only.

Why each exists:
- base: the 5.0 install owns the cluster key, the cluster topology, the listener sections and the certificate
  paths. Carrying the 4.x values cut a worker off, opened 1516 on 0.0.0.0 and carried NODE_IP, and a
  candidate without <remote><https> reset the listeners to defaults.
- schema: 5.0 ships /etc/wazuh-manager/wazuh-manager.schema.json; a path it lists is a 5.0 option and its
  type and range can be checked before the file is staged.
- stock: a value equal to the stock 4.x file is not a customization; 5.0 compiles its own defaults (F3 asked
  128 questions about two unmodified stock files).
- ranges: an out-of-range internal option stops the daemon that reads it, and with it the manager.
"""
import ipaddress
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

# Paths whose value the 5.0 install decides. The converter never writes the 4.x value over them.
OWNED_PREFIXES = (
    ('cluster',),
    ('indexer', 'hosts'),
    ('indexer', 'ssl'),
    ('auth', 'ssl_manager_cert'),
    ('auth', 'ssl_manager_key'),
    ('remote', 'https'),
    ('remote', 'legacy', 'enabled'),
)
# 4.x values that are template placeholders, never addresses or keys.
PLACEHOLDER = re.compile(r'^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$')
HOSTNAME = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
# 4.x OpenSSL cipher-list strings govern TLS 1.2 and lower only; TLS 1.3 suites are separate in OpenSSL.
TLS13 = set('TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256 TLS_AES_128_CCM_8_SHA256'.split())
# 4.x API certificate defaults: the 5.0 defaults replace them when the 4.x file kept the default name.
API_CERT_DEFAULTS_4X = {'https.key': 'server.key', 'https.cert': 'server.crt', 'https.ca': 'ca.crt'}


def owned(tags):
    return any(tuple(tags[:len(p)]) == p for p in OWNED_PREFIXES)


def is_placeholder(value):
    return bool(value) and bool(PLACEHOLDER.match(value))


def is_address(value):
    if not value or is_placeholder(value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME.match(value)) and '_' not in value


def tls13_list(value):
    return bool(value) and all(x in TLS13 for x in value.split(':'))


def is_loopback(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.strip('^$') in ('localhost', 'localhost.localdomain')


# --- base (installed 5.0) -------------------------------------------------------------------------------------

class Base:
    """The installed 5.0 files the candidate is merged into."""

    def __init__(self, directory):
        d = Path(directory)
        self.dir = d
        self.conf_bytes = (d / 'wazuh-manager.conf').read_bytes()
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        self.root = ET.fromstring(self.conf_bytes, parser=parser)
        if self.root.tag != 'wazuh_config':
            raise ValueError('base wazuh-manager.conf has no <wazuh_config> root')
        self.internal = (d / 'wazuh-manager-internal-options.conf').read_bytes() if (d / 'wazuh-manager-internal-options.conf').is_file() else None
        self.api = (d / 'api.yaml').read_bytes() if (d / 'api.yaml').is_file() else None
        self.cluster_json = json.loads((d / 'cluster.json').read_text()) if (d / 'cluster.json').is_file() else None
        self.schema = Schema(d / 'wazuh-manager.schema.json') if (d / 'wazuh-manager.schema.json').is_file() else None
        # The API's own closed schema (api.validator.api_config_schema), dumped on the 5.0 host.
        self.api_schema = json.loads((d / 'api.schema.json').read_text()) if (d / 'api.schema.json').is_file() else None

    def api_check(self, path, value):
        """None if the API schema accepts this key and value; 'unknown' if the key is not in it; else a reason."""
        node = self.api_schema
        for p in path:
            props = (node or {}).get('properties', {})
            if p not in props:
                return 'unknown'
            node = props[p]
        t = node.get('type')
        types = t if isinstance(t, list) else [t]
        v = value
        if 'object' in types and v == '':
            return None
        if 'boolean' in types and str(v).lower() in ('yes', 'no', 'true', 'false'):
            return None
        if ('integer' in types or 'number' in types) and re.fullmatch(r'-?[0-9]+', str(v)):
            n = int(v)
            if 'minimum' in node and n < node['minimum']:
                return 'below the minimum %s' % node['minimum']
            if 'maximum' in node and n > node['maximum']:
                return 'above the maximum %s' % node['maximum']
            return None
        if 'string' in types:
            if 'enum' in node and v not in node['enum']:
                return 'not one of %s' % node['enum']
            if 'pattern' in node and not re.search(node['pattern'], v):
                return 'does not match %s' % node['pattern']
            return None
        if 'array' in types:
            return 'a list: merge by hand'
        return 'not of type %s' % '/'.join(str(x) for x in types)

    def values(self, tags):
        """Texts of every element at this tag path (no attributes, comments skipped)."""
        nodes = [self.root]
        for t in tags:
            nodes = [c for n in nodes for c in n if isinstance(c.tag, str) and c.tag == t]
        return [(n.text or '').strip() for n in nodes]

    def has(self, tags):
        return bool(self.values(tags))

    def value(self, tags):
        v = self.values(tags)
        return v[0] if v else None

    def standalone(self):
        """A single-node 5.0 install: master, cluster bound to loopback, its only node loopback."""
        return (self.value(['cluster', 'node_type']) == 'master' and is_loopback(self.value(['cluster', 'bind_addr']) or '')
                and all(is_loopback(n) for n in self.values(['cluster', 'nodes', 'node'])))


def merge(base, out, skip):
    """Write the converted leaves of `out` into a copy of the base tree. `skip(tags)` says a path is owned.
    Returns (bytes, list of (tags, old, new)) for every leaf whose value changed."""
    import copy
    root = copy.deepcopy(base.root)
    changes = []

    def leaves(e, tags):
        kids = [c for c in e if isinstance(c.tag, str)]
        if not kids:
            yield tags, (e.text or '').strip()
        for c in kids:
            yield from leaves(c, tags + [c.tag])

    for section in out:
        for tags, value in leaves(section, [section.tag]):
            if skip(tags):
                continue
            node = root
            for i, t in enumerate(tags):
                found = [c for c in node if isinstance(c.tag, str) and c.tag == t]
                if found:
                    node = found[0]
                else:
                    new = ET.SubElement(node, t)
                    node = new
            old = (node.text or '').strip()
            if old != value:
                changes.append((tags, old if old else None, value))
                node.text = value
    ET.indent(root, space='  ')
    body = ET.tostring(root, encoding='unicode')
    # Keep the installer's leading comment block (outside the root).
    head = base.conf_bytes.decode('utf-8').split('<wazuh_config', 1)[0]
    return (head + body + '\n').encode('utf-8'), changes


# --- schema -----------------------------------------------------------------------------------------------------

class Schema:
    """Leaf lookup and value check against /etc/wazuh-manager/wazuh-manager.schema.json (the subset of JSON
    Schema it uses: $ref, allOf, type, minimum, maximum, pattern, enum, minLength, maxLength, items)."""

    def __init__(self, path):
        self.s = json.loads(Path(path).read_text())

    def _resolve(self, node):
        node = dict(node)
        while '$ref' in node:
            ref = node.pop('$ref').split('/')[-1]
            merged = dict(self.s['definitions'][ref])
            merged.update(node)
            node = merged
        for sub in node.pop('allOf', []):
            r = self._resolve(sub)
            for k, v in r.items():
                node.setdefault(k, v)
        return node

    def leaf(self, tags):
        node = self._resolve(self.s)
        for t in tags:
            node = self._resolve(node)
            if node.get('type') == 'array' and 'items' in node:
                node = self._resolve(node['items'])
            props = node.get('properties', {})
            if t not in props:
                return None
            node = self._resolve(props[t])
        if node.get('type') == 'array' and 'items' in node:
            node = self._resolve(node['items'])
        return node

    def check(self, tags, value):
        """None when the value is valid for the leaf, else a short reason. Unknown path: 'not a 5.0 option'."""
        node = self.leaf(tags)
        if node is None:
            return 'not a 5.0 option'
        types = node.get('type')
        types = types if isinstance(types, list) else [types] if types else []
        if 'boolean' in types and value in ('yes', 'no', 'true', 'false'):
            return None
        if 'enum' in node and value not in [str(x) for x in node['enum']]:
            return 'not one of %s' % node['enum']
        num = None
        if re.fullmatch(r'-?[0-9]+', value or ''):
            num = int(value)
        if 'integer' in types and num is not None:
            if 'minimum' in node and num < node['minimum']:
                return 'below the minimum %s' % node['minimum']
            if 'maximum' in node and num > node['maximum']:
                return 'above the maximum %s' % node['maximum']
            return None
        if 'string' in types or not types:
            if 'pattern' in node and not re.search(node['pattern'], value or ''):
                return 'does not match %s' % node['pattern'][:60]
            if 'minLength' in node and len(value or '') < node['minLength']:
                return 'shorter than %s' % node['minLength']
            if 'maxLength' in node and len(value or '') > node['maxLength']:
                return 'longer than %s' % node['maxLength']
            return None
        if 'object' in types:
            return 'is a section, not a value'
        return 'not of type %s' % '/'.join(types)


# --- stock 4.x reference ----------------------------------------------------------------------------------------

def canonical(node):
    """Order-insensitive signature of a parsed migration_common.Node subtree."""
    return (node.tag, tuple(sorted(node.attrs.items())), node.text if not node.children else '',
            tuple(sorted(canonical(c) for c in node.children)))


def section_key(node):
    return node.tag + ('[' + node.attrs.get('name', '') + ']' if node.tag == 'wodle' else '')


class Stock:
    def __init__(self, directory, parse_xml, internal_entries):
        d = Path(directory)
        self.blocks, self.leaves, self.internal, self.cluster = set(), set(), {}, None
        if (d / 'ossec.conf').is_file():
            for root in parse_xml((d / 'ossec.conf').read_bytes()):
                for n in root.children:
                    self.blocks.add(canonical(n))
                    for tags, value in self._leaves(n, []):
                        self.leaves.add((section_key(n), tuple(tags), value))
        if (d / 'internal_options.conf').is_file():
            for _, _, key, value in internal_entries((d / 'internal_options.conf').read_bytes(), 'internal_options.conf'):
                if key:
                    self.internal[key] = value
        if (d / 'cluster.json').is_file():
            self.cluster = json.loads((d / 'cluster.json').read_text())

    def _leaves(self, n, tags):
        if not n.children:
            yield tags, n.text
        for c in n.children:
            yield from self._leaves(c, tags + [c.tag])

    def block_is_stock(self, node):
        return canonical(node) in self.blocks

    def leaf_is_stock(self, section, tags, value):
        return (section_key(section), tuple(tags), value) in self.leaves

    def cluster_value(self, path):
        cur = self.cluster
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
                cur = cur[int(p)]
            else:
                return KeyError
        return cur


# --- 5.0 internal option ranges ---------------------------------------------------------------------------------

class Ranges:
    """Every getDefine_Int / getDefine_Int_default read of the 5.0 source the build was made from
    (tool/extract_ranges.py), plus the options read outside C (documented ranges)."""
    EXTRA = {'wazuh_clusterd.debug': (0, 2, 'wazuh-manager-clusterd'), 'analysisd.debug': (0, 2, 'wazuh-manager-analysisd')}

    def __init__(self, path):
        self.t = json.loads(Path(path).read_text())

    def get(self, key):
        if key in self.EXTRA:
            lo, hi, daemon = self.EXTRA[key]
            return lo, hi, daemon
        e = self.t.get(key)
        if not e:
            return None
        daemon = self.daemon(e['files'])
        return e['min'], e['max'], daemon

    @staticmethod
    def daemon(files):
        f = ' '.join(files)
        for part, name in (('src/remoted', 'wazuh-manager-remoted'), ('src/os_auth', 'wazuh-manager-authd'),
                           ('src/wazuh_db', 'wazuh-manager-db'), ('src/config/src/wmodules', 'wazuh-manager-modulesd'),
                           ('src/wazuh_modules', 'wazuh-manager-modulesd'), ('src/shared', 'every daemon')):
            if part in f:
                return name
        return 'a manager daemon'
