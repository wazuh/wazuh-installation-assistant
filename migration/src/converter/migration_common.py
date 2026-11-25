"""Offline migration primitives. Python 3.9+, standard library only."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat

GUIDE = 'manager-configuration-migration.md'
GROUPS = 'manager-4x-to-5x.md#groups'
UPGRADE = 'upgrade-4x-to-5x.md#configuration-migration-ossecconf'
CARRY = 'carried_as_is'
CHANGE = 'carried_with_change'
DROP = 'dropped_with_replacement'
NONE = 'dropped_without_replacement'
DECIDE = 'needs_decision'
UNKNOWN = 'unknown'


class InputError(ValueError):
    pass


class Node:
    def __init__(self, tag, attrs, start, line):
        self.tag, self.attrs, self.start, self.line = tag, dict(attrs), start, line
        self.children, self.parts = [], []
        self.end = start
        self.path = ''

    @property
    def text(self):
        return ''.join(self.parts).strip()

    def element(self):
        e = ET.Element(self.tag, self.attrs)
        e.text = self.text or None
        for child in self.children:
            e.append(child.element())
        return e


def parse_xml(data):
    """Read sibling roots, with byte spans for surgical group edits. No DTDs."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        raise InputError('Only UTF-8 XML is supported; review the encoding.')
    # Spaces retain byte positions and line numbers of an optional declaration/BOM.
    work = re.sub(br'^\xef\xbb\xbf', b'   ', data)
    work = re.sub(br'<\?xml\s[^?]*\?>', lambda m: b' ' * len(m[0]), work, count=1)
    prefix = b'<migration_input>'
    parser = expat.ParserCreate('UTF-8')
    roots, stack = [], []

    def start(tag, attrs):
        if not stack:
            stack.append(None)
            return
        n = Node(tag, attrs, parser.CurrentByteIndex - len(prefix), parser.CurrentLineNumber)
        quote, idx = None, n.start
        while idx < len(work):
            char = work[idx:idx + 1]
            if char == quote:
                quote = None
            elif char in (b'"', b"'") and quote is None:
                quote = char
            elif char == b'>' and quote is None:
                break
            idx += 1
        n.self_closing = work[n.start:idx + 1].endswith(b'/>')
        if len(stack) == 1:
            roots.append(n)
        else:
            stack[-1].children.append(n)
        stack.append(n)

    def end(tag):
        n = stack.pop()
        if n is None:
            return
        idx = parser.CurrentByteIndex - len(prefix)
        if not n.self_closing:
            n.end = work.index(b'>', idx) + 1
        else:
            n.end = idx  # Expat reports the byte after a self-closing tag.

    def chars(value):
        if len(stack) > 1:
            stack[-1].parts.append(value)
        elif value.strip():
            raise InputError('Text outside XML roots requires review.')

    def forbidden(*args):
        raise InputError('DTD/entity declarations are unsupported; review manually.')

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    try:
        parser.Parse(prefix + work + b'</migration_input>', True)
    except expat.ExpatError as e:
        raise InputError('Malformed XML at line %d; normalize legacy syntax manually.' % e.lineno)
    if not roots:
        raise InputError('No XML root found.')

    def paths(nodes, base):
        counts = collections.Counter()
        for n in nodes:
            counts[n.tag] += 1
            n.path = '%s/%s[%d]' % (base, n.tag, counts[n.tag])
            paths(n.children, n.path)
    paths(roots, '')
    return roots


def options(node):
    """Each leaf/empty element, mixed text, and each attribute is an option."""
    for key, value in node.attrs.items():
        yield node.path + '/@' + key, value, node
    if not node.children or node.text:
        yield node.path, node.text, node
    for child in node.children:
        yield from options(child)


def xml_bytes(element):
    ET.indent(element, space='  ')
    return ET.tostring(element, encoding='utf-8', xml_declaration=True) + b'\n'


class Report:
    def __init__(self, decisions=None):
        self.rows = []
        self.inputs = {}
        self.decisions = decisions or {}
        if not isinstance(self.decisions, dict):
            raise InputError('decisions.json must be an object keyed by report option id.')
        self.used = set()

    def record_input(self, source, data):
        digest = hashlib.sha256(data).hexdigest()
        if source in self.inputs and self.inputs[source] != digest:
            raise InputError('Different inputs have the same source label; use distinct file names.')
        self.inputs[source] = digest

    def add(self, source, path, classification, section, action, value='', rule='', option=True,
            output=False):
        ident = source + ':' + path
        if any(r['id'] == ident for r in self.rows):
            raise InputError('Duplicate report option id; use distinct input file names.')
        row = dict(id=ident, source=source, option=path, classification=classification,
                   guide=section, action=action, value='[masked]' if value else '', rule=rule,
                   input_option=option, emitted=output, automatic=classification not in (DECIDE, UNKNOWN),
                   resolved=classification not in (DECIDE, UNKNOWN))
        self.rows.append(row)
        return row

    def decide(self, row, original, validator=None):
        decision = self.decisions.get(row['id'])
        if decision is None:
            return None
        self.used.add(row['id'])
        if (not isinstance(decision, dict) or decision.get('action') not in ('keep', 'replace', 'omit')
                or not isinstance(decision.get('reason'), str) or not decision['reason'].strip()):
            raise InputError('Each decision needs action keep/replace/omit and a nonempty reason.')
        act = decision['action']
        value = original if act == 'keep' else decision.get('value')
        if act != 'omit':
            if not isinstance(value, str) or (validator and not validator(value)):
                raise InputError('Decision value does not satisfy the documented constraint for ' + row['id'])
        row.update(resolved=True, automatic=False, emitted=act != 'omit',
                   action=row['action'] + ' Decision applied: ' + act + '; verify in the 5.0 lab.')
        # Do not echo supplied reason/value; either may contain credentials.
        return (act, value)

    def subtree(self, source, node, classification, section, action, rule, output=False):
        rows = []
        for path, value, _ in options(node):
            rows.append(self.add(source, path, classification, section, action, value, rule, output=output))
        return rows

    def payload(self):
        unused = set(self.decisions) - self.used
        if unused:
            raise InputError('Unused decision ids: check the input fingerprint and option paths.')
        counts = collections.Counter(r['classification'] for r in self.rows if r['input_option'])
        return dict(format_version=1, input_sha256=self.inputs, status='needs_review' if any(not r['resolved'] for r in self.rows)
                    else 'candidate_requires_lab_validation', counts=dict(sorted(counts.items())),
                    options=self.rows,
                    warning='Candidate files are incomplete while decisions remain. No runtime validation was run.')

    def files(self):
        payload = self.payload()
        lines = ['# Migration report', '', 'Status: ' + payload['status'] + '.', '', payload['warning'], '',
                 'All input values are masked, including unknown values. Generated configs retain required secrets; protect them.', '',
                 '| Option id | Classification | Guide section | Action left to user |',
                 '|---|---|---|---|']
        def cell(v):
            return str(v).replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')
        for r in self.rows:
            lines.append('| %s | %s | %s | %s |' % tuple(cell(r[k]) for k in
                         ('id', 'classification', 'guide', 'action')))
        template = {r['id']: {'action': None, 'reason': ''} for r in self.rows if not r['resolved']}
        return {'report.json': (json.dumps(payload, indent=2, sort_keys=True) + '\n').encode(),
                'report.md': ('\n'.join(lines) + '\n').encode(),
                'decisions.required.json': (json.dumps(template, indent=2, sort_keys=True) + '\n').encode()}


def load_decisions(path):
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text())
    except (ValueError, OSError):
        raise InputError('Cannot read decisions.json as JSON.')


def write_run(out, files, inputs):
    """Require a fresh output directory; never write through output links or onto inputs."""
    out = Path(out).absolute()
    if out.exists() or out.is_symlink():
        raise InputError('Output directory must not exist; choose a fresh run directory.')
    for item in inputs:
        p = Path(item).resolve()
        resolved_out = out.resolve()
        if resolved_out == p or p in resolved_out.parents or resolved_out in p.parents:
            raise InputError('Output must be separate from all input files/directories.')
    # Existing ancestors must not be symlinks.
    if any(p.is_symlink() for p in [out] + list(out.parents)):
        raise InputError('Output ancestors must not be symbolic links.')
    out.mkdir(mode=0o700, parents=True)
    for name, data in files.items():
        p = out / name
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
