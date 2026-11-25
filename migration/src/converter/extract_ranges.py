#!/usr/bin/env python3
"""Build the internal-option range table from a 5.0 source tree: every getDefine_Int / getDefine_Int_default call
whose module and option are string literals. Output: JSON {"module.option": {"min":..,"max":..,"default":..,"files":[..]}}.
Usage: extract_ranges.py <wazuh-src-root> <out.json>"""
import json, re, sys
from pathlib import Path
root, out = Path(sys.argv[1]), sys.argv[2]
CONST = {'INT_MAX': 2147483647, 'INT_MIN': -2147483648, 'UINT_MAX': 4294967295}
call = re.compile(r'getDefine_Int(_default)?\s*\(\s*"([A-Za-z0-9_]+)"\s*,\s*"([A-Za-z0-9_]+)"\s*,\s*((?:[^,()]|\([^()]*\))+?)\s*,\s*((?:[^,()]|\([^()]*\))+?)\s*(?:,\s*((?:[^,()]|\([^()]*\))+?)\s*)?\)', re.S)
defines = {}
for p in list(root.rglob('*.h')) + list(root.rglob('*.c')) + list(root.rglob('*.cpp')):
    if '/test' in str(p) or '/unit_tests' in str(p):
        continue
    for m in re.finditer(r'^\s*#define\s+([A-Z_][A-Z0-9_]*)\s+\(?(-?[0-9]+)\)?\s*(?:/[*/].*)?$', p.read_text(errors='replace'), re.M):
        defines.setdefault(m.group(1), int(m.group(2)))
def num(tok):
    tok = re.sub(r'/\*.*?\*/', ' ', tok, flags=re.S).strip()
    tok = re.sub(r'\b([A-Z_][A-Z0-9_]*)\b', lambda m: str(CONST.get(m.group(1), defines.get(m.group(1), m.group(1)))), tok)
    if re.fullmatch(r'[0-9xXa-fA-F\s<>*+()-]+', tok):
        try:
            return int(eval(tok, {'__builtins__': {}}, {}))
        except Exception:
            pass
    return tok
table, unresolved = {}, []
for p in sorted(list(root.rglob('*.c')) + list(root.rglob('*.cpp'))):
    s = str(p)
    if '/test' in s or 'unit_tests' in s or s.endswith('log_builder.c') or s.endswith('validate_op.c'):
        continue
    for m in call.finditer(p.read_text(errors='replace')):
        _, mod, opt, lo, hi, dflt = m.groups()
        key = mod + '.' + opt
        e = table.setdefault(key, {'min': num(lo), 'max': num(hi), 'default': num(dflt) if dflt else None, 'files': []})
        rel = str(p.relative_to(root))
        if rel not in e['files']: e['files'].append(rel)
        if any(isinstance(v, str) for v in (e['min'], e['max'])): unresolved.append(key)
# The one wrapper that passes a variable key: wm_task_manager_zeroable("key", min, max) reads wazuh_modules.<key>.
zero = re.compile(r'wm_task_manager_zeroable\s*\(\s*"([A-Za-z0-9_]+)"\s*,\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)')
for p in sorted(root.rglob('*.c')):
    if '/test' in str(p) or 'unit_tests' in str(p):
        continue
    for m in zero.finditer(p.read_text(errors='replace')):
        key = 'wazuh_modules.' + m.group(1)
        e = table.setdefault(key, {'min': num(m.group(2)), 'max': num(m.group(3)), 'default': None, 'files': []})
        rel = str(p.relative_to(root))
        if rel not in e['files']: e['files'].append(rel)
json.dump(dict(sorted(table.items())), open(out, 'w'), indent=1)
print('options with a range:', len(table), '; unresolved bounds:', sorted(set(unresolved)))
