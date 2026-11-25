#!/usr/bin/env python3
"""Convert offline 4.14 manager settings to reviewable 5.0 candidates.

Run --help for input selection. No files are installed and inputs are never edited.
"""
import argparse
import collections
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from migration_common import (CARRY, CHANGE, DROP, NONE, DECIDE, UNKNOWN, GUIDE, InputError,
                              Report, load_decisions, options, parse_xml, write_run, xml_bytes)
import c4_ext

# C4: run context. base = installed 5.0 files (c4_ext.Base), stock = stock 4.x files (c4_ext.Stock),
# ranges = 5.0 internal-option ranges (c4_ext.Ranges), standalone = the 4.x <cluster> was disabled.
CTX = dict(base=None, stock=None, ranges=None, standalone=False)

ACCEPTED = set('global logging remote auth wdb vulnerability-detection indexer task-manager cluster'.split())
LEGACY = set('port protocol queue_size ipv6 local_ip rids_closing_time connection_overtake_time'.split())
SUITES = set('TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256 TLS_AES_128_CCM_8_SHA256'.split())
GLOBAL_REMOVED = set('jsonout_output alerts_log logall logall_json email_notification smtp_server email_from email_to email_maxperhour email_log_source update_check agents_disconnection_alert_time'.split())
REPLACEMENTS = {
    'alerts': None,
    'command': '5.0 Active Response definitions; use rmig report references',
    'ruleset': 'engine content management; run rmig',
    'rootcheck': "agent's ossec.conf",
    'syscheck': "agent's ossec.conf (FIM)",
    'localfile': "agent's ossec.conf (log collection)",
    'agent-upgrade': 'task-manager; map options with the remote-agent-upgrade guide',
    'active-response': '5.0 Active Response; use rmig report references',
    'email_alerts': 'mail-forwarding-reporting.md; rmig monitor/channel checklist',
    'reports': 'mail-forwarding-reporting.md; rmig monitor/channel checklist',
    'syslog_output': 'remote-syslog-output.md',
    'integration': 'notifications plugin; rmig monitor/channel checklist',
    'agentless': 'agentless-4x-to-5x.md supported alternatives',
}
RENAMED = dict(zip(
    ('monitord.' + x for x in 'delete_old_agents monitor_agents rotate_log compress keep_log_days day_wait size_rotate daily_rotations'.split()),
    ('wazuh_modules.manager_task_' + x for x in 'delete_old_agents monitor_agents log_rotate log_compress log_keep_days log_day_wait log_size_rotate log_daily_rotations'.split())))
REMOVED_INTERNAL = set('''analysisd.default_timeframe analysisd.stats_maxdiff analysisd.stats_mindiff
analysisd.stats_percent_diff analysisd.fts_list_size analysisd.fts_min_size_for_str analysisd.log_fw
analysisd.decoder_order_size analysisd.geoip_jsonout analysisd.label_cache_maxage analysisd.show_hidden_labels
analysisd.rlimit_nofile analysisd.min_rotate_interval analysisd.event_threads analysisd.syscheck_threads
analysisd.syscollector_threads analysisd.rootcheck_threads analysisd.sca_threads analysisd.hostinfo_threads
analysisd.winevt_threads analysisd.rule_matching_threads analysisd.dbsync_threads analysisd.decode_event_queue_size
analysisd.decode_syscheck_queue_size analysisd.decode_syscollector_queue_size analysisd.decode_rootcheck_queue_size
analysisd.decode_sca_queue_size analysisd.decode_hostinfo_queue_size analysisd.decode_winevt_queue_size
analysisd.decode_output_queue_size analysisd.archives_queue_size analysisd.statistical_queue_size
analysisd.alerts_queue_size analysisd.firewall_queue_size analysisd.fts_queue_size analysisd.dbsync_queue_size
analysisd.upgrade_queue_size analysisd.state_interval remoted.guess_agent_group remoted.state_interval
remoted.router_forwarding_disabled maild.strict_checking maild.grouping maild.full_subject maild.geoip
monitord.sign monitord.debug wazuh_download.enabled dbd.reconnect_attempts integrator.debug'''.split())
AGENT_PREFIXES = set('agent execd logcollector rootcheck sca syscheck wazuh_command windows'.split())
MASTER_DEFAULTS = dict(sync_disconnected_agent_groups=300, sync_disconnected_agent_groups_batch_size=100,
                       sync_disconnected_agent_groups_min_offline=600, sync_disconnected_agent_cluster_name_delay=300,
                       metrics_frequency=600, metrics_bulk_size=100)
COMMON_DEFAULTS = dict(active_response_polling=30, active_response_page_size=1000, active_response_event_grace=120)


def section(name):
    return GUIDE + '#' + name


def valid_duration(value, minimum=0):
    m = re.fullmatch(r'([0-9]+)([smhdw]?)', value)
    if not m:
        return False
    digits, unit = m.groups()
    scale, limit = {'': (1, 9), 's': (1, 9), 'm': (60, 7), 'h': (3600, 5),
                    'd': (86400, 4), 'w': (604800, 3)}[unit]
    return len(digits) <= limit and minimum <= int(digits) * scale <= 999999999


def cert_path(value):
    return bool(re.fullmatch(r'/etc/wazuh-manager/certs/[A-Za-z0-9_.-]+', value)) and value.rsplit('/', 1)[-1] not in ('.', '..')


def host_url(value):
    try:
        url = urlsplit(value)
        return url.scheme in ('http', 'https') and bool(url.hostname) and not url.username and not url.password
    except ValueError:
        return False


def ciphers(value):
    return bool(value) and all(x in SUITES for x in value.split(':'))


def bind_address(value):
    return bool(re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', value)) and value not in ('.', '..')


def rule_for(path, value):
    """Rules only from the guide. Unenumerated children are deliberately unknown."""
    top = path[0]
    s = section(top + '-section')
    c4 = c4_rule(path, value)
    if c4:
        return c4
    if top == 'global':
        s = section('global-section')
        if path[1:] == ['agents_disconnection_time']:
            return CARRY, s, 'Keep; validate duration in 5.0.', 'global.keep', lambda x: valid_duration(x)
        if len(path) == 2 and path[1] == 'white_list':
            return DROP, s, "Recreate as agent active-response/allowlist; manager and loopback are protected.", 'global.whitelist', None
        if len(path) == 2 and path[1] in GLOBAL_REMOVED:
            repl = 'mail-forwarding-reporting.md; rmig monitor/channel checklist' if path[1].startswith('email') or path[1] == 'smtp_server' else None
            return DROP if repl else NONE, s, 'Remove. Replacement: ' + repl if repl else 'Remove; guide names no replacement.', 'global.remove', None
    if top == 'remote':
        if len(path) == 2 and path[1] in ('connection', 'allowed-ips', 'denied-ips'):
            if path[1] == 'connection' and value != 'secure':
                return DECIDE, s, '4.x listener was not secure; remove obsolete connection option and decide how to replace that listener (remote-syslog-output.md is output only).', 'remote.nonsecure', None
            if path[1] != 'connection':
                return NONE, s, 'Remove obsolete IP filter; guide names no same-option replacement. Review required access controls before cutover.', 'remote.remove', None
            return DROP, s, 'Remove secure connection flag; secure communication is now the default.', 'remote.remove', None
        if len(path) == 2 and path[1] in LEGACY:
            validator = None
            if path[1] == 'rids_closing_time':
                validator = lambda x: valid_duration(x, 1)
            elif path[1] in ('port', 'queue_size'):
                validator = lambda x: bool(re.fullmatch(r'[0-9]+', x))
            elif path[1] == 'ipv6':
                validator = lambda x: x in ('yes', 'no')
            return CHANGE, s, 'Move to remote/legacy/' + path[1] + '; validate in 5.0.', 'remote.nest', validator
        if len(path) >= 2 and path[1] == 'agents':
            return DECIDE, s, 'Agents block is unchanged, but children/types are not enumerated; confirm against 5.0 schema.', 'remote.agents', None
    if top == 'auth':
        if path[1:] == ['ssl_auto_negotiate']:
            return NONE, s, 'Remove; enrollment requires TLS 1.3.', 'auth.remove', None
        if path[1:] == ['ciphers']:
            return CARRY, s, 'Keep TLS 1.3 suites; replace any 4.x cipher-list with chosen TLS 1.3 suites.', 'auth.ciphers', ciphers
        if len(path) == 2 and path[1] in ('ssl_manager_cert', 'ssl_manager_key'):
            return DECIDE, s, 'Select remoted.pem/remoted-key.pem or supplied PKI pair directly in /etc/wazuh-manager/certs; verify ownership, SAN and key pair.', 'auth.cert', cert_path
    if top == 'vulnerability-detection':
        if path[1:] == ['index-status']:
            return NONE, s, 'Remove; index-status has no 5.0 option.', 'vulnerability.remove', None
        if path[1:] == ['enabled']:
            return CARRY, s, 'Keep yes/no.', 'vulnerability.keep', lambda x: x in ('yes', 'no')
        if path[1:] == ['feed-update-interval']:
            return CARRY, s, 'Keep positive bounded interval; zero in any unit is refused.', 'vulnerability.interval', lambda x: valid_duration(x, 1)
    if top == 'indexer':
        if path[1:] == ['enabled']:
            return DROP, s, 'Remove flag; indexer connection is always active.', 'indexer.remove', None
        if path[1:] == ['hosts', 'host']:
            return CARRY, s, 'Keep indexer URL; credentials go in the 5.0 keystore.', 'indexer.host', host_url
        if path[1:] == ['ssl', 'certificate_authorities', 'ca']:
            return DECIDE, s, 'Select actual manager CA file directly in /etc/wazuh-manager/certs; example is indexer-ca.pem. No certificates are copied.', 'indexer.ca', cert_path
        if len(path) == 3 and path[1] == 'ssl' and path[2] in ('certificate', 'key'):
            return DECIDE, s, 'Omit unless indexer requires client certificates; otherwise select a file directly in /etc/wazuh-manager/certs.', 'indexer.mtls', cert_path
    if top == 'cluster':
        if path[1:] == ['disabled']:
            return DROP, s, 'Remove; cluster is always active. Standalone must become a single master. Review listener exposure.', 'cluster.disabled', None
        if path[1:] == ['key']:
            return CARRY, s, 'Keep only a 32-character alphanumeric key; share it securely with cluster nodes.', 'cluster.key', lambda x: bool(re.fullmatch(r'[A-Za-z0-9]{32}', x))
        if path[1:] == ['hidden']:
            return CARRY, s, 'Accepted but has no effect in 5.0.', 'cluster.hidden', lambda x: x in ('yes', 'no')
        if path[1:] == ['bind_addr']:
            return CARRY, s, 'Keep explicit bind address; ensure workers can reach master.', 'cluster.bind', bind_address
        if path[1:] == ['node_type']:
            return CARRY, s, 'Keep topology role; standalone requires master.', 'cluster.role', lambda x: x in ('master', 'worker')
        if path[1:] == ['port']:
            return CARRY, s, 'Keep; validate numeric port and range in 5.0.', 'cluster.port', lambda x: x.isascii() and x.isdigit()
        if path[1:] in (['name'], ['node_name'], ['nodes', 'node']):
            return CARRY, s, 'Keep; verify topology and explicit master address.', 'cluster.keep', None
    return UNKNOWN, section('strict-xml'), 'Not specified by the migration guide; confirm exact option/type with manager owners or omit explicitly.', 'xml.unknown', None


C4_AGENT_SECTIONS = set('sca rule_test rootcheck syscheck localfile'.split())
C4_AGENT_WODLES = set('cis-cat osquery syscollector docker-listener command open-scap'.split())


def c4_remove_rows(report, source, n, cls, action):
    """One row per option of a section 5.0 removed; options equal to the stock 4.x file need nobody."""
    stock = CTX['stock']
    whole = stock is not None and stock.block_is_stock(n)
    rows = []
    for path, value, _ in options(n):
        rel = [re.sub(r'\[[0-9]+\]$', '', p) for p in path[len(n.path):].split('/') if p]
        if stock is None:
            st = False
        elif whole:
            st = True
        elif rel and rel[-1].startswith('@'):
            st = any(k[0] == c4_ext.section_key(n) for k in stock.leaves)
        else:
            st = stock.leaf_is_stock(n, rel, value)
        if st:
            rows.append(report.add(source, path, NONE, section('sections-to-remove-from-wazuh-managerconf'),
                                   'Stock 4.x default in a section 5.0 removed; nothing to carry.', value, 'xml.stock-section'))
        else:
            rows.append(report.add(source, path, cls, section('sections-to-remove-from-wazuh-managerconf'), action, value, 'xml.remove-section'))
    return rows


def c4_finish(out, report, source, nodes):
    """Topology check against the installed 5.0 node, then the merge into the installed file."""
    base = CTX['base']
    clustered = any(n.tag == 'cluster' for n in nodes) and not CTX['standalone']
    if CTX['standalone'] and base.standalone():
        report.add(source, '/$topology/standalone', CHANGE, section('cluster-section'),
                   '4.x cluster was disabled and this 5.0 install is single-node: one master on loopback, kept as installed.', rule='cluster.standalone-installed', option=False)
    elif CTX['standalone'] or (clustered and base.standalone()):
        row = report.add(source, '/$topology/mismatch', DECIDE, section('cluster-section'),
                         'The 4.x topology (%s) differs from this 5.0 node (%s). Plan the 5.0 install from the 4.x topology, or confirm.' %
                         ('single node' if CTX['standalone'] else 'cluster', 'single node' if base.standalone() else 'cluster node'),
                         rule='cluster.topology-mismatch', option=False)
        report.decide(row, 'confirmed', lambda x: x == 'confirmed')
    merged, changes = c4_ext.merge(base, out, c4_ext.owned)
    CTX.setdefault('changes', {})[source] = changes
    return merged


def c4_rule(path, value):
    """C4 rules. Returns None to fall through to C1's rules."""
    base = CTX['base']
    s = section(path[0] + '-section')
    tags = path
    stock = CTX['stock']
    if tags[0] == 'global' and len(tags) == 2 and tags[1] in GLOBAL_REMOVED and stock is not None and ('global', (tags[1],), value) in stock.leaves:
        return NONE, section('global-section'), 'Stock 4.x default of an option 5.0 removed; nothing to rebuild.', 'global.stock-remove', None
    if tags[0] == 'global' and tags[1:] == ['white_list'] and c4_ext.is_loopback(value or ''):
        return NONE, s, 'Remove: 5.0 always protects the manager and loopback from active response.', 'global.whitelist-loopback', None
    if tags[0] == 'cluster':
        bval = base.values(tags) if base else []
        if tags[1:] == ['disabled']:
            return None
        if tags[1:] == ['key']:
            if base:
                return DROP, s, 'The 4.x cluster key is never carried: the 5.0 install generated one key for every node of this cluster, and a node with another key is cut off silently (F3). Kept the installed key.', 'cluster.key-installed', None
            return DECIDE, s, 'Supply the 5.0 cluster key that the 5.0 install gave every node. Never the 4.x key: a master with another key cuts its workers off silently.', 'cluster.key-5x', lambda x: bool(re.fullmatch(r'[A-Za-z0-9]{32}', x))
        if base:
            if tags[1:] in (['node_type'], ['node_name']) and bval and value not in bval:
                return DECIDE, s, 'This 4.x file is for another node than the 5.0 node it is merged into (4.x %s differs). Use the file of this node.' % tags[1], 'cluster.wrong-node', None
            if value in bval:
                return CARRY, s, 'Same as the 5.0 install; the installed value is kept.', 'cluster.installed-equal', None
            why = '4.x template placeholder' if c4_ext.is_placeholder(value or '') else '4.x value differs from the 5.0 install'
            return DROP, s, 'Kept the value the 5.0 install wrote (%s). The 5.0 install owns the cluster topology.' % why, 'cluster.installed-kept', None
        if CTX['standalone'] and tags[1:] in (['bind_addr'], ['nodes', 'node']):
            return CHANGE, s, '4.x cluster was disabled: 5.0 runs one master bound to loopback, as a single-node install writes it.', 'cluster.standalone-loopback', None
        if tags[1:] == ['nodes', 'node'] and not c4_ext.is_address(value or ''):
            return DECIDE, s, 'Not an address (a 4.x template placeholder or invalid name): supply the master address.', 'cluster.placeholder', c4_ext.is_address
        return None
    if base:
        if c4_ext.owned(tags):
            bval = base.values(tags)
            if value in bval:
                return CARRY, s, 'Same as the 5.0 install; the installed value is kept.', 'install.owned-equal', None
            return DROP, s, 'The 5.0 install owns this value (listener, certificate or indexer connection); the installed value is kept.', 'install.owned-kept', None
        if tags == ['auth', 'ciphers'] and not c4_ext.tls13_list(value or ''):
            return CHANGE, s, 'A 4.x OpenSSL cipher list applied to TLS 1.2 and lower only; 5.0 enrollment is TLS 1.3. Replaced with the TLS 1.3 suites the 5.0 install wrote.', 'auth.ciphers-installed', None
        if base.schema and base.schema.leaf(tags) is not None and base.schema.check(tags, value or '') != 'is a section, not a value':
            if base.value(tags) == value:
                return CARRY, s, 'Same as the 5.0 install.', 'schema.equal', None
            return CARRY, s, '5.0 option (in the shipped schema); 4.x value carried and checked against the schema.', 'schema.carry', None
    return None


def convert_xml(data, report, source='ossec.conf'):
    if isinstance(data, str):
        data = data.encode('utf-8')
    report.record_input(source, data)
    try:
        roots = parse_xml(data)
    except InputError as exc:
        report.add(source, '/$syntax', DECIDE, section('strict-xml'), str(exc), rule='xml.syntax', option=False)
        return None
    if any(r.tag != 'ossec_config' for r in roots):
        for r in roots:
            report.subtree(source, r, UNKNOWN, section('root-element'), 'Expected ossec_config; normalize a working copy.', 'xml.root')
        return None
    report.add(source, '/$root', CHANGE, section('root-element'),
               'Rename root to wazuh_config; combine sibling 4.x roots into one, preserving section order.', rule='xml.root', option=False)
    nodes = [c for root in roots for c in root.children]
    CTX['standalone'] = any(c.tag == 'disabled' and c.text == 'yes' for n in nodes if n.tag == 'cluster' for c in n.children)
    counts = collections.Counter(n.tag for n in nodes if n.tag in ACCEPTED)
    # Repeated globals that contain only removed options can be omitted safely.
    global_kept = [n for n in nodes if n.tag == 'global' and any(c.tag not in GLOBAL_REMOVED | {'white_list'} for c in n.children)]
    duplicates = {k for k, v in counts.items() if v > 1 and k != 'global'}
    if len(global_kept) > 1:
        duplicates.add('global')
    out = ET.Element('wazuh_config')
    for root in roots:
        for key, value in root.attrs.items():
            row = report.add(source, root.path + '/@' + key, UNKNOWN, section('strict-xml'), 'Root attributes are not specified; omitted pending review.', value, 'xml.unknown')
            choice = report.decide(row, value)
            if choice and choice[0] != 'omit':
                out.set(key, choice[1])
    for n in nodes:
        top = n.tag
        if top not in ACCEPTED:
            replacement = REPLACEMENTS.get(top)
            if top == 'wodle':
                replacement = {'syscollector': "agent's ossec.conf", 'open-scap': 'SCA (ciscat-openscap-to-sca.md)'}.get(n.attrs.get('name'))
            if top == 'var':
                cls, action = NONE, 'Remove var definitions; they had no effect on the manager. Resolve any variable uses explicitly.'
            elif replacement:
                cls, action = DROP, 'Remove manager block. Replacement: ' + replacement + '. Recreate functionality before cutover.'
                if top in ('syslog_output', 'agentless'):
                    cls, action = DECIDE, 'Section must be removed. The guide points to ' + replacement + ' but does not name an actual replacement mechanism here. Select an alternative with the owners; omit acknowledges the removal.'
            elif top in REPLACEMENTS:
                cls, action = NONE, 'Remove; no replacement is named in the guide.'
            else:
                cls, action = UNKNOWN, 'Not admitted among the nine 5.0 sections. Omitted; owner must identify any replacement.'
            if top in C4_AGENT_SECTIONS or (top == 'wodle' and n.attrs.get('name') in C4_AGENT_WODLES):
                if cls in (DECIDE, UNKNOWN) and top not in ('syslog_output', 'agentless'):
                    cls, action = (NONE, 'Remove; the 5.0 engine has no rule_test section (it has its own test API).') if top == 'rule_test' else \
                        (DROP, 'Remove manager block: a 5.0 manager runs no agent modules. Replacement: a 5.0 agent on the manager host, with this block in its ossec.conf.')
            rows = c4_remove_rows(report, source, n, cls, action)
            if cls in (DECIDE, UNKNOWN):
                for row in rows:
                    if row['resolved']:
                        continue
                    choice = report.decide(row, '')
                    if choice and choice[0] != 'omit':
                        raise InputError('A section outside the nine admitted manager sections cannot be kept; omit it or normalize a working copy.')
            continue
        if top in duplicates:
            report.subtree(source, n, DECIDE, section('strict-xml'), 'Duplicate section; reconcile a working copy before rerunning. No section occurrence was selected.', 'xml.duplicate')
            continue

        def visit(node, tags, parent_force=False):
            attrs = {}
            for key, value in node.attrs.items():
                row = report.add(source, node.path + '/@' + key, UNKNOWN, section('strict-xml'), 'Attribute is not specified; omitted pending review.', value, 'xml.attribute')
                choice = report.decide(row, value)
                if choice and choice[0] != 'omit':
                    attrs[key] = choice[1]
            if node.children:
                e = ET.Element(node.tag, attrs)
                seen = collections.Counter(c.tag for c in node.children)
                repeatable = (tags == ['indexer', 'hosts'] or tags == ['indexer', 'ssl', 'certificate_authorities'] or tags == ['cluster', 'nodes']
                              or (tags == ['global'] and set(c.tag for c in node.children) == {'white_list'}))
                for child in node.children:
                    dup = seen[child.tag] > 1 and not repeatable
                    v = visit(child, tags + [child.tag], parent_force or dup)
                    if v is not None:
                        e.append(v)
                if node.text:
                    report.add(source, node.path, UNKNOWN, section('strict-xml'), 'Mixed text omitted; review manually.', node.text, 'xml.mixed')
                return e if len(e) else None
            # Empty known section/container means defaults, not an unknown leaf option.
            if len(tags) == 1 or tags in (['indexer', 'ssl'], ['indexer', 'hosts'], ['cluster', 'nodes']):
                row = report.add(source, node.path, DECIDE, section('strict-xml'), 'Empty section: verify required children and defaults.', rule='xml.empty')
                choice = report.decide(row, '')
                return ET.Element(node.tag, attrs) if choice and choice[0] == 'keep' else None
            cls, guide, action, rule, validator = rule_for(tags, node.text)
            if parent_force:
                cls, action, rule = DECIDE, 'Duplicate child; reconcile a working copy before rerunning.', 'xml.duplicate'
            if cls not in (NONE, DROP) and (b'&amp;' in data[node.start:node.end] or b'&lt;' in data[node.start:node.end] or '$' in node.text):
                cls, action, rule = DECIDE, 'XML entities are decoded in 5.0, and variables are unsupported; confirm the intended value.', 'xml.value-semantics'
            if validator and not validator(node.text) and cls in (CARRY, CHANGE):
                cls, action = DECIDE, action + ' Current value violates the documented 5.0 constraint; replace or omit.'
            value = node.text
            if rule == 'auth.ciphers-installed':
                value = CTX['base'].value(['auth', 'ciphers'])
            elif rule == 'cluster.standalone-loopback':
                value = '127.0.0.1'
            base = CTX['base']
            if base and base.schema and cls in (CARRY, CHANGE) and not c4_ext.owned(tags):
                target = ['remote', 'legacy', tags[1]] if rule == 'remote.nest' else tags
                why = base.schema.check(target, value or '')
                if why:
                    cls, action, rule = DECIDE, action + ' The 5.0 schema refuses this value (%s): replace or omit.' % why, 'schema.refused'
            row = report.add(source, node.path, cls, guide, action, node.text, rule, output=cls in (CARRY, CHANGE))
            if cls in (DECIDE, UNKNOWN):
                decision = report.decide(row, value, validator)
                if rule == 'xml.duplicate' and decision and decision[0] != 'omit':
                    raise InputError('Reconcile duplicate elements in a working copy; only omit decisions are safe here.')
                if decision is None or decision[0] == 'omit':
                    return None
                value = decision[1]
            elif cls not in (CARRY, CHANGE):
                return None
            e = ET.Element(node.tag, attrs)
            e.text = value or None
            return e

        e = visit(n, [top])
        if e is not None:
            if top == 'remote':
                legacy = ET.Element('legacy')
                for child in list(e):
                    if child.tag in LEGACY:
                        e.remove(child)
                        legacy.append(child)
                if len(legacy):
                    e.insert(0, legacy)
            out.append(e)
    # Never emit an invalid duplicate document; normalize on a copy first.
    if duplicates:
        return None
    if CTX['base'] is not None:
        return c4_finish(out, report, source, nodes)
    for top, child, validator in [('cluster', 'key', lambda x: bool(re.fullmatch('[A-Za-z0-9]{32}', x))),
                                  ('indexer', 'hosts', host_url)]:
        target = out.find(top)
        if target is None or target.find(child) is None or (child == 'hosts' and target.find('hosts/host') is None):
            # A present value held for a decision already asks this question. Do not
            # create two competing decisions for the same required output value.
            original_paths = set()
            for src_node in nodes:
                if src_node.tag == top:
                    for src_child in src_node.children:
                        if src_child.tag == child:
                            if child == 'key':
                                original_paths.add(src_child.path)
                            else:
                                original_paths.update(n.path for n in src_child.children if n.tag == 'host')
            if any(row['source'] == source and row['option'] in original_paths and not row['resolved'] for row in report.rows):
                continue
            row = report.add(source, '/$required/' + top + '/' + child, DECIDE, section('strict-xml'),
                             'Required in 5.0. Supply the actual cluster key or one indexer host URL; merge installer defaults in the lab.', rule='xml.required', option=False)
            decision = report.decide(row, '', validator)
            if decision and decision[0] == 'omit':
                row['resolved'] = False
            if decision and decision[0] != 'omit':
                if target is None:
                    target = ET.SubElement(out, top)
                old = target.find(child)
                if old is not None:
                    target.remove(old)
                leaf = ET.SubElement(target, child)
                if child == 'hosts':
                    leaf = ET.SubElement(leaf, 'host')
                leaf.text = decision[1]
    cluster_sources = [n for n in nodes if n.tag == 'cluster']
    standalone = any(c.tag == 'disabled' and c.text == 'yes' for n in cluster_sources for c in n.children)
    cluster = out.find('cluster')
    if standalone:
        row = report.add(source, '/$topology/standalone', DECIDE, section('cluster-section'),
                   '4.x cluster was disabled. Confirm single master, loopback listeners and nodes against installed defaults before enabling 5.0.', rule='cluster.standalone', option=False)
        report.decide(row, 'confirmed', lambda x: x == 'confirmed')
    elif cluster_sources:
        for tag in ('bind_addr', 'nodes'):
            if cluster is None or cluster.find(tag) is None:
                row = report.add(source, '/$topology/' + tag, DECIDE, section('cluster-section'),
                                 'Set explicit master address; 5.0 loopback default may prevent cluster joins.', rule='cluster.missing-address', option=False)
                decision = report.decide(row, '', bind_address)
                if decision and decision[0] != 'omit' and cluster is not None:
                    leaf = ET.SubElement(cluster, tag)
                    if tag == 'nodes':
                        leaf = ET.SubElement(leaf, 'node')
                    leaf.text = decision[1]
    return xml_bytes(out)


def internal_entries(data, source):
    entries = []
    for line, raw in enumerate(data.decode('utf-8').splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_.-]+)\s*=\s*([^#\r\n]*?)(?:\s*#.*)?', raw)
        entries.append((source, line, match.group(1) if match else None, match.group(2).strip() if match else ''))
    return entries


def convert_internal(inputs, report):
    """inputs: sequence of (source label, bytes, is_local_override)."""
    for source, data, _ in inputs:
        report.record_input(source, data)
    entries = [(src, line, key, val, local) for src, data, local in inputs for src, line, key, val in internal_entries(data, src)]
    locals_set = {key for _, _, key, _, local in entries if local}
    counts = collections.Counter((src, key) for src, _, key, _, _ in entries)
    base = CTX['base']
    header = base.internal.decode('utf-8').rstrip('\n') + '\n' if base is not None and base.internal else ''
    lines = [header + '# Carried from 4.x by the migration tool. Ranges checked against the 5.0 build\'s option table.' if header
             else '# User overrides only. Validate ranges with the 5.0 daemons.']
    stock, ranges = CTX['stock'], CTX['ranges']
    for src, line, key, value, local in entries:
        s, cls, rule, validator = section('removed-options'), UNKNOWN, 'internal.unknown', None
        action = 'Not enumerated by guide; verify option and range with manager owners.'
        target = key
        if key and not local and stock is not None and stock.internal.get(key) == value and key not in locals_set:
            row = report.add(src, '/line[%d]/%s' % (line, key), NONE, s,
                             'Stock 4.x default, not a customization; 5.0 compiles its own defaults.', value, 'internal.stock')
            continue
        if key and ranges is not None and counts[(src, key)] == 1 and not (not local and key in locals_set):
            c4 = c4_internal(key, value)
            if c4:
                cls, rule, action, target = c4
                row = report.add(src, '/line[%d]/%s' % (line, key), cls, s, action, value, rule)
                if cls in (CARRY, CHANGE):
                    row['emitted'] = True
                    lines.append(target + '=' + value)
                elif cls in (DECIDE, UNKNOWN):
                    lo_hi = ranges.get(target)
                    def ranged(candidate, lo_hi=lo_hi):
                        return '\n' not in candidate and (not lo_hi or (re.fullmatch(r'-?[0-9]+', candidate) and lo_hi[0] <= int(candidate) <= lo_hi[1]))
                    decision = report.decide(row, value, ranged)
                    if decision and decision[0] != 'omit':
                        lines.append(target + '=' + decision[1])
                continue
        if key in RENAMED:
            cls, rule, s, target = CHANGE, 'internal.rename', section('renamed-options'), RENAMED[key]
            action = 'Rename to ' + target + '; validate 5.0 range/default in lab.'
            validator = lambda x: bool(re.fullmatch(r'[0-9]+', x))
        elif key in REMOVED_INTERNAL:
            cls, rule = NONE, 'internal.remove'
            action = 'Remove; no same-key replacement. Configure engine/Task Manager or removed-feature replacement as appropriate.'
            if key == 'remoted.guess_agent_group':
                cls, action = DROP, 'Remove; preserve global.db assignments or declare enrollment groups; see agent-groups-migration.md.'
        elif key and key.split('.')[0] in AGENT_PREFIXES:
            cls, rule, action = DROP, 'internal.agent', 'Remove from manager; keep applicable overrides in agent local_internal_options.conf.'
        elif key in ('analysisd.debug', 'wazuh_clusterd.debug'):
            cls, rule, action = CARRY, 'internal.debug', 'Keep verbosity 0, 1 or 2.'
            validator = lambda x: x in ('0', '1', '2')
        elif key and key.startswith('remoted.'):
            cls, rule = DECIDE, 'internal.remoted'
            action = 'Guide preserves other stock 4.x remoted keys but does not enumerate them. Confirm this is a stock key and validate range.'
        if key is None:
            cls, rule, action = UNKNOWN, 'internal.syntax', 'Unparsed internal option line; omitted. Normalize a working copy.'
        if not local and key in locals_set:
            cls, rule, action = CHANGE, 'internal.precedence', 'System value is superseded by local_internal_options.conf; only local override may be emitted.'
        elif not local and cls in (CARRY, CHANGE):
            cls, rule, action = DECIDE, 'internal.system', 'Confirm this system-file value was customized; stock defaults must come from the 5.0 binary.'
        if counts[(src, key)] > 1:
            cls, rule, action = DECIDE, 'internal.duplicate', 'Duplicate key; reconcile a working copy before rerunning.'
        if validator and not validator(value) and cls in (CARRY, CHANGE):
            cls, action = DECIDE, action + ' Invalid documented value.'
        row = report.add(src, '/line[%d]/%s' % (line, key or '$unparsed'), cls, s, action, value, rule)
        if rule == 'internal.precedence':
            continue
        if cls in (CARRY, CHANGE):
            row['emitted'] = True
            lines.append(target + '=' + value)
        elif cls in (DECIDE, UNKNOWN):
            def internal_validator(candidate):
                return '\n' not in candidate and '\r' not in candidate and (not validator or validator(candidate))
            decision = report.decide(row, value, internal_validator)
            if decision and decision[0] != 'omit' and key is None:
                raise InputError('Unparsed internal option lines can only be omitted; normalize a working copy.')
            if decision and decision[0] != 'omit' and key:
                lines.append(target + '=' + decision[1])
    # Decisions cannot produce duplicate effective keys.
    emitted = [line.split('=', 1)[0] for line in lines if not line.startswith('#')]
    if len(set(emitted)) != len(emitted):
        raise InputError('Decisions produced duplicate internal option keys.')
    return ('\n'.join(lines) + '\n').encode()


def c4_internal(key, value):
    """Internal option against the 5.0 range table. Returns (cls, rule, action, target) or None for C1's rules."""
    ranges = CTX['ranges']
    target = RENAMED.get(key, key)
    if key in REMOVED_INTERNAL or key.split('.')[0] in AGENT_PREFIXES:
        return None
    r = ranges.get(target)
    if r is None:
        return NONE, 'internal.unread', '5.0 reads no such key (not in the build\'s option table): it would be silently ignored. Not carried.', target
    lo, hi, daemon = r
    ok = bool(re.fullmatch(r'-?[0-9]+', value)) and lo <= int(value) <= hi
    renamed = ' Renamed to ' + target + '.' if target != key else ''
    if ok:
        return (CHANGE if target != key else CARRY), ('internal.rename' if target != key else 'internal.ranged'), \
            'Read by %s, range %s..%s; value in range.%s' % (daemon, lo, hi, renamed), target
    return DECIDE, 'internal.out-of-range', ('Read by %s with range %s..%s: this value would stop %s and with it the manager. '
                                             'Replace with a value in range or omit.%s' % (daemon, lo, hi, daemon, renamed)), target


def yaml_mapping(data):
    """Conservative YAML subset: block mappings and single-line scalar values.

    Anything requiring a full YAML implementation is refused rather than misparsed.
    """
    text = data.decode('utf-8')
    stack, found, paths = [(-1, ())], [], set()
    for line, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        m = re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_-]*):(?: +(.*))?', raw)
        if not m:
            raise InputError('Unsupported YAML syntax at line %d; use simple block mappings on a copy.' % line)
        indent, key, value = len(m[1]), m[2], m[3]
        while stack[-1][0] >= indent:
            stack.pop()
        if stack[-1][0] == -1 and indent != 0:
            raise InputError('Ambiguous YAML indentation; normalize a working copy.')
        path = stack[-1][1] + (key,)
        if path in paths:
            raise InputError('Duplicate YAML mapping key; reconcile a working copy.')
        paths.add(path)
        if value is None or value.startswith('#'):
            stack.append((indent, path))
            continue
        # Strip a comment only outside quotes; refuse multiline/flow/tags/aliases.
        quote, escaped, end = None, False, len(value)
        for i, char in enumerate(value):
            if escaped:
                escaped = False
            elif char == '\\' and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            elif char in ('"', "'") and quote is None:
                quote = char
            elif char == '#' and quote is None and (i == 0 or value[i - 1].isspace()):
                end = i
                break
        value = value[:end].rstrip()
        if quote or not value or value[0] in '|>{[&*!' or '\t' in raw:
            raise InputError('Unsupported YAML scalar at line %d; normalize a working copy.' % line)
        if value.startswith('"'):
            try:
                scalar = json.loads(value)
            except ValueError:
                raise InputError('Unsupported YAML quoted escape; use JSON-compatible quoting.')
            if not isinstance(scalar, str):
                raise InputError('Expected scalar string.')
        elif value.startswith("'"):
            if not value.endswith("'"):
                raise InputError('Unclosed YAML scalar.')
            scalar = value[1:-1].replace("''", "'")
        else:
            if ': ' in value or value in ('---', '...'):
                raise InputError('Ambiguous YAML scalar; quote it on a copy.')
            scalar = value
        found.append((path, scalar, value, line))
    # Include empty mappings, which are still explicit options.
    containers = paths - {p for p, _, _, _ in found}
    for p in sorted(containers):
        if not any(len(q) > len(p) and q[:len(p)] == p for q in paths):
            found.append((p, '', '{}', 0))
    return found


def convert_api(data, report, source='api.yaml'):
    report.record_input(source, data)
    try:
        entries = yaml_mapping(data)
    except (InputError, UnicodeDecodeError) as exc:
        report.add(source, '/$syntax', DECIDE, GUIDE + '#apiyaml', str(exc) if isinstance(exc, InputError) else 'Only UTF-8 YAML is supported.', rule='api.syntax', option=False)
        return None
    result = {}
    default_names = {'https.key': ('server.key', 'apid-key.pem'), 'https.cert': ('server.crt', 'apid.pem'), 'https.ca': ('ca.crt', 'root-ca.pem')}
    carried = {'https.enabled', 'https.use_ca', 'https.ssl_ciphers', 'upload_configuration.agents.allow_higher_versions.allow', 'upload_configuration.indexer.allow'}
    for path, value, literal, line in entries:
        key = '.'.join(path)
        cls, rule, s = UNKNOWN, 'api.unknown', GUIDE + '#apiyaml'
        action, validator = 'Guide does not enumerate this API option; verify against 5.0 schema or omit.', None
        if key in ('https.ssl_protocol', 'experimental_features', 'drop_privileges') or key.startswith('upload_configuration.integrations.') or key == 'upload_configuration.integrations':
            cls, rule, s = NONE, 'api.remove', section('removed-options-1')
            action = 'Remove unsupported API key; API runs as wazuh-manager; VirusTotal moves out of manager (virustotal-migration.md).'
        elif key in default_names and value == c4_ext.API_CERT_DEFAULTS_4X[key]:
            cls, rule, s = NONE, 'api.cert-default', section('ssl-certificate-names')
            action = '4.x default name; the 5.0 default (%s) applies, which is the pair the 5.0 install issued.' % default_names[key][1]
        elif key == 'host' and CTX['base'] is not None:
            cls, rule, s = DROP, 'api.host-installed', GUIDE + '#apiyaml'
            action = 'The 5.0 install decides where the API listens (loopback on a single node); the installed value is kept.'
        elif key in default_names:
            cls, rule, s = DECIDE, 'api.cert', section('ssl-certificate-names')
            action = 'Choose installed certificate filename only; guide default changes %s to %s. Copy custom files as root:wazuh-manager 0640; verify pair.' % default_names[key]
            validator = lambda x: bool(re.fullmatch('[A-Za-z0-9_.-]+', x)) and x not in ('.', '..')
        elif key in carried:
            cls, rule, s = CARRY, 'api.keep', section('upload_configuration') if key.startswith('upload_configuration') else section('ssl-certificate-names')
            action = 'Keep documented switch/cipher string; validate API schema in lab.'
            if key.endswith('.allow') or key in ('https.enabled', 'https.use_ca'):
                validator = lambda x: x.lower() in ('yes', 'no', 'true', 'false')
        elif key in ('remote_commands.localfile', 'remote_commands.wodle_command', 'limits.eps', 'upload_configuration.remote_commands.localfile', 'upload_configuration.remote_commands.wodle_command', 'upload_configuration.limits.eps'):
            cls, rule, s, action = DECIDE, 'api.ignored', section('upload_configuration'), 'Guide calls this suffix accepted-but-unread, but does not show the full nesting. Confirm the exact API schema path; omit the no-op after review.'
        base = CTX['base']
        if base is not None and base.api_schema is not None and cls in (UNKNOWN, CARRY, DECIDE) and rule not in ('api.cert',):
            why = base.api_check(path, value)
            if why == 'unknown':
                cls, rule, action = NONE, 'api.schema-unknown', "Not in 5.0's closed API schema: the API would refuse the whole file with error 2000. Not carried."
            elif why is None and rule == 'api.ignored':
                cls, rule, action = NONE, 'api.ignored-unread', 'Accepted by the 5.0 schema but read by no 5.0 code (guide): no effect, not carried.'
            elif why is None:
                if cls != CARRY:
                    cls, rule, action = CARRY, 'api.schema-carry', "In 5.0's API schema; 4.x value carried and checked against it."
            else:
                cls, rule, action = DECIDE, 'api.schema-refused', "5.0's API schema refuses this value (%s): replace or omit." % why
        if validator and cls == CARRY and not validator(value):
            cls = DECIDE
            action += ' Invalid documented value; replace or omit.'
        row = report.add(source, '/' + '/'.join(path), cls, s, action, value, rule, output=cls == CARRY)
        if cls in (DECIDE, UNKNOWN):
            decision = report.decide(row, value, validator)
            if not decision or decision[0] == 'omit':
                continue
            if decision[0] == 'replace':
                literal = json.dumps(decision[1]) if rule != 'api.keep' else decision[1].lower()
        elif cls != CARRY:
            continue
        current = result
        for part in path[:-1]:
            current = current.setdefault(part, {})
        current[path[-1]] = literal
    base = CTX['base']
    if base is not None and base.api is not None:
        base_text = base.api.decode('utf-8')
        base_keys = set(re.findall(r'^([A-Za-z_][A-Za-z0-9_-]*):', base_text, re.M))
        clash = sorted(set(result) & base_keys)
        if clash:
            raise InputError('4.x API settings collide with keys the 5.0 install set (%s); merge them in a working copy.' % ', '.join(clash))
        lines = [base_text.rstrip('\n'), '', '# Carried from 4.x by the migration tool.'] if result else [base_text.rstrip('\n')]
    else:
        lines = ['# Candidate API customizations; merge with the 5.0 template and validate.']
    def emit(mapping, depth=0):
        for key, value in mapping.items():
            lines.append('  ' * depth + key + ':' + ('' if isinstance(value, dict) else ' ' + value))
            if isinstance(value, dict):
                emit(value, depth + 1)
    emit(result)
    return ('\n'.join(lines) + '\n').encode()


def convert_cluster(data, report, source='cluster.json'):
    report.record_input(source, data)
    try:
        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError('duplicate')
                d[k] = v
            return d
        obj = json.loads(data, object_pairs_hook=unique)
        if not isinstance(obj, dict):
            raise ValueError('object required')
    except (ValueError, UnicodeDecodeError):
        report.add(source, '/$syntax', DECIDE, GUIDE + '#clusterjson', 'Invalid/duplicate JSON; normalize a working copy.', rule='cluster-json.syntax', option=False)
        return None
    patch = {}
    def walk(value, path):
        if isinstance(value, dict) and value:
            for key, item in value.items():
                walk(item, path + [key])
            return
        if isinstance(value, list) and value:
            for i, item in enumerate(value):
                walk(item, path + [str(i)])
            return
        s, cls, rule = GUIDE + '#clusterjson', UNKNOWN, 'cluster-json.unknown'
        action = 'Do not copy 4.x cluster.json. Use installed 5.0 defaults; owner must identify this customization.'
        stock, base = CTX['stock'], CTX['base']
        stock_value = stock.cluster_value(path) if stock is not None and stock.cluster is not None else KeyError
        if stock_value is not KeyError and stock_value == value:
            report.add(source, '/' + '/'.join(path), NONE, s, 'Stock 4.x default, not a customization; the installed 5.0 cluster.json applies.', str(value), 'cluster-json.stock')
            return
        if stock_value is not KeyError and len(path) == 3 and path[0] == 'intervals' and path[1] in ('master', 'worker', 'common', 'communication') \
                and path != ['intervals', 'worker', 'sync_agent_groups'] and isinstance(value, int) and not isinstance(value, bool):
            base_has = base is not None and base.cluster_json is not None and path[2] in base.cluster_json.get('intervals', {}).get(path[1], {})
            if base is None or base_has:
                val = value
                if path == ['intervals', 'master', 'metrics_frequency'] and 0 < val < 600:
                    val = 600
                report.add(source, '/' + '/'.join(path), CHANGE if val != value else CARRY, s,
                           'Customized 4.x interval (differs from the stock file); applied over the installed 5.0 value.' + (' Raised to 600, the 5.0 minimum.' if val != value else ''),
                           str(value), 'cluster-json.custom-interval', output=True)
                patch.setdefault('intervals', {}).setdefault(path[1], {})[path[2]] = val
                return
            report.add(source, '/' + '/'.join(path), NONE, s, 'Customized 4.x interval that 5.0 no longer reads; not carried.', str(value), 'cluster-json.unread')
            return
        if path == ['intervals', 'worker', 'sync_agent_groups']:
            cls, rule, s, action = NONE, 'cluster-json.worker', section('removed-worker-interval'), 'Remove; only master sync_agent_groups remains.'
        elif len(path) == 3 and path[0] == 'intervals' and path[1] in ('master', 'worker', 'common'):
            cls, rule = DECIDE, 'cluster-json.interval'
            action = 'Confirm this interval was customized and is supported; emit only an override for the installed 5.0 default. Metrics frequency 1..599 becomes 600.'
        elif path and path[0] in ('files', 'excluded_files', 'sync_options'):
            cls, rule, s = DROP, 'cluster-json.sync', section('files-synchronized-in-the-cluster')
            action = 'Discard old sync layout; replacement is installed 5.0 sync defaults (client.keys, authd.pass, enrollment_tokens.json, shared, merged.mg; exclude wazuh-manager.conf). Rules/decoders/lists use engine content management.'
        row = report.add(source, '/' + '/'.join(path), cls, s, action, str(value), rule)
        if cls in (DECIDE, UNKNOWN):
            decision = report.decide(row, str(value), lambda x: bool(re.fullmatch('[0-9]+', x)))
            if decision and decision[0] != 'omit':
                if rule != 'cluster-json.interval':
                    raise InputError('Only confirmed interval overrides may be emitted from cluster.json.')
                val = int(decision[1])
                if path == ['intervals', 'master', 'metrics_frequency'] and 0 < val < 600:
                    val = 600
                patch.setdefault('intervals', {}).setdefault(path[1], {})[path[2]] = val
    walk(obj, [])
    CTX['cluster_patch'] = patch
    return (json.dumps(patch, indent=2, sort_keys=True) + '\n').encode()


def c4_full_cluster_json():
    """The installed 5.0 cluster.json with the carried interval overrides applied."""
    base = CTX['base']
    if base is None or base.cluster_json is None:
        return None
    import copy
    full = copy.deepcopy(base.cluster_json)
    for group, values in CTX.get('cluster_patch', {}).get('intervals', {}).items():
        full.setdefault('intervals', {}).setdefault(group, {}).update(values)
    return (json.dumps(full, indent=4) + '\n').encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', help='4.x etc directory or one ossec.conf, api.yaml, internal options or cluster.json')
    for flag in ('ossec-conf', 'local-internal-options', 'internal-options', 'api-yaml', 'cluster-json'):
        parser.add_argument('--' + flag)
    parser.add_argument('--out', required=True, help='New output directory, separate from input')
    parser.add_argument('--decisions', help='JSON object keyed by report option id; see README.md')
    parser.add_argument('--base-5x', help='C4: directory with the installed 5.0 wazuh-manager.conf, wazuh-manager-internal-options.conf, api.yaml, cluster.json and wazuh-manager.schema.json; output is then complete files merged into them')
    parser.add_argument('--stock-4x', help='C4: directory with the stock 4.x ossec.conf, internal_options.conf and cluster.json of the same version and OS')
    parser.add_argument('--ranges', help='C4: 5.0 internal-option range table (tool/ranges-5.0.0.json)')
    args = parser.parse_args(argv)
    CTX.update(base=None, stock=None, ranges=None, standalone=False)
    CTX.pop('changes', None); CTX.pop('cluster_patch', None)
    try:
        if args.base_5x:
            CTX['base'] = c4_ext.Base(args.base_5x)
        if args.stock_4x:
            CTX['stock'] = c4_ext.Stock(args.stock_4x, parse_xml, internal_entries)
        if args.ranges:
            CTX['ranges'] = c4_ext.Ranges(args.ranges)
    except (OSError, ValueError, ET.ParseError) as exc:
        print('Conversion refused: cannot read a C4 reference input (%s).' % exc, file=sys.stderr)
        return 1
    try:
        paths = {}
        names = {'ossec.conf': 'ossec_conf', 'local_internal_options.conf': 'local_internal_options',
                 'internal_options.conf': 'internal_options', 'api.yaml': 'api_yaml', 'cluster.json': 'cluster_json'}
        etc = None
        if args.input:
            p = Path(args.input)
            if p.is_dir():
                etc = p
                for name, key in names.items():
                    candidate = p / name
                    if candidate.is_file():
                        paths[key] = candidate
                for key, candidate in [('api_yaml', p.parent / 'api/configuration/api.yaml'),
                                       ('cluster_json', p.parent / 'framework/wazuh/core/cluster/cluster.json')]:
                    if candidate.is_file() and key not in paths:
                        paths[key] = candidate
            else:
                if p.name not in names:
                    raise InputError('Unrecognized single input name; use an explicit input flag.')
                paths[names[p.name]] = p
        for key in names.values():
            value = getattr(args, key)
            if value:
                paths[key] = Path(value)
        group_paths = sorted((etc / 'shared').glob('*/agent.conf')) if etc else []
        if not paths and not group_paths:
            raise InputError('No supported input files found.')
        report = Report(load_decisions(args.decisions))
        files = {}
        for key, func, name in [('ossec_conf', convert_xml, 'wazuh-manager.conf'), ('api_yaml', convert_api, 'api.yaml'),
                                ('cluster_json', convert_cluster, 'cluster-values.json')]:
            if key in paths:
                converted = func(paths[key].read_bytes(), report, paths[key].name)
                if converted is not None:
                    files[name] = converted
        internals = [(paths[k].name, paths[k].read_bytes(), k == 'local_internal_options')
                     for k in ('internal_options', 'local_internal_options') if k in paths]
        if internals:
            files['wazuh-manager-internal-options.conf'] = convert_internal(internals, report)
        full_cluster = c4_full_cluster_json() if 'cluster_json' in paths else None
        if full_cluster is not None:
            files['cluster.json'] = full_cluster
        if CTX.get('changes'):
            files['changes-from-installed.json'] = (json.dumps({src: [{'option': '/'.join(t), 'installed': o, 'candidate': n} for t, o, n in ch]
                                                                for src, ch in CTX['changes'].items()}, indent=2) + '\n').encode()
        if group_paths:
            from clean_agent_conf import clean
            for p in group_paths:
                rel = p.relative_to(etc).as_posix()
                converted = clean(p.read_bytes(), report, rel)
                if converted is not None:
                    files[rel] = converted
        files.update(report.files())
        inputs = list(paths.values()) + group_paths + ([etc] if etc else []) + ([args.decisions] if args.decisions else [])
        write_run(args.out, files, inputs)
        print('Wrote candidate files and masked reports to ' + str(args.out))
        return 2 if any(not r['resolved'] for r in report.rows) else 0
    except (InputError, OSError, UnicodeDecodeError) as exc:
        print('Conversion refused: ' + (str(exc) if isinstance(exc, InputError) else 'cannot read/write input or output; check paths and encoding.'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
