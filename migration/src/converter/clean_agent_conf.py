#!/usr/bin/env python3
"""Remove documented 5.0 agent no-ops from a group agent.conf, preserving all other bytes."""
import argparse
from pathlib import Path
import re
import sys

from migration_common import (CARRY, DROP, NONE, DECIDE, UNKNOWN, GROUPS, UPGRADE, InputError,
                              Report, load_decisions, options, parse_xml, write_run)

TOP_REMOVED = set('labels client_buffer integration email_alerts reports syslog_output agentless database_output alerts command ruleset rule_test agent-key-polling fluent-forward'.split())
SYSCHECK_REMOVED = set('scan_on_start alert_new_files auto_ignore database prefilter_cmd allow_remote_prefilter_cmd remove_old_diff'.split())
SYNC_REMOVED = set('max_eps max_interval response_timeout queue_size registry_enabled thread_pool'.split())
ENROLLMENT_REMOVED = set('auto_method manager_address port interface_index ssl_cipher server_ca_path agent_certificate_path agent_key_path'.split())
# These are evidenced examples in the supplied guides/transcripts, not a complete agent schema.
KNOWN_LEAVES = {
    ('localfile', 'log_format'), ('localfile', 'location'), ('localfile', 'label'),
    ('syscheck', 'directories'), ('syscheck', 'frequency'), ('sca', 'policies', 'policy'),
    ('sca', 'interval'), ('wodle', 'disabled'), ('wodle', 'interval'), ('wodle', 'run_on_start'),
}
KNOWN_ATTRS = {('agent_config', 'os'), ('agent_config', 'name'), ('agent_config', 'profile'),
               ('directories', 'check_all'), ('directories', 'realtime'), ('label', 'key'), ('wodle', 'name')}


# two passes. `pre-upgrade` runs while any agent of the group is 4.x (phase 6): it removes only what makes a
# 4.x agent refuse its whole shared configuration (syscheck prefilter_cmd) or what the 5.0 API refuses (a label
# key starting with "_"), and keeps every option a 4.x agent still applies, such as <client_buffer> (removing it
# shrank a 4.x agent's buffer from 20000 to 5000, E1). `post-upgrade` (phase 11, every agent of the group on 5.0)
# is C1's full clean.
PRE_UPGRADE_REMOVED = {('syscheck', 'prefilter_cmd')}
# Rootcheck/SCA options whose value names a file the agent reads from its etc/shared/ (shared\ on Windows).
FILE_REFERENCES = {('rootcheck', 'system_audit'), ('rootcheck', 'rootkit_files'), ('rootcheck', 'rootkit_trojans'),
                   ('rootcheck', 'windows_audit'), ('rootcheck', 'windows_apps'), ('rootcheck', 'windows_malware'),
                   ('sca', 'policies', 'policy')}
PHASE = {'value': 'post-upgrade'}


def pre_upgrade_removal(node, tags):
    if tuple(tags) in PRE_UPGRADE_REMOVED:
        return NONE, UPGRADE, 'Remove now: a 4.x agent refuses its whole shared configuration when a group file sets it, and 5.0 ignores it.', 'agent.pre-upgrade-remove'
    if node.tag == 'label' and node.attrs.get('key', '').startswith('_'):
        return NONE, GROUPS, 'Remove now: the 5.0 API refuses a reserved label key.', 'agent.invalid-label'
    return None


def referenced_file(value):
    """The file name a rootcheck/SCA option reads from the agent's shared folder, or None."""
    m = re.fullmatch(r'(?:\./|etc/)?shared[/\\]([^/\\]+)', (value or '').strip())
    return m.group(1) if m else None


def removal(node, tags, wodle):
    if PHASE['value'] == 'pre-upgrade':
        return pre_upgrade_removal(node, tags)
    if len(tags) == 1 and tags[0] in TOP_REMOVED:
        repl = {'client_buffer': 'agent/batch; choose batching settings separately',
                'integration': 'notifications plugin; rmig checklist',
                'email_alerts': 'mail-forwarding-reporting.md; rmig checklist',
                'reports': 'mail-forwarding-reporting.md; rmig checklist',
                'syslog_output': 'remote-syslog-output.md',
                'agentless': 'agentless-4x-to-5x.md',
                'ruleset': 'engine content management; rmig',
                'command': '5.0 Active Response definitions'}
        if tags[0] in repl:
            return DROP, GROUPS, 'Remove ignored block; replacement: ' + repl[tags[0]] + '.', 'agent.top-remove'
        return NONE, GROUPS, 'Remove ignored block; no direct replacement. For labels, review group membership (wazuh.agent.groups) as an alternative event key.', 'agent.top-remove'
    if tags[:1] == ['localfile'] and len(tags) == 2:
        if node.tag == 'labels' or (node.tag == 'label' and node.attrs.get('key', '').startswith('_')):
            return NONE, GROUPS, 'Remove rejected labels wrapper/reserved label key; review required event enrichment separately.', 'agent.invalid-label'
    if len(tags) == 2 and tags[0] == 'syscheck' and tags[1] in SYSCHECK_REMOVED:
        return NONE, UPGRADE, 'Remove ignored FIM option; scan always runs on start.', 'agent.syscheck-remove'
    if tags[:2] == ['syscheck', 'synchronization'] and len(tags) == 3 and tags[2] in SYNC_REMOVED:
        return NONE, UPGRADE, 'Remove ignored synchronization option.', 'agent.sync-remove'
    if len(tags) == 2 and tags[0] == 'sca' and tags[1] in ('day', 'wday', 'time', 'skip_nfs'):
        return NONE, UPGRADE, 'Remove ignored option; SCA uses interval.', 'agent.sca-remove'
    if len(tags) == 2 and tags[0] == 'rootcheck' and tags[1] in ('check_files', 'check_trojans', 'rootkit_files'):
        repl = tags[1] != 'rootkit_files'
        return DROP if repl else NONE, UPGRADE, 'Remove; use FIM (syscheck) controls.' if repl else 'Remove unsupported rootkit_files.', 'agent.rootcheck-remove'
    if len(tags) == 1 and node.tag == 'wodle' and wodle in ('cis-cat', 'osquery'):
        return DROP, UPGRADE, 'Remove ignored module; migrate functionality to ' + ('SCA' if wodle == 'cis-cat' else 'IT Hygiene / Syscollector') + ' before distribution.', 'agent.wodle-remove'
    if wodle == 'syscollector' and tags == ['wodle', 'synchronization', 'max_eps']:
        return NONE, UPGRADE, 'Remove ignored syscollector synchronization max_eps.', 'agent.syscollector-remove'
    if tags == ['agent', 'ip_update_interval'] or tags == ['client', 'ip_update_interval']:
        return NONE, UPGRADE, 'Remove ignored ip_update_interval.', 'agent.connection-remove'
    if tags[:-1] in (['client', 'enrollment'], ['agent', 'enrollment'], ['enrollment']) and tags[-1] in ENROLLMENT_REMOVED:
        return NONE, UPGRADE, 'Remove ignored enrollment option; 5.0 uses agent/manager and agent/ssl.', 'agent.enrollment-remove'
    return None


CARRY_FILES = {}


def clean(data, report, source='agent.conf'):
    if isinstance(data, str):
        data = data.encode('utf-8')
    report.record_input(source, data)
    try:
        roots = parse_xml(data)
    except InputError as exc:
        report.add(source, '/$syntax', DECIDE, GROUPS, str(exc), rule='agent.syntax', option=False)
        return None
    if any(root.tag != 'agent_config' for root in roots):
        for root in roots:
            report.subtree(source, root, UNKNOWN, GROUPS, 'Expected agent_config roots; no output produced.', 'agent.root')
        return None
    cuts = []

    def visit(node, tags, wodle='', held=False):
        if node.tag == 'wodle':
            wodle = node.attrs.get('name', '')
        rule = removal(node, tags, wodle)
        if rule:
            cls, guide, action, name = rule
            report.subtree(source, node, cls, guide, action, name)
            cuts.append((node.start, node.end))
            return
        client = bool(tags and tags[0] == 'client') and PHASE['value'] != 'pre-upgrade'
        if tags == ['client'] and node.children and PHASE['value'] != 'pre-upgrade':
            row = report.add(source, node.path + '/$centralized-support', DECIDE, GROUPS,
                             'A group client block may be rejected even when its ignored options are removed. Validate centralized support or remove it in a reviewed working copy.',
                             rule='agent.client', option=False)
            report.decide(row, 'confirmed', lambda x: x == 'confirmed')
        for attr, value in node.attrs.items():
            cls = CARRY if (node.tag, attr) in KNOWN_ATTRS or PHASE['value'] == 'pre-upgrade' else UNKNOWN
            row = report.add(source, node.path + '/@' + attr, cls, GROUPS,
                       'Preserved byte for byte; validate selection/attribute on target agents.' if cls == CARRY else
                       'Unspecified attribute preserved byte for byte; check target agent schema.', value, 'agent.attribute', output=True)
            if cls == UNKNOWN:
                choice = report.decide(row, value)
                if choice and choice[0] != 'keep':
                    raise InputError('Unknown agent attributes support keep acknowledgement only; review a working copy to remove or change them.')
        if (not node.children or node.text) and tuple(tags) in FILE_REFERENCES and referenced_file(node.text) \
                and (PHASE['value'] == 'pre-upgrade' or tags[0] == 'rootcheck'):
            name = referenced_file(node.text)
            held_files = CARRY_FILES.get('available')
            if PHASE['value'] == 'pre-upgrade' and held_files is not None and name in held_files:
                CARRY_FILES.setdefault('carry', set()).add(name)
                report.add(source, node.path, CARRY, GROUPS, 'References %s in the group folder: kept, and the file is carried into the 5.0 group folder so 4.x agents still find it.' % name,
                           node.text, 'agent.file-carried', output=True)
            elif PHASE['value'] == 'pre-upgrade' and held_files is not None:
                report.add(source, node.path, CARRY, GROUPS, 'References %s, which the 4.x group folder did not hold either: kept as it was.' % name,
                           node.text, 'agent.file-missing-before', output=True)
            elif PHASE['value'] == 'post-upgrade' and tags[0] == 'rootcheck':
                report.add(source, node.path, NONE, UPGRADE, 'Remove: a rootcheck file a 5.0 agent never reads; delete the carried file from the 5.0 group folder too.',
                           node.text, 'agent.file-reference-remove')
                cuts.append((node.start, node.end))
                CARRY_FILES.setdefault('delete', set()).add(name)
            else:
                report.add(source, node.path, CARRY, GROUPS, 'References %s; keep the file in the group folder.' % name, node.text, 'agent.file-reference', output=True)
            return
        if not node.children or node.text:
            if tags == ['syscheck', 'restart_audit']:
                cls, action, name = DECIDE, 'Still applied but deprecated; choose syscheck/whodata/restart_audit, respecting existing precedence.', 'agent.restart-audit'
            elif client:
                cls, action, name = DECIDE, 'Group client content may be rejected; verify centralized-configuration support. Do not rewrite manager addresses automatically.', 'agent.client'
            elif PHASE['value'] == 'pre-upgrade' and tags:
                cls, action, name = CARRY, 'Kept until every agent of the group runs 5.0: the 4.x agents accept and apply their group file as it was. The post-upgrade pass decides it.', 'agent.kept-until-upgrade'
            elif tuple(tags) in KNOWN_LEAVES and (tags[0] != 'wodle' or wodle in ('syscollector', 'docker-listener')):
                cls, action, name = CARRY, 'Preserve exact bytes; this is an evidenced surviving setting, not a full schema check.', 'agent.keep'
            elif not tags and not node.text:
                cls, action, name = CARRY, 'Keep empty agent_config wrapper.', 'agent.keep'
            else:
                cls, action, name = UNKNOWN, 'Unspecified option preserved byte for byte; verify against target agent schema. Unknowns can be fatal.', 'agent.unknown'
            row = report.add(source, node.path, cls, UPGRADE if name == 'agent.restart-audit' else GROUPS,
                             action, node.text, name, output=True)
            if cls in (DECIDE, UNKNOWN):
                decision = report.decide(row, node.text)
                if decision:
                    if decision[0] == 'replace':
                        raise InputError('Agent cleaner supports keep/omit decisions only; edit values in a separate reviewed copy.')
                    if decision[0] == 'omit':
                        cuts.append((node.start, node.end))
        for child in node.children:
            visit(child, tags + [child.tag], wodle, held)
    for root in roots:
        visit(root, [])
    # Only element spans are removed, including their contents, never surrounding whitespace.
    result, last = [], 0
    for start, end in sorted(cuts):
        if start < last:
            continue
        result.append(data[last:start])
        last = end
    result.append(data[last:])
    return b''.join(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Group agent.conf')
    parser.add_argument('--out', required=True, help='New output directory')
    parser.add_argument('--decisions', help='JSON keep/omit decisions keyed by report option id')
    parser.add_argument('--phase', choices=('pre-upgrade', 'post-upgrade'), default='post-upgrade',
                        help='pre-upgrade while any agent of the group is 4.x (phase 6); post-upgrade once all run 5.0 (phase 11)')
    parser.add_argument('--group-dir', help='the 4.x group folder; referenced files it holds are carried (pre-upgrade)')
    parser.add_argument('--default-group', action='store_true', help='this is the default group: carry its stock rootcheck *.txt files for 4.x agents (pre-upgrade) or list them for deletion (post-upgrade)')
    args = parser.parse_args(argv)
    try:
        PHASE['value'] = args.phase
        CARRY_FILES.clear()
        gdir = Path(args.group_dir) if args.group_dir else None
        if gdir is not None:
            CARRY_FILES['available'] = {p.name for p in gdir.iterdir() if p.is_file() and p.name not in ('agent.conf', 'merged.mg', 'ar.conf')}
        report = Report(load_decisions(args.decisions))
        converted = clean(Path(args.input).read_bytes(), report)
        if args.default_group and gdir is not None:
            stock_txt = sorted(n for n in CARRY_FILES.get('available', ()) if n.endswith('.txt'))
            if args.phase == 'pre-upgrade':
                CARRY_FILES.setdefault('carry', set()).update(stock_txt)
            else:
                CARRY_FILES.setdefault('delete', set()).update(stock_txt)
        files = report.files()
        if converted is not None:
            files['agent.conf'] = converted
        for name in sorted(CARRY_FILES.get('carry', ())):
            files['carry/' + name] = (gdir / name).read_bytes()
        if CARRY_FILES.get('delete'):
            files['delete-from-group.txt'] = ('\n'.join(sorted(CARRY_FILES['delete'])) + '\n').encode()
        write_run(args.out, files, [args.input] + ([args.decisions] if args.decisions else []))
        print('Wrote candidate and masked reports to ' + str(args.out))
        return 2 if any(not r['resolved'] for r in report.rows) else 0
    except (InputError, OSError, UnicodeDecodeError) as exc:
        print('Conversion refused: ' + (str(exc) if isinstance(exc, InputError) else 'check paths and UTF-8 encoding.'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
