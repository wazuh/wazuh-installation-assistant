import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

from migration_common import (CARRY, CHANGE, DROP, NONE, DECIDE, UNKNOWN, InputError, Report,
                              options, parse_xml, write_run)
import convert_manager_conf as manager
import clean_agent_conf as agent

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def wrap(body):
    return ('<ossec_config>' + body + '</ossec_config>').encode()


def group(body):
    return ('<agent_config>' + body + '</agent_config>').encode()


def row_at(report, suffix):
    return next(r for r in report.rows if r['option'].endswith(suffix))


class ManagerTests(unittest.TestCase):
    def convert(self, body):
        r = Report()
        data = manager.convert_xml(wrap(body), r)
        return ET.fromstring(data) if data else None, r

    def test_root_merges_siblings(self):
        r = Report()
        out = manager.convert_xml(wrap('<global><agents_disconnection_time>15m</agents_disconnection_time></global>') + wrap('<remote><port>1514</port></remote>'), r)
        e = ET.fromstring(out)
        self.assertEqual(e.tag, 'wazuh_config')
        self.assertEqual(e.findtext('remote/legacy/port'), '1514')
        self.assertEqual(len(e.findall('global')), 1)

    def test_global_whitelist_does_not_duplicate_global(self):
        # C4: a loopback entry needs nothing (5.0 protects loopback); any other entry still points to the allowlist.
        e, r = self.convert('<global><agents_disconnection_time>15m</agents_disconnection_time></global><global><white_list>127.0.0.1</white_list><white_list>192.0.2.9</white_list></global>')
        self.assertEqual(len(e.findall('global')), 1)
        self.assertEqual(row_at(r, 'white_list[1]')['classification'], NONE)
        self.assertIn('allowlist', row_at(r, 'white_list[2]')['action'])

    def test_global_unknown_never_silently_dropped(self):
        e, r = self.convert('<global><surprise>top-secret</surprise></global>')
        row = row_at(r, 'surprise[1]')
        self.assertEqual(row['classification'], UNKNOWN)
        self.assertFalse(row['resolved'])
        self.assertIsNone(e.find('global/surprise'))
        self.assertIn(row['id'], json.loads(r.files()['decisions.required.json']))

    def test_accepted_but_unspecified_sections(self):
        for section in ('logging', 'wdb', 'task-manager', 'auth'):
            with self.subTest(section=section):
                e, r = self.convert('<%s><unlisted>v</unlisted></%s>' % (section, section))
                self.assertEqual(row_at(r, 'unlisted[1]')['classification'], UNKNOWN)
                self.assertIsNone(e.find(section))

    def test_arbitrary_top_unknown_is_reported(self):
        e, r = self.convert('<invented><key>secret</key></invented>')
        self.assertEqual(row_at(r, 'key[1]')['classification'], UNKNOWN)
        self.assertIsNone(e.find('invented'))

    def test_vars_removed_and_uses_held(self):
        e, r = self.convert('<var name="port">1514</var><remote><port>$port</port></remote>')
        self.assertIsNone(e.find('var'))
        self.assertEqual(row_at(r, 'port[1]')['classification'], DECIDE)

    def test_malformed_xml_refused(self):
        for data in (b'', wrap('<global><foo>a&b</foo></global>'), wrap('<! legacy !>'), wrap('<!-- a -- b -->'),
                     b'<!DOCTYPE ossec_config [<!ENTITY x "DTD-SENSITIVE-VALUE">]><ossec_config>&x;</ossec_config>'):
            with self.subTest(data=data):
                r = Report()
                self.assertIsNone(manager.convert_xml(data, r))
                self.assertEqual(r.rows[0]['rule'], 'xml.syntax')
                self.assertNotIn('DTD-SENSITIVE-VALUE', r.files()['report.md'].decode())

    def test_duplicate_section_refused(self):
        e, r = self.convert('<remote><port>1514</port></remote><remote><port>1515</port></remote>')
        self.assertIsNone(e)
        self.assertEqual(sum(x['rule'] == 'xml.duplicate' for x in r.rows), 2)

    def test_duplicate_child_held(self):
        e, r = self.convert('<remote><port>1514</port><port>1515</port></remote>')
        self.assertIsNone(e.find('remote'))
        self.assertEqual(sum(x['rule'] == 'xml.duplicate' for x in r.rows), 2)

    def test_entity_value_needs_decision(self):
        e, r = self.convert('<cluster><name>a&amp;b</name></cluster>')
        self.assertEqual(row_at(r, 'name[1]')['classification'], DECIDE)
        self.assertIsNone(e.find('cluster/name'))

    def test_remote_absent_local_ip_not_invented(self):
        e, r = self.convert('<remote><port>1514</port></remote>')
        self.assertIsNone(e.find('remote/legacy/local_ip'))

    def test_remote_agents_unchanged_but_not_enumerated(self):
        e, r = self.convert('<remote><agents><allow_higher_versions>yes</allow_higher_versions></agents></remote>')
        self.assertEqual(row_at(r, 'allow_higher_versions[1]')['classification'], DECIDE)

    def test_auth_ciphers_legacy_and_tls13(self):
        for cipher, cls in [('HIGH:!MD5', DECIDE), ('TLS_UNKNOWN', DECIDE), ('TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256', CARRY)]:
            e, r = self.convert('<auth><ciphers>%s</ciphers></auth>' % cipher)
            self.assertEqual(row_at(r, 'ciphers[1]')['classification'], cls)

    def test_cert_choices_not_guessed(self):
        body = '<auth><ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert><ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key></auth><indexer><ssl><certificate_authorities><ca>/etc/filebeat/certs/root-ca.pem</ca></certificate_authorities><certificate>old.pem</certificate><key>old-key.pem</key></ssl></indexer>'
        e, r = self.convert(body)
        self.assertEqual(sum(x['classification'] == DECIDE and x['input_option'] for x in r.rows), 5)
        self.assertIsNone(e.find('auth'))
        self.assertIsNone(e.find('indexer'))

    def test_vulnerability_zero_units_rejected(self):
        for val in ('0', '0s', '0m', '0h', '0d', '0w', '-1', '1234567890s', '60m'):
            e, r = self.convert('<vulnerability-detection><feed-update-interval>%s</feed-update-interval></vulnerability-detection>' % val)
            self.assertEqual(row_at(r, 'feed-update-interval[1]')['classification'], CARRY if val == '60m' else DECIDE)

    def test_duration_boundaries(self):
        for val in ('999999999s', '9999999m', '99999h', '9999d', '999w'):
            self.assertTrue(manager.valid_duration(val, 1), val)
        for val in ('1000000000s', '10000000m', '100000h', '10000d', '1000w', '٠s', '1K'):
            self.assertFalse(manager.valid_duration(val, 1), val)

    def test_indexer_host_urls(self):
        for value, valid in [('https://127.0.0.1:9200', True), ('https://[::1]:9200', True), ('http://indexer', True), ('ftp://a', False), ('https://', False), ('https://u:p@h', False)]:
            e, r = self.convert('<indexer><hosts><host>%s</host></hosts></indexer>' % value)
            self.assertEqual(row_at(r, 'host[1]')['classification'], CARRY if valid else DECIDE)

    def test_multiple_indexer_hosts_and_cas(self):
        e, r = self.convert('<indexer><hosts><host>https://a</host><host>https://b</host></hosts></indexer>')
        self.assertEqual(len(e.findall('indexer/hosts/host')), 2)
        self.assertFalse(any(x['rule'] == 'xml.duplicate' for x in r.rows))

    def test_cluster_key_required_and_masked(self):
        for value, valid in [('', False), ('bad', False), ('a' * 32, True), ('_' * 32, False)]:
            e, r = self.convert('<cluster><key>%s</key></cluster>' % value)
            # C4: the 4.x key is never carried, valid or not: without the installed 5.0 file it is a question.
            self.assertEqual(row_at(r, 'key[1]')['classification'], DECIDE)
            self.assertNotIn('a' * 32, r.files()['report.md'].decode())

    def test_cluster_standalone_topology_needs_confirmation(self):
        e, r = self.convert('<cluster><disabled>yes</disabled><node_type>master</node_type></cluster>')
        self.assertIsNone(e.find('cluster/disabled'))
        self.assertTrue(any(x['rule'] == 'cluster.standalone' and not x['resolved'] for x in r.rows))

    def test_cluster_missing_addresses_are_questions(self):
        e, r = self.convert('<cluster><disabled>no</disabled><key>%s</key></cluster>' % ('a' * 32))
        self.assertEqual(sum(x['rule'] == 'cluster.missing-address' for x in r.rows), 2)

    def test_required_values_can_be_supplied(self):
        decisions = {'ossec.conf:/$required/cluster/key': {'action': 'replace', 'value': 'a' * 32, 'reason': 'lab key'},
                     'ossec.conf:/$required/indexer/hosts': {'action': 'replace', 'value': 'https://indexer:9200', 'reason': 'lab host'}}
        r = Report(decisions)
        out = ET.fromstring(manager.convert_xml(wrap(''), r))
        self.assertEqual(out.findtext('cluster/key'), 'a' * 32)
        self.assertEqual(out.findtext('indexer/hosts/host'), 'https://indexer:9200')
        r.payload()

    def test_unknown_decision_is_explicit_and_masked(self):
        source = wrap('<logging><custom>PRIVATE-OPTION-VALUE</custom></logging>')
        r = Report()
        manager.convert_xml(source, r)
        ident = row_at(r, 'custom[1]')['id']
        decisions = {ident: {'action': 'keep', 'reason': 'PRIVATE-REASON'}}
        r = Report(decisions)
        e = ET.fromstring(manager.convert_xml(source, r))
        self.assertEqual(e.findtext('logging/custom'), 'PRIVATE-OPTION-VALUE')
        row = row_at(r, 'custom[1]')
        self.assertTrue(row['resolved'])
        self.assertFalse(row['automatic'])
        self.assertEqual(row['classification'], UNKNOWN)
        for data in r.files().values():
            self.assertNotIn(b'PRIVATE-OPTION-VALUE', data)
            self.assertNotIn(b'PRIVATE-REASON', data)

    def test_decision_constraint_and_stale_id(self):
        ident = 'ossec.conf:/ossec_config[1]/auth[1]/ciphers[1]'
        r = Report({ident: {'action': 'replace', 'value': 'TLS_BOGUS', 'reason': 'chosen'}})
        with self.assertRaises(InputError):
            manager.convert_xml(wrap('<auth><ciphers>HIGH</ciphers></auth>'), r)
        with self.assertRaises(InputError):
            Report({'stale': {'action': 'keep', 'reason': 'x'}}).files()

    def test_unknown_attributes_reported(self):
        e, r = self.convert('<cluster><name special="secret">n</name></cluster>')
        self.assertEqual(row_at(r, '/@special')['classification'], UNKNOWN)
        self.assertNotIn('special', e.find('cluster/name').attrib)


class InternalTests(unittest.TestCase):
    def test_local_priority(self):
        r = Report()
        out = manager.convert_internal([('internal_options.conf', b'analysisd.debug=0\n', False), ('local_internal_options.conf', b'analysisd.debug=2\n', True)], r)
        self.assertIn(b'analysisd.debug=2\n', out)
        self.assertNotIn(b'analysisd.debug=0', out)
        self.assertEqual(r.rows[0]['rule'], 'internal.precedence')

    def test_system_defaults_require_customization_proof(self):
        r = Report()
        out = manager.convert_internal([('internal_options.conf', b'monitord.rotate_log=1\n', False)], r)
        self.assertNotIn(b'=', out)
        self.assertEqual(r.rows[0]['classification'], DECIDE)

    def test_remoted_unenumerated_is_held(self):
        r = Report()
        manager.convert_internal([('local_internal_options.conf', b'remoted.arbitrary=999\n', True)], r)
        self.assertEqual(r.rows[0]['classification'], DECIDE)

    def test_invalid_debug_and_duplicate_are_held(self):
        for data in (b'analysisd.debug=3', b'analysisd.debug=1\nanalysisd.debug=2', b'not-an-assignment'):
            r = Report()
            out = manager.convert_internal([('local_internal_options.conf', data, True)], r)
            self.assertNotIn(b'=', out)
            self.assertTrue(all(not x['resolved'] for x in r.rows))


class APITests(unittest.TestCase):
    def test_removed_keys_and_nested_integrations(self):
        r = Report()
        data = b'https:\n  ssl_protocol: auto\nexperimental_features: yes\ndrop_privileges: yes\nupload_configuration:\n  integrations:\n    virustotal:\n      public_key:\n        allow: yes\n        minimum_quota: 240\n'
        out = manager.convert_api(data, r)
        self.assertEqual(len(r.rows), 5)
        self.assertTrue(all(x['classification'] == NONE for x in r.rows))
        self.assertNotIn(b'ssl_protocol', out)
        self.assertNotIn(b'virustotal', out)

    def test_documented_keep_options(self):
        r = Report()
        out = manager.convert_api(b'https:\n  enabled: yes\n  use_ca: False\n  ssl_ciphers: ""\nupload_configuration:\n  agents:\n    allow_higher_versions:\n      allow: no\n  indexer:\n    allow: yes\n', r)
        self.assertEqual(len(r.rows), 5)
        self.assertTrue(all(x['classification'] == CARRY for x in r.rows))
        self.assertIn(b'allow: no', out)

    def test_ssl_names_require_decision_and_filename_only(self):
        r = Report()
        # C4: the 4.x default names are replaced by the 5.0 defaults with no question; custom names still ask.
        out = manager.convert_api(b'https:\n  key: server.key\n  cert: server.crt\n  ca: ca.crt\n', r)
        self.assertTrue(all(x['classification'] == NONE for x in r.rows))
        r = Report()
        manager.convert_api(b'https:\n  key: custom.key\n', r)
        self.assertEqual(r.rows[0]['classification'], DECIDE)
        ident = r.rows[0]['id']
        r = Report({ident: {'action': 'replace', 'value': '/tmp/key.pem', 'reason': 'invalid'}})
        with self.assertRaises(InputError):
            manager.convert_api(b'https:\n  key: custom.key\n', r)
        r = Report({ident: {'action': 'replace', 'value': 'apid-key.pem', 'reason': 'installed'}})
        self.assertIn(b'"apid-key.pem"', manager.convert_api(b'https:\n  key: custom.key\n', r))

    def test_ignored_options_both_ambiguous_nestings(self):
        for prefix in ('', 'upload_configuration:\n'):
            indent = '  ' if prefix else ''
            data = prefix + indent + 'remote_commands:\n' + indent + '  localfile: yes\n' + indent + '  wodle_command: yes\n' + indent + 'limits:\n' + indent + '  eps: 100\n'
            r = Report()
            manager.convert_api(data.encode(), r)
            self.assertEqual(len(r.rows), 3)
            self.assertTrue(all(x['classification'] == DECIDE for x in r.rows))

    def test_unknown_api_key_is_not_silently_dropped(self):
        r = Report()
        out = manager.convert_api(b'host: secret\n', r)
        self.assertNotIn(b'host:', out)
        self.assertEqual(r.rows[0]['classification'], UNKNOWN)
        self.assertNotIn(b'secret', r.files()['report.json'])

    def test_yaml_complex_syntax_refused(self):
        for data in (b'a: [x, y]', b'a: &ref yes', b'a: |\n  secret', b'a:\n\tkey: x', b'a: x\na: y', b'a:\n  - list', b'a: "unterminated', b'a: {x: y}', b'  a: yes'):
            r = Report()
            self.assertIsNone(manager.convert_api(data, r), data)
            self.assertEqual(r.rows[0]['rule'], 'api.syntax')

    def test_commented_api_template_is_inert(self):
        r = Report()
        out = manager.convert_api(b'# https:\n#   key: server.key\n', r)
        self.assertEqual(r.rows, [])
        self.assertNotIn(b'key:', out)

    def test_hash_inside_quoted_scalar(self):
        r = Report()
        out = manager.convert_api(b'https:\n  ssl_ciphers: "a#b" # comment\n', r)
        self.assertIn(b'"a#b"', out)


class ClusterJSONTests(unittest.TestCase):
    def test_patch_only_after_customization_decision(self):
        data = json.dumps({'intervals': {'master': {'metrics_frequency': 5}, 'worker': {'sync_agent_groups': 3}}, 'files': {'etc/rules/': {'excluded_files': ['ar.conf', 'ossec.conf']}}}).encode()
        r = Report()
        self.assertEqual(json.loads(manager.convert_cluster(data, r)), {})
        self.assertEqual(row_at(r, '/worker/sync_agent_groups')['classification'], NONE)
        self.assertEqual(row_at(r, '/excluded_files/0')['classification'], DROP)
        ident = row_at(r, '/master/metrics_frequency')['id']
        r = Report({ident: {'action': 'keep', 'reason': 'customized and supported'}})
        self.assertEqual(json.loads(manager.convert_cluster(data, r)), {'intervals': {'master': {'metrics_frequency': 600}}})

    def test_all_new_defaults_not_invented_as_4x_customizations(self):
        values = {'intervals': {'master': manager.MASTER_DEFAULTS, 'common': manager.COMMON_DEFAULTS}}
        r = Report()
        patch = json.loads(manager.convert_cluster(json.dumps(values).encode(), r))
        self.assertEqual(patch, {})
        self.assertEqual(len(r.rows), 9)
        self.assertTrue(all(x['classification'] == DECIDE for x in r.rows))

    def test_unknown_cluster_option_reported(self):
        r = Report()
        self.assertEqual(json.loads(manager.convert_cluster(b'{"future":"secret"}', r)), {})
        self.assertEqual(r.rows[0]['classification'], UNKNOWN)

    def test_invalid_or_duplicate_json_refused(self):
        for data in (b'[]', b'{"x":1,"x":2}', b'bad'):
            r = Report()
            self.assertIsNone(manager.convert_cluster(data, r))
            self.assertEqual(r.rows[0]['rule'], 'cluster-json.syntax')


class AgentTests(unittest.TestCase):
    def test_other_bytes_exact_with_bom_crlf_comments_and_unicode(self):
        data = '\ufeff<!-- café -->\r\n<agent_config os="Linux">\r\n <labels><label key="site">x</label></labels>\r\n <localfile><location>café.log</location><log_format>syslog</log_format></localfile>\r\n</agent_config>\r\n'.encode()
        r = Report()
        out = agent.clean(data, r)
        removed = b'<labels><label key="site">x</label></labels>'
        self.assertEqual(out, data.replace(removed, b''))

    def test_mixed_wrappers_multiple_roots_and_selfclosing(self):
        data = b'<agent_config><labels/><localfile><label key="fine">x</label><location>x</location></localfile></agent_config>\n<agent_config os="Windows"><client_buffer /></agent_config>'
        self.assertEqual(agent.clean(data, Report()), data.replace(b'<labels/>', b'').replace(b'<client_buffer />', b''))

    def test_label_wrapper_and_reserved_keys_removed_only_at_localfile(self):
        data = group('<localfile><labels><label key="x">y</label></labels><label key="_reserved">s</label><label key="normal">v</label></localfile><syscheck><label key="_keep">v</label></syscheck>')
        out = agent.clean(data, Report())
        self.assertNotIn(b'<labels>', out)
        self.assertNotIn(b'_reserved', out)
        self.assertIn(b'key="normal"', out)
        self.assertIn(b'_keep', out)

    def test_unknown_agent_option_retained_and_flagged(self):
        data = group('<mystery private="secret">hidden</mystery>')
        r = Report()
        self.assertEqual(agent.clean(data, r), data)
        self.assertTrue(all(x['classification'] == UNKNOWN for x in r.rows))
        self.assertTrue(all(not x['resolved'] for x in r.rows))
        self.assertNotIn(b'hidden', r.files()['report.json'])
        self.assertNotIn(b'secret', r.files()['report.json'])

    def test_client_and_restart_audit_flagged_without_rewriting(self):
        data = group('<client><server><address>host</address></server><notify_time>10</notify_time></client><syscheck><restart_audit>yes</restart_audit></syscheck>')
        r = Report()
        self.assertEqual(agent.clean(data, r), data)
        self.assertTrue(all(x['classification'] == DECIDE for x in r.rows))

    def test_agent_decision_omit_or_keep(self):
        data = group('<future>x</future>')
        r = Report()
        agent.clean(data, r)
        ident = r.rows[0]['id']
        r = Report({ident: {'action': 'omit', 'reason': 'unsupported'}})
        self.assertEqual(agent.clean(data, r), group(''))
        r.files()
        r = Report({ident: {'action': 'keep', 'reason': 'target schema checked'}})
        self.assertEqual(agent.clean(data, r), data)
        r.files()
        r = Report({ident: {'action': 'replace', 'value': 'y', 'reason': 'not a block removal'}})
        with self.assertRaises(InputError):
            agent.clean(data, r)

    def test_bad_group_root_or_syntax(self):
        for data in (b'<ossec_config/>', b'<agent_config><x>a&b</x></agent_config>', b''):
            self.assertIsNone(agent.clean(data, Report()))

    def test_scope_of_removed_names(self):
        data = group('<syscheck><scan_on_start>yes</scan_on_start><future><scan_on_start>keep</scan_on_start></future></syscheck><localfile><scan_on_start>keep</scan_on_start></localfile>')
        out = agent.clean(data, Report())
        self.assertEqual(out.count(b'<scan_on_start>'), 2)


class SafetyTests(unittest.TestCase):
    def test_reports_mask_all_values_and_decision_reasons(self):
        r = Report()
        manager.convert_xml(wrap('<integration><api_key>password</api_key><hook_url>https://u:p@h/secret</hook_url></integration><cluster><key>' + 'K' * 32 + '</key></cluster>'), r)
        for data in r.files().values():
            for secret in (b'password', b'https://u:p', b'K' * 32):
                self.assertNotIn(secret, data)

    def test_fresh_output_and_permissions_input_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inp = root / 'ossec.conf'
            inp.write_bytes(wrap('<global><jsonout_output>yes</jsonout_output></global>'))
            before = inp.read_bytes()
            result = subprocess.run([sys.executable, str(ROOT / 'convert_manager_conf.py'), str(inp), '--out', str(root / 'out')], capture_output=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(inp.read_bytes(), before)
            self.assertEqual((root / 'out/report.json').stat().st_mode & 0o777, 0o600)
            again = subprocess.run([sys.executable, str(ROOT / 'convert_manager_conf.py'), str(inp), '--out', str(root / 'out')], capture_output=True)
            self.assertEqual(again.returncode, 1)
            self.assertEqual(inp.read_bytes(), before)

    def test_reject_overlap_symlinks_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'etc'
            source.mkdir()
            with self.assertRaises(InputError):
                write_run(source / 'out', {'a': b'x'}, [source])
            dest = root / 'out'
            dest.mkdir()
            with self.assertRaises(InputError):
                write_run(dest, {'a': b'x'}, [])
            link = root / 'linked'
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaises(InputError):
                write_run(link / 'new', {'a': b'x'}, [])

    def test_etc_directory_auto_discovers_api_cluster_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            etc = root / 'install/etc'
            (etc / 'shared/g').mkdir(parents=True)
            (etc / 'ossec.conf').write_bytes(wrap('<global><logall>yes</logall></global>'))
            (etc / 'local_internal_options.conf').write_text('monitord.rotate_log=1\n')
            (etc / 'shared/g/agent.conf').write_bytes(group('<labels/>'))
            api = root / 'install/api/configuration/api.yaml'
            api.parent.mkdir(parents=True)
            api.write_text('experimental_features: yes\n')
            cluster = root / 'install/framework/wazuh/core/cluster/cluster.json'
            cluster.parent.mkdir(parents=True)
            cluster.write_text('{"intervals":{"worker":{"sync_agent_groups":5}}}')
            inputs = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (etc / 'ossec.conf', etc / 'local_internal_options.conf', etc / 'shared/g/agent.conf', api, cluster)}
            result = subprocess.run([sys.executable, str(ROOT / 'convert_manager_conf.py'), str(etc), '--out', str(root / 'out')], capture_output=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            for name in ('wazuh-manager.conf', 'wazuh-manager-internal-options.conf', 'api.yaml', 'cluster-values.json', 'shared/g/agent.conf', 'report.md', 'report.json', 'decisions.required.json'):
                self.assertTrue((root / 'out' / name).is_file(), name)
            for path, digest in inputs.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_cleaner_cli_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inp = root / 'agent.conf'
            inp.write_bytes(group('<labels/>'))
            result = subprocess.run([sys.executable, str(ROOT / 'clean_agent_conf.py'), str(inp), '--out', str(root / 'out')], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'out/agent.conf').read_bytes(), group(''))

    def test_python39_syntax(self):
        for path in list(ROOT.glob('*.py')) + list(HERE.glob('*.py')):
            ast.parse(path.read_text(), feature_version=(3, 9))


class GoldenTests(unittest.TestCase):
    def test_every_available_configuration_fixture(self):
        inventory = json.loads((HERE / 'fixtures/inventory.json').read_text())
        for record in inventory['fixtures']:
            fixture = ROOT / record['path']
            with self.subTest(fixture=fixture.name):
                r = Report()
                data = fixture.read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), record['sha256'])
                convert = manager.convert_xml if 'ossec' in fixture.name else agent.clean
                out = convert(data, r, fixture.name)
                golden = HERE / 'golden' / fixture.stem
                expected = golden / ('wazuh-manager.conf' if 'ossec' in fixture.name else 'agent.conf')
                self.assertEqual(out, expected.read_bytes())
                self.assertEqual(json.loads(r.files()['report.json']), json.loads((golden / 'report.json').read_text()))



# Each enumerated rule/key gets its own unittest, not only a loop in one broad test.
def manager_removal_test(tag):
    def test(self):
        e, r = self.convert('<%s><sample>v</sample></%s>' % (tag, tag))
        self.assertIsNone(e.find(tag))
        self.assertEqual(row_at(r, 'sample[1]')['classification'], NONE if tag == 'alerts' else DECIDE if tag in ('agentless', 'syslog_output') else DROP)
    return test


for _tag in manager.REPLACEMENTS:
    setattr(ManagerTests, 'test_remove_section_' + _tag.replace('-', '_'), manager_removal_test(_tag))

for _tag in sorted(manager.GLOBAL_REMOVED):
    def test(self, tag=_tag):
        e, r = self.convert('<global><%s>yes</%s></global>' % (tag, tag))
        self.assertIsNone(e.find('global/' + tag))
        self.assertIn(row_at(r, tag + '[1]')['classification'], (DROP, NONE))
    setattr(ManagerTests, 'test_global_remove_' + _tag, test)

for _tag in sorted(manager.LEGACY):
    def test(self, tag=_tag):
        value = {'protocol': 'tcp', 'local_ip': '0.0.0.0', 'ipv6': 'yes', 'rids_closing_time': '1s'}.get(tag, '1514')
        e, r = self.convert('<remote><%s>%s</%s></remote>' % (tag, value, tag))
        self.assertEqual(e.findtext('remote/legacy/' + tag), value)
        self.assertEqual(row_at(r, tag + '[1]')['classification'], CHANGE)
    setattr(ManagerTests, 'test_remote_nest_' + _tag, test)

for _top, _tag in [('remote', x) for x in ('connection', 'allowed-ips', 'denied-ips')] + [('auth', 'ssl_auto_negotiate'), ('vulnerability-detection', 'index-status'), ('indexer', 'enabled'), ('cluster', 'disabled')]:
    def test(self, top=_top, tag=_tag):
        value = 'secure' if tag == 'connection' else 'yes'
        e, r = self.convert('<%s><%s>%s</%s></%s>' % (top, tag, value, tag, top))
        self.assertIsNone(e.find(top + '/' + tag))
        self.assertIn(row_at(r, tag + '[1]')['classification'], (DROP, NONE))
    setattr(ManagerTests, 'test_remove_' + _top.replace('-', '_') + '_' + _tag.replace('-', '_'), test)

for _key, _target in manager.RENAMED.items():
    def test(self, key=_key, target=_target):
        r = Report()
        out = manager.convert_internal([('local_internal_options.conf', (key + '=1\n').encode(), True)], r)
        self.assertIn((target + '=1\n').encode(), out)
        self.assertEqual(r.rows[0]['classification'], CHANGE)
    setattr(InternalTests, 'test_rename_' + _key.replace('.', '_'), test)

for _key in sorted(manager.REMOVED_INTERNAL):
    def test(self, key=_key):
        r = Report()
        out = manager.convert_internal([('local_internal_options.conf', (key + '=1\n').encode(), True)], r)
        self.assertNotIn(b'=', out)
        self.assertIn(r.rows[0]['classification'], (DROP, NONE))
    setattr(InternalTests, 'test_remove_' + _key.replace('.', '_'), test)

for _prefix in sorted(manager.AGENT_PREFIXES):
    def test(self, prefix=_prefix):
        r = Report()
        out = manager.convert_internal([('local_internal_options.conf', (prefix + '.debug=1\n').encode(), True)], r)
        self.assertNotIn(b'=', out)
        self.assertEqual(r.rows[0]['classification'], DROP)
    setattr(InternalTests, 'test_agent_prefix_' + _prefix, test)

_AGENT_CASES = []
_AGENT_CASES += [(tag, '<%s><value>v</value></%s>' % (tag, tag)) for tag in sorted(agent.TOP_REMOVED)]
_AGENT_CASES += [('syscheck_' + tag, '<syscheck><%s>v</%s></syscheck>' % (tag, tag)) for tag in sorted(agent.SYSCHECK_REMOVED)]
_AGENT_CASES += [('sync_' + tag, '<syscheck><synchronization><%s>v</%s></synchronization></syscheck>' % (tag, tag)) for tag in sorted(agent.SYNC_REMOVED)]
_AGENT_CASES += [('sca_' + tag, '<sca><%s>v</%s></sca>' % (tag, tag)) for tag in ('day', 'wday', 'time', 'skip_nfs')]
_AGENT_CASES += [('rootcheck_' + tag, '<rootcheck><%s>v</%s></rootcheck>' % (tag, tag)) for tag in ('check_files', 'check_trojans', 'rootkit_files')]
_AGENT_CASES += [('wodle_' + name, '<wodle name="%s"><value>v</value></wodle>' % name) for name in ('cis-cat', 'osquery')]
_AGENT_CASES += [('enrollment_' + tag, '<client><enrollment><%s>v</%s></enrollment></client>' % (tag, tag)) for tag in sorted(agent.ENROLLMENT_REMOVED)]
_AGENT_CASES += [('syscollector_max_eps', '<wodle name="syscollector"><synchronization><max_eps>2</max_eps></synchronization></wodle>'), ('agent_ip_update_interval', '<agent><ip_update_interval>2</ip_update_interval></agent>'), ('client_ip_update_interval', '<client><ip_update_interval>2</ip_update_interval></client>')]
for _name, _body in _AGENT_CASES:
    def test(self, body=_body):
        data, r = group(body), Report()
        out = agent.clean(data, r)
        self.assertNotIn(b'>v<', out)
        self.assertTrue(any(x['classification'] in (DROP, NONE) for x in r.rows))
        self.assertNotEqual(out, data)
    setattr(AgentTests, 'test_remove_' + _name.replace('-', '_'), test)

class AdditionalRuleTests(unittest.TestCase):
    def test_nonsecure_remote_listener_needs_decision(self):
        r = Report()
        manager.convert_xml(wrap('<remote><connection>syslog</connection></remote>'), r)
        self.assertEqual(row_at(r, 'connection[1]')['classification'], DECIDE)

    def test_all_cluster_carried_fields(self):
        body = '<cluster><name>wazuh</name><node_name>node01</node_name><node_type>worker</node_type><key>' + 'a' * 32 + '</key><port>1516</port><bind_addr>0.0.0.0</bind_addr><nodes><node>master.example</node><node>other.example</node></nodes><hidden>no</hidden></cluster><indexer><hosts><host>https://indexer:9200</host></hosts></indexer>'
        r = Report()
        out = ET.fromstring(manager.convert_xml(wrap(body), r))
        self.assertEqual(len(out.findall('cluster/nodes/node')), 2)
        # C4: everything but the key is carried; the 4.x key is a question (the 5.0 key is needed).
        self.assertTrue(all(row['classification'] == CARRY for row in r.rows if row['input_option'] and not row['option'].endswith('key[1]')))
        self.assertEqual(row_at(r, 'key[1]')['classification'], DECIDE)

    def test_internal_cluster_debug_range(self):
        for val in ('0', '1', '2', '3'):
            r = Report()
            out = manager.convert_internal([('local_internal_options.conf', ('wazuh_clusterd.debug=' + val).encode(), True)], r)
            self.assertEqual(r.rows[0]['classification'], DECIDE if val == '3' else CARRY)

    def test_internal_decision_cannot_inject_second_option(self):
        ident = 'local_internal_options.conf:/line[1]/future.debug'
        r = Report({ident: {'action': 'replace', 'value': '1\nfuture.hidden=2', 'reason': 'bad'}})
        with self.assertRaises(InputError):
            manager.convert_internal([('local_internal_options.conf', b'future.debug=1', True)], r)

    def test_omit_required_value_stays_unresolved(self):
        ident = 'ossec.conf:/$required/cluster/key'
        r = Report({ident: {'action': 'omit', 'reason': 'missing key'}})
        manager.convert_xml(wrap(''), r)
        self.assertFalse(row_at(r, '/$required/cluster/key')['resolved'])

    def test_agent_attribute_acknowledgement(self):
        data = group('<localfile custom="x"><location>x</location></localfile>')
        ident = 'agent.conf:/agent_config[1]/localfile[1]/@custom'
        r = Report({ident: {'action': 'keep', 'reason': 'target schema confirmed'}})
        self.assertEqual(agent.clean(data, r), data)
        r.files()

    def test_manager_attribute_explicit_omit_and_keep(self):
        data = wrap('<cluster><name custom="x">wazuh</name></cluster>')
        ident = 'ossec.conf:/ossec_config[1]/cluster[1]/name[1]/@custom'
        for action in ('omit', 'keep'):
            r = Report({ident: {'action': action, 'reason': 'owner decided'}})
            out = ET.fromstring(manager.convert_xml(data, r))
            self.assertEqual(out.find('cluster/name').get('custom'), 'x' if action == 'keep' else None)
            r.files()

    def test_wodle_removal_known_and_unknown(self):
        for name, cls in [('syscollector', DROP), ('open-scap', DROP), ('future', UNKNOWN)]:
            r = Report()
            manager.convert_xml(wrap('<wodle name="%s"><disabled>no</disabled></wodle>' % name), r)
            self.assertTrue(all(row['classification'] == cls for row in r.rows if row['input_option']))

    def test_xml_span_angle_bracket_in_attribute(self):
        data = group('<labels note="a > b"><label key="x">y</label></labels><localfile><location>x</location></localfile>')
        self.assertEqual(agent.clean(data, Report()), group('<localfile><location>x</location></localfile>'))

    def test_xml_attribute_decision_cannot_hide_unknown_silently(self):
        r = Report()
        manager.convert_xml(b'<ossec_config extra="value"><global><agents_disconnection_time>1m</agents_disconnection_time></global></ossec_config>', r)
        self.assertEqual(row_at(r, '/@extra')['classification'], UNKNOWN)

    def test_api_json_booleans_after_explicit_invalid_switch_replacement(self):
        ident = 'api.yaml:/https/enabled'
        r = Report({ident: {'action': 'replace', 'value': 'yes', 'reason': 'enable TLS'}})
        self.assertIn(b'enabled: yes', manager.convert_api(b'https:\n  enabled: maybe\n', r))

class FinalConstraintTests(unittest.TestCase):
    def test_vulnerability_enabled_boolean(self):
        for value in ('yes', 'no', 'true'):
            r = Report()
            manager.convert_xml(wrap('<vulnerability-detection><enabled>%s</enabled></vulnerability-detection>' % value), r)
            self.assertEqual(row_at(r, 'enabled[1]')['classification'], DECIDE if value == 'true' else CARRY)

    def test_empty_and_mixed_xml_are_flagged(self):
        r = Report()
        manager.convert_xml(wrap('<logging/><remote>mixed<port>1514</port></remote>'), r)
        self.assertEqual(row_at(r, 'logging[1]')['rule'], 'xml.empty')
        self.assertEqual(row_at(r, 'remote[1]')['rule'], 'xml.mixed')

    def test_wrong_manager_root(self):
        r = Report()
        self.assertIsNone(manager.convert_xml(b'<unexpected><x>v</x></unexpected>', r))
        self.assertEqual(r.rows[0]['classification'], UNKNOWN)

    def test_remote_typed_constraints(self):
        for tag, value in [('ipv6', 'true'), ('port', 'abc'), ('queue_size', 'one'), ('rids_closing_time', '0s')]:
            r = Report()
            manager.convert_xml(wrap('<remote><%s>%s</%s></remote>' % (tag, value, tag)), r)
            self.assertEqual(row_at(r, tag + '[1]')['classification'], DECIDE)

    def test_api_unknown_keep_preserves_scalar_type(self):
        ident = 'api.yaml:/port'
        r = Report({ident: {'action': 'keep', 'reason': 'schema verified'}})
        out = manager.convert_api(b'port: 55000\n', r)
        self.assertIn(b'port: 55000', out)
        self.assertNotIn(b'"55000"', out)

    def test_unknown_removed_manager_section_only_accepts_omit(self):
        ident = 'ossec.conf:/ossec_config[1]/future[1]/setting[1]'
        data = wrap('<future><setting>x</setting></future>')
        r = Report({ident: {'action': 'omit', 'reason': 'discard unknown section'}})
        self.assertIsNotNone(manager.convert_xml(data, r))
        r.files()
        r = Report({ident: {'action': 'keep', 'reason': 'cannot keep fatal section'}})
        with self.assertRaises(InputError):
            manager.convert_xml(data, r)

    def test_duplicate_globals_cannot_emit_duplicate_document(self):
        r = Report()
        self.assertIsNone(manager.convert_xml(wrap('<global><agents_disconnection_time>1m</agents_disconnection_time></global><global><future>x</future></global>'), r))

    def test_new_master_frequency_zero_stays_disabled(self):
        data = b'{"intervals":{"master":{"metrics_frequency":0}}}'
        ident = 'cluster.json:/intervals/master/metrics_frequency'
        r = Report({ident: {'action': 'keep', 'reason': 'customization confirmed'}})
        self.assertEqual(json.loads(manager.convert_cluster(data, r))['intervals']['master']['metrics_frequency'], 0)

class StructuralSafetyTests(unittest.TestCase):
    def test_client_container_still_flagged_after_all_ignored_leaves_removed(self):
        r = Report()
        out = agent.clean(group('<client><enrollment><port>1515</port></enrollment></client>'), r)
        self.assertNotIn(b'<port>', out)
        self.assertTrue(any(not row['resolved'] for row in r.rows))

    def test_enrollment_removal_does_not_match_unknown_parent(self):
        data = group('<future><enrollment><port>1234</port></enrollment></future>')
        r = Report()
        self.assertEqual(agent.clean(data, r), data)
        self.assertTrue(all(row['classification'] == UNKNOWN for row in r.rows))

    def test_required_source_value_has_only_one_pending_question(self):
        r = Report()
        manager.convert_xml(wrap('<cluster><key>invalid</key></cluster>'), r)
        self.assertFalse(any(row['option'] == '/$required/cluster/key' for row in r.rows))
        self.assertFalse(row_at(r, 'key[1]')['resolved'])
