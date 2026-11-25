#!/usr/bin/env python3
"""rule_table.py - static check: where each rule of the design (1 to 23) is enforced in src/, as rule -> file and line.

Each rule lists anchors: (file under src/, a regular expression that matches the code that enforces it, what that code
does). The check fails when an anchor matches nothing, so a refactor that drops an enforcement is caught. Gaps are
stated per rule (`gap`), never hidden. Writes ../RULES-TABLE.md; run by tests/test_rules.py.
"""
import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
OUT = os.path.join(os.path.dirname(SRC), "RULES-TABLE.md")

RULES = [
    (1, "The bundle lives outside every directory an installer deletes, is checksummed and verified before 4.x is removed; a snapshot repository follows the same rule", [
        ("migrate.sh", r"^UNSAFE_PATHS=\(", "directories the flow deletes"),
        ("migrate.sh", r"^bundle_path_check\(\)", "refuses a bundle under them or on tmpfs, before anything is created"),
        ("migrate.sh", r"manifest_check \|\| \{ echo \"the bundle does not match its manifest: not removing 4.x\"", "checksums verified right before the removal"),
        ("snapshot_repo.py", r"^REFUSED = \[", "snapshot repository locations refused (H6-D4)"),
        ("snapshot_repo.py", r"^def path_repo_rewrite", "path.repo made a list, never a second line"),
        ("snap_consolidate.py", r"snapshot_repo\.check_path\(a\.repo_path\)", "the transport checks its repository"),
        ("cluster/node/remove4x.sh", r"has no completed export", "cluster: a manager node is removed only with its export done and checksummed (E2-cluster fix 04)"),
        ("cluster/node/indexer-security.sh", r"sha256sum > MANIFEST\.sha256", "cluster: indexer node-1's bundle (indexer security) checksummed before its removal (E2-cluster gap 4)"),
        ("migrate.sh", r"agent_dbs_check \"\$BUNDLE_DIR/v4/rollback/var-ossec\.tar\.gz\"", "the per-agent databases are in the rollback archive at their frozen size before the removal (OF1, E2-deb G4)"),
        ("cluster/node/common.sh", r"^bundle_verify\(\)", "cluster: every bundle check leaves the user's decisions file out of the manifest, which later steps rewrite (E5 fold, E5-cluster-deb 06)")], None),

    (2, "The 5.0 assistant's -o is never what removes 4.x", [
        ("migrate.sh", r"4\.x is still installed: not running the 5\.0 assistant", "the 5.0 assistant runs only once 4.x is gone"),
        ("migrate.sh", r"a partial 5\.0 installation is on the host .*adding -o", "-o only over a partial 5.0, never over 4.x")], None),
    (3, "5.0 is never installed over a leftover 4.x data directory", [
        ("migrate.sh", r"/var/ossec exists: not installing 5\.0 over 4\.x leftovers", "refuses with /var/ossec present")], None),
    (4, "Installed means setup ready and content synchronised; after every restart the cluster daemon answers; the setup wording comes from the build manifest", [
        ("mig_helper.py", r"^def setup_ready\(", "every setup-status document read; ready only with the manifest's words"),
        ("manifest/builds.json", r"\"setup_status\"", "the build vocabulary"),
        ("migrate.sh", r"python3 \"\$HELPER\" setup-status", "the replace gate waits for it"),
        ("migrate.sh", r"^wait_clusterd\(\)", "cluster daemon answering after a restart (G5)"),
        ("migrate.sh", r"wait_api5( \"\$\{API5_WAIT_TRIES:-20\}\")? && \{ wait_clusterd; return; \}", "part of manager5_up"),
        ("identity_stage.py", r"return \[sc, \"restart\", \"wazuh-manager\"\]", "the identity stage restarts through the unit, so the daemons are the unit's (OF1, E2-deb G2)"),
        ("manifest/builds.json", r"\"source_min_version\"", "source builds: only the latest 4.14.x, as data (OF1 item 12, 2026-11-24)"),
        ("mig_helper.py", r"^def source_versions_check\(", "manager, indexer and dashboard of every node: older refused, newer 4.14.x accepted, 4.15+/5.x not a source"),
        ("migrate.sh", r"done_ freeze\.stop_manager \|\| source_version_or_die", "checked again before the outage starts (also before the pre-copy)"),
        ("cluster/node/source-version.sh", r"source-version-cluster", "cluster: every manager node from /cluster/nodes, every node's own packages"),
        ("mig_helper.py", r"^def cluster_nodes_missing\(", "cluster: a node the inventory or the agent registry names that is not connected is refused by name (E3 fold, E3-cluster gap 1)"),
        ("cluster/node/freeze-manager.sh", r"^source_version_gate$", "cluster: the freeze checks again on every forward attempt (E3 fold, E3-cluster gap 5)")], None),
    (5, "Listeners closed and the 4.x enrollment password off 5.0 until the registry import is verified; a non-empty registry is a cut import only if id, name and key match", [
        ("migrate-cluster.sh", r"step master\.guard ", "cluster (CL1, guide point b): the agent guard on each manager from before its 4.x removal to its opening"),
        ("cluster/node/open-node.sh", r"^op_listeners \|\| die", "cluster: each manager opens through the all-in-one's op_listeners (guard off, firewall, restart)"),
        ("migrate.sh", r"WAZUH_REMOTE_HTTPS_BIND_ADDR=127\.0\.0\.1 WAZUH_REMOTE_LEGACY_ENABLED=no", "5.0 installed with the listeners closed"),
        ("migrate.sh", r"done_ import\.gate \|\| die \"the import has not passed its gate", "the opening needs the import gate"),
        ("identity_stage.py", r"^def cut_import_check\(", "id, name and key compared (F7)"),
        ("identity_stage.py", r"REFUSE: the 5\.0 registry holds agents that are not this bundle's", "refuses before writing"),
        ("mig_helper.py", r"never repaired", "the reconcile names impostors and never repairs them")], None),
    (6, "The certificate is planned from the fleet and proven by a handshake before the listeners open", [
        ("cluster/node/fleet-facts.sh", r"agent-san-extra\.txt", "cluster (CL1): the dialled names no manager address carries, passed to -g with -as"),
        ("migrate.sh", r"agent-san-extra\.txt", "dialled addresses the certificate lacks, passed with -as"),
        ("mig_helper.py", r"^def handshake\(", "one handshake per dialled address"),
        ("migrate.sh", r"python3 \"\$HELPER\" handshake ", "called by the replace gate, before any opening")], None),
    (7, "One explicit point of no return, before the first agent upgrade", [
        ("migrate-cluster.sh", r"^cmd_c_confirm\(\)", "cluster (CL1): the confirmation"),
        ("migrate-cluster.sh", r"done_ confirm\.no_return && die \"the point of no return was confirmed", "cluster: going back refused after it"),
        ("migrate-cluster.sh", r"^cbanner_phase9\(\)", "cluster: the PHASE 9 banner"),
        ("migrate.sh", r"^cmd_confirm\(\)", "the confirmation"),
        ("migrate.sh", r"done_ confirm\.no_return \|\| die", "phase 10 refuses without it"),
        ("migrate.sh", r"done_ confirm\.no_return && die \"the point of no return was confirmed", "going back refused after it (decision 11; test since OF1)"),
        ("migrate.sh", r"^history_pending_note\(\)", "the banner says when the history is still pending and that the bundle is kept until it is proven (OF1, E2-deb G7)")], None),
    (8, "Before opening, the decision about unclassified events (default: the rules that verified activated, raw indexing on until the finish; decision 3) is applied and in force before the opening restart; the finish switches raw off only with the migrated rules active (checked against rmig's record) or on an explicit answer", [
        ("mig_helper.py", r"^def raw_decision\(", "the finish switches raw off only with every migrated rule active or on an answer (decision of 2026-11-25; E4-rpm gap 2)"),
        ("mig_helper.py", r"^def rmig_active\(", "the answer \"activated\" is checked against rmig's record on the node before raw goes off (E5 fold, E5-aio gap 6)"),
        ("mig_helper.py", r"^def raw_facts\(", "the rules and custom decoders a refusal names are recorded before the first finish's sweep (E5 fold, E5-aio gap 7)"),
        ("cluster/node/ruleset-node.sh", r"op_decision \|\| exit", "cluster (CL1): the decision applied on the master"),
        ("cluster/node/open-node.sh", r"op_in_force \|\| die", "cluster: in force on each node's engine before it opens"),
        ("migrate.sh", r"^op_decision\(\)", "the decision: an explicit UNCLASSIFIED_DECISION, else the default (ask stops with the listeners closed)"),
        ("migrate.sh", r"^UNCLASSIFIED_DEFAULT=\"verified\+raw\"", "the default answer: the rules that verified activated, raw indexing on until the finish (decision 3, OF1)"),
        ("migrate.sh", r"^op_in_force\(\)", "waits for the engine's synchronisation of every changed space (F6-D3)"),
        ("mig_helper.py", r"^def wait_in_force\(", "the wait itself"),
        ("migrate.sh", r"step open\.in_force", "between the decision and the listeners")], None),
    (9, "History is switched on only after its proof and the role audit, inside `on` itself; never do_not_fail_on_forbidden", [
        ("history_load.py", r"if cmd_prove\(api, a, b\) != 0:", "the proof inside `on`, no bypass flag"),
        ("history_load.py", r"if cmd_audit_roles\(api, a, b\) != 0:", "the role audit inside `on` (S5)")],
        "do_not_fail_on_forbidden: the tool never writes it (checked by absence in tests/test_rules.py)"),
    (10, "Every step records its state; a resume re-applies the guard, reads package state from the database files and repairs an interrupted transaction; a cluster node step decides from the node's state, and a success it records is written on success only", [
        ("cluster/node/run-step.sh", r"setsid nohup bash \"\$0\" __run", "cluster (CL1): node steps run detached; a rerun follows a running step, never starts it twice"),
        ("cluster/node/run-step.sh", r"finished on this node after the call that started it had ended", "cluster: a step that ended after its caller died is reported with its exit code, not started again (E5 fold, E5-cluster-rpm 04)"),
        ("cluster/node/install5.sh", r"\[ \"\$rc\" != 0 \] \|\| mark \"\$ok5\"", "cluster: the 5.0 assistant is not run again over this bundle's own success; the marker is written on success only (E5 fold)"),
        ("cluster/node/goback-install4.sh", r"\[ \"\$rc\" != 0 \] \|\| mark \"\$ok4\"", "cluster: the 4.x reinstall resumes after a cut inside it (E5 fold, E5-cluster-rpm 06)"),
        ("migrate-cluster.sh", r"^step\(\)|step precopy\.history ", "cluster: the all-in-one's step machinery, markers, journal and results on the controller"),
        ("migrate.sh", r"^step\(\) \{", "marker, result file and journal per step"),
        ("migrate.sh", r"^guard_resume\(\)", "guard re-applied on every resume (F5)"),
        ("migrate.sh", r"^pkgdb_problems\(\)", "dpkg journal and rpm temporary files"),
        ("migrate.sh", r"^pkg_repair\(\)", "dpkg --configure -a, forced purge, rpm temporary files deleted"),
        ("migrate.sh", r"^mark\(\) \{ sync;", "a marker only once what its step wrote is on disk (E2-rpm fix 03: power cut)"),
        ("cluster/node/common.sh", r"^mark\(\) \{ sync;", "the same for the cluster node steps"),
        ("identity_stage.py", r"^def durable_write\(", "the identity stage's state, saved original and api.yaml fsynced before they replace anything (E2 fold)"),
        ("migrate.sh", r"^stamp\(\) \{", "markers and recorded times written beside, synced, renamed: whole or absent after a cut (E3 fold, E3-rpm 2 and 6)"),
        ("migrate.sh", r"^collect_base\(\) \{", "the settings base collected complete or not at all (E3-rpm fix 01)"),
        ("settings_stage.py", r"_fsync_path\(os\.path\.join\(saved, name\)\)", "the saved settings a rerun trusts are on disk before saved.json (E3 fold)")], None),
    (11, "Going back proves every agent reconnected with its own id, name and key, behind a guard that is node state surviving a reboot; on a cluster it also covers 1516, and every node's bundle is checked before 5.0 is removed anywhere", [
        ("migrate.sh", r"^bk_verify\(\)", "the proof after the way back"),
        ("guard.sh", r"^persist\(\)", "drop-in re-applying every recorded guard before any manager starts (K5)"),
        ("guard.sh", r"ExecStartPre=\+/bin/bash", "the reapply runs outside the 5.0 unit's sandbox (E2-rpm fix 02)"),
        ("guard.sh", r"cluster\) echo \"1516\"", "the cluster port guard"),
        ("cluster/node/node-state.py", r"4\.x REINSTALLED, NOT RESTORED", "cluster: keep every guard until the registry equals the bundle"),
        ("migrate-cluster.sh", r"step back\.check ", "cluster: every node checked, in parallel, before the guard and any removal: one refusal changes nothing anywhere (E5 fold, E5-cluster-deb gap 2)"),
        ("cluster/node/goback-remove5.sh", r"going back is refused on this node", "cluster: the node's check: its bundle, what its way back needs, no 4.x node without an export (E5 fold)")], None),
    (12, "A bundle is valid only for the source it froze", [
        ("migrate.sh", r"^vb_source\(\)", "refuses a source running again or changed since the freeze (F6)"),
        ("migrate.sh", r"\[ \"\$CUR\" != verify_bundle \]", "never skipped by its marker")], None),
    (13, "Never-connected agents do not block (the finish's legacy ports, nor a group's post-upgrade pass); the finish switches raw indexing off and deletes the bundle's secrets by value", [
        ("bundle_secrets.py", r"os\.O_CREAT \| os\.O_TRUNC, 0o600", "the digests record is owner-only (CL1, E4-cluster note 8)"),
        ("migrate-cluster.sh", r"^fi_c_secrets\(\)", "cluster: every bundle node's sweep at the finish"),
        ("migrate.sh", r"NEVER_CONNECTED_AT_FINISH", "keep, close or remove (F6)"),
        ("migrate.sh", r"^fi_raw_off\(\)", "raw indexing off once no 4.x agent remains"),
        ("migrate.sh", r"^fi_secrets\(\)", "secrets found by value"),
        ("bundle_secrets.py", r"^def sweep\(", "one sweep by value, archives opened, for the finish, going back, discard and the cluster (E2 fold)"),
        ("migrate.sh", r"step back\.secrets", "going back ends with it; abandoned bundles: discard (E2-deb G11)"),
        ("cluster/node/finish-node.sh", r"^legacy-decide\)", "cluster: legacy listeners decided once for every node, F6's rule (E2-cluster gap 6)"),
        ("cluster/node/finish-node.sh", r"bundle_secrets\.py\" sweep", "cluster: every node's bundle swept (E2-cluster gap 6)"),
        ("settings_stage.py", r"nc = sorted\(i for i, v in vs\.items\(\) if v == \"never_connected\"\)", "a never-connected agent does not hold a group's post-upgrade pass back, default included (OF1, E2-deb G9)"),
        ("bundle_secrets.py", r"^def record_digests\(", "a rerun of the sweep still searches: salted digests of the values recorded before the parts go (E3 fold, E3-cluster gap 4)"),
        ("bundle_secrets.py", r"^def holds_parts\(", "only bundles that still hold secret parts are named as holding secrets (E3 fold, E3-deb N2)"),
        ("migrate.sh", r"^  mark legacy\.closed$", "the legacy ports are closed once: a later finish does not restart the manager again (E5 fold)"),
        ("migrate-cluster.sh", r"done_ legacy\.closed", "cluster: the same, on the controller and on each node (E5 fold)")], None),
    (14, "Inventory and vulnerability verdicts in phase 10 wait for the vulnerability feed's first complete load; a load is complete on 'CVE feed fully loaded', or on 'Feed update process completed' for an incremental update or a completed initial download (a restart after a complete load keeps the feed)", [
        ("cluster/node/feed-node.sh", r"^feed_wait \|\|", "cluster (CL1, E4-cluster gap 3): phase 10 waits on every manager"),
        ("migrate-cluster.sh", r"^ag_c_feed\(\)", "cluster: before the agents gate"),
        ("mig_helper.py", r"^def feed_load_state\(", "the feed load read from the manager log"),
        ("mig_helper.py", r"^_FEED_DONE_RX", "the scanner's completion line on this build (E2-deb G8)"),
        ("mig_helper.py", r"^_FEED_UPDATE_DONE_RX", "'Feed update process completed' ends an incremental update after a restart, never a full load still running (E3 fold: E3-cluster fix 04, E3-deb N7)"),
        ("mig_helper.py", r"^def feed_wait\(", "waits for the completion line; silence is not completion; off when vulnerability detection is off"),
        ("migrate.sh", r"^ag_feed\(\) \{ feed_wait; \}", "phase 10 waits before its gate (FEED_WAIT_MAX)"),
        ("migrate.sh", r"^  feed_wait \|\| return 1", "the finish waits before its restart, before touching the configuration"),
        ("cluster/node/finish-node.sh", r"feed-wait", "cluster: each manager waits before its legacy-close restart")],
        "partial: the tool waits for the load (decision of 2026-11-24) but issues no per-agent inventory or vulnerability verdict"),
    (15, "Any setting the tool changes for its own work is saved first and put back in the same phase; later gates refuse while it differs", [
        ("identity_stage.py", r"^def raise_limit\(", "api.yaml saved once, limit raised"),
        ("identity_stage.py", r"^def put_back_yaml\(", "the saved api.yaml put back before the stage ends"),
        ("identity_stage.py", r"\"api_yaml_is_the_original\": yaml_ok", "the stage's gate refuses while it differs (G5)"),
        ("migrate.sh", r"the Server API limit raised for the identity import is not restored", "phase 6's gate refuses too"),
        ("identity_stage.py", r"^def check_saved_original\(", "a damaged saved original is never put back or raised from (E2 fold, power cut)"),
        ("migrate.sh", r"is not the original the identity stage saved", "phase 6's gate compares the bytes, not only the stage's state")],
        "partial: the API limit is the only such setting the merged tool changes; the listener edit is undone by design at the opening"),
    (16, "A requested upgrade task is a commitment: a batch only when every agent in it may upgrade; a rerun never exempts an agent from the brake", [
        ("fleet-upgrade.py", r"^LANE_BUSY = ", "a lane's next batch only after every agent of the batch has a verdict (A5)"),
        ("fleet-upgrade.py", r"brake = len\(closed\) >= a\.min_sample", "the failure brake")], None),
    (17, "Agents behind slow links go in their own batches, last", [
        ("fleet-upgrade.py", r"so the package is still on its way \(slow link\)", "a slow push is 'delivering', not a failure (A5)")],
        "partial: slow links are recognised; separate, last batches per measured push time are not built (A5: sizing inferred)"),
    (18, "A history rerun never reopens or re-creates a loaded index; a journal of months; the retention is the 4.x one unless set (decision 5b)", [
        ("mig_helper.py", r"^def expired_months\(", "the comparison reports months the retention left out as NOT LOADED, not LOST (E4-deb N-H1)"),
        ("cluster/alertsjson-fold.py", r"^def merge\(", "cluster (CL1, guide point a): the folded alerts join the history bundle, loaded and proven with it"),
        ("history_load.py", r"^class Journal:", "the retention journal (H5)"),
        ("history_load.py", r"^def classify_months\(", "loaded and expired months never touched again"),
        ("mig_helper.py", r"^def retention_4x_of\(", "the 4.x ISM delete age of the alert indices, read at pre-copy (OF1, decision 5b)"),
        ("migrate.sh", r"^history_retention\(\)", "explicit HISTORY_RETENTION, else the 4.x retention, else 365 days; the reason reported"),
        ("mig_helper.py", r"^def ism_restore4\(", "going back puts the 4.x ISM policies and their attachments back, so 4.x keeps its retention and a later bundle reads it (E3 fold, E3-deb N4)"),
        ("cluster/node/retention-4x.sh", r"mig_helper\.py\" retention-4x", "cluster: the master reads the 4.x retention through node-1 at the pre-copy (F4)"),
        ("cluster/node/history5-master.sh", r"^history_retention\(\)", "cluster: explicit, else the 4.x retention, else 365 days; the reason reported (F4)"),
        ("cluster/node/retention-4x.sh", r"mig_helper\.py\" ism-restore4", "cluster: the whole-cluster way back puts the 4.x ISM policies back (F4)"),
        ("load_unchanged.py", r"^def creation_ms\(", "going back, each reloaded 4.x index is created with its creation date where the indexer accepts it (F4; 4.14.10 does not)"),
        ("mig_helper.py", r"^def restored_age_report_of\(", "going back names restored indices past their delete age or counting from a later date (F4)"),
        ("mig_helper.py", r"^def source_creation_dates\(", "the extra ISM time is measured from each index's own creation date on 4.x where the dump recorded it (E5 fold, E5-aio gap 3)")],
        "product limit (E5-aio, E5-cluster-deb, 2026-11-25): 4.14.10's indexer refuses index.creation_date at index creation (HTTP 400, every form), so after going back every restored 4.x alert index counts its ISM age from the reload and is kept longer than on 4.x; the tool warns and names them, the user deletes them by hand"),
    (19, "A gate whose input cannot be read stops the run and names the missing permission", [
        ("history_load.py", r"if s == 403:   # H5: a refused count", "a refused count stops"),
        ("history_load.py", r"H5: strict; \[\] on a refusal", "a refused listing stops"),
        ("mig_helper.py", r"rule 19: an unreadable gate input stops the run", "the in-force wait"),
        ("mig_helper.py", r"retention-4x: reading the ISM policies was refused", "the 4.x retention read (OF1, decision 5b)"),
        ("cluster/node/retention-4x.sh", r"could not be read \(rule 19\)", "cluster: a refused retention read stops the pre-copy before the dump (F4)")], None),
    (20, "Saved objects are rolled back by resetting only the attributes the tool changed", [
        ("mig_helper.py", r"^TOOL_ATTRS = \{", "the attributes the dashboard step rewrites, per type"),
        ("mig_helper.py", r"ledger\[key\] = \{\"type\"", "each changed attribute recorded with its value before and the value written"),
        ("mig_helper.py", r"/api/saved_objects/_import\", user", "the import never overwrites an existing object (no overwrite=true)"),
        ("mig_helper.py", r"^def rollback_saved_objects\(", "partial update of only those attributes, only where unchanged since"),
        ("migrate.sh", r"dashboards-rollback\) # rule 20", "the command")], None),
    (21, "The 5.0 install owns the cluster key, topology, listener sections and certificate paths; converted settings are merged into the installed files", [
        ("migrate.sh", r'if \[ "\$CLUSTER_CANDIDATES" = first-node \]; then', "cluster (CL1, order C): the master checked alone, each worker against every node already on 5.0"),
        ("cluster/node/settings-node.sh", r'CLUSTER_CANDIDATES="\$peers"; im_settings', "cluster: a worker's candidate checked against the live 5.0 files before anything is staged"),
        ("converter/c4_ext.py", r"^OWNED_PREFIXES = \(", "sections the install owns"),
        ("converter/c4_ext.py", r"^def merge\(base, out, skip\):", "4.x customisations written into the installed 5.0 file"),
        ("migrate.sh", r"settings_stage\.py\" convert .*--base \"\$S/base-installed\"", "phase 6 converts against the installed base"),
        ("migrate.sh", r"python3 \"\$HERE/converter/cluster_check\.py\"", "cross-node check before staging on a cluster"),
        ("migrate.sh", r"the cross-node check needs the other nodes' candidates", "refused without the other nodes' candidates"),
        ("converter/cluster_check.py", r"one cluster name", "the check itself (C4)"),
        ("settings_stage.py", r"^def cmd_cluster_base\(", "cluster: the pre-copy plans each node against a base with that node's <cluster>, not the all-in-one's (E5 fold)"),
        ("settings_stage.py", r"ans = answers_for\(d, name, set\(required\), group\)", "only the answers to this run's questions go to the converter (E5 fold, E5-cluster-rpm 07 = E5-cluster-deb 05)")],
        "clusters: the cluster controller does not yet gather the other nodes' candidates (CLUSTER_CANDIDATES); the step refuses without them"),
    (22, "Internal options are checked against the build's range table before staging, and with wazuh-manager-control check before the restart; a failed check restores the saved files", [
        ("converter/c4_ext.py", r"^class Ranges:", "the 5.0 build's range table (ranges-5.0.0.json)"),
        ("converter/convert_manager_conf.py", r"lo_hi = ranges\.get\(target\)", "an out-of-range option becomes a question naming the daemon it would stop"),
        ("settings_stage.py", r"^def question\(name, row\):", "the decisions entry carries the question: what is asked, the range, each answer (OF1, E2-deb G6)"),
        ("settings_stage.py", r"^def refuse\(d, name, i, why, group=None\):", "a refused answer is reopened with its reason, named in the stop message (OF1, E2-deb G6)"),
        ("settings_stage.py", r"^def cmd_apply\(", "save once, validate, stage, check"),
        ("settings_stage.py", r"CHECK FAILED: the saved installed files are back", "a failed check restores and stops"),
        ("migrate.sh", r"--check-cmd \"\$V5/bin/wazuh-manager-control check\"", "the product's own check before the restart"),
        ("migrate.sh", r"the manager did not come up on the converted settings: putting the saved installed files back", "the restart that fails restores too")], None),
    (23, "Upgrade requests are sized by time and made only while the delivery thread is idle", [
        ("fleet-upgrade.py", r"st\[\"batch_formula\"\] = ", "safe batch from task expiry, poll, retry list and measured push (A6)"),
        ("fleet-upgrade.py", r"thread_busy = now\(\) - st\.get\(\"thread_busy_until\", 0\)", "no request while the thread is in a cycle (A6)")], None),
]


def find(rel, rx):
    p = os.path.join(SRC, rel)
    try:
        lines = open(p, errors="replace").read().splitlines()
    except OSError:
        return []
    r = re.compile(rx)
    return [i + 1 for i, l in enumerate(lines) if r.search(l)]


def build():
    rows, missing = [], []
    for n, text, anchors, gap in RULES:
        locs = []
        for rel, rx, what in anchors:
            hits = find(rel, rx)
            if not hits:
                missing.append((n, rel, rx))
            locs.append((rel, hits[:3], what))
        rows.append((n, text, locs, gap))
    return rows, missing


def write(rows, missing):
    out = ["# Rules 1 to 23: where the merged tool enforces each one", "",
           "Generated by `tests/rule_table.py` (a static check run by `tests/test_rules.py`): every anchor below is a regular",
           "expression that must match the enforcing code; the test fails when one matches nothing. Paths are under `src/`.", "",
           "| Rule | What | Enforced at (file:line) | Gap |", "|---|---|---|---|"]
    for n, text, locs, gap in rows:
        where = "<br>".join("`%s:%s` %s" % (rel, ",".join(map(str, hits)) or "MISSING", what) for rel, hits, what in locs)
        out.append("| %d | %s | %s | %s |" % (n, text, where, gap or "none known"))
    out += ["", "Anchors that matched nothing: %s" % (missing or "none")]
    open(OUT, "w").write("\n".join(out) + "\n")


if __name__ == "__main__":
    rows, missing = build()
    write(rows, missing)
    print("rules: %d; anchors missing: %s; written %s" % (len(rows), missing or "none", OUT))
    sys.exit(1 if missing else 0)
