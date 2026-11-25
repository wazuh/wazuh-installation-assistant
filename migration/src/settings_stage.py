#!/usr/bin/env python3
"""settings_stage.py - the manager-config stage inside the flow: C4's converter and group cleaner, driven the way C4's
live apply did it (save the installed files once, validate the candidate,
stage, `wazuh-manager-control check`, restart; restore the saved files when the check fails). Rules 21 and 22.
Python 3.8+, standard library only.

    settings_stage.py plan    --v4 DIR --stock DIR --base DIR --decisions FILE --work DIR [--groups DIR]
    settings_stage.py convert --v4 DIR --stock DIR --base DIR --decisions FILE --out DIR
    settings_stage.py apply   --candidate DIR --saved DIR --targets JSON --check-cmd CMD [--validate-cmd CMD]
    settings_stage.py restore --saved DIR --targets JSON
    settings_stage.py groups  --phase pre-upgrade|post-upgrade --groups DIR --decisions FILE --work DIR
                              --shared DIR [--versions JSON] [--dry-run]

The flow's decisions file (migrate.sh MIGRATION_DECISIONS) holds every question the flow asks a person. This stage
uses three sections of it: "settings" (the converter's option ids), "groups-pre-upgrade" and "groups-post-upgrade"
(per group, the cleaner's option ids). `plan` writes every question it cannot answer into the file as an entry with
"action": null, keeps every answer already there, and exits 3 while any entry is unanswered; the flow stops then.
An answer is {"action": "keep" | "replace" | "omit", "value": "..." (replace), "reason": "..."}.

Targets (JSON): {"wazuh-manager.conf": "/etc/wazuh-manager/wazuh-manager.conf", ...}: candidate file -> installed path.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CONV = os.path.join(HERE, "converter")
RANGES = os.path.join(CONV, "ranges-5.0.0.json")
INPUTS = (("ossec-conf", "ossec.conf"), ("internal-options", "internal_options.conf"),
          ("local-internal-options", "local_internal_options.conf"), ("api-yaml", "api.yaml"), ("cluster-json", "cluster.json"))
OPEN, ANSWERED = "open", "answered"


# ------------------------------------------------------------------------------------------- the decisions file
def read_decisions(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise SystemExit("the decisions file %s is not a JSON object" % path)
    return d


def write_decisions(path, d):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def open_entries(d):
    """(section, group or None, id) of every entry still open, for the stop message."""
    for sec in ("settings", "groups-pre-upgrade", "groups-post-upgrade"):
        s = d.get(sec) or {}
        if sec == "settings":
            for i, e in sorted(s.items()):
                if not answered(e):
                    yield sec, None, i
        else:
            for g, ent in sorted(s.items()):
                for i, e in sorted((ent or {}).items()):
                    if not answered(e):
                        yield sec, g, i


def answered(entry):
    return isinstance(entry, dict) and entry.get("action") in ("keep", "replace", "omit")


def section(d, name, group=None):
    s = d.setdefault(name, {})
    return s.setdefault(group, {}) if group is not None else s


ANSWERS = {
    "settings": {"keep": "carry the 4.x value as it is; it must satisfy what 'asks' and 'allowed' say, else the answer is refused",
                 "replace": "write the value given in \"value\" instead; it must satisfy the same constraint",
                 "omit": "do not carry this option: the installed 5.0 file keeps its own value or default"},
    "groups": {"keep": "keep the option in the group's agent.conf as it is",
               "replace": "write the value given in \"value\" instead",
               "omit": "remove the option from the group's agent.conf"},
}
OMIT_ONLY = ("xml.duplicate", "internal.syntax")     # the converter accepts only omit for these (convert_manager_conf.py)


def question(name, row):
    """OF1 (E2-deb G6): the question an entry asks, from the converter's report row: the option, what is asked (the
    converter's own text, e.g. "Read by wazuh-manager-modulesd with range 1..600: this value would stop ..."), the
    answers allowed and what each does, and for an internal option the 5.0 build's range. The 4.x value itself is not
    repeated: the converter masks every value, which may hold a credential."""
    if not row:
        return {"asks": "see the converter's report (no report row for this id)", "answers": ANSWERS["groups" if name.startswith("groups") else "settings"]}
    q = {"option": row.get("option"), "file": row.get("source"), "asks": row.get("action"),
         "classification": row.get("classification"), "guide": row.get("guide"), "rule": row.get("rule")}
    ans = dict(ANSWERS["groups" if name.startswith("groups") else "settings"])
    if row.get("rule") in OMIT_ONLY:
        ans = {"omit": ans["omit"]}
        q["allowed"] = "omit only: reconcile the 4.x file by hand if the option must stay"
    import re
    m = re.search(r"range (-?[0-9]+)\.\.(-?[0-9]+)", row.get("action") or "")   # the converter's text names the 5.0 range of the renamed key
    if m:
        q["allowed"] = "an integer from %s to %s (the 5.0 build's range table)" % m.groups()
    q["answers"] = ans
    return q


def merge_open(d, name, required, group=None, rows=None):
    """Add every unresolved id of a run as an entry with action null and its question; never touch an answer. Returns
    the open ids."""
    s = section(d, name, group)
    rows = rows or {}
    for i in required:
        if not answered(s.get(i)):
            e = s.get(i) if isinstance(s.get(i), dict) else {}
            e.update({"action": None, "reason": e.get("reason", ""), "asked_by": "settings stage (C4 converter)",
                      "question": question(name, rows.get(i))})
            s[i] = e
        elif "question" not in s[i]:
            s[i]["question"] = question(name, rows.get(i))
    # E5 fold (E5-cluster-deb 05): open = this run's questions not answered. An entry this run does not ask (one the
    # pre-copy's plan asked against the shipped base, perhaps reopened by an older tool) stays in the file as it is and
    # does not stop the run: counting every unanswered entry of the section stopped the cluster master on a question
    # nobody asked any more and no answer could close
    return sorted(i for i in required if not answered(s.get(i)))


def refuse(d, name, i, why, group=None):
    """OF1 (E2-deb G6): an answer the converter refused is taken out of force: the entry is open again (action null),
    the refused answer is kept beside it with the reason, so the next run shows what was wrong and where."""
    s = section(d, name, group)
    e = s.get(i) if isinstance(s.get(i), dict) else {}
    old = {k: e[k] for k in ("action", "value", "reason") if k in e}
    e["refused"] = {"answer": old, "why": why, "at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())}
    e["action"] = None
    s[i] = e
    return "%s%s / %s" % (name, (" / " + group) if group else "", i)


def answers_for(d, name, ids, group=None):
    """Only the answered entries whose id is in ids (the questions this run asks): the converter refuses decisions it did
    not use."""
    s = (d.get(name) or {})
    if group is not None:
        s = s.get(group) or {}
    return {i: {k: v for k, v in e.items() if k in ("action", "value", "reason")} for i, e in s.items() if i in ids and answered(e)}


# ------------------------------------------------------------------------------------------------ the converter
def _run(cmd):
    p = subprocess.run(cmd, cwd=CONV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return p.returncode, p.stdout.decode(errors="replace")


def _report(out, rows=False):
    with open(os.path.join(out, "report.json")) as f:
        rep = json.load(f)
    with open(os.path.join(out, "decisions.required.json")) as f:
        req = json.load(f)
    if rows:
        return {r["id"]: r for r in rep["options"]}, sorted(req)
    return {r["id"] for r in rep["options"]}, sorted(req)


def manager_args(v4, stock, base):
    a = [sys.executable, os.path.join(CONV, "convert_manager_conf.py")]
    for flag, name in INPUTS:
        p = os.path.join(v4, name)
        if os.path.isfile(p):
            a += ["--" + flag, p]
    a += ["--stock-4x", stock, "--ranges", RANGES]
    if base:
        a += ["--base-5x", base]
    return a


REFUSED = []        # OF1: "<section> / <id>: why" for every answer refused in this process, printed by the commands


def _converter_with(args_wo_out, ans, work, label):
    dec = os.path.join(work, label + "-decisions.json")
    with open(dec, "w") as f:
        json.dump(ans, f)
    os.chmod(dec, 0o600)
    out = tempfile.mkdtemp(prefix=label + "-", dir=work)
    os.rmdir(out)
    try:
        rc, txt = _run(args_wo_out + ["--decisions", dec, "--out", out])
    finally:
        os.unlink(dec)
    return rc, txt, out


def two_pass(args_wo_out, d, name, work, label, group=None):
    """Run once without decisions to learn the ids, once with the answers that apply. Returns (rc, out, open ids).
    OF1 (E2-deb G6): an answer the converter refuses no longer stops the stage with the converter's bare message: the
    answer that caused it is found (named in the message, or by trying each answer alone), set aside in its entry with
    the reason (refuse), and the run goes on without it, so the entry is reported open with its question."""
    os.makedirs(work, exist_ok=True)
    first = tempfile.mkdtemp(prefix=label + "-ids-", dir=work)
    os.rmdir(first)
    rc, txt = _run(args_wo_out + ["--out", first])
    if rc not in (0, 2):
        raise SystemExit("converter refused (%s): %s" % (label, txt.strip()[-600:]))
    _, required = _report(first)
    shutil.rmtree(first, ignore_errors=True)
    # E5 fold (E5-cluster-rpm 07 = E5-cluster-deb 05): only the answers to the questions THIS run asks (its
    # decisions.required.json), not to every option id the report lists. A question the pre-copy asked against the
    # shipped base (a cluster node's node_name) is a plain row against the installed base ("Same as the 5.0 install");
    # its answer was sent anyway, the converter refused the whole set ("Unused decision ids"), the entry was reopened and
    # the run stopped on every attempt with the master's listeners closed. The converter uses a decision only for an
    # unresolved row, which is exactly what decisions.required.json lists, so no answer it could use is held back.
    ans = answers_for(d, name, set(required), group)
    for i, e in sorted(ans.items()):
        if not isinstance(e.get("reason"), str) or not e["reason"].strip():
            REFUSED.append(refuse(d, name, i, "every answer needs a non-empty \"reason\"", group) + ": every answer needs a non-empty \"reason\"")
            del ans[i]
    rc, txt, out = _converter_with(args_wo_out, ans, work, label)
    while rc not in (0, 2) and ans:
        msg = txt.strip().splitlines()[-1] if txt.strip() else "refused"
        named = msg.split("constraint for ", 1)[1].strip() if "constraint for " in msg else None
        bad = [named] if named in ans else []
        if not bad:              # the message names no id this run answered: try each answer alone
            for i in sorted(ans):
                r1, t1, o1 = _converter_with(args_wo_out, {i: ans[i]}, work, label + "-try")
                shutil.rmtree(o1, ignore_errors=True)
                if r1 not in (0, 2):
                    bad.append(i)
                    msg = t1.strip().splitlines()[-1] if t1.strip() else msg
        if not bad:
            break
        for i in bad:
            why = "the converter refused this answer: %s" % msg.replace("Conversion refused: ", "")
            REFUSED.append(refuse(d, name, i, why, group) + ": " + why)
            del ans[i]
        shutil.rmtree(out, ignore_errors=True)
        rc, txt, out = _converter_with(args_wo_out, ans, work, label)
    if rc not in (0, 2):
        raise SystemExit("converter refused (%s): %s" % (label, txt.strip()[-600:]))
    rows, required = _report(out, rows=True)
    return rc, out, merge_open(d, name, required, group, rows)


def print_refused(path):
    for r in REFUSED:
        print("REFUSED ANSWER in %s: %s. The entry is open again (\"action\": null); the refused answer is kept under its \"refused\" key" % (path, r))


def group_dirs(groups):
    if not groups or not os.path.isdir(groups):
        return []
    return sorted(g for g in os.listdir(groups) if os.path.isfile(os.path.join(groups, g, "agent.conf")))


def cleaner_args(groups, g, phase):
    gd = os.path.join(groups, g)
    a = [sys.executable, os.path.join(CONV, "clean_agent_conf.py"), os.path.join(gd, "agent.conf"), "--phase", phase, "--group-dir", gd]
    if g == "default":
        a.append("--default-group")
    return a


def stock_note(stock, out):
    """OF1 (E2-deb G5): which 4.x stock reference the conversion compared with (migrate.sh settings_stock writes it in
    <stock>/SOURCE), printed and added to the manager report, so a deb host's shipped reference is said, not silent."""
    try:
        src = open(os.path.join(stock, "SOURCE")).read().strip()
    except OSError:
        src = "not recorded (no SOURCE file beside the reference)"
    print("settings: %s" % src)
    md = os.path.join(out, "report.md")
    if os.path.isfile(md):
        with open(md, "a") as f:
            f.write("\n## Stock 4.x reference\n\n%s\n" % src)
    return src


def cmd_plan(a):
    shutil.rmtree(a.work, ignore_errors=True)       # the stage's own scratch: every plan starts clean
    d = read_decisions(a.decisions)
    total = []
    _, out, open_ = two_pass(manager_args(a.v4, a.stock, a.base), d, "settings", a.work, "manager")
    print("settings plan: manager files -> %s; %d question(s) open" % (out, len(open_)))
    stock_note(a.stock, out)
    total += open_
    for phase in ("pre-upgrade", "post-upgrade"):
        for g in group_dirs(a.groups):
            _, gout, gopen = two_pass(cleaner_args(a.groups, g, phase), d, "groups-" + phase, a.work, "%s-%s" % (phase, g), group=g)
            if gopen:
                print("settings plan: group %s, %s pass: %d question(s) open" % (g, phase, len(gopen)))
            total += gopen
    write_decisions(a.decisions, d)
    print_refused(a.decisions)
    if total:
        print("DECISIONS NEEDED: %d question(s) of the settings stage are open in %s (entries with \"action\": null; each "
              "entry's \"question\" says what is asked, the answers allowed and what each does). Answer each with keep, "
              "replace (with \"value\") or omit and a reason, then run again. Nothing was staged." % (len(total), a.decisions))
        for sec, grp, i in open_entries(d):
            if i not in total:           # E5 fold: an entry this run does not ask is not listed as open
                continue
            q = (section(d, sec, grp).get(i) or {}).get("question") or {}
            print("  open: %s%s / %s: %s%s" % (sec, (" / " + grp) if grp else "", i, q.get("asks") or "",
                                                (" Allowed: " + q["allowed"]) if q.get("allowed") else ""))
        return 3
    print("settings plan: every question answered; nothing is left to a person in the converted files")
    return 0


def cmd_convert(a):
    d = read_decisions(a.decisions)
    if os.path.exists(a.out):
        shutil.rmtree(a.out)
    rc, out, open_ = two_pass(manager_args(a.v4, a.stock, a.base), d, "settings", os.path.dirname(os.path.abspath(a.out)), "convert")
    stock_note(a.stock, out)
    write_decisions(a.decisions, d)
    print_refused(a.decisions)
    if open_:
        print("DECISIONS NEEDED: %d settings question(s) open in %s; not staging" % (len(open_), a.decisions))
        return 3
    os.rename(out, a.out)
    print("candidate files in %s: %s" % (a.out, ", ".join(sorted(os.listdir(a.out)))))
    return 0


def cmd_cluster_base(a):
    """E5 fold (E5-cluster-rpm gap 2, E5-cluster-deb gap 4): a cluster node's pre-copy plan was made against the shipped
    all-in-one base, so every node got questions the installed base never asks: "$topology/mismatch" (cluster against a
    single node), "cluster/node_name" and, on a worker, "node_type" ("This 4.x file is for another node"). The base for a
    cluster node is the shipped one with its <cluster> section as the 5.0 install writes it on that node: the node's
    inventory name (install5.sh -wm <name>), its role, every node bound (0.0.0.0) and the master's address as the only
    entry of <nodes>. The installed base is still read at the import, and plans again (rp_settings_plan)."""
    if os.path.exists(a.out):
        shutil.rmtree(a.out)
    shutil.copytree(a.base_from, a.out)
    p = os.path.join(a.out, "wazuh-manager.conf")
    t = open(p).read()
    m = re.search(r"<cluster>.*?</cluster>", t, re.S)
    if not m:
        raise SystemExit("cluster-base: no <cluster> section in %s" % p)
    c = m.group(0)
    for tag, val in (("node_name", a.node_name), ("node_type", a.node_type), ("bind_addr", "0.0.0.0")):
        c, n = re.subn(r"<%s>[^<]*</%s>" % (tag, tag), "<%s>%s</%s>" % (tag, val, tag), c)
        if n != 1:
            raise SystemExit("cluster-base: <%s> not found once in the shipped <cluster> section" % tag)
    c, n = re.subn(r"<nodes>.*?</nodes>", "<nodes>\n        <node>%s</node>\n    </nodes>" % a.master, c, flags=re.S)
    if n != 1:
        raise SystemExit("cluster-base: <nodes> not found once in the shipped <cluster> section")
    c = re.sub(r"<disabled>[^<]*</disabled>", "<disabled>no</disabled>", c)
    with open(p, "w") as f:
        f.write(t[:m.start()] + c + t[m.end():])
    with open(os.path.join(a.out, "SOURCE"), "w") as f:
        f.write("the shipped base %s with <cluster> as the 5.0 install writes it on %s (%s, master %s)\n" % (
            os.path.basename(a.base_from), a.node_name, a.node_type, a.master))
    print("settings: the pre-copy plan uses a cluster base: %s (%s), master %s" % (a.node_name, a.node_type, a.master))
    return 0


# --------------------------------------------------------------------------------------------- stage and restore
def _stat(p):
    st = os.stat(p)
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": st.st_mode & 0o7777}


def save_once(targets, saved):
    """live.sh save-installed: the installed files are saved once, before anything is staged; a rerun keeps the first copy."""
    os.makedirs(saved, mode=0o700, exist_ok=True)
    meta_p = os.path.join(saved, "saved.json")
    if os.path.exists(meta_p):
        return False
    # E3 fold (E3-rpm item 17 sweep): saved.json is what a rerun trusts ("already saved, kept the first copy") and what a
    # failed check restores from, so every copy is on disk before it exists: on XFS (RHEL) a rename can reach the disk
    # before the data it names, and a restore from a 0-byte copy would stop the manager
    meta = {}
    for name, dst in targets.items():
        if os.path.exists(dst):
            shutil.copy2(dst, os.path.join(saved, name))
            _fsync_path(os.path.join(saved, name))
            meta[name] = dict(_stat(dst), path=dst)
        else:
            meta[name] = {"path": dst, "absent": True}
    with open(meta_p + ".tmp", "w") as f:
        json.dump(meta, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(meta_p + ".tmp", meta_p)
    _fsync_path(saved)
    return True


def _fsync_path(p):
    try:
        fd = os.open(p, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _place(src, dst, st):
    tmp = dst + ".migtmp"
    shutil.copyfile(src, tmp)
    try:
        os.chown(tmp, st["uid"], st["gid"])
    except PermissionError:
        pass                        # tests run unprivileged; on the manager this runs as root
    os.chmod(tmp, st["mode"])
    os.replace(tmp, dst)


def stage(candidate, targets, saved):
    """live.sh stage: each candidate file replaces the installed one, keeping the installed owner and mode."""
    meta = json.load(open(os.path.join(saved, "saved.json")))
    staged = []
    for name, dst in targets.items():
        src = os.path.join(candidate, name)
        if not os.path.isfile(src):
            continue
        st = meta[name] if not meta[name].get("absent") else {"uid": os.getuid(), "gid": os.getgid(), "mode": 0o640}
        _place(src, dst, st)
        staged.append(dst)
    return staged


def restore(saved, targets):
    """live.sh restore: the saved installed files back, with their owner and mode."""
    meta = json.load(open(os.path.join(saved, "saved.json")))
    done = []
    for name, dst in targets.items():
        m = meta.get(name)
        if not m:
            continue
        if m.get("absent"):
            if os.path.exists(dst):
                os.unlink(dst)
            continue
        _place(os.path.join(saved, name), dst, m)
        done.append(dst)
    return done


def cmd_apply(a):
    targets = json.loads(a.targets)
    first = save_once(targets, a.saved)
    print("installed files %s in %s" % ("saved" if first else "already saved (kept the first copy)", a.saved))
    if a.validate_cmd:
        p = subprocess.run(a.validate_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print("validate: exit %d %s" % (p.returncode, p.stdout.decode(errors="replace").strip()[-300:]))
        if p.returncode != 0:
            print("the candidate does not validate: nothing staged")
            return 1
    staged = stage(a.candidate, targets, a.saved)
    print("staged: %s" % ", ".join(staged))
    p = subprocess.run(a.check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print("check (%s): exit %d %s" % (a.check_cmd, p.returncode, p.stdout.decode(errors="replace").strip()[-600:]))
    if p.returncode != 0:
        back = restore(a.saved, targets)
        print("CHECK FAILED: the saved installed files are back (%s); the manager was not restarted" % ", ".join(back))
        return 1
    print("check passed: the next restart runs on the converted settings")
    return 0


def cmd_restore(a):
    back = restore(a.saved, json.loads(a.targets))
    print("restored: %s" % ", ".join(back))
    return 0


# ---------------------------------------------------------------------------------------------- the group passes
def major(version):
    """5 for 'Wazuh v5.0.0' or 'v5.0.1', 4 for 'Wazuh v4.14.10', None when the agent never reported a version."""
    import re
    m = re.search(r"(\d+)\.\d+", str(version or ""))
    return int(m.group(1)) if m else None


def cmd_groups(a):
    """Pre-upgrade in phase 6 (while any agent of the group is 4.x), post-upgrade in phase 11 for each group whose agents
    all run 5.0 (C4 D5). The agent.conf of a group other than default goes through the API; carried files are installed
    into the group folder; the post-upgrade pass deletes the files it lists."""
    d = read_decisions(a.decisions)
    versions = json.loads(a.versions) if a.versions else {}
    plan, left, open_all = [], [], []
    for g in group_dirs(a.groups):
        if a.phase == "post-upgrade":
            # OF1 (E2-deb G9): an agent that never connected runs nothing that could refuse the cleaned file, so it does
            # not hold the pass back (before this, default never got it while such an agent was kept); a key it holds
            # later enrolls a 5.0 agent on 1517 or a 4.x one on the legacy port, which then gets the post-upgrade files
            vs = versions.get(g, {})
            nc = sorted(i for i, v in vs.items() if v == "never_connected")
            old = sorted(i for i, v in vs.items() if v != "never_connected" and major(v) != 5)
            if old:
                left.append((g, old))
                continue
            if nc:
                print("group %s: never-connected agent(s) %s do not hold the post-upgrade pass back" % (g, nc))
        _, out, open_ = two_pass(cleaner_args(a.groups, g, a.phase), d, "groups-" + a.phase, a.work, "%s-%s" % (a.phase, g), group=g)
        if open_:
            open_all += ["%s:%s" % (g, i) for i in open_]
            continue
        plan.append((g, out))
    write_decisions(a.decisions, d)
    print_refused(a.decisions)
    for g, old in left:
        print("group %s: kept as the pre-upgrade pass left it: agents below 5.0: %s (run finish again after their upgrade)" % (g, old))
    if open_all:
        print("DECISIONS NEEDED: %d group question(s) open in %s; no group changed" % (len(open_all), a.decisions))
        return 3
    result = {"applied": [], "left": [g for g, _ in left]}
    for g, out in plan:
        conf = os.path.join(out, "agent.conf")
        carry = os.path.join(out, "carry")
        dele = os.path.join(out, "delete-from-group.txt")
        actions = []
        if g != "default" and os.path.isfile(conf):
            actions.append(("upload", conf))
        if os.path.isdir(carry):
            actions += [("carry", os.path.join(carry, f)) for f in sorted(os.listdir(carry))]
        if os.path.isfile(dele):
            actions += [("delete", n.strip()) for n in open(dele) if n.strip()]
        result["applied"].append({"group": g, "actions": [[k, os.path.basename(v)] for k, v in actions]})
        if a.dry_run:
            continue
        for kind, v in actions:
            if kind == "upload":
                code, resp = upload_group_conf(g, open(v, "rb").read())
                if code != 200 or (isinstance(resp, dict) and resp.get("error") not in (0, None)):
                    raise SystemExit("group %s: the API refused the cleaned agent.conf: HTTP %s %s" % (g, code, json.dumps(resp)[:300]))
                record_upload(a.work, g, v)
            elif kind == "carry":
                dst = os.path.join(a.shared, g, os.path.basename(v))
                st = _stat(os.path.join(a.shared, g)) if os.path.isdir(os.path.join(a.shared, g)) else {"uid": os.getuid(), "gid": os.getgid()}
                _place(v, dst, {"uid": st["uid"], "gid": st["gid"], "mode": 0o660})
            elif kind == "delete":
                p = os.path.join(a.shared, g, os.path.basename(v))
                if os.path.exists(p):
                    os.unlink(p)
    print(json.dumps(result))
    return 0


UPLOADED = "uploaded.json"


def record_upload(work, group, conf):
    """E2 fold (E2-rpm fixes 05 and 06, E2-deb fix 1, reconciled): what this pass uploaded, by exact group name, in
    <work>/uploaded.json ({group: {"agent_conf": path relative to work, "sha256": ..., "at": ...}}). Both comparisons of
    phase 8 (mig_helper.py compare and identity_stage.py --expected-conf) read it to accept a group the pass cleaned on
    purpose. The runs found the pass's output by globbing pre-upgrade-<group>-*: that also matches the directories of a
    group whose name starts with "<group>-" (acme and acme-audit), and counts default's agent.conf, which is never uploaded."""
    import hashlib
    import time
    p = os.path.join(work, UPLOADED)
    try:
        d = json.load(open(p))
    except (OSError, ValueError):
        d = {}
    d[group] = {"agent_conf": os.path.relpath(conf, work), "sha256": hashlib.sha256(open(conf, "rb").read()).hexdigest(),
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(p + ".tmp", "w") as f:
        json.dump(d, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(p + ".tmp", p)


def upload_group_conf(group, data):
    sys.path.insert(0, HERE)
    import mig_helper as mh
    api = mh.Api(mh.api_password5())
    return api.call("PUT", "/groups/%s/configuration" % group, body=data, headers={"Content-Type": "application/xml"})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    for x in ("--v4", "--stock", "--decisions", "--work"):
        p.add_argument(x, required=True)
    p.add_argument("--base")
    p.add_argument("--groups")
    p = sub.add_parser("convert")
    for x in ("--v4", "--stock", "--base", "--decisions", "--out"):
        p.add_argument(x, required=True)
    p = sub.add_parser("apply")
    for x in ("--candidate", "--saved", "--targets", "--check-cmd"):
        p.add_argument(x, required=True)
    p.add_argument("--validate-cmd")
    p = sub.add_parser("restore")
    for x in ("--saved", "--targets"):
        p.add_argument(x, required=True)
    p = sub.add_parser("groups")
    p.add_argument("--phase", choices=("pre-upgrade", "post-upgrade"), required=True)
    for x in ("--groups", "--decisions", "--work", "--shared"):
        p.add_argument(x, required=True)
    p.add_argument("--versions", help='JSON {group: {agent id: version}} (post-upgrade)')
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("cluster-base")
    for x in ("--base-from", "--out", "--node-name", "--master"):
        p.add_argument(x, required=True)
    p.add_argument("--node-type", choices=("master", "worker"), required=True)
    a = ap.parse_args(argv)
    for k in ("v4", "stock", "base", "decisions", "work", "out", "groups", "candidate", "saved", "shared", "base_from"):   # the converter runs in its own directory
        if getattr(a, k, None):
            setattr(a, k, os.path.abspath(getattr(a, k)))
    return {"plan": cmd_plan, "convert": cmd_convert, "apply": cmd_apply, "restore": cmd_restore, "groups": cmd_groups, "cluster-base": cmd_cluster_base}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
