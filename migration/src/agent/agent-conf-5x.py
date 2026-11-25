#!/usr/bin/env python3
"""agent-conf-5x.py - bring an upgraded agent's own ossec.conf to the 5.0 shape.

Experiment arm AG1 of the 4.x -> 5.0 migration lab. Python 3 standard library only.

Why: a remote upgrade to 5.0 never rewrites the agent's ossec.conf (pkg_installer.sh and
do_upgrade.ps1 say so, and arm E1 observed it). A 5.0 agent reads only two things out of the 4.x
<client> block: the LAST <server><address> (with port 1517, whatever <port> said) and <enrollment>.
Everything else in <client> is ignored and logged at every start: <config-profile> (so every
<agent_config profile="..."> block in the group configuration stops applying), <notify_time>,
<auto_restart> (an agent that had "no" starts restarting itself on every pushed change), and the
other managers of a multi-address agent (5.0 has no failover). The group configuration cannot carry
any of them: in agent.conf the <agent> block accepts only <batch>.

What it does, on the endpoint (or on a copy of the file, for configuration management):
  1. refuses unless the installed agent is 5.x (a 4.x agent does not start with an <agent> block),
  2. rewrites the first <client> block as <agent>: <manager><endpoint> (one address, see --endpoint),
     <config-profile>, <notify_time>, <auto_restart>, and the <enrollment> options 5.0 still reads,
  3. drops what 5.0 ignores and says so: <client_buffer>, <time-reconnect>, <crypto_method>,
     <ip_update_interval>, <force_reconnect_interval>, the 4.x <enrollment> transport options,
     syscheck <scan_on_start> and <max_eps>, the rootcheck file options, the cis-cat and osquery wodles,
  4. keeps a backup next to the file, validates with the agent's own parser where it can
     (wazuh-agentd -t), restores the backup if validation fails, and restarts the agent (--restart).

Idempotent: a file that already has <agent><manager> and no <client> is left alone (exit 0).

Exit codes: 0 converted or nothing to do; 2 refused (agent not 5.x, or several manager addresses and
no --endpoint/--endpoint-policy); 3 validation failed and the backup was restored; 1 other error.

  sudo python3 agent-conf-5x.py                          # Linux/macOS endpoint, in place, no restart
  sudo python3 agent-conf-5x.py --restart --endpoint wazuh.example.com
  python3 agent-conf-5x.py --file ossec.conf --out ossec.conf.5x --assume-5x   # offline (Windows CM, review)
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

KEEP_IN_AGENT = ("config-profile", "notify_time", "auto_restart")
DROPPED_IN_CLIENT = ("time-reconnect", "crypto_method", "ip_update_interval", "force_reconnect_interval", "remote_conf")
ENROLL_KEEP = ("enabled", "agent_name", "groups", "agent_address", "delay_after_enrollment", "use_source_ip",
               "authorization_pass_path")
ENROLL_DROPPED = ("manager_address", "port", "ssl_cipher", "server_ca_path", "agent_certificate_path",
                  "agent_key_path", "auto_method")


def tag(block, name):
    m = re.search(rf"<{re.escape(name)}>\s*(.*?)\s*</{re.escape(name)}>", block, re.S)
    return m.group(1) if m else None


def strip_comments(s):
    return re.sub(r"<!--.*?-->", "", s, flags=re.S)


def installed_version(home):
    for p in (os.path.join(home, "VERSION.json"), os.path.join(home, "VERSION")):
        if os.path.exists(p):
            txt = open(p, errors="replace").read()
            m = re.search(r"(\d+)\.(\d+)\.(\d+)", txt)
            if m:
                return tuple(int(x) for x in m.groups())
    return None


def convert(text, endpoint=None, policy=None, https_port=None):
    """Returns (new_text, report). report['refused'] is set when a decision is missing."""
    report = {"changes": [], "dropped": {}, "kept": {}, "refused": None}
    live = strip_comments(text)
    if "<client>" not in live:
        if re.search(r"<agent>\s*.*?<manager>", live, re.S):
            report["changes"].append("already in the 5.0 shape (<agent><manager>, no <client>): nothing to do")
        else:
            report["changes"].append("no <client> block: nothing to do")
        return text, report
    m = re.search(r"([ \t]*)<client>(.*?)</client>", text, re.S)
    indent, body = m.group(1), m.group(2)
    body_live = strip_comments(body)
    servers = re.findall(r"<server>(.*?)</server>", body_live, re.S)
    addrs = [tag(s, "address") for s in servers if tag(s, "address")]
    ports = [tag(s, "port") for s in servers]
    report["kept"]["servers_4x"] = [{"address": a, "port": p, "protocol": tag(s, "protocol")} for a, p, s in zip(addrs, ports, servers)]
    if endpoint:
        chosen = endpoint
    elif len(addrs) == 1:
        chosen = addrs[0]
    elif len(addrs) > 1 and policy in ("first", "last"):
        chosen = addrs[0] if policy == "first" else addrs[-1]
    elif len(addrs) > 1:
        report["refused"] = (f"{len(addrs)} manager addresses ({', '.join(addrs)}): 5.0 has no failover and dials only the "
                             f"last one ('{addrs[-1]}'). Name the one address that reaches every manager node "
                             "(a load balancer or DNS name in the listener certificate) with --endpoint, or accept "
                             "--endpoint-policy last (what the agent does today) or first")
        return text, report
    else:
        report["refused"] = "the <client> block names no <server><address>"
        return text, report
    if ":" not in chosen.strip("[]") and https_port:
        chosen = f"{chosen}:{https_port}"
    if len(addrs) > 1:
        report["dropped"]["other_managers"] = [a for a in addrs if a != chosen.split(":")[0]]
    for p in ports:
        if p and p not in ("1514",):
            report["dropped"].setdefault("server_port", []).append(f"{p} (a 4.x legacy port; 5.0 dials the HTTPS port)")
    lines = [f"{indent}<agent>", f"{indent}  <manager>", f"{indent}    <endpoint>{chosen}</endpoint>", f"{indent}  </manager>"]
    for k in KEEP_IN_AGENT:
        v = tag(body_live, k)
        if v is not None:
            lines.append(f"{indent}  <{k}>{v}</{k}>")
            report["kept"][k] = v
    for k in DROPPED_IN_CLIENT:
        v = tag(body_live, k)
        if v is not None:
            report["dropped"][k] = v
    enr = tag(body_live, "enrollment")
    if enr is not None:
        sub = []
        for k in ENROLL_KEEP:
            v = tag(enr, k)
            if k == "authorization_pass_path" and v in ("etc/authd.pass", "authd.pass"):
                # the 4.x installer writes the compiled default explicitly; 5.0 deletes that file at the upgrade and
                # treats an explicit path as operator-owned, so keeping it would point at a file that is gone
                report["dropped"]["enrollment/authorization_pass_path"] = f"{v} (4.x default, file removed by the 5.0 upgrade)"
                continue
            if v is not None:
                sub.append(f"{indent}    <{k}>{v}</{k}>")
        for k in ENROLL_DROPPED:
            v = tag(enr, k)
            if v is not None:
                report["dropped"][f"enrollment/{k}"] = v
        if sub:
            lines += [f"{indent}  <enrollment>"] + sub + [f"{indent}  </enrollment>"]
            report["kept"]["enrollment"] = [s.strip() for s in sub]
    lines.append(f"{indent}</agent>")
    new = text[:m.start()] + "\n".join(lines) + text[m.end():]
    report["changes"].append(f"<client> rewritten as <agent> with <manager><endpoint>{chosen}</endpoint>")

    # sections and options a 5.0 agent ignores and logs at every start
    def drop_block(rx, label):
        nonlocal new
        found = re.findall(rx, new, re.S)
        if found:
            new = re.sub(r"[ \t]*" + rx + r"[ \t]*\n?", "", new, flags=re.S)
            report["dropped"][label] = len(found)
    drop_block(r"<client_buffer>.*?</client_buffer>", "client_buffer (5.0 batches events itself; <agent><batch> if tuning is needed)")
    drop_block(r'<wodle name="cis-cat">.*?</wodle>', "wodle cis-cat")
    drop_block(r'<wodle name="osquery">.*?</wodle>', "wodle osquery")
    for opt in ("scan_on_start", "max_eps"):
        sc = re.search(r"<syscheck>.*?</syscheck>", new, re.S)
        if sc and re.search(rf"<{opt}>", sc.group(0)):
            # only the top-level option: <synchronization><max_eps> is still read
            parts = re.split(r"(<synchronization>.*?</synchronization>)", sc.group(0), flags=re.S)
            parts = [p if p.startswith("<synchronization>") else re.sub(rf"[ \t]*<{opt}>[^<]*</{opt}>[ \t]*\n?", "", p) for p in parts]
            blk = "".join(parts)
            if blk != sc.group(0):
                new = new[:sc.start()] + blk + new[sc.end():]
                report["dropped"][f"syscheck/{opt}"] = "no longer has any effect"
    for opt in ("check_files", "check_trojans", "rootkit_files", "rootkit_trojans"):
        rc = re.search(r"<rootcheck>.*?</rootcheck>", new, re.S)
        if rc and re.search(rf"<{opt}>", rc.group(0)):
            blk = re.sub(rf"[ \t]*<{opt}>[^<]*</{opt}>[ \t]*\n?", "", rc.group(0))
            new = new[:rc.start()] + blk + new[rc.end():]
            report["dropped"][f"rootcheck/{opt}"] = "no longer supported"
    return new, report


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--home", default="/var/ossec", help="agent installation directory")
    ap.add_argument("--file", help="ossec.conf to convert (default <home>/etc/ossec.conf)")
    ap.add_argument("--out", help="write here instead of in place (offline mode; nothing is restarted)")
    ap.add_argument("--endpoint", help="the one manager address (host[:port][/prefix]) a multi-address agent dials after conversion")
    ap.add_argument("--endpoint-policy", choices=["first", "last"], help="for multi-address agents without --endpoint")
    ap.add_argument("--https-port", help="append this port to the endpoint (default: none, the agent's 1517)")
    ap.add_argument("--assume-5x", action="store_true", help="skip the installed-version check (offline conversion)")
    ap.add_argument("--restart", action="store_true", help="restart the agent after a validated in-place conversion")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args()
    path = a.file or os.path.join(a.home, "etc", "ossec.conf")
    if not a.assume_5x and not a.out:
        v = installed_version(a.home)
        if not v or v < (5, 0, 0):
            print(f"refused: the installed agent is {'.'.join(map(str, v)) if v else 'unknown'}; a 4.x agent does not start "
                  "with an <agent> block. Convert after the upgrade.")
            sys.exit(2)
    text = open(path, errors="replace").read()
    new, rep = convert(text, a.endpoint, a.endpoint_policy, a.https_port)
    rep["file"] = path
    if rep["refused"]:
        print(json.dumps(rep, indent=1) if a.json else f"refused: {rep['refused']}")
        sys.exit(2)
    if new == text:
        print(json.dumps(rep, indent=1) if a.json else rep["changes"][0])
        sys.exit(0)
    if a.out:
        open(a.out, "w").write(new)
        rep["written"] = a.out
        print(json.dumps(rep, indent=1) if a.json else f"written to {a.out}: {rep}")
        sys.exit(0)
    backup = f"{path}.4x-backup-{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(path, backup)
    st = os.stat(path)
    tmp = path + ".5x.tmp"
    with open(tmp, "w") as fh:
        fh.write(new)
    os.chmod(tmp, st.st_mode)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except (AttributeError, PermissionError):
        pass
    os.replace(tmp, path)
    rep["backup"] = backup
    agentd = os.path.join(a.home, "bin", "wazuh-agentd")
    if os.path.exists(agentd):
        r = subprocess.run([agentd, "-t"], capture_output=True, text=True)
        rep["validation"] = {"rc": r.returncode, "output": (r.stdout + r.stderr).strip()[-600:]}
        if r.returncode != 0:
            shutil.copy2(backup, path)
            rep["restored"] = True
            print(json.dumps(rep, indent=1))
            sys.exit(3)
    if a.restart:
        if shutil.which("systemctl") and os.path.isdir("/run/systemd/system"):
            r = subprocess.run(["systemctl", "restart", "wazuh-agent"], capture_output=True, text=True)
        else:
            r = subprocess.run([os.path.join(a.home, "bin", "wazuh-control"), "restart"], capture_output=True, text=True)
        rep["restart"] = {"rc": r.returncode, "output": (r.stdout + r.stderr).strip()[-300:]}
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
