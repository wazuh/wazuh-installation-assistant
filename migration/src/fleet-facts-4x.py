#!/usr/bin/env python3
"""fleet-facts-4x.py - capture, on the running 4.x manager, the per-agent facts that predict
whether a remote upgrade to 5.0 will work and that a 5.0 manager can no longer answer.

Run it BEFORE the 4.x manager is stopped for the migration. It only reads (GET requests).

What it records per agent (output: one JSON file, see --out):
  dialed      the manager address(es) the agent has in <client><server><address>, from the agent's
              live configuration (GET /agents/{id}/config/agent/client). The 5.0 listener
              certificate must carry every one of them in its subjectAltName.
  protocol    tcp/udp of the legacy session
  upgrade_module  the agent's own <agent-upgrade> block (enabled, ca_verification)
  openssl / curl  whether the inventory lists the package (Linux); without the openssl command
              a remote upgrade ends "upgraded but verifying nothing"
  version, os, arch, groups, status, lastKeepAlive  as the 4.x manager knew them
  client, buffer, labels  (arm ag1) the agent's whole live <client>, <client_buffer> and <labels>
              blocks: the input of the ossec.conf conversion to 5.0. A 5.0 manager cannot read them
              (GET /agents/{id}/config/... answers 404 for a 5.0 manager), so they exist only here.

Python standard library only.

  WAZUH_API_PASSWORD=... ./fleet-facts-4x.py --api https://localhost:55000 --user wazuh --insecure --out fleet-facts.json
"""
import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


STATS = {"calls": 0, "throttled": 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="https://localhost:55000")
    ap.add_argument("--user", default="wazuh")
    ap.add_argument("--password-file", help="file holding the API password; default: env WAZUH_API_PASSWORD")
    ap.add_argument("--ca", help="CA bundle to verify the API certificate")
    ap.add_argument("--insecure", action="store_true", help="do not verify the API certificate (4.x ships a self-signed one)")
    ap.add_argument("--out", default="fleet-facts.json")
    a = ap.parse_args()

    pw = open(a.password_file).read().strip() if a.password_file else os.environ.get("WAZUH_API_PASSWORD")
    if not pw:
        sys.exit("no API password: set WAZUH_API_PASSWORD or --password-file")
    if a.insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context(cafile=a.ca)

    def call(path, token=None, basic=None, method="GET"):
        req = urllib.request.Request(a.api + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if basic:
            req.add_header("Authorization", "Basic " + base64.b64encode(basic.encode()).decode())
        # (arm ag1) The 4.x API allows 300 requests per minute by default (api.yaml
        # access.max_request_per_minute) and answers HTTP 429 / error 6001 beyond it. Six calls per
        # agent reach that at 50 agents, so the capture waits and retries instead of recording the
        # refusal as the agent's configuration.
        for attempt in range(30):
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                    body = r.read().decode()
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                if e.code == 429 or '"error": 6001' in body or "Maximum number of requests per minute" in body:
                    STATS["throttled"] += 1
                    time.sleep(5)
                    continue
            break
        STATS["calls"] += 1
        try:
            return json.loads(body)
        except ValueError:
            return {"error": -1, "raw": body}

    token = call("/security/user/authenticate", basic=f"{a.user}:{pw}", method="POST").get("data", {}).get("token")
    if not token:
        sys.exit("authentication failed")

    agents, offset = [], 0
    while True:
        r = call(f"/agents?limit=500&offset={offset}&select=id,name,version,status,group,ip,registerIP,"
                 "lastKeepAlive,os.platform,os.name,os.version,os.major,os.minor,os.arch,os.uname", token)
        items = r["data"]["affected_items"]
        agents += items
        offset += len(items)
        if offset >= r["data"]["total_affected_items"] or not items:
            break

    facts = {"captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source_api": a.api, "agents": {}}
    for ag in agents:
        if ag["id"] == "000":
            continue
        f = {"name": ag["name"], "version": ag.get("version"), "status": ag.get("status"),
             "groups": ag.get("group", []), "ip": ag.get("ip"), "os": ag.get("os", {}),
             "lastKeepAlive": ag.get("lastKeepAlive"), "dialed": [], "protocol": [], "notes": []}
        if ag.get("status") == "active":
            c = call(f"/agents/{ag['id']}/config/agent/client", token)
            servers = (c.get("data") or {}).get("client", {}).get("server", [])
            f["dialed"] = [s.get("address") for s in servers if s.get("address")]
            f["protocol"] = sorted({s.get("protocol", "") for s in servers})
            if not servers:
                f["notes"].append("live client configuration not readable: " + json.dumps(c)[:200])
            f["client"] = (c.get("data") or {}).get("client")
            for comp, conf in (("agent", "buffer"), ("agent", "labels")):
                r2 = call(f"/agents/{ag['id']}/config/{comp}/{conf}", token)
                f[conf] = (r2.get("data") or {}).get(conf) if r2.get("error", 0) == 0 else {"error": r2.get("detail") or r2.get("message")}
            w = call(f"/agents/{ag['id']}/config/wmodules/wmodules", token)
            for m in (w.get("data") or {}).get("wmodules", []):
                if "agent-upgrade" in m:
                    f["upgrade_module"] = m["agent-upgrade"]
        else:
            f["notes"].append("agent not active: live configuration not readable")
        if (ag.get("os") or {}).get("platform") not in ("windows", "darwin"):
            for pkg in ("openssl", "curl"):
                p = call(f"/syscollector/{ag['id']}/packages?name={urllib.parse.quote(pkg)}&select=name,version", token)
                items = (p.get("data") or {}).get("affected_items")
                f[pkg] = (items[0]["version"] if items else None) if items is not None else "unknown"
        facts["agents"][ag["id"]] = f

    facts["capture"] = {"api_calls": STATS["calls"], "throttled_retries": STATS["throttled"]}
    print(f"{STATS['calls']} API calls, {STATS['throttled']} answered 'too many requests' and were retried after 5 s")
    with open(a.out, "w") as fh:
        json.dump(facts, fh, indent=1, sort_keys=True)
    addrs = sorted({d for f in facts["agents"].values() for d in f["dialed"]})
    print(f"{len(facts['agents'])} agents written to {a.out}")
    print("distinct manager addresses the fleet dials:", ", ".join(addrs) or "(none readable)")
    for i, f in sorted(facts["agents"].items()):
        print(f"  {i} {f['name']:<24} {str(f['version']):<16} dials={','.join(f['dialed']) or '?'} "
              f"openssl={f.get('openssl', 'n/a')} curl={f.get('curl', 'n/a')} "
              f"upgrade_module={json.dumps(f.get('upgrade_module', {}))}")


if __name__ == "__main__":
    main()
