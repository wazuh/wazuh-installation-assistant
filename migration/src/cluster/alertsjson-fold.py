#!/usr/bin/env python3
"""alertsjson-fold.py - orders B and C (indexers replaced while the 4.x managers keep running).

The alerts a 4.x manager writes while no 4.x indexer is there to take them exist only in that node's
/var/ossec/logs/alerts/alerts.json; the history dump, which reads the indexer, never sees them. This reads the part of
alerts.json that Filebeat had NOT shipped (from the byte offset in Filebeat's registry) and writes a bulk file for the
5.0 history index.  It is NOT a faithful copy of what Filebeat plus the 4.x ingest pipeline would have stored: no
GeoLocation, and only @timestamp and input.type are added.  Document ids are 'YYYY.MM.DD:aj-<node>-<alert id>'.

  alertsjson-fold.py plan  <alerts.json> <filebeat-registry-log.json>          -> offset, bytes and lines not shipped
  alertsjson-fold.py bulk  <alerts.json> <offset> <node-name> <out.ndjson.gz>  -> bulk file (index: wazuh-alerts-4.x-YYYY.MM)
  alertsjson-fold.py load  <out.ndjson.gz> <url> <user> <cafile>               (password in env IDX_PASS)
  alertsjson-fold.py dumpfold <alerts.json> <offset> <node-name> <label> <out-dir>
  alertsjson-fold.py merge <fold-dir> <history-bundle-dir>

CL1 (the guide's unchecked point a): `bulk` + `load` wrote these alerts into wazuh-alerts-4.x-YYYY.MM on 5.0, which
none of the history's aliases (wazuh-findings-v5-legacy-4x over wazuh-legacy-4x-alerts-*) covers, unshaped: they did not
show in the 5.0 screens with the rest of the old alerts. `dumpfold` writes them in the history dump's own format
(data/<daily index>/fold-<label>-<k>.ndjson.gz, a metadata line then the alert, one file record each in fold.json) and
`merge` adds them to the master's history bundle (manifest.json: the file records under their daily source index and
its expected count), so history_load.py loads, shapes, proves and switches them on with the rest, and going back
(load_unchanged.py) puts them back into the 4.x daily indices. Ids stay 'aj-<node>-<alert id>' (the same as `bulk`
gives the way back, so a fold loaded both ways is created once). A label already merged is skipped.
"""
import base64, gzip, hashlib, json, os, re, shutil, ssl, sys, urllib.request


def registry_offset(reg, path):
    off = None
    # E2-cluster fix: no Filebeat registry means Filebeat never shipped anything from this node (the master's 4.x
    # reinstall was cut by a reboot before Filebeat first ran, then restored with Filebeat kept stopped): offset 0.
    # The plan crashed instead, the freeze wrote an empty offset record and the fold refused the generation.
    if not os.path.exists(reg):
        return 0
    for line in open(reg, errors="replace"):
        if '"source":"%s"' % path in line:
            try:
                off = json.loads(line)["v"]["offset"]
            except (ValueError, KeyError):
                pass
    return off


def plan(alerts, reg):
    off = registry_offset(reg, alerts) or 0
    size = os.path.getsize(alerts)
    with open(alerts, "rb") as f:
        f.seek(off)
        lines = sum(1 for _ in f)
    print(json.dumps({"alerts_json": alerts, "size": size, "filebeat_offset": off, "bytes_not_shipped": size - off, "lines_not_shipped": lines}))


def bulk(alerts, off, node, out):
    n = 0
    with open(alerts, "rb") as f, gzip.open(out, "wt") as o:
        f.seek(int(off))
        for raw in f:
            try:
                d = json.loads(raw)
            except ValueError:
                continue
            ts = d.get("timestamp", "")            # 2026-11-23T08:39:41.123+0000
            day = ts[:10].replace("-", ".")
            d["@timestamp"] = ts[:23] + "Z" if len(ts) >= 23 else ts
            d.setdefault("input", {"type": "log"})
            o.write(json.dumps({"create": {"_index": "wazuh-alerts-4.x-" + day[:7], "_id": "%s:aj-%s-%s" % (day, node, d.get("id"))}}) + "\n")
            o.write(json.dumps(d, separators=(",", ":")) + "\n")
            n += 1
    print(json.dumps({"bulk_file": out, "documents": n}))


def load(f, url, user, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    auth = "Basic " + base64.b64encode((user + ":" + os.environ["IDX_PASS"]).encode()).decode()
    body = gzip.open(f, "rt").read()
    if not body:
        print(json.dumps({"created": 0, "already_there": 0, "errors": 0}))
        return
    r = urllib.request.Request(url + "/_bulk", data=body.encode(), method="POST", headers={"Content-Type": "application/x-ndjson", "Authorization": auth})
    d = json.load(urllib.request.urlopen(r, context=ctx, timeout=300))
    st = [list(i.values())[0].get("status") for i in d["items"]]
    bad = [i for i in d["items"] if list(i.values())[0].get("status") not in (201, 409)]
    print(json.dumps({"created": st.count(201), "already_there": st.count(409), "errors": len(bad), "first_error": bad[0] if bad else None})[:600])


def dumpfold(alerts, off, node, label, out):
    os.makedirs(out, exist_ok=True)
    per = {}
    with open(alerts, "rb") as f:
        f.seek(int(off))
        for raw in f:
            try:
                d = json.loads(raw)
            except ValueError:
                continue
            ts = d.get("timestamp", "")
            day = ts[:10].replace("-", ".")
            if not re.match(r"^\d{4}\.\d{2}\.\d{2}$", day):
                continue
            d["@timestamp"] = ts[:23] + "Z" if len(ts) >= 23 else ts
            d.setdefault("input", {"type": "log"})
            per.setdefault("wazuh-alerts-4.x-" + day, []).append(({"_id": "aj-%s-%s" % (node, d.get("id"))}, d))
    files = []
    for index, docs in sorted(per.items()):
        rel = os.path.join("data", index, "fold-%s-0.ndjson.gz" % label)
        p = os.path.join(out, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with gzip.open(p, "wb") as g:
            for m, s in docs:
                g.write(json.dumps(m, separators=(",", ":")).encode() + b"\n" + json.dumps(s, separators=(",", ":")).encode() + b"\n")
        data = open(p, "rb").read()
        files.append({"file": rel, "docs": len(docs), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "index": index, "kind": "fold", "run": "fold-" + label})
    json.dump({"label": label, "node": node, "offset": int(off), "files": files}, open(os.path.join(out, "fold.json"), "w"), indent=1)
    print(json.dumps({"fold": label, "documents": sum(f["docs"] for f in files), "indices": sorted(per)}))


def merge(fold, hist):
    """The fold's files into the history bundle; prints the bundle-relative paths it wrote or changed, one per line, after
    a JSON summary line (the caller refreshes the bundle's MANIFEST.sha256 for them)."""
    fj = json.load(open(os.path.join(fold, "fold.json")))
    mp = os.path.join(hist, "manifest.json")
    man = json.load(open(mp))
    run = "fold-" + fj["label"]
    if any(f.get("run") == run for e in man["indices"].values() for f in e.get("files", [])):
        print(json.dumps({"fold": fj["label"], "merged": 0, "note": "already in the history bundle"}))
        return 0
    changed = ["manifest.json"]
    vc = next((e.get("version_created") for e in man["indices"].values() if e.get("version_created")), None)
    newest = max((n for n in man["indices"] if os.path.exists(os.path.join(hist, "indices", n + ".json"))), default=None)
    for f in fj["files"]:
        n = f["index"]
        src, dst = os.path.join(fold, f["file"]), os.path.join(hist, f["file"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        if hashlib.sha256(open(dst, "rb").read()).hexdigest() != f["sha256"]:
            raise SystemExit("merge: %s does not match its checksum after the copy" % dst)
        changed.append(f["file"])
        e = man["indices"].setdefault(n, {"files": [], "docs_expected": 0, "complete": True, "version_created": vc})
        e["files"] = sorted(e.get("files", []) + [f], key=lambda r: r["file"])
        e["docs_expected"] = int(e.get("docs_expected", 0)) + f["docs"]
        meta = os.path.join(hist, "indices", n + ".json")
        if not os.path.exists(meta) and newest:
            # an index the dump never saw (a day after the delta): the newest source index's settings and mappings, without
            # its creation date (the loader then counts the age from the end of this index's own day)
            ent = json.load(open(os.path.join(hist, "indices", newest + ".json")))
            ent.pop("creation_date", None)
            json.dump(ent, open(meta, "w"), indent=1)
            changed.append(os.path.join("indices", n + ".json"))
    tmp = mp + ".tmp"
    json.dump(man, open(tmp, "w"), indent=1)
    os.replace(tmp, mp)
    print(json.dumps({"fold": fj["label"], "merged": sum(f["docs"] for f in fj["files"]), "indices": sorted({f["index"] for f in fj["files"]})}))
    for c in changed:
        print(os.path.join(os.path.basename(os.path.normpath(hist)), c))
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "plan":
        plan(*sys.argv[2:4])
    elif cmd == "bulk":
        bulk(*sys.argv[2:6])
    elif cmd == "load":
        load(*sys.argv[2:6])
    elif cmd == "dumpfold":
        dumpfold(*sys.argv[2:7])
    elif cmd == "merge":
        sys.exit(merge(*sys.argv[2:4]))
    else:
        sys.exit(__doc__)
