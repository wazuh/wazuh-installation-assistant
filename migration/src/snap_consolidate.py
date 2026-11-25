#!/usr/bin/env python3
"""snap_consolidate.py - arm SC1: the snapshot transport for sites over the shard limit, built for the first time.

A year of daily 4.x indices (3 shards each, about 1,100 shards) cannot be restored into a 5.0 node whose limit is
1,000 shards, and 5.0 does not refuse such a restore itself (T1). So the history is restored ONE MONTH AT A TIME,
each restored daily copy is read with a scroll and sent through the loader's own Python shaping (history_load.load_index:
the corrected field map, the group stamp, the breaker guard; OF1, decision 9) into its monthly indices, and the
restored copies are deleted before the next month is restored. The template is H1's (history_load.build_template:
5.0 types from the installed findings template, the 4.x mappings under legacy.alert). Same target names, same ids
("<source index>:<source _id>"), same aliases, so the three transports give the same documents.

  4.x side (read only, besides the snapshot):
    snap_consolidate.py export-meta --url https://v4.indexer:9200 --meta DIR        4.x mappings and counts (the assess step)
    snap_consolidate.py snapshot    --url https://v4.indexer:9200 --repo-path /mnt/snapshots/sc1 --snapshot NAME
  5.0 side:
    snap_consolidate.py consolidate --url https://v5.indexer:9200 --meta DIR --repo-path /var/lib/wazuh-indexer/backup/sc1
                        --snapshot NAME [--agent-registry FILE] [--parallel 3] [--months 2026.01,...]
    snap_consolidate.py prove ...   (H1's prove: per source index counts and the shape checks)

consolidate is resumable: a month whose two targets already hold the manifest count is finished only; restored
daily copies left by an interrupted run are reused when complete and deleted when not (a killed restore leaves red
indices: T1 11b). Every step logs the cluster's shard count, and before each restore the tool refuses if the
month would take the node above --shard-ceiling of its limit.
Python 3 standard library only (plus history_load.py and history_migrate.py beside this file).
"""
import argparse, json, os, re, sys, threading, time, urllib.parse
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import history_load as hl          # noqa: E402  (merged: H5/M3 loader; was H1's loader: Bundle, build_template, pipeline_body, State, prove)
hm = hl.hm                         # S4's history_migrate.py: Api, policy_body, detect_cluster

REPO = "sc1-history"
DROP = {"uuid", "creation_date", "provided_name", "version", "resize", "routing", "history", "blocks",
        "verified_before_close", "creation_date_string"}


def default_procs():
    """PERF1: the process count the flow uses for the history's shaping (migrate.sh HISTORY_PROCS)."""
    return max(1, min(8, (os.cpu_count() or 2) // 2))


def out(m):
    print(time.strftime("%H:%M:%S ") + m, flush=True)


def must(res, what):
    s, o = res
    if s not in (200, 201):
        raise SystemExit("ERROR %s: HTTP %s %s" % (what, s, json.dumps(o)[:1200]))
    return o


def shards(api):
    h = must(api("GET", "/_cluster/health"), "health")
    return h["active_shards"] + h["unassigned_shards"] + h["initializing_shards"], h["status"]


def shard_limit(api):
    _, cs = api("GET", "/_cluster/settings?include_defaults=true&flat_settings=true&filter_path=**.cluster.max_shards_per_node")
    merged = {}
    for k in ("defaults", "persistent", "transient"):
        merged.update((cs or {}).get(k, {}))
    h = must(api("GET", "/_cluster/health"), "health")
    return int(next(iter(merged.values()), 1000)) * max(h.get("number_of_data_nodes", 1), 1)


# ------------------------------------------------------------------------------------------------ 4.x side
def cmd_export_meta(api, a):
    """The per-index metadata dump.py writes into a bundle (settings, mappings, counts), without the documents:
    what the assess phase reads on 4.x anyway. H1's Bundle class reads it as a bundle with no files."""
    os.makedirs(os.path.join(a.meta, "indices"), mode=0o700, exist_ok=True)
    must(api("POST", "/%s/_refresh" % a.indices), "refresh")
    cat = must(api("GET", "/_cat/indices/%s?format=json&h=index,docs.count,pri&expand_wildcards=open&s=index" % a.indices), "list")
    _, info = api("GET", "/")
    man = {"format": 1, "bundle_id": "snap-%s-%d" % (info["cluster_uuid"][:8], int(time.time())), "indices": {},
           "source": {"cluster_uuid": info["cluster_uuid"]}, "kind": "metadata-only (SC1 snapshot transport)"}
    for x in cat:
        n = x["index"]
        m = must(api("GET", "/" + n), "get " + n)[n]
        s = dict(m["settings"]["index"])
        ent = {"version_created": s["version"]["created"], "shards": int(s["number_of_shards"]),
               "settings": {"index": {k: v for k, v in s.items() if k not in DROP}}, "mappings": m["mappings"], "aliases": m.get("aliases", {})}
        hl.write_json(os.path.join(a.meta, "indices", n + ".json"), ent)
        man["indices"][n] = {"files": [], "docs_expected": int(x["docs.count"]), "complete": True, "version_created": ent["version_created"]}
    hl.write_json(os.path.join(a.meta, "manifest.json"), man)
    out("export-meta: %d indices, %d documents, metadata in %s" % (len(cat), sum(int(x["docs.count"]) for x in cat), a.meta))
    return 0


def cmd_snapshot(api, a):
    T0 = time.time()
    must(api("PUT", "/_snapshot/%s" % REPO, {"type": "fs", "settings": {"location": a.repo_path, "compress": False}}), "register repository")
    s, o = api("GET", "/_snapshot/%s/%s" % (REPO, a.snapshot))
    if s == 200 and o.get("snapshots") and o["snapshots"][0]["state"] == "SUCCESS":
        out("snapshot %s already complete" % a.snapshot)
        return 0
    must(api("PUT", "/_snapshot/%s/%s?wait_for_completion=false" % (REPO, a.snapshot),
             {"indices": a.indices, "include_global_state": False, "ignore_unavailable": False}), "start snapshot")
    while True:
        time.sleep(15)
        s, o = api("GET", "/_snapshot/%s/%s/_status" % (REPO, a.snapshot), timeout=120)
        st = (o.get("snapshots") or [{}])[0] if s == 200 else {}
        sh = st.get("shards_stats", {})
        stats = st.get("stats", {})
        out("snapshot %s: %s, shards %s/%s done, %.1f GB of %.1f GB" % (a.snapshot, st.get("state"), sh.get("done"), sh.get("total"),
            stats.get("processed", {}).get("size_in_bytes", 0) / 1e9, stats.get("total", {}).get("size_in_bytes", 0) / 1e9))
        if st.get("state") in ("SUCCESS", "FAILED", "PARTIAL"):
            break
    o = must(api("GET", "/_snapshot/%s/%s" % (REPO, a.snapshot)), "snapshot info")["snapshots"][0]
    out("snapshot %s: %s, %d indices, %d shards (%d failed), %.1f s" % (a.snapshot, o["state"], len(o["indices"]),
        o["shards"]["total"], o["shards"]["failed"], time.time() - T0))
    return 0 if o["state"] == "SUCCESS" else 3


# ------------------------------------------------------------------------------------------------ 5.0 side
def per_source_counts(api, months_srcs):
    api("POST", "/%s/_refresh?ignore_unavailable=true&allow_no_indices=true" % hl.ALL)
    s, o = api("POST", "/%s/_search?ignore_unavailable=true&allow_no_indices=true" % hl.ALL,
               {"size": 0, "query": {"terms": {"legacy.index": months_srcs}}, "aggs": {"i": {"terms": {"field": "legacy.index", "size": 5000}}}})
    return {b["key"]: b["doc_count"] for b in o.get("aggregations", {}).get("i", {}).get("buckets", [])} if s == 200 else {}


def cmd_consolidate(api, a):
    # OF1 (decision 9, 2026-11-24: shaping stays in Python): each restored 4.x daily copy is read with a scroll and
    # sent through the loader's own Python shaping (history_load.load_index, the corrected field map), not reindexed
    # through an ingest pipeline. Before OF1 this refused: the canonical loader leaves that pipeline empty.
    import snapshot_repo  # rule 1 / H6: the repository location
    if a.repo_path:
        ok, why = snapshot_repo.check_path(a.repo_path)
        if not ok:
            raise SystemExit("REFUSED repository: " + why)
    T0 = time.time()
    b = hl.Bundle(a.meta)
    months = {k: v for k, v in b.months.items() if not a.months or k in a.months.split(",")}
    limit = shard_limit(api)
    have, status = shards(api)
    widest = max(sum(b.ent(n)["shards"] for n in m["srcs"]) for m in months.values())
    out("history: %d months, %d source indices, %d documents; shards now %d (%s), limit %d; the widest month restores %d shards" % (
        len(months), sum(len(m["srcs"]) for m in months.values()), sum(m["docs"] for m in months.values()), have, status, limit, widest))
    if have + widest + 2 * len(b.months) > a.shard_ceiling * limit:
        raise SystemExit("REFUSE: one month (%d shards) plus the %d targets would take the node above %.0f%% of its limit (%d now)" % (
            widest, 2 * len(b.months), 100 * a.shard_ceiling, have))
    # repository: read only on 5.0 (the 4.x indexer wrote it as another uid: T1 3a)
    rs = {"location": a.repo_path, "readonly": True}
    if a.restore_rate:
        rs["max_restore_bytes_per_sec"] = a.restore_rate
    must(api("PUT", "/_snapshot/%s" % REPO, {"type": "fs", "settings": rs}), "register repository")
    if a.restore_rate:
        # restores are recoveries: the node-wide recovery throttle (40 MiB/s by default) caps them too. Transient,
        # and put back to its default at the end of the run.
        must(api("PUT", "/_cluster/settings", {"transient": {"indices.recovery.max_bytes_per_sec": a.restore_rate}}), "recovery throttle")
        out("restore throttle raised for this run: repository max_restore_bytes_per_sec and indices.recovery.max_bytes_per_sec = %s" % a.restore_rate)
    snap = must(api("GET", "/_snapshot/%s/%s" % (REPO, a.snapshot), timeout=300), "read snapshot")["snapshots"][0]
    in_snap = set(snap["indices"])
    missing = [n for m in months.values() for n in m["srcs"] if n not in in_snap]
    if missing:
        raise SystemExit("REFUSE: %d source indices are not in snapshot %s, e.g. %s" % (len(missing), a.snapshot, missing[:3]))
    # the shape: H1's template and the loader's (empty) pipeline, the retention policy (exactly as history_load apply)
    cluster = a.cluster_name or hm.detect_cluster(api)
    if not cluster:
        raise SystemExit("cannot tell the 5.0 cluster name: pass --cluster-name")
    registry = hl.load_registry(a)
    body, nf, copy = hl.build_template(api, b, a.priority, a.agent_ids == "carried", registry)
    must(api("PUT", "/_index_template/%s" % hl.TEMPLATE, body), "PUT template")
    must(api("PUT", "/_ingest/pipeline/%s" % hl.PIPELINE, hl.pipeline_body(cluster, copy, registry)), "PUT pipeline")
    hm.POLICY = hl.POLICY
    s, o = api("GET", "/_plugins/_ism/policies/%s" % hl.POLICY)
    q = "?if_seq_no=%s&if_primary_term=%s" % (o["_seq_no"], o["_primary_term"]) if s == 200 else ""
    must(api("PUT", "/_plugins/_ism/policies/%s%s" % (hl.POLICY, q), hm.policy_body(a)), "PUT policy")
    a.cluster_name = cluster
    out("shape: template %s (%d 5.0 fields + legacy.*), Python shaping with the corrected map, %s, policy %s %s; cluster name %s" % (
        hl.TEMPLATE, nf, "group stamp (%d agents)" % len(registry) if registry else "no group stamp", hl.POLICY, a.retention, cluster))
    timings = []
    for month, x in sorted(months.items()):
        tm = {"month": month, "docs": x["docs"], "indices": len(x["srcs"])}
        main, cloud = hl.MAIN_PREFIX + month, hl.CLOUD_PREFIX + month
        got = per_source_counts(api, x["srcs"])
        if all(got.get(n, 0) == b.man["indices"][n]["docs_expected"] for n in x["srcs"]):
            out("%s: already consolidated (%d documents)" % (month, x["docs"]))
        else:
            # 1. restore the month (reuse complete copies left by an interrupted run, drop incomplete ones)
            t = time.time()
            cat = api("GET", "/_cat/indices/%s?format=json&h=index,health,docs.count&expand_wildcards=all" % ",".join(x["srcs"]))[1]
            present = {r["index"]: r for r in (cat if isinstance(cat, list) else [])}
            todo = []
            for n in x["srcs"]:
                r = present.get(n)
                if r and r["health"] in ("green", "yellow") and r["docs.count"] is not None and int(r["docs.count"]) == b.man["indices"][n]["docs_expected"]:
                    continue
                if r:
                    must(api("DELETE", "/" + n), "delete incomplete restored copy " + n)
                    out("  %s: deleted an incomplete restored copy (%s, %s docs)" % (n, r["health"], r["docs.count"]))
                todo.append(n)
            have, status = shards(api)
            need = sum(b.ent(n)["shards"] for n in todo)
            if have + need > a.shard_ceiling * limit:
                raise SystemExit("REFUSE %s: restoring %d shards on top of %d would pass %.0f%% of the limit %d" % (month, need, have, 100 * a.shard_ceiling, limit))
            if todo:
                must(api("POST", "/_snapshot/%s/%s/_restore?wait_for_completion=true" % (REPO, a.snapshot),
                         {"indices": ",".join(todo), "include_global_state": False, "include_aliases": False,
                          "index_settings": {"index.number_of_replicas": 0}}, timeout=7200), "restore " + month)
            must(api("GET", "/_cluster/health/%s?wait_for_status=green&timeout=600s" % ",".join(x["srcs"]), timeout=700), "green " + month)
            peak, status = shards(api)
            tm["restore_s"] = round(time.time() - t, 1)
            tm["shards_peak"] = peak
            out("%s: restored %d daily indices (%d shards) in %.1fs; cluster shards now %d of %d (%s)" % (month, len(todo), need, tm["restore_s"], peak, limit, status))
            # 2. monthly targets, then reindex each restored day through the pipeline
            for dst in (main, cloud):
                if api("HEAD", "/" + dst)[0] != 200:
                    must(api("PUT", "/" + dst, {"settings": {"index.creation_date": x["cd"], "index.refresh_interval": "-1",
                                                            "index.plugins.index_state_management.auto_manage": False}}), "create " + dst)
                else:
                    api("PUT", "/%s/_settings" % dst, {"index.blocks.write": False, "index.refresh_interval": "-1"})
            t = time.time()
            n_total = n_created = n_conf = n_rej = 0
            sdir = a.state_dir or os.path.join(a.meta, "load-state")
            os.makedirs(sdir, mode=0o700, exist_ok=True)
            rej = {"lock": threading.Lock(), "f": open(os.path.join(sdir, "rejected.ndjson"), "a")}
            order = sorted(x["srcs"], key=lambda n: -b.man["indices"][n]["docs_expected"])
            procs = getattr(a, "procs", 0)
            if procs:   # PERF1: the shaping in processes, as history_load.py --procs (threads cap near 1-2k docs/s: the GIL)
                import multiprocessing
                hl.DOWN = hl.Down(shared=True)
                ex = ProcessPoolExecutor(procs, mp_context=multiprocessing.get_context("fork"), initializer=hl._die_with_parent)
                futs = [ex.submit(hl.load_index_proc, a, b, n) for n in order]
            else:
                ex = ThreadPoolExecutor(a.parallel)
                futs = [ex.submit(hl.load_index, a, b, n, rej) for n in order]
            with ex:
                for f in as_completed(futs):
                    r_ = f.result()
                    src, st = r_[0], r_[1]
                    if procs and r_[2]:
                        rej["f"].write(r_[2]); rej["f"].flush()
                    n_total += st["docs"]; n_created += st["created"]; n_conf += st["existing"]; n_rej += st["rejected"]
                    if a.verbose:
                        out("  %s: %d read, %d created, %d already there, %d rejected" % (src, st["docs"], st["created"], st["existing"], st["rejected"]))
            rej["f"].close()
            if n_rej:
                raise SystemExit("ERROR %s: %d document(s) rejected by the indexer (see %s); the restored copies are kept" % (month, n_rej, rej["f"].name))
            tm["reindex_s"] = round(time.time() - t, 1)
            out("%s: shaped and loaded %d documents (%d created, %d already there) in %.1fs = %.0f docs/s" % (
                month, n_total, n_created, n_conf, tm["reindex_s"], n_total / max(tm["reindex_s"], 0.001)))
            # 3. prove the month per source index, then drop the restored copies
            got = per_source_counts(api, x["srcs"])
            bad = [(n, b.man["indices"][n]["docs_expected"], got.get(n, 0)) for n in x["srcs"] if got.get(n, 0) != b.man["indices"][n]["docs_expected"]]
            if bad:
                raise SystemExit("ERROR %s: %d source indices differ after the reindex, e.g. %s. The restored copies are kept; rerun consolidate." % (month, len(bad), bad[:3]))
            t = time.time()
            must(api("DELETE", "/" + ",".join(x["srcs"])), "delete restored " + month)
            tm["delete_s"] = round(time.time() - t, 1)
            have, status = shards(api)
            out("%s: every source index has its exact count; restored copies deleted in %.1fs; cluster shards %d (%s)" % (month, tm["delete_s"], have, status))
        # 4. finish the month's targets (as history_load apply does)
        t = time.time()
        for dst in (main, cloud):
            if api("HEAD", "/" + dst)[0] != 200:
                continue
            api("POST", "/%s/_refresh" % dst)
            if hl.count(api, dst) == 0:
                api("DELETE", "/" + dst)
                continue
            api("PUT", "/%s/_settings" % dst, {"index.refresh_interval": "5s"})
            if a.forcemerge:
                api("POST", "/%s/_forcemerge?max_num_segments=1" % dst, timeout=7200)
            must(api("PUT", "/%s/_settings" % dst, {"index.blocks.write": True}), "write block " + dst)
            s, ex_ = api("GET", "/_plugins/_ism/explain/%s" % dst)
            cur = (ex_.get(dst) or {}).get("index.plugins.index_state_management.policy_id") if s == 200 else None
            if cur and cur != hl.POLICY:
                api("POST", "/_plugins/_ism/remove/%s" % dst)
            if cur != hl.POLICY:
                api("POST", "/_plugins/_ism/add/%s" % dst, {"policy_id": hl.POLICY})
        tm["finish_s"] = round(time.time() - t, 1)
        out("%s: finished (refresh, %sblock, retention) in %.1fs" % (month, "force merge, " if a.forcemerge else "", tm["finish_s"]))
        timings.append(tm)
        if a.timings:
            hl.write_json(a.timings, {"months": timings, "elapsed_s": round(time.time() - T0, 1)})
    if a.restore_rate:
        api("PUT", "/_cluster/settings", {"transient": {"indices.recovery.max_bytes_per_sec": None}})
        out("recovery throttle put back to its default")
    out("consolidate finished in %.1fs (%.0f docs/s end to end)" % (time.time() - T0, sum(m["docs"] for m in months.values()) / max(time.time() - T0, 0.001)))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["export-meta", "snapshot", "consolidate", "prove", "on", "off", "status"])
    ap.add_argument("--url", required=True); ap.add_argument("--user", default="admin"); ap.add_argument("--password")
    ap.add_argument("--cacert"); ap.add_argument("--cert"); ap.add_argument("--key"); ap.add_argument("--resolve", action="append")
    ap.add_argument("--meta", help="metadata directory (export-meta writes it, consolidate reads it)")
    ap.add_argument("--indices", default="wazuh-alerts-4.x-*")
    ap.add_argument("--repo-path"); ap.add_argument("--snapshot", default="sc1-full")
    ap.add_argument("--months"); ap.add_argument("--parallel", type=int, default=3, help="reindex requests at once (each sliced per shard)")
    ap.add_argument("--slices", default="auto"); ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--shard-ceiling", type=float, default=0.9)
    ap.add_argument("--restore-rate", help="e.g. 2gb: raise the restore and recovery throttles for the run (default: stock, 40 MiB/s)")
    ap.add_argument("--cluster-name"); ap.add_argument("--agent-ids", choices=["carried", "not-carried"], default="carried")
    ap.add_argument("--agent-registry"); ap.add_argument("--retention", default="365d"); ap.add_argument("--priority", type=int, default=500)
    ap.add_argument("--no-forcemerge", dest="forcemerge", action="store_false"); ap.add_argument("--timings")
    ap.add_argument("--state-dir"); ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--bulk-docs", type=int, default=2000); ap.add_argument("--bulk-bytes", type=int, default=8 << 20)
    ap.add_argument("--breaker-max", type=float, default=0.85); ap.add_argument("--breaker-wait-max", type=float, default=1800)
    # PERF1: shaping processes, the flow's default (migrate.sh HISTORY_PROCS: half the CPUs, 1 to 8); 0 = --parallel threads
    ap.add_argument("--procs", type=int, default=default_procs(), help="shape in N processes (default: half the CPUs, 1 to 8, as the flow); 0: --parallel threads")
    a = ap.parse_args()
    api = hm.Api(a)
    if a.cmd == "export-meta":
        sys.exit(cmd_export_meta(api, a))
    if a.cmd == "snapshot":
        sys.exit(cmd_snapshot(api, a))
    if a.cmd == "consolidate":
        sys.exit(cmd_consolidate(api, a))
    b = hl.Bundle(a.meta)
    a.state_dir = a.state_dir or os.path.join(a.meta, "load-state")
    sys.exit({"prove": hl.cmd_prove, "on": hl.cmd_on, "off": hl.cmd_off, "status": hl.cmd_status}[a.cmd](api, a, b))


if __name__ == "__main__":
    main()
