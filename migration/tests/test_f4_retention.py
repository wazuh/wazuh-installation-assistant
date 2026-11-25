"""F4: the two retention gaps the E3 fold left.

1. The cluster pre-copy reads the 4.x retention (retention-4x.sh read, before the first dump) and the whole-cluster way
   back puts the 4.x ISM policies back (retention-4x.sh restore4 in k5.sh goback-security), as the all-in-one's
   precopy.retention and back.retention do. history5-master.sh says which retention it loads and why.
2. Restored 4.x alert indices keep their ISM age: dump.py records each index's creation date and load_unchanged.py (the
   reload when going back, all-in-one and cluster) creates the index with it; ism-restore4 names the indices already past
   their delete age and those whose age still counts from a later date.

The 4.x indexer is a fake over plain HTTP in this process (no TLS, no Docker); dump.py and load_unchanged.py run as
their own processes against it."""
import contextlib
import fnmatch
import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import helpers
from test_e2_cluster import NodeSteps, tgz, write
from test_e3_fold import DAYS, DELETE_90, HOLD_60, FakeISM

SRC = helpers.SRC
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "f4_mig_helper")
LU = helpers.load(os.path.join(SRC, "load_unchanged.py"), "f4_load_unchanged")
DUMP = helpers.load(os.path.join(SRC, "dump.py"), "f4_dump")
DAY = 86400000
PASSWORDS = b"  indexer_username: 'admin'\n  indexer_password: 'adminpw'\n"


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


def ms(y, m, d, hh=0, mm=0):
    import calendar
    return calendar.timegm((y, m, d, hh, mm, 0)) * 1000


class Served:
    """A handler function (method, path, body) -> (code, object or None) served over plain HTTP on 127.0.0.1."""

    def __init__(self, fn):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                code, obj = outer.fn(self.command, self.path, raw)
                data = b"" if obj is None or self.command == "HEAD" else json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _do

        self.fn = fn
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def ism_over_http(fake):
    """FakeISM (test_e3_fold) as the 4.x indexer's REST API, for the node script and the real mig_helper.py."""
    def fn(method, path, raw):
        body = json.loads(raw) if raw else None
        p = urllib.parse.unquote(path.split("?")[0])
        if p.endswith("/_settings/index.creation_date"):
            return 200, {i: {"settings": {"index": {"creation_date": str(c)}}} for i, c in getattr(fake, "created", {}).items()}
        return fake(method, path, "x", body)
    return fn


# =============================================================================================== item 1: the cluster
class ClusterReadsAndRestoresThe4xRetention(unittest.TestCase):
    """OF1 O2 and the E3 fold's G4: the cluster pre-copy read no 4.x retention (history5-master.sh loaded 365 days unless
    retention-4x.json was placed by hand) and the cluster way back did not put the ISM policies back."""

    def setUp(self):
        self.n = NodeSteps(SRC)
        self.addCleanup(self.n.close)
        tgz(self.n.env["V4_TAR"], {"wazuh-install-files/wazuh-passwords.txt": PASSWORDS, "wazuh-install-files/root-ca.pem": b"CA"})
        self.src = FakeISM({"wazuh-alert-retention-policy": DELETE_90, "acme-short-hold": HOLD_60},
                           {DAYS[3]: "acme-short-hold", DAYS[4]: "wazuh-alert-retention-policy"}, DAYS)

    def serve(self, fake):
        s = Served(ism_over_http(fake))
        self.addCleanup(s.close)
        return s.url

    def read(self, fake=None):
        return self.n.run("retention-4x.sh", "read", self.serve(fake or self.src))

    def test_read_writes_the_retention_and_the_policies_into_the_masters_bundle(self):
        rc, out = self.read()
        self.assertEqual(rc, 0, out)
        r = json.load(open(os.path.join(self.n.bundle, "retention-4x.json")))
        self.assertEqual(r["retention_days"], 90)
        rec = json.load(open(os.path.join(self.n.bundle, "ism-4x.json")))
        self.assertEqual(rec["attached"], {DAYS[3]: "acme-short-hold", DAYS[4]: "wazuh-alert-retention-policy"})
        for f in ("retention-4x.json", "ism-4x.json"):
            self.assertEqual(os.stat(os.path.join(self.n.bundle, f)).st_mode & 0o077, 0, f)
        self.assertTrue(os.path.exists(os.path.join(self.n.bundle, "state", "retention.read")))
        self.assertIn("4.x retention of the alert indices: 90 days", out)

    def test_a_refused_read_stops_and_writes_nothing_rule_19(self):
        refuse = lambda m, p, pw, body=None, **k: (403, {"error": "no permissions"}) if "/_ism/policies" in p else self.src(m, p, pw, body)
        rc, out = self.read(refuse)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("rule 19", out)
        self.assertFalse(os.path.exists(os.path.join(self.n.bundle, "retention-4x.json")))
        self.assertFalse(os.path.exists(os.path.join(self.n.bundle, "state", "retention.read")))

    def history_argv(self, tree=SRC, **env):
        node = self.n if tree == SRC else NodeSteps(tree)
        if node is not self.n:
            self.addCleanup(node.close)
        fake = os.path.join(node.t, "fakesrc")
        argv = os.path.join(node.t, "argv.json")
        write(os.path.join(fake, "history_load.py"), "import json, sys\njson.dump(sys.argv[1:], open(%r, 'w'))\n" % argv)
        write(os.path.join(node.bundle, "identity", "manifest.json"), json.dumps({"agents": [{"id": 2, "name": "ag1", "groups": ["default"]}]}))
        write(node.p("/etc/wazuh-manager/certs/indexer-ca.pem"), "CA")
        write(node.p("/etc/wazuh-manager/wazuh-manager.conf"), "<cluster>\n<name>wazuh</name>\n</cluster>\n")
        tgz(node.env["V5_TAR"], {"wazuh-install-files/credentials.env": b'WAZUH_INDEXER_ADMIN_PASSWORD="x"\n'})
        rc, out = node.run("history5-master.sh", "https://idx1:9200", "status", env=dict(env, SRC=fake))
        self.assertEqual(rc, 0, out)
        a = json.load(open(argv))
        return a[a.index("--retention") + 1], out

    def test_the_history_loads_the_retention_the_precopy_read_and_says_why(self):
        self.assertEqual(self.read()[0], 0)
        ret, out = self.history_argv()
        self.assertEqual(ret, "90d")
        why = open(os.path.join(self.n.bundle, "state", "history.retention")).read()
        self.assertIn("90d: the 4.x deployment's own retention: ", why)
        for p in ("ISM policy acme-short-hold deletes alert indices after 60 days", "ISM policy wazuh-alert-retention-policy deletes alert indices after 90 days"):
            self.assertIn(p, why)
        self.assertIn("history retention: 90d", out)

    def test_an_explicit_setting_wins_and_a_bundle_without_the_read_says_so(self):
        self.assertEqual(self.read()[0], 0)
        self.assertEqual(self.history_argv(HISTORY_RETENTION="30d")[0], "30d")
        os.unlink(os.path.join(self.n.bundle, "retention-4x.json"))
        ret, out = self.history_argv()
        self.assertEqual(ret, "365d")
        self.assertIn("retention-4x.sh read did not run for this bundle", out)


    def test_the_way_back_puts_the_policies_and_attachments_back(self):
        self.assertEqual(self.read()[0], 0)
        back = FakeISM({}, {}, DAYS)                       # the reinstalled 4.x indexers: no policy, the alerts reloaded
        rc, out = self.n.run("retention-4x.sh", "restore4", self.serve(back))
        self.assertEqual(rc, 0, out)
        self.assertEqual(back.att, self.src.att)
        self.assertEqual(sorted(back.pol), sorted(self.src.pol))
        self.assertTrue(os.path.exists(os.path.join(self.n.bundle, "state", "goback.retention")))
        # the next pre-copy (a new bundle) reads the site's 90 days again, not "none"
        os.unlink(os.path.join(self.n.bundle, "retention-4x.json"))
        self.assertEqual(self.read(back)[0], 0)
        self.assertEqual(json.load(open(os.path.join(self.n.bundle, "retention-4x.json")))["retention_days"], 90)

    def test_a_refused_attachment_fails_the_way_back_step(self):
        self.assertEqual(self.read()[0], 0)
        back = FakeISM({}, {}, DAYS)
        refuse = lambda m, p, pw, body=None, **k: (403, {"error": "forbidden"}) if "/_ism/add/" in p else back(m, p, pw, body)
        rc, out = self.n.run("retention-4x.sh", "restore4", self.serve(refuse))
        self.assertNotEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.n.bundle, "state", "goback.retention")))

    def test_the_helper_talks_to_the_url_and_verifies_with_the_ca(self):
        seen = []
        with mock.patch.dict(os.environ, {"MIG_IDX_URL": "https://10.0.0.1:9200/", "MIG_IDX_CAFILE": "/x/root-ca.pem"}), \
                mock.patch.object(H.ssl, "create_default_context", lambda cafile=None: ("verifying", cafile)), \
                mock.patch.object(H, "jget", lambda m, url, **kw: seen.append((url, kw.get("ctx"))) or (200, {})):
            H.idx("GET", "/_plugins/_ism/policies", "pw")
        self.assertEqual(seen, [("https://10.0.0.1:9200/_plugins/_ism/policies", ("verifying", "/x/root-ca.pem"))])
        with mock.patch.dict(os.environ, {"MIG_IDX5_HOST": "h"}), mock.patch.object(H, "jget", lambda m, url, **kw: seen.append((url, kw.get("ctx"))) or (200, {})):
            os.environ.pop("MIG_IDX_URL", None)
            H.idx("GET", "/", "pw")
        self.assertEqual(seen[-1], ("https://h:9200/", None))   # unchanged without them (all-in-one: loopback, unverified)


class ControllerStagesCallTheRetentionSteps(unittest.TestCase):
    """k5.sh: precopy reads the retention before the first dump (a refused read stops it); goback-security ends with the
    ISM policies, after the indexer security and the dashboards."""


    # CL1: k5.sh calls the cluster command (migrate-cluster.sh); the same order is asserted on it
    def mc(self, *args, **env):
        from test_cl1_cluster import Cluster
        c = Cluster()
        self.addCleanup(c.close)
        if args[0] == "back":
            os.makedirs(os.path.join(c.t, "st", "state"))
            open(os.path.join(c.t, "st", "state", "indexers.remove4x"), "w").write("x\n")
        rc, out, calls = c.run(*args, **env)
        return rc, out, [n + " " + s for n, s in Cluster.steps(calls)]

    def test_precopy_reads_the_retention_before_the_dump(self):
        rc, out, calls = self.mc("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        i = [k for k, c in enumerate(calls) if "retention-4x.sh read https://10.0.0.1:9200" in c]
        j = [k for k, c in enumerate(calls) if "history-dump.sh" in c]
        self.assertTrue(i and j, calls)
        self.assertLess(i[0], j[0])

    def test_a_refused_read_stops_the_precopy_before_the_dump(self):
        rc, out, calls = self.mc("run", "--through", "precopy", FAIL_PAT="retention-4x.sh read")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAIL  history: the 4.x retention", out)
        self.assertFalse([c for c in calls if "history-dump.sh" in c])

    def test_goback_security_ends_with_the_ism_policies(self):
        rc, out, calls = self.mc("back")
        self.assertEqual(rc, 0, out[-2000:])
        k = [i for i, c in enumerate(calls) if "retention-4x.sh restore4 https://10.0.0.1:9200" in c]
        self.assertTrue(k, calls)
        self.assertTrue(any("dashboard-objects.sh import4" in c for c in calls[:k[0]]))
        self.assertTrue(any("indexer-security.sh verify4" in c for c in calls[:k[0]]))
        self.assertTrue(any("history-load-4x.sh" in c for c in calls[:k[0]]))


    def test_the_new_step_parses_and_the_secret_part_is_swept(self):
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(SRC, "cluster", "node", "retention-4x.sh")]).returncode, 0)
        bs = helpers.load(os.path.join(SRC, "bundle_secrets.py"), "f4_bundle_secrets")
        self.assertIn("ism-4x.json", bs.PARTS)


# =============================================================================================== item 2: ISM age
class FakeOpenSearch:
    """Just enough of an OpenSearch REST API for dump.py (source) and load_unchanged.py (target)."""

    def __init__(self, indices=None, refuse_creation_date=False):
        self.idx = {}           # name -> {"settings": {...}, "docs": [(id, source)]}
        self.created = {}       # name -> the body of the PUT that created it
        self.refuse = refuse_creation_date
        self.lock = threading.Lock()
        for n, (cd, docs) in (indices or {}).items():
            st = {"number_of_shards": "1", "number_of_replicas": "0", "uuid": "u-" + n, "provided_name": n,
                  "version": {"created": "136387927"}}
            if cd is not None:
                st["creation_date"] = str(cd)
            self.idx[n] = {"settings": st, "docs": [("d%d" % k, {"n": k, "index": n}) for k in range(docs)]}

    def match(self, pats):
        return sorted(n for n in self.idx if any(fnmatch.fnmatchcase(n, p) for p in pats.split(",")))

    def __call__(self, method, path, raw):
        u = urllib.parse.urlparse(path)
        parts = [urllib.parse.unquote(x) for x in u.path.strip("/").split("/")] if u.path.strip("/") else []
        with self.lock:
            return self.route(method, parts, raw)

    def route(self, method, parts, raw):
        if not parts:
            return 200, {"version": {"number": "7.10.2", "distribution": "opensearch"}, "cluster_name": "c", "cluster_uuid": "cu"}
        if parts[0] == "_cat":
            return 200, [{"index": n, "pri": "1", "docs.count": str(len(self.idx[n]["docs"])), "store.size": "1"} for n in self.match(parts[2])]
        if parts[0] == "_template":
            return 404, {}
        if parts[0] == "_cluster":
            if parts[1] == "health":
                return 200, {"number_of_data_nodes": 1, "active_shards": 0, "unassigned_shards": 0, "initializing_shards": 0}
            return 200, {"defaults": {"cluster.max_shards_per_node": "1000"}}
        if parts[0] == "_search":
            if method == "DELETE":
                return 200, {}
            return 200, {"_scroll_id": "s", "hits": {"hits": []}}
        name = parts[0]
        if len(parts) == 1:
            if method == "HEAD":
                return (200 if name in self.idx else 404), None
            if method == "GET":
                x = self.idx[name]
                return 200, {name: {"settings": {"index": x["settings"]}, "mappings": {"properties": {}}, "aliases": {}}}
            if method == "PUT":
                body = json.loads(raw)
                st = body["settings"]["index"]
                if self.refuse and "creation_date" in st:
                    return 400, {"error": {"type": "illegal_argument_exception",
                                           "reason": "private index setting [index.creation_date] can not be set explicitly"}}
                self.created[name] = body
                self.idx[name] = {"settings": dict(st), "docs": []}
                return 200, {"acknowledged": True}
        op = parts[1]
        if op == "_refresh" or op == "_settings":
            return 200, {}
        if op == "_stats":
            return 200, {"indices": {n: {"shards": {"0": [{"routing": {"primary": True},
                                                            "seq_no": {"local_checkpoint": len(self.idx[n]["docs"]) - 1,
                                                                       "max_seq_no": len(self.idx[n]["docs"]) - 1}}]}} for n in self.match(name)}}
        if op == "_search":
            return 200, {"_scroll_id": "s", "hits": {"hits": [{"_id": i, "_source": s} for i, s in self.idx[name]["docs"]]}}
        if op == "_bulk":
            lines = raw.decode().splitlines()
            for a, s in zip(lines[0::2], lines[1::2]):
                self.idx[name]["docs"].append((json.loads(a)["create"]["_id"], json.loads(s)))
            return 200, {"errors": False}
        if op == "_count":
            return 200, {"count": len(self.idx[name]["docs"])}
        return 404, {"error": "no route %s %s" % (method, "/".join(parts))}


class RestoredIndicesKeepTheirISMAge(unittest.TestCase):
    """Going back reloaded every 4.x alert index as a new index: ISM's min_index_age counts from the index's creation
    date, so each one was kept up to its own age longer than 4.x would have kept it (90 days of history, 90-day policy:
    nothing deleted for 90 days after the return, about twice the disk and shards)."""

    SOURCE = {"wazuh-alerts-4.x-2026.08.20": (ms(2026, 8, 20, 0, 3), 3),
              "wazuh-alerts-4.x-2026.08.21": (ms(2026, 8, 21, 0, 1), 2),
              "wazuh-alerts-4.x-2026.11.24": (ms(2026, 11, 24, 0, 0), 1)}

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)

    def serve(self, fake):
        s = Served(fake)
        self.addCleanup(s.close)
        return s.url

    def py(self, tree, script, *args):
        r = subprocess.run([sys.executable, os.path.join(tree, script)] + list(args), env=dict(os.environ, P="pw", PYTHONDONTWRITEBYTECODE="1"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        return r.returncode, r.stdout.decode(errors="replace")

    def dump(self, tree, source=None):
        src = FakeOpenSearch(source or self.SOURCE)
        out = os.path.join(self.t, "bundle-" + os.path.basename(tree))
        rc, text = self.py(tree, "dump.py", "--url", self.serve(src), "--user", "admin", "--password-env", "P", "--out", out, "--workers", "1")
        self.assertEqual(rc, 0, text)
        return out

    def load(self, tree, bundle, *extra, refuse=False):
        tgt = FakeOpenSearch(refuse_creation_date=refuse)
        rc, text = self.py(tree, "load_unchanged.py", "--bundle", bundle, "--url", self.serve(tgt), "--user", "admin",
                           "--password-env", "P", "--state-dir", os.path.join(self.t, "state-%d" % len(os.listdir(self.t))), "--workers", "1", *extra)
        return rc, text, tgt

    def cd(self, tgt, name):
        v = tgt.created[name]["settings"]["index"].get("creation_date")
        return int(v) if v is not None else None

    def test_the_reload_creates_each_index_with_its_original_creation_date(self):
        b = self.dump(SRC)
        self.assertEqual(json.load(open(os.path.join(b, "indices", "wazuh-alerts-4.x-2026.08.20.json")))["creation_date"], ms(2026, 8, 20, 0, 3))
        rc, text, tgt = self.load(SRC, b)
        self.assertEqual(rc, 0, text)
        for n, (cd, docs) in self.SOURCE.items():
            self.assertEqual(self.cd(tgt, n), cd, n)
            self.assertEqual(len(tgt.idx[n]["docs"]), docs)
        self.assertIn("3 new target index(es) created with the source's, 0 counted from this load", text)
        self.assertEqual(json.loads(text.strip().splitlines()[-1])["age_from_load"], [])



    def test_an_index_the_source_had_reloaded_is_capped_at_the_end_of_its_day(self):
        b = self.dump(SRC, {"wazuh-alerts-4.x-2026.08.20": (ms(2026, 11, 10, 12, 0), 1)})   # a reload on Nov 10 (a pre-F4 return)
        rc, text, tgt = self.load(SRC, b)
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.cd(tgt, "wazuh-alerts-4.x-2026.08.20"), ms(2026, 8, 20, 23, 59) + 59999)

    def test_a_monthly_target_takes_its_newest_day(self):
        b = self.dump(SRC)
        rc, text, tgt = self.load(SRC, b, "--rollup", "month")
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.cd(tgt, "wazuh-alerts-4.x-2026.08"), ms(2026, 8, 21, 0, 1))

    def test_an_indexer_that_refuses_the_setting_gets_the_index_without_it_named(self):
        b = self.dump(SRC)
        rc, text, tgt = self.load(SRC, b, refuse=True)
        self.assertEqual(rc, 0, text)
        self.assertEqual(sorted(tgt.created), sorted(self.SOURCE))
        self.assertIn("the indexer refused index.creation_date", text)
        self.assertEqual(json.loads(text.strip().splitlines()[-1])["age_from_load"], sorted(self.SOURCE))

    def test_no_creation_date_keeps_the_old_behaviour_on_request(self):
        rc, text, tgt = self.load(SRC, self.dump(SRC), "--no-creation-date")
        self.assertEqual(rc, 0, text)
        self.assertIsNone(self.cd(tgt, "wazuh-alerts-4.x-2026.08.20"))

    def test_index_entry_records_it_outside_the_settings(self):
        e = DUMP.index_entry({"settings": {"index": {"creation_date": "1755648180000", "number_of_shards": "1", "version": {"created": "1"}}},
                              "mappings": {}})
        self.assertEqual(e["creation_date"], 1755648180000)
        self.assertNotIn("creation_date", e["settings"]["index"])   # a 5.0 load from the same bundle never sends it

    def test_both_flows_reload_with_the_shipped_loader(self):
        txt = open(os.path.join(SRC, "cluster", "node", "history-load-4x.sh")).read()
        self.assertIn('"$SRC/load_unchanged.py"', txt)
        self.assertNotIn('"$F3/tools/load.py"', txt)
        self.assertIn('"$HERE/load_unchanged.py"', open(os.path.join(SRC, "migrate.sh")).read())


class TheWayBackSaysWhatTheISMAgeMeans(unittest.TestCase):
    """ism-restore4 names the restored indices already past their policy's delete age (ISM deletes them at its next run,
    as 4.x would have) and those whose age counts from a later date than their own day (kept longer than on 4.x)."""

    NOW = ms(2026, 11, 25, 10, 0)

    def rec(self):
        return {"policies": [{"policy_id": "p90", "policy": DELETE_90}, {"policy_id": "p60", "policy": HOLD_60}],
                "attached": {"wazuh-alerts-4.x-2026.08.20": "p90", "wazuh-alerts-4.x-2026.09.01": "p60",
                             "wazuh-alerts-4.x-2026.11.20": "p90", "wazuh-alerts-4.x-2026.11.21": "p90"}}

    def test_due_and_late_indices_are_named(self):
        created = {"wazuh-alerts-4.x-2026.08.20": ms(2026, 8, 20, 0, 3),      # 97 days: past 90, deleted at the next run
                   "wazuh-alerts-4.x-2026.09.01": ms(2026, 9, 1, 0, 2),       # 85 days: past 60
                   "wazuh-alerts-4.x-2026.11.20": ms(2026, 11, 20, 0, 1),     # carried
                   "wazuh-alerts-4.x-2026.11.21": ms(2026, 11, 25, 9, 0)}     # created at the return (not carried)
        lines = H.restored_age_report_of(self.rec(), created, self.NOW)
        self.assertIn("2 restored alert index(es) are already past their policy's delete age", lines[0])
        self.assertIn("wazuh-alerts-4.x-2026.08.20 wazuh-alerts-4.x-2026.09.01", lines[0])
        self.assertIn("WARNING 1 restored alert index(es) count their ISM age from a date after their own day", lines[1])
        self.assertIn("up to 3 day(s) longer", lines[1])
        self.assertIn("wazuh-alerts-4.x-2026.11.21", lines[1])

    def test_all_carried_says_so(self):
        created = {i: ms(int(i[17:21]), int(i[22:24]), int(i[25:27]), 0, 5) for i in ("wazuh-alerts-4.x-2026.11.20", "wazuh-alerts-4.x-2026.11.21")}
        self.assertEqual(H.restored_age_report_of(self.rec(), created, self.NOW),
                         ["ism-restore4: every restored alert index counts its ISM age from its original creation date"])

    def test_ism_restore4_prints_it_after_the_attachments(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        p = os.path.join(t, "ism-4x.json")
        json.dump(self.rec(), open(p, "w"))
        back = FakeISM({}, {}, list(self.rec()["attached"]))
        back.created = {"wazuh-alerts-4.x-2026.11.21": ms(2026, 11, 25, 9, 0)}     # created at the return

        def api(m, path, pw, body=None, **k):
            if path.endswith("/_settings/index.creation_date"):
                return 200, {i: {"settings": {"index": {"creation_date": str(c)}}} for i, c in back.created.items()}
            return back(m, path, pw, body)
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), mock.patch.object(H, "idx", api):
            rc, text = quiet(H.ism_restore4, p)
        self.assertEqual(rc, 0, text)
        self.assertLess(text.index("attached to"), text.index("WARNING 1 restored alert index(es)"))



if __name__ == "__main__":
    unittest.main()
