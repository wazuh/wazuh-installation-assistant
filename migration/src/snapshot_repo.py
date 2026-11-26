#!/usr/bin/env python3
"""snapshot_repo.py - the snapshot transport's repository and restore rules (rule 1), as checks the tool runs.
Python 3.8+, standard library only.

    snapshot_repo.py check-path PATH                 rule 1 / H6-D4: may the repository live there? (exit 0 yes, 2 no)
    snapshot_repo.py path-repo OPENSEARCH_YML PATH   H1/H6: the shipped `path.repo` line rewritten as a list with PATH
                                                     (a second `path.repo` line stops the indexer); prints the new file
    snapshot_repo.py restore-body INDEX_PATTERN      H6-D8/D9: the only restore body the tool sends (JSON)

What the transport must do around these (the steps are not built into migrate.sh yet): the repository is created by root, owned by the 4.x indexer user while 4.x writes and checked writable
before the restart that adds it; the proof restore uses the snapshot taken AFTER the freeze; after a failed snapshot
the covering snapshot is deleted, `_cleanup` reclaims nothing; on 5.0 the repository is registered read-only and
handed to root after the final snapshot; restores run through REST as an ordinary admin, never with the node's admin
certificate; raw restored indices keep 4.x names, are invisible and are deleted once the reshaped copy is proven; going back restores before the reinstalled 4.x manager and Filebeat start.
"""
import json
import os
import re
import sys

DEFAULT_REPO = "/var/lib/wazuh-migration/repo"
# every tree an installer, a rollback or a unit option deletes, hides or makes unreachable
REFUSED = [
    ("/var/lib/wazuh-indexer", "deleted by the 4.x removal, the 5.0 rollback and 5.0's -u (5.0's own path.repo is under it)"),
    ("/usr/share/wazuh-indexer", "the indexer package's tree"),
    ("/etc", "read-only to the 5.0 indexer (ProtectSystem=full) and /etc/wazuh-indexer is deleted by both assistants"),
    ("/tmp", "the indexer units use PrivateTmp: the snapshot lands in the service's private /tmp and is deleted at its stop"),
    ("/var/tmp", "PrivateTmp, as /tmp"),
    ("/root", "the indexer user cannot reach it; as a path.repo entry it stops the indexer at start"),
    ("/var/ossec", "deleted by the 4.x removal"),
    ("/var/wazuh-manager", "the 5.0 manager's tree"),
    ("/run", "tmpfs, gone at a reboot"),
    ("/dev/shm", "tmpfs, gone at a reboot"),
]
TESTED_OK = ["/var/lib/wazuh-migration", "/srv", "/opt", "/var/backups"]


def check_path(path):
    """(ok, reason). Rule 1 for a snapshot repository; the bundle follows the same rule in migrate.sh."""
    if not path or not path.startswith("/"):
        return False, "the repository path must be absolute"
    p = os.path.normpath(path)
    for bad, why in REFUSED:
        if p == bad or p.startswith(bad + "/"):
            return False, "%s is under %s: %s" % (p, bad, why)
    if not any(p == ok or p.startswith(ok + "/") for ok in TESTED_OK):
        return True, "%s is outside every deleted tree, but not one of the locations H6 tested (%s)" % (p, ", ".join(TESTED_OK))
    return True, "%s is outside every tree an installer or a rollback deletes (tested by H6)" % p


def path_repo_rewrite(yml_text, repo):
    """The one shipped `path.repo` line made into a list that also holds `repo`. A second `path.repo` line stops the
    indexer (T1, product issue 29), so the line is rewritten, never added; re-applied after every 5.0 install."""
    lines = yml_text.splitlines()
    idx = [i for i, l in enumerate(lines) if re.match(r"^\s*path\.repo\s*:", l)]
    if len(idx) > 1:
        raise ValueError("more than one path.repo line: the indexer would not start; fix the file by hand first")
    if not idx:
        lines.append("path.repo: [%s]" % json.dumps(repo))
        return "\n".join(lines) + "\n"
    i = idx[0]
    val = lines[i].split(":", 1)[1].strip()
    if val.startswith("["):
        items = [x.strip().strip("'\"") for x in val.strip("[]").split(",") if x.strip()]
    else:
        items = [val.strip("'\"")] if val else []
    if repo not in items:
        items.append(repo)
    lines[i] = "path.repo: [%s]" % ", ".join(json.dumps(x) for x in items)
    return "\n".join(lines) + "\n"


def restore_body(indices):
    """H6-D9: never the global state (with the node's admin certificate a 4.x snapshot's global state replaced all 54
    composable templates); no rename into the findings name space (the stock retention adopts such indices)."""
    if re.search(r"(^|,)\s*wazuh-(findings|events)-v5", indices):
        raise ValueError("restored raw indices must keep 4.x names, never names inside the 5.0 name spaces")
    return {"indices": indices, "include_global_state": False, "include_aliases": False, "ignore_unavailable": False}


def main(argv):
    if len(argv) >= 2 and argv[0] == "check-path":
        ok, why = check_path(argv[1])
        print(("OK " if ok else "REFUSED ") + why)
        return 0 if ok else 2
    if len(argv) >= 3 and argv[0] == "path-repo":
        sys.stdout.write(path_repo_rewrite(open(argv[1]).read(), argv[2]))
        return 0
    if len(argv) >= 2 and argv[0] == "restore-body":
        print(json.dumps(restore_body(argv[1])))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
