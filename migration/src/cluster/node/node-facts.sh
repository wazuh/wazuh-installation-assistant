#!/usr/bin/env bash
# node-facts.sh <role> : CL1, read-only, on any node (assess). What the cluster steps choose from on this node, by the
# all-in-one's own logic (migrate.sh's functions): the package family (deb or rpm: package manager and package queries),
# the host firewall (firewalld, ufw or none) and whether the agent ports are allowed, Python, free disk where the bundle
# lives. A blocker exits 1.
. "$(dirname "$(readlink -f "$0")")/common.sh"
role=${1:-unknown}; aio_lib
. /etc/os-release 2>/dev/null || true
py=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo none)
echo "facts: $(nodelabel) role $role, ${PRETTY_NAME:-unknown OS}, packages $PKGFAM, python3 $py, free in $(dirname "$BUNDLE_DIR"): $(df -Pm "$(dirname "$BUNDLE_DIR")" | awk 'NR==2{print $4}') MB"
echo "facts: installed: $(pkgs | tr '\n' ';')"
case "$role" in master|worker)
  k=$(fw_kind)
  if [ "$k" = none ]; then echo "facts: host firewall: none active (firewalld, ufw): no port to open or close"
  else for p in 1514 1515 1516 1517 55000; do h=$(fw_how $p); echo "facts: host firewall $k $(fw_zone): $p/tcp $( [ -n "$h" ] && echo "allowed ($h)" || echo "NOT allowed")"; done   # was "allowed (port)port"
       [ -n "$(fw_how 1516)" ] || echo "WARN $k does not allow 1516/tcp: the 5.0 workers cannot reach this node's cluster port"
       [ -n "$(fw_how 1517)" ] || echo "facts: $k does not allow 1517/tcp yet: the opening adds it (and going back removes it)"; fi;;
esac
# an indexer node's 5.0 heap, as the 5.0 assistant (-wi) will set it: half of the node's RAM
[ "$role" = indexer ] && { l=$(heap5_plan node); case "$l" in WARN*) echo "WARN node $(nodelabel): ${l#WARN }";; *) echo "facts: ${l#OK }";; esac; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || die "BLOCKER: python3 3.8 or later is needed on every node (found $py)"
