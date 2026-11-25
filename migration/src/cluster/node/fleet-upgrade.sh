#!/usr/bin/env bash
# fleet-upgrade.sh <command> [options] : on the 5.0 MASTER, fleet-upgrade.py with the cluster's connection (CL1: the
# lab's fixed fleet facts path and development-build package address are gone; agents-node.sh says where both come from).
# Kept for finish-node.sh legacy-decide (legacy-status) and the lab driver.
exec bash "$(dirname "$(readlink -f "$0")")/agents-node.sh" raw "$@"
