#!/usr/bin/env bash
# run_tests.sh - every unit test of the merged tool, standard library unittest, output kept in tests/OUTPUT.txt.
# Temporary files go under tests/.tmp (removed at the end); nothing is written outside migration/.
set -uo pipefail
T="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$T/.tmp"
export TMPDIR="$T/.tmp" PYTHONDONTWRITEBYTECODE=1
{
  echo "# unit tests of the merged migration tool, $(date -u +%Y-%m-%dT%H:%M:%SZ), $(python3 -V), $(bash --version | head -n1)"
  cd "$T" && python3 -W ignore::ResourceWarning -m unittest -v test_contract_script test_helper test_history test_identity_guard_fleet test_static test_settings_rule20 test_e2_fold test_e2_cluster test_of1 test_e3_fold test_f4_retention test_cl1_cluster test_e5_fold test_r1_rmig test_rules test_one_command test_compact_map test_f6_fold test_e8_fix01 test_f7_fold test_f7_walk test_f8_fold test_e9_fix01 2>&1
  rc=$?
  echo "# exit $rc"
  python3 "$T/rule_table.py"
  exit $rc
} | tee "$T/OUTPUT.txt"
rc=${PIPESTATUS[0]}
rm -rf "$T/.tmp"
exit $rc
