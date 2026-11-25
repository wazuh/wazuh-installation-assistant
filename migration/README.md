# Wazuh 4.x to 5.0 migration tool

This tool migrates a Wazuh 4.14.x deployment to Wazuh 5.0.x on the same hosts. It works on package installations
(deb and rpm, amd64 and arm64), for an all-in-one host and for a cluster (indexer nodes, a master, workers and a
dashboard).

It carries the agent registry, groups and their files, API users and roles, the manager settings that still apply in
5.0, custom rules and decoders, indexer users and roles, custom dashboards, and the 4.x alert history. It then
upgrades the agents and closes the 4.x agent ports. Until the explicit point of no return, it can put the 4.x
deployment back as it was.

## Status

Work in progress. The tool is being tested in lab deployments and is **not ready for production use**. Do not run it
on a deployment you cannot rebuild.

## How it works

The migration is one command that can be run again after any failure or interruption: each step records when it
ends, and a new run continues from the first step that did not.

| Phase | What it does |
| - | - |
| `assess` | Checks the source (only the latest 4.14.x is accepted), the hosts, disk space and the inputs. Changes nothing. |
| `precopy` | While 4.x is still running: exports the configuration, the alert history and what is needed to go back. |
| `freeze` | Stops 4.x. The agent outage starts here. |
| `verify_bundle` | Checks every file of the export against its checksum before anything is removed. |
| `replace` | Removes 4.x and installs 5.0 with the installation assistant, with the agent ports closed. |
| `import` | Imports identity, settings, rules, indexer security and dashboards into 5.0. |
| `open` | Opens the agent ports. The outage ends here. |
| `verify` | Compares 5.0 with what 4.x had. |
| `history` | Loads the 4.x alert history into 5.0. |

Then, as separate commands: `confirm-no-return` (the point of no return), `agents` (upgrades the agents to 5.0) and
`finish` (closes the 4.x agent ports and deletes the history data and the secrets the export held). `back` returns to
4.14.x from the export, up to `confirm-no-return`.

Entry points:

- All-in-one, on the host, as root: `src/migrate.sh run`, then `confirm-no-return`, `agents`, `finish`.
  `src/migrate.sh status` shows where the run is. The settings are environment variables listed at the top of the
  script.
- Cluster, from a control host that reaches every node over SSH: `src/migrate-cluster.sh --inventory FILE run`, with the
  same commands. The phases are `assess precopy freeze verify_bundle indexers master import open workers verify history`:
  the indexers and the dashboard are replaced first while the 4.x managers keep serving agents, then the master, then
  each worker. `src/cluster/inventory.py` describes the inventory file.

## Requirements

- Wazuh 4.14.x installed with packages, at the version `src/manifest/builds.json` names as the minimum source, and the
  `wazuh-install-files.tar` its installation assistant wrote.
- A Wazuh 5.0 installation assistant and packages.
- Bash and Python 3.8 or later (standard library only) on every host.
- Free disk space for the export outside every directory the removal deletes (`BUNDLE_DIR`, `/root/wazuh-migration-bundle`
  by default).
- The identity tool `wazuh-migrate-identity.py` from Wazuh 5.0 (`tools/migration` in `wazuh/wazuh`).
- For custom rules and decoders: the ruleset migration tool `rmig` at commit `1c2e672a9446a57fbf3d9a6861006ecb62745589`
  (`tools/ruleset-migration` in the `wazuh/intelligence-data` repository, which is private today).

## Unit tests

From the repository root:

```
bash migration/tests/run_tests.sh
```

The tests need bash and Python 3.8 or later, run without root and without network access, and stub every system command
the tool would call. The output is kept in `migration/tests/OUTPUT.txt`. The settings converter has its own tests,
which this suite also runs (`migration/src/converter/tests`).
