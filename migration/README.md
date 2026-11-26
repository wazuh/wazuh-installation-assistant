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

## How to run it

The tool is one file, `wazuh-migrate.sh`, and one command. Build the file from this repository with
`bash builder.sh -m` (it writes `wazuh-migrate.sh` at the repository root), or take it from a release. Copy it to the
4.x host (the master of a cluster) and run it as root. Each run goes as far as it can and stops at the next point that
needs you: it prints every open question, each with what its answer needs, and the one decisions file to answer them in
(a JSON file), and exits with code 3. Answer them all, run the same command again, and it goes on. It ends with `MIGRATION FINISHED`. After any failure or interruption, the
same command continues from the step that did not finish.

```
./wazuh-migrate.sh --version      # the tool fingerprint and the ruleset tool commit it needs
./wazuh-migrate.sh --self-test    # checks the file (checksum, fingerprint, syntax); changes nothing
```

### All-in-one host

```
# on the 4.x host, as root, in /root (beside wazuh-install-files.tar and the ruleset tool directory)
./wazuh-migrate.sh
#   assess, then the copy while 4.x keeps running; stops with exit 3 on every question before the outage at once:
#   the ruleset tool's review and its questions, and the manager settings questions
#   QUESTION: ... answer in: /root/wazuh-migration-bundle/decisions.json (then each other open question with its "how")
vi /root/wazuh-migration-bundle/decisions.json      # "review": "accepted", and every other entry it lists
./wazuh-migrate.sh
#   the outage: 4.x stops, 5.0 is installed, everything is imported, the agent ports open, the old alerts load;
#   stops with exit 3: QUESTION: POINT OF NO RETURN ... answer "confirm" (and, when the migrated rules are not
#   active, what the finish does with raw event indexing: the same round)
vi /root/wazuh-migration-bundle/decisions.json      # "action": "confirm"
./wazuh-migrate.sh
#   upgrades the agents, closes the 4.x agent ports, deletes the secrets the export held:
#   === MIGRATION FINISHED
```

Three runs and two answer rounds. Until the point of no return is confirmed, `./wazuh-migrate.sh back` returns the
host to 4.14.x from the export. After going back, `./wazuh-migrate.sh` starts a new attempt by itself: the earlier
bundle is kept beside the new one (`/root/wazuh-migration-bundle.attempt-1`) and the answers given then are kept,
except the point of no return and the finish's raw indexing answer: those belong to one outage, so they are set aside
(under `"earlier-attempts"` in the decisions file) and asked again after the new attempt's outage. A `"confirm"` given to
an earlier attempt never skips the new attempt's stop. The way back keeps the 4.x alerts it copied at the freeze (as
`v4/alerts-sample` in the earlier bundle): the new attempt checks your migrated rules against them too.

### Cluster

Run the same file on the 4.x master. It sees the cluster in `ossec.conf`, builds the inventory itself (the managers from
the cluster API, the indexer and dashboard nodes from the `config.yml` inside `wazuh-install-files.tar`), writes it to
`/root/wazuh-migration-cluster/inventory.json` with the 5.0 `config.yml` beside it, and asks only for SSH access.

```
# on the 4.x master, as root, in /root
./wazuh-migrate.sh
#   writes the inventory and stops with exit 3:
#   QUESTION: Which SSH user and private key does this host use to reach every node ... answer in:
#   /root/wazuh-migration-cluster/decisions.json
vi /root/wazuh-migration-cluster/decisions.json     # "user": "root", "key": "/root/.ssh/<key>", "port": 22
./wazuh-migrate.sh
#   assess and the copy on every node; stops with exit 3 on every question before the outage at once, all in
#   /root/wazuh-migration-cluster/decisions.json: the ruleset review and questions (section "ruleset") and each
#   manager's settings questions (under "nodes", "<node name>")
vi /root/wazuh-migration-cluster/decisions.json     # "review": "accepted", and every other entry it lists
./wazuh-migrate.sh
#   indexers and dashboard, then the master, then each worker; the old alerts; stops with exit 3:
#   QUESTION: POINT OF NO RETURN ... (and the raw indexing question when the migrated rules are not active)
vi /root/wazuh-migration-cluster/decisions.json     # "action": "confirm"
./wazuh-migrate.sh
#   === MIGRATION FINISHED
```

Four runs and three answer rounds. `./wazuh-migrate.sh back` on the master goes back the whole cluster
(`./wazuh-migrate.sh back master`: the master alone, while every worker is still on 4.x). After `back master`, the same
`./wazuh-migrate.sh` installs, imports and opens the master again, then goes on with the workers. Every command the tool
prints is one you can type as printed (`./wazuh-migrate.sh ...`); `./wazuh-migrate.sh --help` lists them.

The key must let the master log in to every node, itself included, as root or as a user with sudo without a password.
To use an inventory of your own instead (from a control host), run `./wazuh-migrate.sh --inventory FILE`.

### Exit codes

| Code | Meaning |
| - | - |
| 0 | The migration is finished (or nothing was left to do). |
| 3 | A question is open: answer it in the file printed, then run the same command again. |
| 4 | Agents are still on 4.x (connected, or stopped: each is named), so the 4.x agent ports stay open: run it again later. |
| 10 | The 5.0 installation is left to your own deployment tool (`V5_INSTALLER=external`): run it again once it is done. |
| other | A step failed: the output says which, the command and line it stopped at, and where its log is. Fix the cause and run the same command again. |

### Settings

Nothing has to be set. Every setting has a default, is detected, or is asked in the decisions file; an environment
variable of the same name still overrides it (the full list, with what each does, is at the top of `src/migrate.sh`).

| Setting | How it is filled |
| - | - |
| `V4_INSTALL_FILES_TAR` | found in the current directory, `/root` or beside the file; else asked |
| `RMIG_DIR` (the ruleset tool) | found as `ruleset-migration/` in the current directory, `/root` or beside the file; else asked |
| `IDENTITY_TOOL` | embedded in `wazuh-migrate.sh`; with `src/migrate.sh`, found or asked like the others |
| `BUNDLE_DIR`, `WORK_DIR`, `MIGRATION_DECISIONS` | defaults under `/root` |
| `V4_ASSISTANT`, `V5_ASSISTANT`, `V5_ARTIFACT_URLS`, `WPK_REPO` | defaults (the published 4.14 assistant; the 5.0 build) |
| `HISTORY_RETENTION`, `HISTORY_PROCS`, `RMIG_ENGINE_HELPERS`, `AGENT_ADDRESSES` | detected |
| `UNCLASSIFIED_DECISION` | default: activate the migrated rules when they verify (not when most had no 4.x alert to check them against), keep raw indexing on until the finish |
| roles that lose access when the old alerts are switched on | asked (`ACCEPT_ROLE_LOSS=1` answers it) |
| the point of no return | asked |
| raw indexing at the finish, when the migrated rules are not active | asked with the point of no return (`activate-force`, `keep-raw`, `accept-loss`) |
| agents that never connected, at the finish | the legacy ports stay open for them; `"close"` or `"remove"` in the decisions file's `never-connected` entry changes it |
| every other setting | a default |

### What it does

Each run of the command goes through these phases, skipping what is done.

| Phase | What it does |
| - | - |
| `assess` | Checks the source (only the latest 4.14.x is accepted), the hosts, disk space and the inputs. Changes nothing. It runs on every command; once it has passed, a later command prints only blockers, warnings and one count line (every check is in the logs' `assess-again.log`). |
| `precopy` | While 4.x is still running: exports the configuration, the alert history and what is needed to go back. Asks every question it can before the outage. |
| `freeze` | Stops 4.x. The agent outage starts here. |
| `verify_bundle` | Checks every file of the export against its checksum before anything is removed. |
| `replace` | Removes 4.x and installs 5.0 with the installation assistant, with the agent ports closed. |
| `import` | Imports identity, settings, rules, indexer security and dashboards into 5.0. |
| `open` | Opens the agent ports. The outage ends here. |
| `verify` | Compares 5.0 with what 4.x had. |
| `history` | Loads the 4.x alert history into 5.0. |
| point of no return | The question; until it is answered, `back` returns to 4.14.x. |
| `agents` | Upgrades the agents to 5.0. |
| `finish` | Closes the 4.x agent ports and deletes the history data and the secrets the export held. |

On a cluster the phases are `assess precopy freeze verify_bundle indexers master import open workers verify history`:
the indexers and the dashboard are replaced first while the 4.x managers keep serving agents, then the master, then
each worker.

### Advanced commands

For recovery and tests, each part can be run on its own: `run [--from PHASE] [--only PHASE] [--through PHASE]`,
`confirm-no-return`, `agents`, `finish`, `status`, `discard`, `guard`, `dashboards-rollback`, and for a cluster
`src/migrate-cluster.sh --inventory FILE <command>` (`src/cluster/inventory.py` describes the inventory file).
`src/build-wazuh-migrate.sh` builds the single file from a checkout.

## Requirements

- Wazuh 4.14.x installed with packages, at the version `src/manifest/builds.json` names as the minimum source, and the
  `wazuh-install-files.tar` its installation assistant wrote.
- A Wazuh 5.0 installation assistant and packages.
- Bash and Python 3.8 or later (standard library only) on every host.
- Free disk space for the export outside every directory the removal deletes (`BUNDLE_DIR`, `/root/wazuh-migration-bundle`
  by default).
- The identity tool `wazuh-migrate-identity.py` from Wazuh 5.0 (`tools/migration` in `wazuh/wazuh`): `wazuh-migrate.sh`
  carries it, at the commit `src/manifest/builds.json` pins.
- The ruleset migration tool `rmig` at commit `7976ef5422cdf677b702bf774645b0f6f4be9218`
  (`tools/ruleset-migration` in the `wazuh/intelligence-data` repository, which is private today, so it is not inside
  `wazuh-migrate.sh`). Without it the run stops at the first step and asks for its directory.

## Unit tests

From the repository root:

```
bash migration/tests/run_tests.sh
```

The tests need bash and Python 3.8 or later, run without root and without network access, and stub every system command
the tool would call. The output is kept in `migration/tests/OUTPUT.txt`. The settings converter has its own tests,
which this suite also runs (`migration/src/converter/tests`).
