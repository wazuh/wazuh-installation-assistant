# Integration tests

End-to-end validation of the Wazuh Installation Assistant tools. The workflow provisions real AWS EC2 instances, builds the tools directly from the pull request branch, runs actual installations on multiple operating systems and architectures, and validates every result using the `integration-test-module` from `wazuh/wazuh-automation`.

## Overview

The integration test suite validates three tools from this repository:

| Tool | Script built | What it does |
| ---- | ------------ | ------------ |
| **Installation assistant** | `wazuh-install.sh` | Downloads and installs all Wazuh components. Supports AIO (all components on one node), distributed (each component installed separately), and offline (no internet access during installation). |
| **Certificates tool** | `wazuh-certs-tool.sh` | Generates the TLS certificates required for secure communication between Wazuh components, based on a `config.yml` file. |
| **Passwords tool** | `wazuh-passwords-tool.sh` | Rotates passwords for Wazuh internal users (indexer users, API users) and updates all components to use the new credentials. |

Each tool is built from the PR branch by `builder.sh` before being deployed to test instances.

## Workflow file

[`.github/workflows/check_integration_tools.yaml`](../../../../.github/workflows/check_integration_tools.yaml)

## Trigger methods

Integration tests are not run automatically on every push. They must be triggered explicitly, either via a PR comment command or manually via workflow dispatch.

### PR comment commands

Post one of the following commands as a comment on an open, non-draft pull request. The workflow reacts with a 🚀 emoji and creates a GitHub check run that tracks the result.

| Comment | Tool tested | Installation mode |
| ------- | ----------- | ----------------- |
| `/test-install` | Installation assistant | AIO |
| `/test-install-distributed` | Installation assistant | Distributed |
| `/test-install-offline` | Installation assistant | Offline |
| `/test-cert-tool` | Certificates tool | — |
| `/test-passwords-tool` | Passwords tool | — |
| `/test-assistant` | All three tools in sequence | AIO |

> **note**: Comments on draft PRs or closed PRs are ignored.

### Manual dispatch (workflow_dispatch)

Navigate to **Actions → PR Check - Test Integration Tools → Run workflow**, or use the GitHub CLI:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=my-feature-branch \
  --field tool_type=installer \
  --field install_mode=aio
```

#### Workflow dispatch inputs

| Input | Description | Options | Default |
| ----- | ----------- | ------- | ------- |
| `pr_head_ref` | Branch of the installation assistant to test | any branch name | required |
| `automation_reference` | Branch of `wazuh-automation` to use | any branch name | `main` |
| `tool_type` | Tool to test | `installer` / `cert-tool` / `passwords-tool` / `all` | required |
| `install_mode` | Installation mode (installer only) | `aio` / `distributed` / `offline` | `aio` |
| `package_type` | Package source | `staging` / `production` | `staging` |
| `systems` | Comma-separated list of systems to test, or `all` | see table below | `all` |

By default all supported systems are tested in parallel. To test a subset, pass a comma-separated list to the `systems` input:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=my-feature-branch \
  --field tool_type=cert-tool \
  --field systems="ubuntu-24-amd64,redhat-9-arm64"
```

## Test matrix — supported systems

One independent job runs per system, in parallel (`fail-fast: false`), so a failure on one OS does not cancel the others.

| System identifier | OS | Architecture |
| ----------------- | -- | ------------ |
| `ubuntu-24-amd64` | Ubuntu 24 | x86_64 |
| `ubuntu-24-arm64` | Ubuntu 24 | ARM64 |
| `ubuntu-22-amd64` | Ubuntu 22 | x86_64 |
| `ubuntu-22-arm64` | Ubuntu 22 | ARM64 |
| `redhat-9-amd64` | Red Hat Enterprise Linux 9 | x86_64 |
| `redhat-9-arm64` | Red Hat Enterprise Linux 9 | ARM64 |
| `redhat-10-amd64` | Red Hat Enterprise Linux 10 | x86_64 |
| `redhat-10-arm64` | Red Hat Enterprise Linux 10 | ARM64 |
| `amazon-2023-amd64` | Amazon Linux 2023 | x86_64 |
| `amazon-2023-arm64` | Amazon Linux 2023 | ARM64 |

## Installation modes

The installation assistant supports three deployment modes. The mode is selected by the `install_mode` input (or inferred from the PR comment command). All modes install Wazuh on a single AWS EC2 instance with `127.0.0.1` as the node IP.

### AIO (All-In-One)

All three Wazuh components — indexer, manager, and dashboard — are installed on the same node in a single command. This is the simplest and most common test mode.

```bash
sudo bash wazuh-install.sh -a -d local -id
```

The `-a` flag triggers the all-in-one installation. `-d local` uses the pre-built `artifact_urls.yaml` (staging packages), and `-id` installs missing system dependencies automatically.

After installation the workflow waits for the Wazuh dashboard to respond at `https://localhost/status` before running tests.

### Distributed

Each Wazuh component is installed in a separate step on the same node. This mode tests the distributed installation code paths — certificate generation from `config.yml`, component-by-component installation, and indexer cluster security initialization.

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../configuration/configuration-files.md#other-configyml-examples).

A `config.yml` file with `127.0.0.1` as the IP for all three nodes is generated and transferred to the instance before installation:

```yaml
nodes:
  indexer:
    - name: indexer
      ip: 127.0.0.1
  manager:
    - name: manager
      ip: 127.0.0.1
  dashboard:
    - name: dashboard
      ip: 127.0.0.1
```

Installation steps run in order:

```bash
sudo bash wazuh-install.sh -g -id                    # generate wazuh-install-files.tar (certs + config)
sudo bash wazuh-install.sh -wi indexer -d local -id  # install Wazuh indexer
sudo bash wazuh-install.sh -s                        # initialize indexer cluster security
sudo bash wazuh-install.sh -wm manager -d local -id  # install Wazuh manager
sudo bash wazuh-install.sh -wd dashboard -d local -id # install Wazuh dashboard
```

### Offline

Tests the offline installation capability. Packages are downloaded on the GitHub Actions runner (which has internet access), then transferred along with all other required files to the EC2 instance. The instance's internet access is revoked (AWS security group change) before the installation begins to verify that no outbound connections are made during the process.

Steps:

```bash
# 1. On the runner: detect package format and architecture from the target system
#    Ubuntu systems use .deb; Red Hat / Amazon Linux use .rpm
sudo bash wazuh-install.sh -dw deb -da amd64 -d local   # produces wazuh-offline.tar.gz
# or
sudo bash wazuh-install.sh -dw rpm -da aarch64 -d local

# 2. On the runner: generate certificates and config
sudo bash wazuh-install.sh -g                            # produces wazuh-install-files.tar

# 3. Transfer wazuh-install.sh, wazuh-offline.tar.gz, wazuh-install-files.tar,
#    artifact_urls.yaml, and config.yml to the remote instance

# 4. Remove the instance's internet access (switch AWS security group to no-internet)

# 5. On the instance: install without any outbound network access
sudo bash wazuh-install.sh -a -of
```

> **note**: For Amazon Linux 2023 instances, `dnf-utils` is installed as a prerequisite in place of `yum-utils` before the offline installation begins, since AL2023 does not ship `yum-utils`.

## Test types

After installation (or tool execution), the workflow calls `test_runner` from the `wazuh/wazuh-automation/integration-test-module` to validate the result. The test type determines which validations are run.

### `installer` — validate a full Wazuh installation

Runs after any installation mode (AIO, distributed, offline). Verifies that all three Wazuh components are correctly installed and operational.

| Test module | What it checks |
| ----------- | -------------- |
| `test_services` | All three services (`wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`) are active (`systemctl is-active`) and running, expected ports are listening (9200, 443, 55000), required directories exist, health API endpoints return HTTP 200 |
| `test_certificates` | Certificate files exist in the expected paths for each component, file permissions are `400`, certificates are not expired, subject and issuer fields match the expected patterns (`CN=indexer`, `CN=dashboard`, `CN=manager`, `OU=Wazuh`) |
| `test_logs` | Log files exist for each component, no critical error patterns (`ERROR`, `CRITICAL`, `FATAL`, `Failed to`) found in recent log entries, known false positives (e.g. `ErrorDocument`) are excluded |
| `test_version` | The installed version and revision reported by each component match the expected values from `VERSION.json` |

### `cert-tool` — validate certificate generation

Runs `wazuh-certs-tool.sh -A` on the instance (generates all certificates for all nodes in `config.yml`) and then validates the output. No Wazuh installation is required on the instance for this test.

| Test module | What it checks |
| ----------- | -------------- |
| `test_certificates` | All expected certificate files exist under `WAZUH_CERT_TOOL_OUTPUT_DIR` (`/tmp/wazuh-certificates`), file permissions are `400`, certificates are not expired, subject DN and issuer DN match the node names specified in `config.yml` |

The `config.yml` used defines three nodes (`indexer`, `manager`, `dashboard`) all pointing to `127.0.0.1`.

### `passwords-tool` — validate password rotation

Runs after an AIO installation. Changes the passwords for the following users:

```bash
sudo bash wazuh-passwords-tool.sh -u admin -p 'T3sting-Password'
sudo bash wazuh-passwords-tool.sh -u wazuh-server -p 'T3sting-Password'
sudo bash wazuh-passwords-tool.sh -u wazuh-dashboard -p 'T3sting-Password'
sudo bash wazuh-passwords-tool.sh -au wazuh -ap wazuh -u wazuh-wui -p 'T3sting-Password' -A
```

All services are restarted after the password changes. The workflow then waits for each service to accept the new credentials before running validation.

| Test module | What it checks |
| ----------- | -------------- |
| `test_services` | Services are still active and health endpoints are reachable using the new password |
| `test_passwords` | New password is accepted by indexer (`https://localhost:9200`) and dashboard (`https://localhost/status`) with HTTP 200, old password (`admin`) is rejected with HTTP 401, Wazuh Manager API accepts the new `wazuh-wui` credentials at `https://localhost:55000/security/user/authenticate` |

### `uninstall` — validate complete removal

Runs automatically after every `installer` or `all` test. Executes `wazuh-install.sh --uninstall` and then validates that the system is clean.

| Test module | What it checks |
| ----------- | -------------- |
| `test_uninstall` | None of the Wazuh services are active, none of the Wazuh packages remain installed, all data and configuration directories (`/etc/wazuh-*`, `/var/wazuh-*`) have been removed |

### `all` — full end-to-end sequence

Triggered by `/test-assistant`. Runs all three tools on the same AIO installation in sequence:

1. AIO install → `installer` validation
2. `wazuh-certs-tool.sh` → `cert-tool` validation
3. `wazuh-passwords-tool.sh` → `passwords-tool` validation
4. Uninstall → `uninstall` validation

### Test execution matrix

| test_type | `test_services` | `test_certificates` | `test_passwords` | `test_logs` | `test_version` | `test_uninstall` |
| --------- | :---: | :---: | :---: | :---: | :---: | :---: |
| `installer` | ✓ | ✓ | — | ✓ | ✓ | — |
| `cert-tool` | — | ✓ | — | — | — | — |
| `passwords-tool` | ✓ | — | ✓ | — | — | — |
| `uninstall` | — | — | — | — | — | ✓ |

## Workflow jobs

The workflow is composed of four jobs.

### Job 1 — `get_pr_info` (comment trigger only)

1. Adds a 🚀 reaction to the triggering comment.
2. Fetches the PR head branch and commit SHA via the GitHub API.
3. Maps the comment body to a `tool_type` and `install_mode`.
4. Creates a GitHub check run in `in_progress` state, visible on the PR commits view.

### Job 2 — `build_tools`

1. Checks out the PR branch and `wazuh/wazuh-automation`.
2. Reads the Wazuh version from `VERSION.json`.
3. Builds the required tools via `builder.sh`:
   - `-i` always → `wazuh-install.sh`
   - `-c` for `cert-tool` or `all` → `wazuh-certs-tool.sh`
   - `-p` for `passwords-tool` or `all` → `wazuh-passwords-tool.sh`
4. Generates presigned S3 URLs for staging packages into `artifact_urls.yaml`.
5. Uploads the built tools and `artifact_urls.yaml` as a GitHub Actions artifact (1-day retention).

### Job 3 — `vm_test` (matrix: one job per system)

The main job. Runs in parallel for each OS:

1. Allocates an AWS EC2 `large` instance via the `wazuh-automation` deployability allocator (1-day termination label).
2. Downloads the built tools artifact.
3. Copies tools to the remote instance via SCP.
4. Runs the installation according to the selected mode.
5. Runs `test_runner` against the instance via SSH.
6. For `installer` and `all`: runs uninstall and `test_runner --test-type uninstall`.
7. Posts a per-OS result comment on the PR (comment trigger only).
8. Uploads test result files as artifacts (7-day retention).
9. **Always** deallocates the instance, even if previous steps failed.

### Job 4 — `update_check` (comment trigger only)

Updates the GitHub check run from Job 1 with the final conclusion (`success`, `failure`, or `cancelled`) based on the overall result of Job 3.

## Environment variables for `test_runner`

| Variable | Description | Value in CI |
| -------- | ----------- | ----------- |
| `WAZUH_NEW_PASSWORD` | New password set by `wazuh-passwords-tool.sh` | `T3sting-Password` |
| `WAZUH_SERVICE_PASSWORD` | Password used for health check API calls | `T3sting-Password` |
| `WAZUH_CERT_TOOL_OUTPUT_DIR` | Directory where `wazuh-certs-tool.sh` writes certificates | `/tmp/wazuh-certificates` |

## Results and artifacts

### PR comments

After each OS job completes, a bot comment is posted (or updated if one already exists) on the PR with:

- The tool, installation mode, and OS tested.
- Overall pass/fail status.
- Detailed test output from `test_runner`.
- A link to the workflow run.

For the `all` command, a separate uninstall result section is appended to the same comment.

### GitHub check run

When triggered via PR comment, a named check run is created on the PR commit and updated when all OS jobs finish. Check run names:

| Command | Check run name |
| ------- | -------------- |
| `/test-install` | Installation Assistant Check |
| `/test-install-distributed` | Installation Assistant Check (Distributed) |
| `/test-install-offline` | Installation Assistant Check (Offline) |
| `/test-cert-tool` | Certificates Tool Check |
| `/test-passwords-tool` | Passwords Tool Check |
| `/test-assistant` | Full Integration Check |

### Artifacts

Test result files are uploaded as GitHub Actions artifacts with a 7-day retention period. The artifact name format is:

```
test-results-<tool_type>-<install_mode>-<system>
```

For example: `test-results-installer-aio-ubuntu-24-amd64`

## Examples

### Trigger via PR comment

Post any of the following as a comment on an open, non-draft PR:

```
/test-install
```

Test the AIO installer and validate services, certificates, logs, and version. Runs on all supported systems.

```
/test-install-distributed
```

Test the distributed installation flow (separate install of each component). Runs on all supported systems.

```
/test-install-offline
```

Test the offline installation flow (no internet access on the instance during install). Runs on all supported systems.

```
/test-cert-tool
```

Test certificate generation only. No Wazuh installation is performed. Runs on all supported systems.

```
/test-passwords-tool
```

Perform an AIO installation, rotate passwords for all internal users, and validate the new credentials. Runs on all supported systems.

```
/test-assistant
```

Run the full end-to-end sequence: AIO install → cert-tool → passwords-tool → uninstall. Runs on all supported systems.

---

### Trigger via GitHub CLI

Test the AIO installer on a specific branch, limited to two systems:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=enhancement/my-feature \
  --field tool_type=installer \
  --field install_mode=aio \
  --field systems="ubuntu-24-amd64,redhat-9-amd64"
```

Test the distributed installer on all systems using production packages:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=main \
  --field tool_type=installer \
  --field install_mode=distributed \
  --field package_type=production
```

Test the offline installer on ARM64 systems only:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=fix/offline-install \
  --field tool_type=installer \
  --field install_mode=offline \
  --field systems="ubuntu-24-arm64,redhat-9-arm64"
```

Test the cert-tool using a custom `wazuh-automation` branch:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=fix/cert-generation \
  --field tool_type=cert-tool \
  --field automation_reference=feature/new-cert-tests
```

Run the full sequence on a single system:

```bash
gh workflow run check_integration_tools.yaml \
  --field pr_head_ref=main \
  --field tool_type=all \
  --field systems=ubuntu-24-amd64
```
