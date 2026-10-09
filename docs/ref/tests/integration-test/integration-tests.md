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

[`.github/workflows/5_check_integration_tools.yaml`](../../../../.github/workflows/5_check_integration_tools.yaml)

## Trigger methods

Integration tests are not run automatically on every push. They must be triggered explicitly, either by adding a label to the PR or manually via workflow dispatch.

### PR labels

Add one of the following labels to a non-draft pull request opened from a branch of this repository. Each label added starts one run against the PR head at that moment, and the run shows up in the PR checks.

| Label | Tool tested | Installation mode |
| ----- | ----------- | ----------------- |
| `test/install` | Installation assistant | AIO |
| `test/install-distributed` | Installation assistant | Distributed |
| `test/install-offline` | Installation assistant | Offline |
| `test/cert-tool` | Certificates tool | — |
| `test/passwords-tool` | Passwords tool | — |
| `test/assistant` | All three tools in sequence | AIO |

> **note**: To run the tests again (for example after pushing new commits), remove the label and add it again. Labels added while the PR is a draft are ignored: mark the PR as ready for review and add the label again. PRs opened from forks do not run, because GitHub does not pass secrets to `pull_request` runs from forks.

### Manual dispatch (workflow_dispatch)

Navigate to **Actions → PR Check - Test Integration Tools → Run workflow**, or use the GitHub CLI:

```bash
gh workflow run 5_check_integration_tools.yaml \
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
gh workflow run 5_check_integration_tools.yaml \
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

## Installation modes

The installation assistant supports three deployment modes. The mode is selected by the `install_mode` input (or inferred from the PR label). All modes install Wazuh on a single AWS EC2 instance with `127.0.0.1` as the node IP.

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

`-g` refuses to issue an agent listener certificate that names only loopback addresses, so the workflow adds the private address of the instance with `-as`. The nodes stay on `127.0.0.1`, so the services listen on localhost.

Installation steps run in order:

```bash
sudo bash wazuh-install.sh -g -as <private IP> -id   # generate wazuh-install-files.tar (certs + config + credentials.env)
sudo bash wazuh-install.sh -wi indexer -d local -id  # install Wazuh indexer
sudo bash wazuh-install.sh -s                        # initialize indexer cluster security
sudo bash wazuh-install.sh -wm manager -d local -id  # install Wazuh manager
sudo bash wazuh-install.sh -wd dashboard -d local -id # install Wazuh dashboard
```

After `-g` the workflow checks that `wazuh-install-files.tar` contains `credentials.env`, does not contain `root-ca.key`, and that the agent listener certificate (`manager-remoted.pem`) names the private address.

### Offline

Tests the offline installation capability. Packages are downloaded on the GitHub Actions runner (which has internet access), then transferred along with all other required files to the EC2 instance. The instance's internet access is revoked (AWS security group change) before the installation begins to verify that no outbound connections are made during the process.

Steps:

```bash
# 1. On the runner: detect package format and architecture from the target system
#    Ubuntu systems use .deb; Red Hat / Amazon Linux use .rpm
sudo bash wazuh-install.sh -dw deb -da amd64 -d local   # produces wazuh-offline.tar.gz
# or
sudo bash wazuh-install.sh -dw rpm -da aarch64 -d local

# 2. Transfer wazuh-install.sh, wazuh-offline.tar.gz, and artifact_urls.yaml to the remote instance

# 3. Remove the instance's internet access (switch AWS security group to no-internet)

# 4. On the instance: install without any outbound network access
sudo bash wazuh-install.sh -a -of
```

The offline all-in-one install does not use `wazuh-install-files.tar` nor `config.yml`: the packages create the root CA, the certificates, and the passwords.

> **note**: For Amazon Linux 2023 instances, `dnf-utils` is installed as a prerequisite in place of `yum-utils` before the offline installation begins, since AL2023 does not ship `yum-utils`.

## Test types

After installation (or tool execution), the workflow calls `test_runner` from the `wazuh/wazuh-automation/integration-test-module` to validate the result. The test type determines which validations are run.

### `installer` — validate a full Wazuh installation

Runs after any installation mode (AIO, distributed, offline). Verifies that all three Wazuh components are correctly installed and operational.

| Test module | What it checks |
| ----------- | -------------- |
| `test_services` | All three services (`wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`) are active (`systemctl is-active`) and running, expected ports are listening (9200, 443, 55000), required directories exist, health API endpoints return HTTP 200 |
| `test_certificates` | Certificate files exist in the expected paths for each component, file permissions are `400`, certificates are not expired, subject and issuer fields match the expected patterns. The common name of the node certificates depends on the mode: the node names of `config.yml` (`CN=indexer`, `CN=dashboard`, `CN=manager`) for distributed, and the short host name (`hostname -s`) for AIO and offline, where the packages issue them |
| `test_logs` | Log files exist for each component, no critical error patterns (`ERROR`, `CRITICAL`, `FATAL`, `Failed to`) found in recent log entries, known false positives (e.g. `ErrorDocument`) are excluded |
| `test_version` | The installed version and revision reported by each component match the expected values from `VERSION.json` |
| `test_default_credentials` | The default credentials of previous versions are rejected with HTTP 401: `admin:admin` on the indexer and the dashboard, `wazuh:wazuh` and `wazuh-internal-client:wazuh-wui` (the default password of the account, named `wazuh-wui` before) on the Wazuh server API |

There are no default passwords: the packages save the generated ones in `/etc/wazuh/credentials.env`, and `test_runner` reads them from there over SSH.

### `cert-tool` — validate certificate generation

Runs after an AIO installation. The workflow removes any previous `/tmp/wazuh-certificates` directory and runs `wazuh-certs-tool.sh -A` on the instance, which generates all certificates for all nodes in `config.yml` with the root CA in `/etc/wazuh/ca` that the installation created, and then validates the result.

| Test module | What it checks |
| ----------- | -------------- |
| `test_certificates` | The installed certificates of each component, as in the `installer` test |
| `test_cert_tool` | The tool output (`WAZUH_CERT_TOOL_OUTPUT_DIR`, `/tmp/wazuh-certificates`) does not contain `root-ca.key`, its `root-ca.pem` is the root CA in `/etc/wazuh/ca`, and every certificate it issued verifies against that root CA |
| `test_default_credentials` | The default credentials of previous versions are rejected with HTTP 401 |

The `config.yml` used defines three nodes (`indexer`, `manager`, `dashboard`) all pointing to `127.0.0.1`.

### `passwords-tool` — validate password rotation

Runs after an AIO installation. The installation generates random passwords and saves them in `/etc/wazuh/credentials.env`. The workflow first reads the `admin` password set by the installation (`WAZUH_INDEXER_ADMIN_PASSWORD`), masks it in the log and passes it to the tests as `WAZUH_OLD_PASSWORD`. It then sets the same new password for every user the tool supports, passing it on the standard input with `-p`:

```bash
for user in admin kibanaserver wazuh-manager wazuh wazuh-internal-client; do
  printf '%s\n' "$WAZUH_NEW_PASSWORD" | sudo bash wazuh-passwords-tool.sh -u "$user" -p
done
```

Before that, it runs the tool once without `-p` for `kibanaserver`, and checks that the generated password is saved in `credentials.env`, is accepted by the indexer, and replaces the previous one.

All services are restarted after the password changes. The workflow then waits for each service to accept the new credentials before running validation.

| Test module | What it checks |
| ----------- | -------------- |
| `test_services` | Services are still active and health endpoints are reachable using the new password |
| `test_passwords` | New password is accepted by indexer (`https://localhost:9200`) and dashboard (`https://localhost/status`) with HTTP 200, old password (`WAZUH_OLD_PASSWORD`, the `admin` password set by the installation) is rejected with HTTP 401, Wazuh Manager API accepts the new `wazuh-internal-client` credentials at `https://localhost:55000/security/user/authenticate`. Without `WAZUH_OLD_PASSWORD` the old-password check fails |
| `test_default_credentials` | The default credentials of previous versions are rejected with HTTP 401 |

### `uninstall` — validate complete removal

Runs automatically after every `installer` or `all` test. Executes `wazuh-install.sh --uninstall` and then validates that the system is clean.

| Test module | What it checks |
| ----------- | -------------- |
| `test_uninstall` | None of the Wazuh services are active, none of the Wazuh packages remain installed, all data and configuration directories (`/etc/wazuh-*`, `/var/wazuh-*`, and `/etc/wazuh` with the credentials file and the root CA) have been removed |

### `all` — full end-to-end sequence

Triggered by the `test/assistant` label. Runs all three tools on the same AIO installation in sequence:

1. AIO install → `installer` validation
2. `wazuh-certs-tool.sh` → `cert-tool` validation
3. `wazuh-passwords-tool.sh` → `passwords-tool` validation
4. Uninstall → `uninstall` validation

### Test execution matrix

| test_type | `test_services` | `test_certificates` | `test_cert_tool` | `test_passwords` | `test_default_credentials` | `test_logs` | `test_version` | `test_uninstall` |
| --------- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `installer` | ✓ | ✓ | — | — | ✓ | ✓ | ✓ | — |
| `cert-tool` | — | ✓ | ✓ | — | ✓ | — | — | — |
| `passwords-tool` | ✓ | — | — | ✓ | ✓ | — | — | — |
| `all` | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | — |
| `uninstall` | — | — | — | — | — | — | — | ✓ |

## Workflow jobs

The workflow is composed of three jobs.

### Job 1 — `get_pr_info` (label trigger only)

1. Reads the PR number, head branch and commit SHA from the event payload.
2. Maps the label name to a `tool_type` and `install_mode`.

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
7. Posts a per-OS result comment on the PR (label trigger only).
8. Uploads test result files as artifacts (7-day retention).
9. **Always** deallocates the instance, even if previous steps failed.
10. Fails the job when `test_runner` reported a failed test. The test steps continue on error so that the results are reported and the instance is deallocated first.

## Environment variables for `test_runner`

| Variable | Description | Value in CI |
| -------- | ----------- | ----------- |
| `WAZUH_NEW_PASSWORD` | New password set by `wazuh-passwords-tool.sh` | `T3sting-Password` |
| `WAZUH_SERVICE_PASSWORD` | Password used for health check API calls | `T3sting-Password` |
| `WAZUH_CERT_TOOL_OUTPUT_DIR` | Directory where `wazuh-certs-tool.sh` writes certificates | `/tmp/wazuh-certificates` |
| `WAZUH_OLD_PASSWORD` | `admin` password set by the installation, read from `/etc/wazuh/credentials.env` before the rotation (masked) | `passwords-tool` and `all` |
| `WAZUH_INSTALL_MODE` | Installation mode, for the common name expected in the node certificates | `aio` / `distributed` / `offline` |
| `WAZUH_MANAGER_EXPECTED_VERSION`, `WAZUH_INDEXER_EXPECTED_VERSION`, `WAZUH_DASHBOARD_EXPECTED_VERSION` | Expected version, from `VERSION.json` of the branch under test (with `-latest` for staging packages) | e.g. `5.0.0-latest` |

For the `installer` and `cert-tool` test types, `WAZUH_SERVICE_PASSWORD` is empty and `test_runner` reads the passwords from `/etc/wazuh/credentials.env` on the instance. It masks every value it reads in the workflow log.

## Results and artifacts

### PR comments

After each OS job completes, a bot comment is posted (or updated if one already exists) on the PR with:

- The tool, installation mode, and OS tested.
- Overall pass/fail status.
- Detailed test output from `test_runner`.
- A link to the workflow run.

For the `test/assistant` label, a separate uninstall result section is appended to the same comment.

### GitHub checks

When triggered by a label, each job of the run shows up in the PR checks with its own result.

### Artifacts

Test result files are uploaded as GitHub Actions artifacts with a 7-day retention period. The artifact name format is:

```
test-results-<tool_type>-<install_mode>-<system>
```

For example: `test-results-installer-aio-ubuntu-24-amd64`

## Examples

### Trigger via PR label

Add any of the following labels to a non-draft PR:

```
test/install
```

Test the AIO installer and validate services, certificates, logs, and version. Runs on all supported systems.

```
test/install-distributed
```

Test the distributed installation flow (separate install of each component). Runs on all supported systems.

```
test/install-offline
```

Test the offline installation flow (no internet access on the instance during install). Runs on all supported systems.

```
test/cert-tool
```

Test certificate generation only. No Wazuh installation is performed. Runs on all supported systems.

```
test/passwords-tool
```

Perform an AIO installation, rotate passwords for all internal users, and validate the new credentials. Runs on all supported systems.

```
test/assistant
```

Run the full end-to-end sequence: AIO install → cert-tool → passwords-tool → uninstall. Runs on all supported systems.

---

### Trigger via GitHub CLI

Test the AIO installer on a specific branch, limited to two systems:

```bash
gh workflow run 5_check_integration_tools.yaml \
  --field pr_head_ref=enhancement/my-feature \
  --field tool_type=installer \
  --field install_mode=aio \
  --field systems="ubuntu-24-amd64,redhat-9-amd64"
```

Test the distributed installer on all systems using production packages:

```bash
gh workflow run 5_check_integration_tools.yaml \
  --field pr_head_ref=main \
  --field tool_type=installer \
  --field install_mode=distributed \
  --field package_type=production
```

Test the offline installer on ARM64 systems only:

```bash
gh workflow run 5_check_integration_tools.yaml \
  --field pr_head_ref=fix/offline-install \
  --field tool_type=installer \
  --field install_mode=offline \
  --field systems="ubuntu-24-arm64,redhat-9-arm64"
```

Test the cert-tool using a custom `wazuh-automation` branch:

```bash
gh workflow run 5_check_integration_tools.yaml \
  --field pr_head_ref=fix/cert-generation \
  --field tool_type=cert-tool \
  --field automation_reference=feature/new-cert-tests
```

Run the full sequence on a single system:

```bash
gh workflow run 5_check_integration_tools.yaml \
  --field pr_head_ref=main \
  --field tool_type=all \
  --field systems=ubuntu-24-amd64
```
