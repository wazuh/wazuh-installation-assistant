# Installation assistant workflows

This repository includes several GitHub Actions workflows. They build the tools and scripts, and test them in different environments.

The prefix of each workflow file is the major version it belongs to. The `5_*` workflows build and test this branch. The `4_*` workflows are kept for the maintenance of the 4.x branches: they come from those branches and describe the 4.x tools and operating systems.

## 5.x workflows

| Workflow | File | Trigger | Description |
|---|---|---|---|
| `(5.x) Build Installation Assistant` | `5_builder_installation_assistant.yml` | Manual (`workflow_dispatch`), `workflow_call` | Builds `wazuh-install`, `wazuh-certs-tool` and `wazuh-passwords-tool` with `builder.sh`, and uploads them and the `config.yml` template to S3 with the version in their file names. See [Generate Artifacts Automatically](../../docs/dev/generate-artifact/generate-artifacts-workflow.md). |
| `(5.x) PR Check - Unit Tests` | `5_check_unit_tests.yaml` | Every pull request (opened, updated, reopened, ready for review) | Runs the unit tests with `hatch run dev:test-cov` and comments the results on the pull request. See [Unit tests](../../docs/ref/tests/unit-test/unit-tests.md). |
| `(5.x) PR Check - Test Integration Tools` | `5_check_integration_tools.yaml` | A test label added to a pull request, or manual (`workflow_dispatch`) | Builds the tools from the pull request branch, allocates AWS instances, installs Wazuh and runs the integration tests. See [Installation Assistant Integration Tests](../../docs/ref/integration_test/installation_assistant_integration_tests.md). |
| `5.x Changelog check` | `5_changelog_check.yml` | Every non-draft pull request | Checks that `CHANGELOG.md` has new, well-formed entries. The `no-changelog` label skips it. |
| `(5.x) Repository bumper` | `5_bumper_repository.yml` | Manual (`workflow_dispatch`) | Bumps the version and stage of the repository. |

### Integration test labels

The integration tests run when one of these labels is added to a non-draft pull request opened from a branch of this repository:

| Label | Test |
|---|---|
| `test/install` | Installation assistant, all-in-one |
| `test/install-distributed` | Installation assistant, distributed |
| `test/install-offline` | Installation assistant, offline |
| `test/cert-tool` | Certs tool |
| `test/passwords-tool` | Passwords tool |
| `test/assistant` | The three tools in sequence (all-in-one, certs tool, passwords tool) |

A manual run takes the branch, the tool, the installation mode, the package source and the systems as inputs. The systems are identifiers such as `ubuntu-24-amd64` or `redhat-9-arm64`, or `all`.

## 4.x workflows

| Workflow | File | Trigger | Description |
|---|---|---|---|
| `(4.x) Build Installation Assistant` | `4_builder_installation_assistant.yml` | Manual, `workflow_call` | Builds the 4.x tools and uploads them to S3. |
| `(4.x) Test installation assistant` | `4_test_installation_assistant.yml` | Pull requests to `4.*` branches, manual | Tests the installation assistant in a single-node setup. |
| `(4.x) (Distributed) Test installation assistant` | `4_test_installation_assistant_distributed.yml` | Pull requests to `4.*` branches, manual | Tests a distributed deployment (indexers, managers and dashboard) on three instances. |
| `(4.x) Offline installation test` | `4_offline_installation.yml` | Pull requests to `4.*` branches, manual | Tests the offline installation. |
| `(4.x) Password tool and wazuh-install scripts` | `4_password_tool.yml` | Pull requests to `4.*` branches, manual | Tests the passwords tool. |
| `(4.x) Repository bumper` | `4_bumper_repository.yml` | Manual | Bumps the version and stage of a 4.x branch. |

The rest of this section describes the two `Test installation assistant` workflows.

### Automatic trigger

The test workflows run when a pull request to a `4.*` branch is created or updated and it changes one of these paths:

- `cert_tool/`
- `common_functions/`
- `config/`
- `install_functions/`
- `passwords_tool/`
- `tests/`

A pull request run tests `Ubuntu_22` with the `pre-release` packages.

### Manual trigger

The test workflows can be triggered manually via the GitHub interface under the "Actions" tab, using the `workflow_dispatch` event. When triggered manually, several input parameters are required:

- **REPOSITORY**: Defines the repository environment (`staging` or `pre-release`).
- **WAZUH_INSTALLATION_ASSISTANT_REFERENCE**: The branch or tag of the `wazuh-installation-assistant` repository to test.
- **AUTOMATION_REFERENCE**: The branch or tag of the `wazuh-automation` repository, used to clone the Allocation module.
- **SYSTEMS**: A comma-separated list of operating systems to be tested, enclosed in square brackets (e.g., `["CentOS_8", "AmazonLinux_2", "Ubuntu_22", "RHEL8"]`). The available options are: `CentOS_7`, `CentOS_8`, `AmazonLinux_2`, `Ubuntu_16`, `Ubuntu_18`, `Ubuntu_20`, `Ubuntu_22`, `RHEL7`, `RHEL8`.
- **VERBOSITY**: The verbosity level for Ansible playbook execution, with options `-v`, `-vv`, `-vvv`, and `-vvvv`.
- **DESTROY**: Boolean value (true or false) indicating whether to destroy the instances after testing.

### Workflow structure

The test workflows follow a similar structure with the following key steps:

1. **Checkout Code**: The workflow fetches the code from the `wazuh-automation` and `wazuh-installation-assistant` repositories.

2. **Set Up Environment**: The operating system is configured based on the selected OS in the `SYSTEMS` input. The corresponding OS name is stored in the environment variable `COMPOSITE_NAME`.

3. **Install Ansible**: Ansible is installed for managing the provisioning of instances and running the necessary playbooks.

4. **Provisioning Instances**: The workflow allocates AWS instances using the allocation module of the `wazuh-automation` repository. The distributed workflow creates the instance inventory dynamically and uses it for later playbook executions.

5. **Ansible Playbooks Execution**: Provision playbooks are executed to prepare the environments for Wazuh components.

6. **Test Execution**: A Python-based testing framework is executed to verify the successful installation and functionality of the Wazuh components on the allocated instances.

7. **Destroy Instances (Optional)**: If the `DESTROY` parameter is set to true, or the run comes from a pull request, the allocated AWS instances are terminated after the tests. If set to false in a manual run, the instances are kept and their details are saved for later analysis.

### Saved instance details

If instances are not destroyed, the workflow compresses the directory of the allocated instances with a password and uploads it to S3, one file per OS selected. Ask the DevOps team for the password.

### Notes

- Instance allocation: The distributed workflow provisions three instances. The roles are distributed as follows:
  - `indexer1`, `indexer2`, `indexer3`: Indexers in the Wazuh cluster, one per instance.
  - `master`, `worker1`, `worker2`: Wazuh managers, one per instance, where `master` is the main manager, and `worker1` and `worker2` are worker nodes.
  - `dashboard`: Wazuh dashboard, on the third instance.

- Customization: These workflows allow for customization through the various input parameters, making it easy to test different operating systems, verbosity levels, or different versions of the repositories.
