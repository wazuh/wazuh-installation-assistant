# Installation assistant workflows

This repository includes several GitHub Actions workflows. These workflows are designed to automate the testing process for the installation of the Wazuh Installation Assistant in various environments and to build the different tools and scripts.

## Workflows Overview

1. `Test_installation_assistant`.
This workflow tests the installation of the Wazuh Installation Assistant in a single-node setup. It triggers on pull requests that modify specific directories or files, and can also be manually dispatched.

2. `Test_installation_assistant_distributed`.
This workflow is an extension of the Test_installation_assistant workflow, intended for distributed environments. It provisions three instances and simulates a distributed Wazuh deployment across multiple nodes (indexers, managers, and dashboards).

## Triggering the Workflows
### Automatic Trigger
The workflows tests are triggered automatically when a pull request (PR) is created or updated, affecting the following paths:

- `cert_tool/`
- `common_functions/`
- `config/`
- `install_functions/`
- `passwords_tool/`
- `tests/`

### Manual Trigger
The test workflows can be triggered manually via the GitHub interface under the "Actions" tab, using the workflow_dispatch event. When triggered manually, several input parameters are required:

- **REPOSITORY**: Defines the repository environment (e.g., staging, pre-release).
- **AUTOMATION_REFERENCE**: The branch or tag of the `wazuh-automation` repository, used to clone the Allocation module.
- **SYSTEMS**: A comma-separated list of operating systems to be tested, enclosed in square brackets (e.g., `["CentOS_8", "AmazonLinux_2", "Ubuntu_22", "RHEL8"]`). The available options are: `CentOS_7`, `CentOS_8`, `AmazonLinux_2`, `Ubuntu_16`, `Ubuntu_18`, `Ubuntu_20`, `Ubuntu_22`, `RHEL7`, `RHEL8`.
- **VERBOSITY**: The verbosity level for Ansible playbook execution, with options `-v`, `-vv`, `-vvv`, and `-vvvv`.
- **DESTROY**: Boolean value (true or false) indicating whether to destroy the instances after testing. 

## Workflow Structure
### Jobs

The tests workflows follow a similar structure with the following key jobs:

1. **Checkout Code**: The workflow fetches the latest code from the wazuh-automation and wazuh-installation-assistant repositories.

2. **Set Up Environment**: The operating system is configured based on the selected OS in the SYSTEMS input. The corresponding OS name is stored in the environment variable COMPOSITE_NAME.

3. **Install Ansible**: Ansible is installed for managing the provisioning of instances and running the necessary playbooks.

4. **Provisioning Instances**: The distributed workflow allocates AWS instances using the wazuh-automation repository’s allocation module. It provisions indexers, managers, and dashboards across the instances. The instance inventory is dynamically created and used for later playbook executions.

5. **Ansible Playbooks Execution**: Provision playbooks are executed to prepare the environments for Wazuh components.

6. **Test Execution**: A Python-based testing framework is executed to verify the successful installation and functionality of the Wazuh components on the allocated instances.

7. **Destroy Instances (Optional)**: If the `DESTROY` parameter is set to true, the allocated AWS instances are terminated after the tests. If set to false, the instances and their details are saved as artifacts for later analysis.

### Artifacts
If instances are not destroyed, the workflow compresses the allocated instances' directory and uploads it as an artifact. Also, the artifacts are compressed with a password. Ask @devel-devops teams for this password. An artifact is uploaded per OS selected. 
## Notes
- Instance allocation: The `Test_installation_assistant_distributed` workflow provisions three instances by default. The roles are distributed as follows:
  - `indexer1`, `indexer2`, `indexer3`: Indexers in the Wazuh cluster.
  - `master`, `worker1`, `worker2`: Wazuh managers, where `master` is the main manager, and `worker1` and `worker2` are worker nodes.
  - `dashboard`: Wazuh dashboard.

- Customization: These workflows allow for customization through the various input parameters, making it easy to test different operating systems, verbosity levels, or different versions of the repositories.