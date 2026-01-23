# Generate Artifacts Automatically

This section covers the process for generating artifacts for the Installation Assistant tools automatically using the GitHub Actions workflow called `Build Installation Assistant`.
The workflow is defined in the `.github/workflows/builder_installation_assistant.yml` file.

This workflow builds all artifacts in the same execution. Once the execution is complete, the generated artifacts are uploaded to an S3 bucket in AWS. If you need more information about where they are stored, please contact the **DevOps** team.

## Build Parameters

To run the workflow, you must provide various inputs:

- `wazuh installation assistant reference`: Branch or tag of the wazuh-installation-assistant repository.
- `is stage`: Tag that indicates how to name the generated artifact. By default, the name of each artifact includes `\<version\>-\<revision\>`. If set to false, the name of the generated artifact will include `\<version\>-\<revision\>-\<commit-hash\>`. This helps identify when the file is built for development (false) or when it is built for a release or pre-release (true).
- `add last stage`: The installation assistant tool, when built for releases or pre-releases, needs to set a script variable called `last_stage` with the pre-release version it is being built with (alpha1, beta1, rc1, etc). If set to true, the workflow will set this variable with the value provided in the input.
- `file revision`: Revision number that will be added to the name of the generated artifact.
- `checksum`: If set to true, the workflow will generate a SHA256 checksum file for each generated artifact.
- `id`: Unique identifier for the workflow execution.
