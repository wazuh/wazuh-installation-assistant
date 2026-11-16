# Generate Artifacts Automatically

This section covers the process for generating artifacts for the Installation Assistant tools automatically using the GitHub Actions workflow called `Build Installation Assistant`.
The workflow is defined in the `.github/workflows/5_builder_installation_assistant.yml` file.

This workflow builds all artifacts in the same execution. Once the execution is complete, the generated artifacts are uploaded to an S3 bucket in AWS. If you need more information about where they are stored, please contact the **DevOps** team.

## Build Parameters

To run the workflow, you must provide various inputs:

- `wazuh installation assistant reference`: Branch or tag of the wazuh-installation-assistant repository.
- `is stage`: Tag that indicates how to name the generated artifact. If set to true, the name of each artifact includes `\<version\>-\<revision\>`. If set to false (the default), each artifact is generated twice, with `\<version\>-\<revision\>_\<commit-hash\>` and with `\<version\>-latest` in its name. This helps identify when the file is built for development (false) or when it is built for a release or pre-release (true).
- `file revision`: Revision number that will be added to the name of the generated artifact.
- `checksum`: If set to true, the workflow will generate a SHA512 checksum file (`.sha512`) for each generated artifact.
- `id`: Unique identifier for the workflow execution.
