# Change Log
All notable changes to this project will be documented in this file.

## [1.2.3]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [v5.0.0]

### Added

- Add integration test module docs ([#894](https://github.com/wazuh/wazuh-installation-assistant/pull/894))
- The passwords tool corrupts the admin hash ([#843](https://github.com/wazuh/wazuh-installation-assistant/issues/843))
- Add open and reopened types for pull requests trigger in check_unit_tests workflow ([#805](https://github.com/wazuh/wazuh-installation-assistant/issues/805))
- Dashboard connection error messages with the API. ([#785](https://github.com/wazuh/wazuh-installation-assistant/issues/785))
- Added support for pre-release installation in documentation ([#784](https://github.com/wazuh/wazuh-installation-assistant/issues/784))
- Add repository installation documentation ([#710](https://github.com/wazuh/wazuh-installation-assistant/issues/710))
- Inconsistency in Amazon Linux 2023 dependencies in the assistant ([#778](https://github.com/wazuh/wazuh-installation-assistant/issues/778))
- Support Revert bump functionality in wazuh-installation-assistant ([#713](https://github.com/wazuh/wazuh-installation-assistant/issues/713))
- Missing documentation in the wazuh-installation-assistant repository ([#602](https://github.com/wazuh/wazuh-installation-assistant/issues/602))
- Wazuh installation assistant test documentation. ([#592](https://github.com/wazuh/wazuh-installation-assistant/issues/592))
- Wazuh installation assistant integration tests ([#590](https://github.com/wazuh/wazuh-installation-assistant/issues/590))
- Add --set-as-main flag support to repository bumper. ([#666](https://github.com/wazuh/wazuh-installation-assistant/issues/666))
- Missing wazuh-offline-installation documentation ([#662](https://github.com/wazuh/wazuh-installation-assistant/issues/662))
- wazuh-passwords-tool integration tests and unit tests ([#589](https://github.com/wazuh/wazuh-installation-assistant/issues/589))
- Certificates with multiple SAN ([#628](https://github.com/wazuh/wazuh-installation-assistant/issues/628))
- Add documentation for Installation Assistant Tools in 5.0 ([#579](https://github.com/wazuh/wazuh-installation-assistant/issues/579))
- Ensure the artifacts contain the version to the patch and revision level ([#571](https://github.com/wazuh/wazuh-installation-assistant/issues/571))
- Backport the --install-dependencies option from 6.0 to main ([#518](https://github.com/wazuh/wazuh-installation-assistant/issues/518))
- Add new custom internal users to the password file generation process in the password tool ([#513](https://github.com/wazuh/wazuh-installation-assistant/issues/513))
- Remove Filebeat references from the password tool ([#511](https://github.com/wazuh/wazuh-installation-assistant/issues/511))
- Remove all the custom option from the installation assistant ([#515](https://github.com/wazuh/wazuh-installation-assistant/issues/515))
- Update the build workflow to upload config.yml along with the generated artifacts ([#520](https://github.com/wazuh/wazuh-installation-assistant/issues/520))

### Changed

- PR Revamp 5.0.0 ([#885](https://github.com/wazuh/wazuh-installation-assistant/issues/885))
- Migrate GH runner to codebuild ([#876](https://github.com/wazuh/wazuh-installation-assistant/issues/876))
- Minor change in step-by-step AIO documentation ([#855](https://github.com/wazuh/wazuh-installation-assistant/issues/855))
- E2E documentation error found ([#835](https://github.com/wazuh/wazuh-installation-assistant/issues/835))
- Change run_as: false default reference to run_as: true ([#829](https://github.com/wazuh/wazuh-installation-assistant/issues/829))
- Recommended systems in the installation assistant differ from the compatibility matrix. ([#793](https://github.com/wazuh/wazuh-installation-assistant/issues/793))
- Delete Vulnerability Detection configuration log from the installation assistant ([#792](https://github.com/wazuh/wazuh-installation-assistant/issues/792))
- wazuh-certs-tool script referenced but never used on Clusterized installations. ([#776](https://github.com/wazuh/wazuh-installation-assistant/issues/776))
- Update step-by-step installation documentation. ([#757](https://github.com/wazuh/wazuh-installation-assistant/issues/757))
- Change the destination path of the artifact_urls file in wazuh-installation-assistant. ([#720](https://github.com/wazuh/wazuh-installation-assistant/issues/720))
- Improve the usage example for DNS or IP in config.yml ([#694](https://github.com/wazuh/wazuh-installation-assistant/issues/694))
- Adapt the config.yml component names to match the default certificate names. ([#649](https://github.com/wazuh/wazuh-installation-assistant/issues/649))
- Updated GitHub actions version for wazuh-installation-assistant main workflows. ([#678](https://github.com/wazuh/wazuh-installation-assistant/issues/678))
- Ensure correct Wazuh manager certificates ownership ([#673](https://github.com/wazuh/wazuh-installation-assistant/issues/673))
- Standarize Artifact URL keys. ([#668](https://github.com/wazuh/wazuh-installation-assistant/issues/668))
- unneeded verification of package sudo in wazuh-password-tool.sh. ([#663](https://github.com/wazuh/wazuh-installation-assistant/issues/663))
- Missing documentation in the wazuh-installation-assistant repository ([#602](https://github.com/wazuh/wazuh-installation-assistant/issues/602))
- Review and update the passwords tool's naming conventions. ([#656](https://github.com/wazuh/wazuh-installation-assistant/issues/656))
- Installation assistant update pre release and prod artifact urls file paths bucket and naming. ([#655](https://github.com/wazuh/wazuh-installation-assistant/issues/655))
- Updated wazuh-installation-assistant documentation config and tooling versions to meet new standards. ([#650](https://github.com/wazuh/wazuh-installation-assistant/issues/650))
- Update artifact generation jobs to use wz-linux dedicated runner group ([#641](https://github.com/wazuh/wazuh-installation-assistant/issues/641))
- Wazuh Manager/Agent Separation — Breaking Changes Summary ([#625](https://github.com/wazuh/wazuh-installation-assistant/issues/625))
- Verify that the Wazuh installation tools comply with the development naming convention ([#619](https://github.com/wazuh/wazuh-installation-assistant/issues/619))
- Change path and artifact names ([#600](https://github.com/wazuh/wazuh-installation-assistant/issues/600))
- Change server references to manager ([#601](https://github.com/wazuh/wazuh-installation-assistant/issues/601))
- Composite names update ([#562](https://github.com/wazuh/wazuh-installation-assistant/issues/562))
- Change component installation to use packages instead of repositories ([#519](https://github.com/wazuh/wazuh-installation-assistant/issues/519))
- Change the wazuh.yml references to opensearch_dashboards.yml ([#538](https://github.com/wazuh/wazuh-installation-assistant/issues/538))
- Remove Filebeat references from the certs tool ([#510](https://github.com/wazuh/wazuh-installation-assistant/issues/510))

### Removed

- Wazuh dashboard initialization message. ([#836](https://github.com/wazuh/wazuh-installation-assistant/issues/836))
- Remove -i option from installation assistant ([#811](https://github.com/wazuh/wazuh-installation-assistant/issues/811))
- Disable 4.x test triggers in the main branch. ([#787](https://github.com/wazuh/wazuh-installation-assistant/issues/787))
- Offline prerequisites mismatch (lsof, yum-utils / dnf-utils) causes errors and confusing UX ([#653](https://github.com/wazuh/wazuh-installation-assistant/issues/653))
- Remove last_stage variable from the Installation Assistant ([#587](https://github.com/wazuh/wazuh-installation-assistant/issues/587))
- RRemove options related with the certs path in the Passwords Tool ([#582](https://github.com/wazuh/wazuh-installation-assistant/issues/582))
- Remove harcoded configuration files and modify them instead ([#542](https://github.com/wazuh/wazuh-installation-assistant/issues/542))
- The Password tool should support only individual password changes and remove file-based options ([#555](https://github.com/wazuh/wazuh-installation-assistant/issues/555))
- Remove the Password Tool from the Installation Assistant ([#554](https://github.com/wazuh/wazuh-installation-assistant/issues/554))

### Fixed

- Incorrect behavior when using the -d option in the Installation Assistant ([#822](https://github.com/wazuh/wazuh-installation-assistant/issues/822))
- Recommended systems in the installation assistant differ from the compatibility matrix ([#793](https://github.com/wazuh/wazuh-installation-assistant/issues/793))
- Removed simple quote from manager.sh. ([#799](https://github.com/wazuh/wazuh-installation-assistant/issues/799))
- E2E documentation errors found ([#758](https://github.com/wazuh/wazuh-installation-assistant/issues/758))
- Unexpected log messages in 4.14.5 RC1 assistant ([#704](https://github.com/wazuh/wazuh-installation-assistant/issues/704))
- Improve input handling in YAML configuration parser. ([#693](https://github.com/wazuh/wazuh-installation-assistant/issues/693))
- Wazuh Dashboard API host misconfigured (blank) leads to Invalid manager API URL. ([#654](https://github.com/wazuh/wazuh-installation-assistant/issues/654))
- Offline one-liner (quickstart) AIO hang during files validation. ([#652](https://github.com/wazuh/wazuh-installation-assistant/issues/652))
- The certificates script does not generate certificates when a valid YAML format is used ([#622](https://github.com/wazuh/wazuh-installation-assistant/issues/622))
- Improve cluster initialization message to cluster security settings ([#533](https://github.com/wazuh/wazuh-installation-assistant/issues/533))

## Prior version
- []()
