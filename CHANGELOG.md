# Change Log
All notable changes to this project will be documented in this file.

## [4.14.2]

### Added

- None

### Changed

- Updated Wazuh Filebeat module from 0.4 to 0.5 version. ([#529](https://github.com/wazuh/wazuh-installation-assistant/pull/529))

### Fixed

- Changed main branch as default branch for Filebeat module. ([#531](https://github.com/wazuh/wazuh-installation-assistant/pull/531))

### Deleted

- None

## [4.14.1]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.14.0]

### Added

- None

### Changed

- Remove dashboard chat setting([#476](https://github.com/wazuh/wazuh-installation-assistant/pull/476)).
- Rollback data source setting([#460](https://github.com/wazuh/wazuh-installation-assistant/pull/460)).
- Dashboard settings added ([#459](https://github.com/wazuh/wazuh-installation-assistant/pull/459)).
- Increase filebeat revision ([#400](https://github.com/wazuh/wazuh-installation-assistant/pull/400)).

### Fixed

- Fixed deb dependencies ([#458](https://github.com/wazuh/wazuh-installation-assistant/pull/458))

### Deleted

- None

## [4.13.1]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.13.0]

### Added

- Add opensearch_dashboard.yml parameters. ([#447](https://github.com/wazuh/wazuh-installation-assistant/pull/447))
- Integrate bumper script via GitHub action. ([#382](https://github.com/wazuh/wazuh-installation-assistant/pull/382))
- Added repository_bumper.sh script. ([#315](https://github.com/wazuh/wazuh-installation-assistant/pull/315))

### Changed

- None

### Fixed

- Added AL2023 and Rocky Linux 9.4 to recommended OS list ([#327](https://github.com/wazuh/wazuh-installation-assistant/pull/327))
- Fix wazuh_major version string ([#272](https://github.com/wazuh/wazuh-installation-assistant/pull/272))

### Deleted

- Remove default installation assistant reference version from workflow ([#284](https://github.com/wazuh/wazuh-installation-assistant/pull/284))

## [4.12.0]

### Added

- Add workflow step to add last_stage variable to the `wazuh-install.sh` ([#226](https://github.com/wazuh/wazuh-installation-assistant/pull/226))

### Changed

- Adapt existing workflows to new allocator YAML inventory ([#254](https://github.com/wazuh/wazuh-installation-assistant/pull/254))
- Changed VERSION file to the new standard format. ([#244](https://github.com/wazuh/wazuh-installation-assistant/pull/244))
- Added support ARM architecture for Wazuh central components ([#225](https://github.com/wazuh/wazuh-installation-assistant/pull/225))
- Change gha runners to Ubuntu 22.04 ([#186](https://github.com/wazuh/wazuh-installation-assistant/pull/186))

### Fixed

- Fix Offline Download with new variable offline_filebeat_version. ([#314](https://github.com/wazuh/wazuh-installation-assistant/pull/314))
- Fixed offline download for Filebeat package. ([#301](https://github.com/wazuh/wazuh-installation-assistant/pull/301))
- Added revision to Filebeat package. ([#300](https://github.com/wazuh/wazuh-installation-assistant/pull/300))
- Fixed handling of hash.sh script output in Password Tool. ([#290](https://github.com/wazuh/wazuh-installation-assistant/pull/290))

### Deleted

- None

## [4.11.2]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.11.1]

### Added

- None

### Changed

- None

### Fixed

- Changed uninstall variables names. ([#259](https://github.com/wazuh/wazuh-installation-assistant/pull/259))

### Deleted

- None

## [4.11.0]

### Added

- Refactor offline instalation test ([#191](https://github.com/wazuh/wazuh-installation-assistant/pull/191))

### Changed

- Add function to change the source_branch with the current stage with --develoment flag activated ([#211](https://github.com/wazuh/wazuh-installation-assistant/pull/211))
- Update upload and download artifact actions to v4 ([#198](https://github.com/wazuh/wazuh-installation-assistant/pull/198))
- Add venv to installation assistant workflows ([#134](https://github.com/wazuh/wazuh-installation-assistant/pull/134))

### Fixed

- Fix error related with Filebeat template ([#222](https://github.com/wazuh/wazuh-installation-assistant/pull/222))
- Update `-d` option in the password tool workflow and fix test scripts ([#170](https://github.com/wazuh/wazuh-installation-assistant/pull/170))
- Added architecture information to assistant. ([#92](https://github.com/wazuh/wazuh-installation-assistant/pull/92))

### Deleted

- None

## [4.10.1]

### Added

- None

### Changed

- None

### Fixed

- Add matrix for pull request and fix provision playbook reference in test workflows ([#136](https://github.com/wazuh/wazuh-installation-assistant/pull/136))
- Added architecture information to assistant. ([#92](https://github.com/wazuh/wazuh-installation-assistant/pull/92))

### Deleted

- None

## [4.10.0]

### Added

- Migrated documentation templates to wazuh-installation-assistant repository. ([#144](https://github.com/wazuh/wazuh-installation-assistant/pull/144))

### Changed

- Removed check functions for Wazuh manager and Filebeat. ([#138](https://github.com/wazuh/wazuh-installation-assistant/pull/138))
- Add checksum input and update the upload files to S3 steps ([#106](https://github.com/wazuh/wazuh-installation-assistant/pull/106))
- Deleted the offline_checkDependencies function and unified logic in offline_checkPrerequisites function. ([#99](https://github.com/wazuh/wazuh-installation-assistant/pull/99))
- Add input for wazuh installation assistant reference in workflows. ([#98](https://github.com/wazuh/wazuh-installation-assistant/pull/98))
- Create GHA workflow to build Wazuh Installation Assistant files. ([#77](https://github.com/wazuh/wazuh-installation-assistant/pull/77))
- Installation assistant distributed test rework and migration. ([#60](https://github.com/wazuh/wazuh-installation-assistant/pull/60))
- Installation assistant test and tier workflow migration ([#46](https://github.com/wazuh/wazuh-installation-assistant/pull/46/))
- Added post-install validations for the Wazuh manager and Filebeat. ([#3059](https://github.com/wazuh/wazuh-packages/pull/3059))
- Update SECURITY.md file. ([#59](https://github.com/wazuh/wazuh-installation-assistant/pull/59))

### Fixed

- Fixed bug when trying to download nonexistent filebeat_wazuh_template ([#124](https://github.com/wazuh/wazuh-installation-assistant/pull/124))
- Fixed offline pre-release package download process ([#121](https://github.com/wazuh/wazuh-installation-assistant/pull/121))
- Changed GitHub Runner version to fix Python error ([#110](https://github.com/wazuh/wazuh-installation-assistant/pull/110))
- Fixed Wazuh API validation ([#29](https://github.com/wazuh/wazuh-installation-assistant/pull/29))
- Fixed token variable empty in Wazuh manager check ([#45](https://github.com/wazuh/wazuh-installation-assistant/pull/45))
- Fixed manager check in distributed deployment ([#52](https://github.com/wazuh/wazuh-installation-assistant/pull/52))
- Changed command order execution to get the TOKEN ([#57](https://github.com/wazuh/wazuh-installation-assistant/pull/57))

## [4.9.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.2

## [4.9.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.1

## [4.9.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.0

## [4.8.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.2

## [4.8.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.1

## [4.8.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.0

## [4.7.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.5

## [4.7.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.4

## [4.7.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.3

## [4.7.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.2

## [4.7.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.1

## [v4.7.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.0

## [v4.6.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.6.0

## [v4.5.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.4

## [v4.5.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.3

## [v4.5.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.2

## [v4.5.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.1

## [v4.5.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.0

## [v4.4.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.5

## [v4.4.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.4

## [v4.4.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.3

## [v4.4.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.2

## [v4.3.11]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.11

## [v4.4.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.1

## [v4.4.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.0

## [v4.3.10]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.10

## [v4.3.9]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.9

## [v4.3.8]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.8

## [v4.3.7]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.7

## [v4.3.6]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.6

## [v4.3.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.5

## [v4.3.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.4

## [v4.3.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.3

## [v4.3.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.2

## [v4.2.7]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.7

## [v4.3.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.1

## [v4.3.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.0

## [v4.2.7]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.7

## [v4.2.6]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.7

## [v4.2.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.5

## [v4.2.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.4

## [v4.2.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.3
