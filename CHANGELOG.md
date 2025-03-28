# Change Log
All notable changes to this project will be documented in this file.


## [5.0.0]

### Added

- Improve asistant test completion status ([#188](https://github.com/wazuh/wazuh-installation-assistant/pull/188))
- Added available packages check before installation ([#80](https://github.com/wazuh/wazuh-installation-assistant/pull/80))

### Changed

- Removed node_type option for wazuh-certs-tool.sh. ([#268](https://github.com/wazuh/wazuh-installation-assistant/pull/268))
- Changed VERSION file to the new standard format. ([#245](https://github.com/wazuh/wazuh-installation-assistant/pull/245))
- Check available space before the installation with the installation assistant ([#56](https://github.com/wazuh/wazuh-installation-assistant/pull/56))
- Dependencies installation is reworked in Installation assistant. ([#90](https://github.com/wazuh/wazuh-installation-assistant/pull/90))
- Change apt to dpkg for better performance. ([#89](https://github.com/wazuh/wazuh-installation-assistant/pull/89))
- Added check when generating certificates for multiple DNS. ([#88](https://github.com/wazuh/wazuh-installation-assistant/pull/88))
- Change cert-tool to use only one wazuh-certificates folder. ([#87](https://github.com/wazuh/wazuh-installation-assistant/pull/87))
- Solve bugs when changing passwords in the manager, indexer and dashboard services. ([#86](https://github.com/wazuh/wazuh-installation-assistant/pull/86))
- Fixed typo in Wazuh Installation Assistant. ([#85](https://github.com/wazuh/wazuh-installation-assistant/pull/85))
- Print on console the wazuh user's password when installing Wazuh server. ([#84](https://github.com/wazuh/wazuh-installation-assistant/pull/84))
- Improved service status and output management in Installation assistant. ([#82](https://github.com/wazuh/wazuh-installation-assistant/pull/82))
- Fixed API password change to match the user in wazuh.yml. ([#81](https://github.com/wazuh/wazuh-installation-assistant/pull/81))

### Fixed

- Fixed Version file name. ([#247](https://github.com/wazuh/wazuh-installation-assistant/pull/247))
- Solve confict in installVariables ([#149](https://github.com/wazuh/wazuh-installation-assistant/pull/149))
- Print getHelp output when no parameter is passed to the builder script. ([#142](https://github.com/wazuh/wazuh-installation-assistant/pull/142))

### Deleted

- None

## [4.10.2]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.10.1]

### Added

- None

### Changed

- None

### Fixed

- Added architecture information to assistant. ([#92](https://github.com/wazuh/wazuh-installation-assistant/pull/92))

### Deleted

- None

## [4.10.0]

### Changed

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
