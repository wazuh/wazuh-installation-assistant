# Change Log
All notable changes to this project will be documented in this file.

## [5.0.0]

### Added

- Fix password tool generateHash ([#846](https://github.com/wazuh/wazuh-installation-assistant/pull/846))
- Add open and reopened types for pull requests trigger in check_unit_tests workflow ([#805](https://github.com/wazuh/wazuh-installation-assistant/pull/805))
- A validation for the status of services is added to the password tool. ([#786](https://github.com/wazuh/wazuh-installation-assistant/pull/786))
- Added support for pre-release installation in documentation ([#784](https://github.com/wazuh/wazuh-installation-assistant/pull/784))
- Added repository download documentation ([#783](https://github.com/wazuh/wazuh-installation-assistant/pull/783))
- Fix offline dependency installation for Amazon Linux 2023 ([#782](https://github.com/wazuh/wazuh-installation-assistant/pull/782))
- Add 5.x bumper revert changes ([#727](https://github.com/wazuh/wazuh-installation-assistant/pull/727))
- Added upgrade documentation and modify summary accordingly ([#703](https://github.com/wazuh/wazuh-installation-assistant/pull/703))
- Add test documentation and fix all documetations with mermaid problems. ([#702](https://github.com/wazuh/wazuh-installation-assistant/pull/702))
- Add distributed, AIO and Offline test into the integration test checks ([#684](https://github.com/wazuh/wazuh-installation-assistant/pull/684))
- Updated bumper script with --set-as-main parameter. ([#686](https://github.com/wazuh/wazuh-installation-assistant/pull/686))
- Added offline installation documentation ([#683](https://github.com/wazuh/wazuh-installation-assistant/pull/683))
- Add unit and integration test ([#630](https://github.com/wazuh/wazuh-installation-assistant/pull/630))
- Add DNS support to the certs-tool ([#634](https://github.com/wazuh/wazuh-installation-assistant/pull/634))
- Add documentation for Installation Assistant Tools in 5.0 ([#583](https://github.com/wazuh/wazuh-installation-assistant/pull/583))
- Add version and revision suffix to built files ([#578](https://github.com/wazuh/wazuh-installation-assistant/pull/578))
- Back port install-dependencies option ([#557](https://github.com/wazuh/wazuh-installation-assistant/pull/557))
- Add new internal users to the password generation process in the Password tool ([#540](https://github.com/wazuh/wazuh-installation-assistant/pull/540))
- Remove filebeat references and replace wazuh.yml to opensearch_dashboards.yml in the password tool ([#539](https://github.com/wazuh/wazuh-installation-assistant/pull/539))
- Remove all the custom option from the installation assistant ([#534](https://github.com/wazuh/wazuh-installation-assistant/pull/534))
- Update the build workflow to upload config.yml ([#526](https://github.com/wazuh/wazuh-installation-assistant/pull/526))

### Changed

- PR Revamp 5.0.0 ([#885](https://github.com/wazuh/wazuh-installation-assistant/pull/885))
- Migrate GH runner to codebuild ([#876](https://github.com/wazuh/wazuh-installation-assistant/pull/876))
- Fix certificate paths on wazuh-manager.conf ([#858](https://github.com/wazuh/wazuh-installation-assistant/pull/858))
- Change Wazuh dashboard certificates path for clusterized deployment ([#841](https://github.com/wazuh/wazuh-installation-assistant/pull/841))
- Changed run_as: false to true in step-by-step documentation ([#834](https://github.com/wazuh/wazuh-installation-assistant/pull/834))
- Updated test instances size. ([#804](https://github.com/wazuh/wazuh-installation-assistant/pull/804))
- VD log message removed ([#795](https://github.com/wazuh/wazuh-installation-assistant/pull/795))
- Fixed clusterized documentation for wazuh-install.sh download file. ([#794](https://github.com/wazuh/wazuh-installation-assistant/pull/794))
- Updated step by step documentation with apt and yum commands. ([#779](https://github.com/wazuh/wazuh-installation-assistant/pull/779))
- Added artifact_urls s3 bucket folder to the download process. ([#731](https://github.com/wazuh/wazuh-installation-assistant/pull/731))
- Changed config.yml template to show only ip keys ([#717](https://github.com/wazuh/wazuh-installation-assistant/pull/717))
- Adapted the config.yml component names to match the default certificate names. ([#679](https://github.com/wazuh/wazuh-installation-assistant/pull/679))
- Updated GitHub actions version for wazuh-installation-assistant main workflows. ([#678](https://github.com/wazuh/wazuh-installation-assistant/pull/678))
- Change wazuh-manager certs folder ownership to wazuh-manager ([#676](https://github.com/wazuh/wazuh-installation-assistant/pull/676))
- Updated Wazuh installation assistant to use packages archichecture key names. ([#675](https://github.com/wazuh/wazuh-installation-assistant/pull/675))
- Updated user ownership for wazuh manager certificates. ([#674](https://github.com/wazuh/wazuh-installation-assistant/pull/674))
- Removed sudo command from Wazuh installation assistant 5.0.0. ([#667](https://github.com/wazuh/wazuh-installation-assistant/pull/667))
- Updated installation assistant documentation ([#661](https://github.com/wazuh/wazuh-installation-assistant/pull/661))
- Updated passwords tool convention naming. ([#658](https://github.com/wazuh/wazuh-installation-assistant/pull/658))
- Installation assistant update pre release and prod artifact urls file paths bucket and naming. ([#655](https://github.com/wazuh/wazuh-installation-assistant/pull/655))
- Updated wazuh-installation-assistant documentation config and tooling versions to meet new standards. ([#650](https://github.com/wazuh/wazuh-installation-assistant/pull/650))
- Update artifact generation jobs to use wz-linux dedicated runner group ([#641](https://github.com/wazuh/wazuh-installation-assistant/pull/641))
- Breaking Changes Summary ([#627](https://github.com/wazuh/wazuh-installation-assistant/pull/627))
- Change naming convention ([#626](https://github.com/wazuh/wazuh-installation-assistant/pull/626))
- Change ossec references to wazuh-manager ([#612](https://github.com/wazuh/wazuh-installation-assistant/pull/612))
- Change server references to manager ([#613](https://github.com/wazuh/wazuh-installation-assistant/pull/613))
- Composite names update ([#562](https://github.com/wazuh/wazuh-installation-assistant/pull/562))
- Change offline assistant install from repositories to packages ([#550](https://github.com/wazuh/wazuh-installation-assistant/pull/550))
- Replace wazuh.yml references to opensearch_dashboards.yml in the installation assistant ([#545](https://github.com/wazuh/wazuh-installation-assistant/pull/545))
- Change Filebeat references to server in the certs tool ([#528](https://github.com/wazuh/wazuh-installation-assistant/pull/528))

### Fixed

- Fix behavior with -d option when it has an empty parameter ([#830](https://github.com/wazuh/wazuh-installation-assistant/pull/830))
- Update the OS compatibility matrix and ram specs ([#802](https://github.com/wazuh/wazuh-installation-assistant/pull/802))
- Removed simple quote from manager.sh. ([#800](https://github.com/wazuh/wazuh-installation-assistant/pull/800))
- Fixed step-by-step installation documentation errors ([#781](https://github.com/wazuh/wazuh-installation-assistant/pull/781))
- Fix install dependencies logic and delete redundant functions ([#748](https://github.com/wazuh/wazuh-installation-assistant/pull/748))
- The security of the installation assistant is improved when creating configuration files in main. ([#737](https://github.com/wazuh/wazuh-installation-assistant/pull/737))
- Fixed Wazuh Dashboard API host. ([#681](https://github.com/wazuh/wazuh-installation-assistant/pull/681))
- Fixed offline one liner quickstart aio hang during files validation. ([#680](https://github.com/wazuh/wazuh-installation-assistant/pull/680))
- Fix YAML Parser to Accept Multiple Indentation Formats ([#631](https://github.com/wazuh/wazuh-installation-assistant/pull/631))
- Update Indexer cluster security initialization message ([#563](https://github.com/wazuh/wazuh-installation-assistant/pull/563))

### Deleted

- Removed dashboard connection validation message, and dashboard_obtainNodeIp method. ([#842](https://github.com/wazuh/wazuh-installation-assistant/pull/842))
- Removed support for -i option in the Installation Assistant ([#817](https://github.com/wazuh/wazuh-installation-assistant/pull/817))
- Removed old Wazuh installation assistant test workflows. ([#803](https://github.com/wazuh/wazuh-installation-assistant/pull/803))
- Deleted yum-utils and lsof dependencies ([#692](https://github.com/wazuh/wazuh-installation-assistant/pull/692))
- Remove last_stage and other deprecated variables and functions in the installation Assistant ([#593](https://github.com/wazuh/wazuh-installation-assistant/pull/593))
- Remove admin key custom paths options from the Password Tool ([#586](https://github.com/wazuh/wazuh-installation-assistant/pull/586))
- Remove hardcoded config files and use component defaults ([#572](https://github.com/wazuh/wazuh-installation-assistant/pull/572))
- Delete all passwords change option and passwords file support ([#567](https://github.com/wazuh/wazuh-installation-assistant/pull/567))
- Remove the Password Tool from the Installation Assistant files ([#560](https://github.com/wazuh/wazuh-installation-assistant/pull/560))

## Prior version
- []()