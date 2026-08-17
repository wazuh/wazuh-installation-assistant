## [v5.0.0]

### Added

| Issue | Comment |
| - | - |
| [#862](https://github.com/wazuh/wazuh-installation-assistant/pull/862) | Added bump-issue-link input in the 5.x bumper workflow. |
| [#894](https://github.com/wazuh/wazuh-installation-assistant/pull/894) | Add integration test module docs |
| [#843](https://github.com/wazuh/wazuh-installation-assistant/issues/843) | The passwords tool corrupts the admin hash |
| [#805](https://github.com/wazuh/wazuh-installation-assistant/issues/805) | Add open and reopened types for pull requests trigger in check_unit_tests workflow |
| [#785](https://github.com/wazuh/wazuh-installation-assistant/issues/785) | Dashboard connection error messages with the API. |
| [#784](https://github.com/wazuh/wazuh-installation-assistant/issues/784) | Added support for pre-release installation in documentation |
| [#710](https://github.com/wazuh/wazuh-installation-assistant/issues/710) | Add repository installation documentation |
| [#778](https://github.com/wazuh/wazuh-installation-assistant/issues/778) | Inconsistency in Amazon Linux 2023 dependencies in the assistant |
| [#713](https://github.com/wazuh/wazuh-installation-assistant/issues/713) | Support Revert bump functionality in wazuh-installation-assistant |
| [#602](https://github.com/wazuh/wazuh-installation-assistant/issues/602) | Missing documentation in the wazuh-installation-assistant repository |
| [#592](https://github.com/wazuh/wazuh-installation-assistant/issues/592) | Wazuh installation assistant test documentation. |
| [#590](https://github.com/wazuh/wazuh-installation-assistant/issues/590) | Wazuh installation assistant integration tests |
| [#666](https://github.com/wazuh/wazuh-installation-assistant/issues/666) | Add --set-as-main flag support to repository bumper. |
| [#662](https://github.com/wazuh/wazuh-installation-assistant/issues/662) | Missing wazuh-offline-installation documentation |
| [#589](https://github.com/wazuh/wazuh-installation-assistant/issues/589) | wazuh-passwords-tool integration tests and unit tests |
| [#628](https://github.com/wazuh/wazuh-installation-assistant/issues/628) | Certificates with multiple SAN |
| [#579](https://github.com/wazuh/wazuh-installation-assistant/issues/579) | Add documentation for Installation Assistant Tools in 5.0 |
| [#571](https://github.com/wazuh/wazuh-installation-assistant/issues/571) | Ensure the artifacts contain the version to the patch and revision level |
| [#518](https://github.com/wazuh/wazuh-installation-assistant/issues/518) | Backport the --install-dependencies option from 6.0 to main |
| [#513](https://github.com/wazuh/wazuh-installation-assistant/issues/513) | Add new custom internal users to the password file generation process in the password tool |
| [#511](https://github.com/wazuh/wazuh-installation-assistant/issues/511) | Remove Filebeat references from the password tool |
| [#515](https://github.com/wazuh/wazuh-installation-assistant/issues/515) | Remove all the custom option from the installation assistant |
| [#520](https://github.com/wazuh/wazuh-installation-assistant/issues/520) | Update the build workflow to upload config.yml along with the generated artifacts |

### Changed

| Issue | Comment |
| - | - |
| [#974](https://github.com/wazuh/wazuh-installation-assistant/pull/974) | Adapt Allocator install and invocation to the new installable Python package |
| [#972](https://github.com/wazuh/wazuh-installation-assistant/issues/972) | Change Codebuild runners to Github runners |
| [#909](https://github.com/wazuh/wazuh-installation-assistant/issues/909) | Change upload and download methods |
| [#928](https://github.com/wazuh/wazuh-installation-assistant/issues/928) | Update deployment for Wazuh Indexer 5.0.0 RBAC. |
| [#917](https://github.com/wazuh/wazuh-installation-assistant/pull/917) | The Wazuh indexer heap size was modified for the AIO installation. |
| [#930](https://github.com/wazuh/wazuh-installation-assistant/pull/930) | Add new WF for changelog check |
| [#885](https://github.com/wazuh/wazuh-installation-assistant/issues/885) | PR Revamp 5.0.0 |
| [#876](https://github.com/wazuh/wazuh-installation-assistant/issues/876) | Migrate GH runner to codebuild |
| [#855](https://github.com/wazuh/wazuh-installation-assistant/issues/855) | Minor change in step-by-step AIO documentation |
| [#835](https://github.com/wazuh/wazuh-installation-assistant/issues/835) | E2E documentation error found |
| [#829](https://github.com/wazuh/wazuh-installation-assistant/issues/829) | Change run_as: false default reference to run_as: true |
| [#793](https://github.com/wazuh/wazuh-installation-assistant/issues/793) | Recommended systems in the installation assistant differ from the compatibility matrix. |
| [#792](https://github.com/wazuh/wazuh-installation-assistant/issues/792) | Delete Vulnerability Detection configuration log from the installation assistant |
| [#776](https://github.com/wazuh/wazuh-installation-assistant/issues/776) | wazuh-certs-tool script referenced but never used on Clusterized installations. |
| [#757](https://github.com/wazuh/wazuh-installation-assistant/issues/757) | Update step-by-step installation documentation. |
| [#720](https://github.com/wazuh/wazuh-installation-assistant/issues/720) | Change the destination path of the artifact_urls file in wazuh-installation-assistant. |
| [#694](https://github.com/wazuh/wazuh-installation-assistant/issues/694) | Improve the usage example for DNS or IP in config.yml |
| [#649](https://github.com/wazuh/wazuh-installation-assistant/issues/649) | Adapt the config.yml component names to match the default certificate names. |
| [#678](https://github.com/wazuh/wazuh-installation-assistant/issues/678) | Updated GitHub actions version for wazuh-installation-assistant main workflows. |
| [#673](https://github.com/wazuh/wazuh-installation-assistant/issues/673) | Ensure correct Wazuh manager certificates ownership |
| [#668](https://github.com/wazuh/wazuh-installation-assistant/issues/668) | Standarize Artifact URL keys. |
| [#663](https://github.com/wazuh/wazuh-installation-assistant/issues/663) | unneeded verification of package sudo in wazuh-password-tool.sh. |
| [#602](https://github.com/wazuh/wazuh-installation-assistant/issues/602) | Missing documentation in the wazuh-installation-assistant repository |
| [#656](https://github.com/wazuh/wazuh-installation-assistant/issues/656) | Review and update the passwords tool's naming conventions. |
| [#655](https://github.com/wazuh/wazuh-installation-assistant/issues/655) | Installation assistant update pre release and prod artifact urls file paths bucket and naming. |
| [#650](https://github.com/wazuh/wazuh-installation-assistant/issues/650) | Updated wazuh-installation-assistant documentation config and tooling versions to meet new standards. |
| [#641](https://github.com/wazuh/wazuh-installation-assistant/issues/641) | Update artifact generation jobs to use wz-linux dedicated runner group |
| [#625](https://github.com/wazuh/wazuh-installation-assistant/issues/625) | Wazuh Manager/Agent Separation — Breaking Changes Summary |
| [#619](https://github.com/wazuh/wazuh-installation-assistant/issues/619) | Verify that the Wazuh installation tools comply with the development naming convention |
| [#600](https://github.com/wazuh/wazuh-installation-assistant/issues/600) | Change path and artifact names |
| [#601](https://github.com/wazuh/wazuh-installation-assistant/issues/601) | Change server references to manager |
| [#562](https://github.com/wazuh/wazuh-installation-assistant/issues/562) | Composite names update |
| [#519](https://github.com/wazuh/wazuh-installation-assistant/issues/519) | Change component installation to use packages instead of repositories |
| [#538](https://github.com/wazuh/wazuh-installation-assistant/issues/538) | Change the wazuh.yml references to opensearch_dashboards.yml |
| [#510](https://github.com/wazuh/wazuh-installation-assistant/issues/510) | Remove Filebeat references from the certs tool |

### Removed

| Issue | Comment |
| - | - |
| [#836](https://github.com/wazuh/wazuh-installation-assistant/issues/836) | Wazuh dashboard initialization message. |
| [#811](https://github.com/wazuh/wazuh-installation-assistant/issues/811) | Remove -i option from installation assistant |
| [#787](https://github.com/wazuh/wazuh-installation-assistant/issues/787) | Disable 4.x test triggers in the main branch. |
| [#653](https://github.com/wazuh/wazuh-installation-assistant/issues/653) | Offline prerequisites mismatch (lsof, yum-utils / dnf-utils) causes errors and confusing UX |
| [#587](https://github.com/wazuh/wazuh-installation-assistant/issues/587) | Remove last_stage variable from the Installation Assistant |
| [#582](https://github.com/wazuh/wazuh-installation-assistant/issues/582) | RRemove options related with the certs path in the Passwords Tool |
| [#542](https://github.com/wazuh/wazuh-installation-assistant/issues/542) | Remove harcoded configuration files and modify them instead |
| [#555](https://github.com/wazuh/wazuh-installation-assistant/issues/555) | The Password tool should support only individual password changes and remove file-based options |
| [#554](https://github.com/wazuh/wazuh-installation-assistant/issues/554) | Remove the Password Tool from the Installation Assistant |

### Fixed

| Issue | Comment |
| - | - |
| [#933](https://github.com/wazuh/wazuh-installation-assistant/issues/933) | E2E Documentation issues in Release 5.0.0. |
| [#924](https://github.com/wazuh/wazuh-installation-assistant/issues/924) | Change minimum hardware requirements |
| [#925](https://github.com/wazuh/wazuh-installation-assistant/issues/925) | Fix typo |
| [#922](https://github.com/wazuh/wazuh-installation-assistant/pull/922) | Fix bumper workflow failure when bump produces no changes |
| [#875](https://github.com/wazuh/wazuh-installation-assistant/issues/875) | Bumper script issue when the tag is set to false |
| [#822](https://github.com/wazuh/wazuh-installation-assistant/issues/822) | Incorrect behavior when using the -d option in the Installation Assistant |
| [#793](https://github.com/wazuh/wazuh-installation-assistant/issues/793) | Recommended systems in the installation assistant differ from the compatibility matrix |
| [#799](https://github.com/wazuh/wazuh-installation-assistant/issues/799) | Removed simple quote from manager.sh. |
| [#758](https://github.com/wazuh/wazuh-installation-assistant/issues/758) | E2E documentation errors found |
| [#704](https://github.com/wazuh/wazuh-installation-assistant/issues/704) | Unexpected log messages in 4.14.5 RC1 assistant |
| [#693](https://github.com/wazuh/wazuh-installation-assistant/issues/693) | Improve input handling in YAML configuration parser. |
| [#654](https://github.com/wazuh/wazuh-installation-assistant/issues/654) | Wazuh Dashboard API host misconfigured (blank) leads to Invalid manager API URL. |
| [#652](https://github.com/wazuh/wazuh-installation-assistant/issues/652) | Offline one-liner (quickstart) AIO hang during files validation. |
| [#622](https://github.com/wazuh/wazuh-installation-assistant/issues/622) | The certificates script does not generate certificates when a valid YAML format is used |
| [#533](https://github.com/wazuh/wazuh-installation-assistant/issues/533) | Improve cluster initialization message to cluster security settings |

## Prior versions
- []()
