# Wazuh installation assistant

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)

## Table of Contents
- [Wazuh installation assistant](#wazuh-installation-assistant)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Tools](#tools)
  - [User Guide](#user-guide)
    - [Downloads](#downloads)
    - [Build the scripts](#build-the-scripts)
  - [Use Cases](#use-cases)
    - [Common commands](#common-commands)
  - [Options Table](#options-table)
  - [Contribute](#contribute)
  - [Development Guide](#development-guide)
  - [More Information](#more-information)
  - [Authors](#authors)

## Overview

The Wazuh installation Assistant is a tool designed to simplify the deployment of Wazuh. It guides users through the process of installing Wazuh components. Key features include:

- **Guided Installation**: Step-by-step instructions for easy setup.
- **Component Selection**: Install only the Wazuh components you need.
- **System Requirements Check**: Automatically checks if your system meets the necessary requirements.
- **Automated Configuration**: Reduces errors by automating most of the setup.
- **Multi-Platform Support**: Compatible with various Linux distributions like Ubuntu, CentOS, and Debian.

## Tools

The Wazuh installation assistant uses the following tools to enhance security during the installation process:

- **Wazuh password tool**: Securely generate and manage passwords. [Learn more](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html).
- **Wazuh cert tool**: Manage SSL/TLS certificates for secure communications. [Learn more](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/certificates.html).



## User Guide

### Downloads
- [Download the Wazuh installation assistant.](https://packages.wazuh.com/4.14/wazuh-install.sh)
- [Download the Wazuh password tool.](https://packages.wazuh.com/4.14/wazuh-passwords-tool.sh)
- [Download the Wazuh cert tool.](https://packages.wazuh.com/4.14/wazuh-certs-tool.sh)

### Build the scripts
As an alternative to downloading, use the `builder.sh` script to build the Wazuh installation assistant and tools:


1. Build the Wazuh installation assistant - `wazuh-install.sh`:
   ```bash
   bash builder.sh -i
   ```

2. Build the Wazuh password tool - `wazuh-passwords-tool.sh`:
   ```bash
   bash builder.sh -p
   ```

3. Build the Wazuh cert tool - `wazuh-certs-tool.sh`:
   ```bash
   bash builder.sh -c
   ```

## Use Cases

Start by downloading the [configuration file](https://packages.wazuh.com/4.14/config.yml) and replace the node names and IP values with the corresponding ones.

> [!NOTE]
> It is not necessary to download the Wazuh password tool and the Wazuh cert tool to use the Wazuh installation assistant. The Wazuh installation assistant has embedded the previous tools.

### Common commands

1. Generate the passwords and certificates. Needs the [configuration file](https://packages.wazuh.com/4.14/config.yml).
   ```bash
   bash wazuh-install.sh -g
   ```
2. Install all central components on the local machine:
   ```bash
   bash wazuh-install.sh -a
   ```

3. Uninstall all central components:
   ```bash
   bash wazuh-install.sh -u
   ```

4. Install the Wazuh indexer specifying the same name as specified in the configuration file:
   ```bash
   bash wazuh-install.sh --wazuh-indexer <NODE_NAME>
   ```

5. Initialize the Wazuh indexer cluster:
   ```bash
   bash wazuh-install.sh --start-cluster
   ```

6. Install the Wazuh server specifying the same name as specified in the configuration file:
   ```bash
   bash wazuh-install.sh --wazuh-server <NODE_NAME>
   ```

7. Install the Wazuh dashboard specifying the same name as specified in the configuration file:
   ```bash
   bash wazuh-install.sh --wazuh-dashboard <NODE_NAME>
   ```

8. Display all options and help:
   ```bash
   bash wazuh-install.sh -h
   ```

## Options Table

All the options for the Wazuh installation assistant are listed in the following table:
| Option | Description |
|---------------------------------------|----------------------------------------|
| `-a`, `--all-in-one`                  | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard.  |
| `-c`, `--config-file <path-to-config-yml>` | Path to the configuration file used to generate `wazuh-install-files.tar` file containing the files needed for installation. By default, the Wazuh installation assistant will search for a file named `config.yml` in the same path as the script.  |
| `-dw`, `--download-wazuh <deb,rpm>`   | Download all the packages necessary for offline installation. Specify the type of packages to download for offline installation (`rpm`, `deb`).  |
| `-fd`, `--force-install-dashboard`    | Force Wazuh dashboard installation to continue even when it is not capable of connecting to the Wazuh indexer.  |
| `-g`, `--generate-config-files`       | Generate `wazuh-install-files.tar` file containing the files needed for installation from `config.yml`. In distributed deployments, you will need to copy this file to all hosts.  |
| `-h`, `--help`                        | Display this help and exit.  |
| `-i`, `--ignore-check`                | Ignore the check for minimum hardware requirements.  |
| `-o`, `--overwrite`                   | Overwrite previously installed components. This will erase all the existing configuration and data.  |
| `-of`, `--offline-installation`       | Perform an offline installation. This option must be used with `-a`, `-ws`, `-s`, `-wi`, or `-wd`.  |
| `-p`, `--port`                        | Specify the Wazuh web user interface port. Default is the `443` TCP port. Recommended ports are: `8443`, `8444`, `8080`, `8888`, `9000`.  |
| `-s`, `--start-cluster`               | Initialize Wazuh indexer cluster security settings.  |
| `-t`, `--tar <path-to-certs-tar>`     | Path to tar file containing certificate files. By default, the Wazuh installation assistant will search for a file named `wazuh-install-files.tar` in the same path as the script.  |
| `-u`, `--uninstall`                   | Uninstall all Wazuh components. This will erase all the existing configuration and data.  |
| `-v`, `--verbose`                     | Show the complete installation output.  |
| `-V`, `--version`                     | Show the version of the script and Wazuh packages.  |
| `-wd`, `--wazuh-dashboard <dashboard-node-name>`  | Install and configure Wazuh dashboard, used for distributed deployments.  |
| `-wi`, `--wazuh-indexer <indexer-node-name>`      | Install and configure Wazuh indexer, used for distributed deployments.  |
| `-ws`, `--wazuh-server <server-node-name>`        | Install and configure Wazuh manager and Filebeat, used for distributed deployments.  |


## Contribute

If you want to contribute to our repository, please fork our GitHub repository and submit a pull request. Alternatively, you can share ideas through [our users' mailing list](https://groups.google.com/d/forum/wazuh).

## Development Guide

To ensure consistency in development, please follow these guidelines:

- Write functions with a single objective and limited arguments.
- Use libraries selectively (e.g., `install_functions`).
- Main functions should not depend on specific implementations.
- Use descriptive names for variables and functions.
- Use `${var}` instead of `$(var)` and `$(command)` instead of backticks.
- Always quote variables: `"${var}"`.
- Use the `common_logger` function instead of `echo`.
- Check command results with `$?` or `PIPESTATUS`.
- Use timeouts for long commands.
- Ensure all necessary resources are available both online and offline.
- Check command existence with `command -v`.
- Parametrize all package versions.
- Use `| grep -q` instead of `| grep`.
- Use standard `$((..))` instead of old `$[]`.

> [!TIP]
> *Additional check*: Run unit [tests](/tests/unit/README) before preparing a pull request.

Some useful links and acknowledgment:
- [Bash meets solid](https://codewizardly.com/bash-meets-solid/)
- [Shellcheck](https://github.com/koalaman/shellcheck#gallery-of-bad-code)

## More Information

For more detailed instructions and advanced use cases, please refer to the [Wazuh Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html).


## Authors

Wazuh Copyright (C) 2015-2023 Wazuh Inc. (License GPLv2)