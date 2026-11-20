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
- **Multi-Platform Support**: Runs on Red Hat Enterprise Linux 9 and 10, Amazon Linux 2023, and Ubuntu 24.04 and 26.04. See [Compatibility](docs/ref/introduction/compatibility.md).

## Tools

The Wazuh installation assistant uses the following tools to enhance security during the installation process:

- **Wazuh passwords tool**: Securely generate and manage passwords. [Learn more](docs/ref/getting-started/usage.md#wazuh-password-tool).
- **Wazuh cert tool**: Manage SSL/TLS certificates for secure communications. [Learn more](docs/ref/getting-started/usage.md#wazuh-certs-tool).

## User Guide

### Downloads

The published scripts include the version in their file names:

- [Download the Wazuh installation assistant.](https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.1.sh)
- [Download the Wazuh passwords tool.](https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-passwords-tool-5.0.1.sh)
- [Download the Wazuh cert tool.](https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-certs-tool-5.0.1.sh)

For example:

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.1.sh
```

See [Installation](docs/ref/installation/installation.md) for the download commands of each tool, including the pre-release ones.

### Build the scripts

As an alternative to downloading, use the `builder.sh` script to build the Wazuh installation assistant and tools. The scripts it builds have no version in their file names:

1. Build the Wazuh installation assistant - `wazuh-install.sh`:

   ```bash
   bash builder.sh -i
   ```

2. Build the Wazuh passwords tool - `wazuh-passwords-tool.sh`:

   ```bash
   bash builder.sh -p
   ```

3. Build the Wazuh cert tool - `wazuh-certs-tool.sh`:

   ```bash
   bash builder.sh -c
   ```

## Use Cases

The commands below use the downloaded `wazuh-install-5.0.1.sh`. A script built with `builder.sh` is named `wazuh-install.sh`.

For a distributed deployment, start by downloading the configuration file as `config.yml`, next to the script, and replace the node names and IP values with the corresponding ones:

```bash
curl -fsS -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.0.1.yml
```

For DNS-based or mixed address configurations, see [Other `config.yml` examples](docs/ref/configuration/configuration-files.md#other-configyml-examples).

> [!NOTE]
> It is not necessary to download the Wazuh passwords tool and the Wazuh cert tool to use the Wazuh installation assistant. The Wazuh installation assistant has embedded the previous tools.

### Common commands

1. Generate the passwords and certificates. Needs the `config.yml` configuration file.

   ```bash
   bash wazuh-install-5.0.1.sh -g
   ```

2. Install all central components on the local machine:

   ```bash
   bash wazuh-install-5.0.1.sh -a
   ```

3. Uninstall all central components:

   ```bash
   bash wazuh-install-5.0.1.sh -u
   ```

4. Install the Wazuh indexer specifying the same name as specified in the configuration file:

   ```bash
   bash wazuh-install-5.0.1.sh --wazuh-indexer <NODE_NAME>
   ```

5. Initialize the Wazuh indexer cluster:

   ```bash
   bash wazuh-install-5.0.1.sh --start-cluster
   ```

6. Install the Wazuh manager specifying the same name as specified in the configuration file:

   ```bash
   bash wazuh-install-5.0.1.sh --wazuh-manager <NODE_NAME>
   ```

7. Install the Wazuh dashboard specifying the same name as specified in the configuration file:

   ```bash
   bash wazuh-install-5.0.1.sh --wazuh-dashboard <NODE_NAME>
   ```

8. Display all options and help:

   ```bash
   bash wazuh-install-5.0.1.sh -h
   ```

## Options Table

All the options for the Wazuh installation assistant are listed in the following table:

| Option | Description |
| --------------------------------------- | ---------------------------------------- |
| `-a`, `--all-in-one`                  | Install and configure Wazuh manager, Wazuh indexer, Wazuh dashboard.  |
| `-as`, `--agent-san <ip\|dns>`        | Add an extra address to the subject alternative name of the agent listener certificate of every Wazuh manager node. Repeat it for more than one. This option must be used with `-a` or `-g`.  |
| `-ap`, `--api-san <ip\|dns>`          | Add an extra address to the subject alternative name of the Server API certificate of every Wazuh manager node. Repeat it for more than one. With `-a`, the Server API also listens on all network interfaces instead of only on the local host. This option must be used with `-a` or `-g`.  |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If `local` is specified, it uses a local `artifact_urls.yaml` file located in the same directory as the script.  |
| `--skip-signature-check`              | Install packages that are not signed with the Wazuh key. Only for development packages, must be used with `-d`.  |
| `-dw`, `--download-wazuh <deb\|rpm>`  | Download all the packages necessary for offline installation. Specify the type of packages to download for offline installation (`rpm`, `deb`).  |
| `-da`, `--download-arch <amd64\|arm64\|x86_64\|aarch64>` | Define the architecture of the packages to download for offline installation.  |
| `-g`, `--generate-config-files`       | Generate `wazuh-install-files.tar` file containing the files needed for installation from `config.yml`. In distributed deployments, you will need to copy this file to all hosts.  |
| `-h`, `--help`                        | Display this help and exit.  |
| `-id`, `--install-dependencies`       | Install automatically the necessary dependencies for the installation.  |
| `-o`, `--overwrite`                   | Overwrite previously installed components. This will erase all the existing configuration and data.  |
| `-of`, `--offline-installation`       | Perform an offline installation. This option must be used with `-a`, `-wm`, `-s`, `-wi`, or `-wd`.  |
| `-s`, `--start-cluster`               | Initialize Wazuh indexer cluster security settings.  |
| `-u`, `--uninstall`                   | Uninstall all Wazuh components. This will erase all the existing configuration and data.  |
| `-v`, `--verbose`                     | Show the complete installation output.  |
| `-V`, `--version`                     | Show the version of the script and Wazuh packages.  |
| `-wd`, `--wazuh-dashboard <dashboard-node-name>`  | Install and configure Wazuh dashboard, used for distributed deployments.  |
| `-wi`, `--wazuh-indexer <indexer-node-name>`      | Install and configure Wazuh indexer, used for distributed deployments.  |
| `-wm`, `--wazuh-manager <manager-node-name>`        | Install and configure Wazuh manager, used for distributed deployments.  |

The options of the Wazuh cert tool and the Wazuh passwords tool are in [Command line options](docs/ref/configuration/command-line-options.md).

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
> *Additional check*: Run unit [tests](tests/unit/README.md) before preparing a pull request.

Some useful links and acknowledgment:

- [Shellcheck](https://github.com/koalaman/shellcheck#gallery-of-bad-code)

## More Information

For more detailed instructions and advanced use cases, please refer to the [documentation](docs/README.md) in this repository: the [usage reference](docs/ref/getting-started/usage.md) and the [deployment guides](docs/guide/installation-assistant-deployments/installation-assistant-deployments.md).

## Authors

Wazuh Copyright (C) Wazuh Inc. (License GPLv2)
