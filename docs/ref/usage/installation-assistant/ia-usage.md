# Installation Assistant Usage

The Installation Assistant is used by running the previously downloaded `wazuh-install.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

## Option list

| Option | Description |
|--------|-------------|
| `-a`, `--all-in-one` | Install and configure Wazuh manager, Wazuh indexer, Wazuh dashboard. |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If local is specified, it will use a local artifact_urls.yml file located in the same path as the wazuh-install.sh. |
| `-dw`, `--download-wazuh <deb\|rpm>` | Download all the packages necessary for offline installation. Type of packages to download for offline installation (rpm, deb) |
| `-da`, `--download-arch <amd64\|arm64\|x86_64\|aarch64>` | Define the architecture of the packages to download for offline installation. |
| `-g`, `--generate-config-files` | Generate wazuh-install-files.tar file containing the files that will be needed for installation from config.yml. In distributed deployments you will need to copy this file to all hosts. |
| `-h`, `--help` | Display this help and exit. |
| `-i`, `--ignore-check` | Ignore the check for minimum hardware requirements. |
| `-id`, `--install-dependencies` | Installs automatically the necessary dependencies for the installation. |
| `-o`, `--overwrite` | Overwrites previously installed components. This will erase all the existing configuration and data. |
| `-of`, `--offline-installation` | Perform an offline installation. This option must be used with -a, -wm, -s, -wi, or -wd. |
| `-s`, `--start-cluster` | Initialize Wazuh indexer cluster security settings. |
| `-u`, `--uninstall` | Uninstalls all Wazuh components. This will erase all the existing configuration and data. |
| `-v`, `--verbose` | Shows the complete installation output. |
| `-V`, `--version` | Shows the version of the script and Wazuh packages. |
| `-wd`, `--wazuh-dashboard <dashboard-node-name>` | Install and configure Wazuh dashboard, used for distributed deployments. |
| `-wi`, `--wazuh-indexer <indexer-node-name>` | Install and configure Wazuh indexer, used for distributed deployments. |
| `-wm`, `--wazuh-manager <manager-node-name>` | Install and configure Wazuh manager, used for distributed deployments. |

## AIO Installation

To perform an AIO (All In One) installation, simply run the following command:

```bash
sudo bash wazuh-install.sh --all-in-one
# or use the short form
sudo bash wazuh-install.sh -a
```

This command will download, install, and configure all Wazuh components on the same machine automatically without the need to configure anything else.

## Specific Component Installation

If you want to install a specific Wazuh component, first make sure you have the `config.yml` file downloaded.

The `config.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [certs-tool-usage.md](../certs-tool/certs-tool-usage.md) section.


The steps to perform the installation are as follows:
> **note**: If you have already configured the `config.yml` and generated the `wazuh-install-files.tar` in the installation of another Wazuh component, you can skip directly to step 4.

1. Edit the `config.yml` file with the desired configuration for each of the Wazuh components.
2. Create the necessary files for installation that will be stored in `wazuh-install-files.tar` with the following command:

    ```bash
    sudo bash wazuh-install.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install.sh -g
    ```
3. The `wazuh-install-files.tar` file will be necessary for the installation of each component that will be part of the distributed installation as it includes the certificates for each of the components specified in the `config.yml` file. Therefore, copy this file to each of the machines where you will install a Wazuh component.
4. Once you have the `wazuh-install-files.tar` file on the machine where you will install the component, you just need to run the installation command for the desired component:

    4.1 To install the Wazuh Manager:
    ``` bash
    sudo bash wazuh-install.sh --wazuh-manager
    # or use the short form
    sudo bash wazuh-install.sh -wm
    ```
    4.2 To install the Wazuh Indexer:
    ``` bash
    sudo bash wazuh-install.sh --wazuh-indexer
    # or use the short form
    sudo bash wazuh-install.sh -wi
    ```
    4.3 To install the Wazuh Dashboard:
    ``` bash
    sudo bash wazuh-install.sh --wazuh-dashboard
    # or use the short form
    sudo bash wazuh-install.sh -wd
    ```

> **note**: The installation assistant is designed to facilitate the initial installation of Wazuh, so the passwords for each Wazuh internal user are set to default. Therefore, it is highly recommended to change them to more secure ones using this tool. You can see how to use this tool in the [Passwords Tool Usage](../../usage/passwords-tool/passwords-tool-usage.md) section.


## Offline Installation

You can install Wazuh even without an Internet connection. Installing the solution offline involves first downloading the Wazuh central components on a system with Internet access, then transferring and installing them on the offline system. Wazuh supports both all-in-one and distributed deployments.

### Download packages necessary for offline installation

1. On a system with Internet access, download the packages of the central components you want to install on the offline system. Note that you also need to have the wazuh-install.sh on the system with Internet access.
See the [Installation Assistant Installation](../../installation/installation-assistant/ia-installation.md) section to learn how to download `wazuh-install.sh`.

    To download the packages necessary for offline installation, run the following command:

    ```bash
    sudo bash wazuh-install.sh --download-wazuh <TYPE> --download-arch <ARCH>
    # or use the short form
    sudo bash wazuh-install.sh -dw <TYPE> -da <ARCH>
    ```

    Where `<TYPE>` is the Linux distribution of the offline system (`deb` or `rpm`) and `<ARCH>` is the architecture of the offline system (`x86_64` or `arm64`).

    This command will generate the `wazuh-offline.tar.gz` file which contains all the packages necessary to install Wazuh on the offline system.

2. Next, create the necessary certificates that will be used in the offline installation. To do this, modify the `config.yml` file with the desired configuration for each of the Wazuh components and run the following command:

    ```bash
    sudo bash wazuh-install.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install.sh -g
    ```
    This command will generate the `wazuh-install-files.tar` file which contains the necessary certificates for offline installation.

3. Transfer all files (`wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install.sh`) to the offline system where you want to install Wazuh using your preferred method (USB, SCP, etc).

### Perform the offline installation

Once you have the `wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install.sh` files on the offline system, the installation is done the same way as a normal Wazuh installation (you can see how it's done in the `AIO Installation` and `Specific Component Installation` sections found above in this document), but by specifying the `-of, --offline-installation` option to the installation command.
For example, to perform an offline AIO installation, the command would be:

```bash
sudo bash wazuh-install.sh --all-in-one --offline-installation
# or use the short form
sudo bash wazuh-install.sh -a -of
```

If you want to install a specific Wazuh component, the command would be similar to the following (depending on the component you are going to install):

```bash
sudo bash wazuh-install.sh --wazuh-manager --offline-installation
# or use the short form
sudo bash wazuh-install.sh -wm -of
```


## Use development packages in the installation

When you use the installation assistant to install Wazuh, the official Wazuh packages are downloaded by default. However, if you are developing or testing new features or want to try the `pre-release` version instead of the official ones, you can do so by specifying the `-d [pre-release|local], --development` option to the installation command.

### Use pre-release packages

If you want to use Wazuh `pre-release` packages instead of the official ones, simply add the `-d pre-release, --development pre-release` option to the installation command. For example, to perform an AIO installation using `pre-release` packages, the command would be:
```bash
sudo bash wazuh-install.sh --all-in-one --development pre-release
# or use the short form
sudo bash wazuh-install.sh -a -d pre-release
```

### Use development packages

To use packages that are in development, it is necessary to have an `artifact_urls.yml` file located in the same path as the `wazuh-install.sh` script. This file must contain the URLs of the development packages that will be used in the installation. It must have the following format:

``` yaml
wazuh_manager_amd64_deb: "http://example.com/wazuh-manager-amd64.deb"
wazuh_manager_arm64_deb: "http://example.com/wazuh-manager-arm"
wazuh_manager_amd64_rpm: "http://example.com/wazuh-manager-amd64.rpm"
wazuh_manager_arm64_rpm: "http://example.com/wazuh-manager-arm.rpm"
wazuh_indexer_amd64_deb: "http://example.com/wazuh-indexer-amd64.deb"
wazuh_indexer_arm64_deb: "http://example.com/wazuh-indexer-arm"
wazuh_indexer_amd64_rpm: "http://example.com/wazuh-indexer-amd64.rpm"
wazuh_indexer_arm64_rpm: "http://example.com/wazuh-indexer-arm.rpm"
wazuh_dashboard_amd64_deb: "http://example.com/wazuh-dashboard-amd64.deb"
wazuh_dashboard_arm64_deb: "http://example.com/wazuh-dashboard-arm"
wazuh_dashboard_amd64_rpm: "http://example.com/wazuh-dashboard-amd64.rpm"
wazuh_dashboard_arm64_rpm: "http://example.com/wazuh-dashboard-arm.rpm"
...
```

Then, to use these development packages in the installation, simply add the `-d local, --development local` option to the installation command. For example, to perform an AIO installation using development packages, the command would be:

```bash
sudo bash wazuh-install.sh --all-in-one --development local
# or use the short form
sudo bash wazuh-install.sh -a -d local
```

This command will automatically detect the `artifact_urls.yml` file in the same path as the `wazuh-install.sh` script and will use the URLs specified in it to download the necessary packages for the installation.
