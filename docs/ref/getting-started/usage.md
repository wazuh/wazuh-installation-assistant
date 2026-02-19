# Usage

## Wazuh installation assistant

The Wazuh Installation Assistant is used by running the previously downloaded `wazuh-install-5.0.0-1.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

### Option list

| Option | Description |
|--------|-------------|
| `-a`, `--all-in-one` | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard. |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If local is specified, it will use a local artifact_urls.yml file located in the same path as the wazuh-install-5.0.0-1.sh. |
| `-dw`, `--download-wazuh <deb\|rpm>` | Download all the packages necessary for offline installation. Type of packages to download for offline installation (rpm, deb) |
| `-da`, `--download-arch <amd64\|arm64\|x86_64\|aarch64>` | Define the architecture of the packages to download for offline installation. |
| `-g`, `--generate-config-files` | Generate wazuh-install-files.tar file containing the files that will be needed for installation from config-5.0.0-1.yml. In distributed deployments you will need to copy this file to all hosts. |
| `-h`, `--help` | Display this help and exit. |
| `-i`, `--ignore-check` | Ignore the check for minimum hardware requirements. |
| `-id`, `--install-dependencies` | Installs automatically the necessary dependencies for the installation. |
| `-o`, `--overwrite` | Overwrites previously installed components. This will erase all the existing configuration and data. |
| `-of`, `--offline-installation` | Perform an offline installation. This option must be used with -a, -ws, -s, -wi, or -wd. |
| `-s`, `--start-cluster` | Initialize Wazuh indexer cluster security settings. |
| `-u`, `--uninstall` | Uninstalls all Wazuh components. This will erase all the existing configuration and data. |
| `-v`, `--verbose` | Shows the complete installation output. |
| `-V`, `--version` | Shows the version of the script and Wazuh packages. |
| `-wd`, `--wazuh-dashboard <dashboard-node-name>` | Install and configure Wazuh dashboard, used for distributed deployments. |
| `-wi`, `--wazuh-indexer <indexer-node-name>` | Install and configure Wazuh indexer, used for distributed deployments. |
| `-ws`, `--wazuh-server <server-node-name>` | Install and configure Wazuh manager, used for distributed deployments. |

### AIO Installation

To perform an AIO (All In One) installation, simply run the following command:

```bash
sudo bash wazuh-install-5.0.0-1.sh --all-in-one
# or use the short form
sudo bash wazuh-install-5.0.0-1.sh -a
```

This command will download, install, and configure all Wazuh components on the same machine automatically without the need to configure anything else.

### Specific Component Installation

If you want to install a specific Wazuh component, first make sure you have the `config-5.0.0-1.yml` file downloaded.

The `config-5.0.0-1.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [certs-tool-usage.md](../certs-tool/certs-tool-usage.md) section.


The steps to perform the installation are as follows:
> **note**: If you have already configured the `config-5.0.0-1.yml` and generated the `wazuh-install-files.tar` in the installation of another Wazuh component, you can skip directly to step 4.

1. Edit the `config-5.0.0-1.yml` file with the desired configuration for each of the Wazuh components.
2. Create the necessary files for installation that will be stored in `wazuh-install-files.tar` with the following command:

    ```bash
    sudo bash wazuh-install-5.0.0-1.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -g
    ```
3. The `wazuh-install-files.tar` file will be necessary for the installation of each component that will be part of the distributed installation as it includes the certificates for each of the components specified in the `config-5.0.0-1.yml` file. Therefore, copy this file to each of the machines where you will install a Wazuh component.
4. Once you have the `wazuh-install-files.tar` file on the machine where you will install the component, you just need to run the installation command for the desired component:

    4.1 To install the Wazuh Manager:
    ``` bash
    sudo bash wazuh-install-5.0.0-1.sh --wazuh-server
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -ws
    ```
    4.2 To install the Wazuh Indexer:
    ``` bash
    sudo bash wazuh-install-5.0.0-1.sh --wazuh-indexer
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -wi
    ```
    4.3 To install the Wazuh Dashboard:
    ``` bash
    sudo bash wazuh-install-5.0.0-1.sh --wazuh-dashboard
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -wd
    ```

> **note**: The installation assistant is designed to facilitate the initial installation of Wazuh, so the passwords for each Wazuh internal user are set to default. Therefore, it is highly recommended to change them to more secure ones using this tool. You can see how to use this tool in the [Passwords Tool Usage](../../usage/passwords-tool/passwords-tool-usage.md) section.


### Offline Installation

You can install Wazuh even without an Internet connection. Installing the solution offline involves first downloading the Wazuh central components on a system with Internet access, then transferring and installing them on the offline system. Wazuh supports both all-in-one and distributed deployments.

#### Download packages necessary for offline installation

1. On a system with Internet access, download the packages of the central components you want to install on the offline system. Note that you also need to have the wazuh-install-5.0.0-1.sh on the system with Internet access.
See the [Installation Assistant Installation](../../installation/installation-assistant/ia-installation.md) section to learn how to download `wazuh-install-5.0.0-1.sh`.

    To download the packages necessary for offline installation, run the following command:

    ```bash
    sudo bash wazuh-install-5.0.0-1.sh --download-wazuh <TYPE> --download-arch <ARCH>
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -dw <TYPE> -da <ARCH>
    ```

    Where `<TYPE>` is the Linux distribution of the offline system (`deb` or `rpm`) and `<ARCH>` is the architecture of the offline system (`x86_64` or `arm64`).

    This command will generate the `wazuh-offline.tar.gz` file which contains all the packages necessary to install Wazuh on the offline system.

2. Next, create the necessary certificates that will be used in the offline installation. To do this, modify the `config-5.0.0-1.yml` file with the desired configuration for each of the Wazuh components and run the following command:

    ```bash
    sudo bash wazuh-install-5.0.0-1.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install-5.0.0-1.sh -g
    ```
    This command will generate the `wazuh-install-files.tar` file which contains the necessary certificates for offline installation.

3. Transfer all files (`wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install-5.0.0-1.sh`) to the offline system where you want to install Wazuh using your preferred method (USB, SCP, etc).

#### Perform the offline installation

Once you have the `wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install-5.0.0-1.sh` files on the offline system, the installation is done the same way as a normal Wazuh installation (you can see how it's done in the `AIO Installation` and `Specific Component Installation` sections found above in this document), but by specifying the `-of, --offline-installation` option to the installation command.
For example, to perform an offline AIO installation, the command would be:

```bash
sudo bash wazuh-install-5.0.0-1.sh --all-in-one --offline-installation
# or use the short form
sudo bash wazuh-install-5.0.0-1.sh -a -of
```

If you want to install a specific Wazuh component, the command would be similar to the following (depending on the component you are going to install):

```bash
sudo bash wazuh-install-5.0.0-1.sh --wazuh-server --offline-installation
# or use the short form
sudo bash wazuh-install-5.0.0-1.sh -ws -of
```


### Use development packages in the installation

When you use the installation assistant to install Wazuh, the official Wazuh packages are downloaded by default. However, if you are developing or testing new features or want to try the `pre-release` version instead of the official ones, you can do so by specifying the `-d [pre-release|local], --development` option to the installation command.

#### Use pre-release packages

If you want to use Wazuh `pre-release` packages instead of the official ones, simply add the `-d pre-release, --development pre-release` option to the installation command. For example, to perform an AIO installation using `pre-release` packages, the command would be:
```bash
sudo bash wazuh-install-5.0.0-1.sh --all-in-one --development pre-release
# or use the short form
sudo bash wazuh-install-5.0.0-1.sh -a -d pre-release
```

#### Use development packages

To use packages that are in development, it is necessary to have an `artifact_urls.yml` file located in the same path as the `wazuh-install-5.0.0-1.sh` script. This file must contain the URLs of the development packages that will be used in the installation. It must have the following format:

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
sudo bash wazuh-install-5.0.0-1.sh --all-in-one --development local
# or use the short form
sudo bash wazuh-install-5.0.0-1.sh -a -d local
```

This command will automatically detect the `artifact_urls.yml` file in the same path as the `wazuh-install-5.0.0-1.sh` script and will use the URLs specified in it to download the necessary packages for the installation.

## Wazuh certs tool

The certs-tool is used by running the previously downloaded `wazuh-certs-tool-5.0.0-1.sh` script along with the `config-5.0.0-1.yml` configuration file. The certs tool generates the necessary certificates for the nodes specified in the configuration file.

### Options list

| Option | Description |
|--------|-------------|
| `-a`, `--admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the admin certificates, add root-ca.pem and root-ca.key. |
| `-A`, `--all </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates certificates specified in config-5.0.0-1.yml and admin certificates. Add a root-ca.pem and root-ca.key or leave it empty so a new one will be created. |
| `-ca`, `--root-ca-certificates` | Creates the root-ca certificates. |
| `-v`, `--verbose` | Enables verbose mode. |
| `-wd`, `--wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh dashboard certificates, add root-ca.pem and root-ca.key. |
| `-wi`, `--wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh indexer certificates, add root-ca.pem and root-ca.key. |
| `-ws`, `--wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh server certificates, add root-ca.pem and root-ca.key. |
| `-tmp`, `--cert_tmp_path </path/to/tmp_dir>` | Modifies the default tmp directory (/tmp/wazuh-ceritificates) to the specified one. Must be used along with one of these options: -a, -A, -ca, -wi, -wd, -ws |

### config-5.0.0-1.yml configuration

The `config-5.0.0-1.yml` file is a YAML format configuration file that contains the necessary information to generate certificates for Wazuh nodes.
It is very important to ensure that the `config-5.0.0-1.yml` file is correctly configured with both the name of each node and the IP address, as they will be used to generate the corresponding certificate.

Here is a basic example of how this file should be structured:

```yaml
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "<indexer-node-ip>"
    #- name: node-2
    #  ip: "<indexer-node-ip>"
    #- name: node-3
    #  ip: "<indexer-node-ip>"

  # Wazuh server nodes
  # If there is more than one Wazuh server
  # node, each one must have a node_type
  server:
    - name: wazuh-1
      ip: "<wazuh-manager-ip>"
    #  node_type: master
    #- name: wazuh-2
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
    #- name: wazuh-3
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "<dashboard-node-ip>"
```

Each node must have a unique name and an associated IP address. In the case of Wazuh server nodes, if there is more than one node, it is necessary to specify the node type (master or worker) using the `node_type` field.

For the certs-tool to detect the file, it must be located in the same path as the `wazuh-certs-tool-5.0.0-1.sh` script.

### Create certificates

#### Create all certificates

To create all the certificates specified in the `config-5.0.0-1.yml` file, run the following command:

```bash
sudo bash wazuh-certs-tool-5.0.0-1.sh --all
# or use the short version
sudo bash wazuh-certs-tool-5.0.0-1.sh -A
```

This will generate all the necessary certificates for the nodes defined in the configuration file, as well as the CA.

If you already had a CA created previously, you can use it to generate the certificates by running the following command:

```bash
sudo bash wazuh-certs-tool-5.0.0-1.sh -A </path/to/root-ca.pem> </path/to/root-ca.key>
```

#### Create specific certificates

You can create only the certificates for a component as well as the CA or admin certificates (used in the indexer) using the following options:
- Create root CA:
    ```bash
    sudo bash wazuh-certs-tool-5.0.0-1.sh --root-ca-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0-1.sh -ca
    ```
- Create Wazuh indexer certificates:
    ```bash
    sudo bash wazuh-certs-tool-5.0.0-1.sh --wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0-1.sh -wi </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create Wazuh server certificates:
    ```bash
    sudo bash wazuh-certs-tool-5.0.0-1.sh --wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0-1.sh -ws </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create Wazuh dashboard certificates:
    ```bash
    sudo bash wazuh-certs-tool-5.0.0-1.sh --wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0-1.sh -wd </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create admin certificates:
    ```bash
    sudo bash wazuh-certs-tool-5.0.0-1.sh --admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0-1.sh -a </path/to/root-ca.pem> </path/to/root-ca.key>
    ```


All these certificates will be generated in the `wazuh-certificates` directory within the current directory where the script is executed.

## Wazuh password tool

### Options

The `wazuh-passwords-tool-5.0.0-1.sh` script provides the following options for managing Wazuh internal user passwords:

| Options | Purpose |
|---------|---------|
| `-A\|--api` | Change the Wazuh server API password given the current password. Requires `-u\|--user <USER>`, `-p\|--password <PASSWORD>`, `-au\|--admin-user <ADMIN_USER>`, and `-ap\|--admin-password <ADMIN_PASSWORD>`. |
| `-au\|--admin-user <ADMIN_USER>` | Admin user for the Wazuh server API. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-ap\|--admin-password <ADMIN_PASSWORD>` | Password for the Wazuh server API admin user. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-u\|--user <USER>` | Indicates the name of the user whose password will be changed. If no password is specified, it will generate a random one. |
| `-p\|--password <PASSWORD>` | Indicates the new password. Must be used with option `-u\|--user <USER>`. |
| `-v\|--verbose` | Shows the complete script execution output. |
| `-h\|--help` | Shows help. |

The passwords tool changes passwords by specifying the user whose password you want to change and the new password. The password must have a length between 8 and 64 characters and contain at least one upper case letter, one lower case letter, a number and one of the following symbols: `.*+?-` If no password is specified, the tool will generate a random one.

There are two types of users whose passwords can be changed with this tool: Wazuh indexer users and Wazuh server API users. For the latter, it is necessary to provide an administrator user and their password to authenticate the password change request.

### Change Wazuh indexer password

Wazuh Indexer users are defined in `/etc/wazuh-indexer/opensearch-security/internal_users.yml`. To change the password of a Wazuh indexer user, use the following syntax:

```bash
sudo ./wazuh-passwords-tool-5.0.0-1.sh -u <USER> [-p <PASSWORD>]
```
Where `<USER>` is the name of the user whose password you want to change and `<PASSWORD>` is the new password. If `<PASSWORD>` is not specified, the tool will generate a random password.

For example, to change the password of the `admin` user to `Secr3tP4ssw*rd`, run the following command:

```bash
sudo ./wazuh-passwords-tool-5.0.0-1.sh -u admin -p Secr3tP4ssw*rd
```

El output del comando será similar al siguiente:

```bash
INFO: Generating password hash
WARNING: Password changed. Remember to update the password in the Wazuh dashboard node if necessary, and restart the services.
```

### Change Wazuh server API password

To change the password of a Wazuh server API user, use the following syntax:

```bash
sudo ./wazuh-passwords-tool-5.0.0-1.sh -A -au <ADMIN_USER> -ap <ADMIN_PASSWORD> -u <USER> [-p <PASSWORD>]
```

Where `<ADMIN_USER>` is the Wazuh server API administrator user, `<ADMIN_PASSWORD>` is the administrator user's password, `<USER>` is the name of the user whose password you want to change, and `<PASSWORD>` is the new password. If `<PASSWORD>` is not specified, the tool will generate a random password.
For example, to change the password of the `wazuh` user to `N3wS3cr3tP4ss*`, run the following command:

```bash
sudo ./wazuh-passwords-tool-5.0.0-1.sh -A -au wazuh -ap wazuh -u wazuh -p N3wS3cr3tP4ss*
```

The command output will be similar to the following:

```bash
INFO: The password for Wazuh API user wazuh is N3wS3cr3tP4ss*
```
