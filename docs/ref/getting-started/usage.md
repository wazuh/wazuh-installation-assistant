# Usage

## Wazuh installation assistant

The Wazuh Installation Assistant is used by running the previously downloaded `wazuh-install-5.0.0.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

### Option list

| Option | Description |
| -------- | ------------- |
| `-a`, `--all-in-one` | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard. |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If local is specified, it will use a local artifact_urls.yml file located in the same path as the wazuh-install-5.0.0.sh. |
| `-dw`, `--download-wazuh <deb\|rpm>` | Download all the packages necessary for offline installation. Type of packages to download for offline installation (rpm, deb) |
| `-da`, `--download-arch <amd64\|arm64\|x86_64\|aarch64>` | Define the architecture of the packages to download for offline installation. |
| `-g`, `--generate-config-files` | Generate wazuh-install-files.tar file containing the files that will be needed for installation from config.yml. In distributed deployments you will need to copy this file to all hosts. |
| `-h`, `--help` | Display this help and exit. |
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
sudo bash wazuh-install-5.0.0.sh --all-in-one
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a
```

This command will download, install, and configure all Wazuh components on the same machine automatically without the need to configure anything else.

### Specific Component Installation

If you want to install a specific Wazuh component, first make sure you have the `config.yml` file downloaded.

The `config.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [certs-tool-usage.md](../certs-tool/certs-tool-usage.md) section.

For additional `config.yml` formats (`dns`, DNS lists, and mixed configurations), see [Other `config.yml` examples](../configuration/configuration-files.md#other-configyml-examples).

The steps to perform the installation are as follows:
> **note**: If you have already configured the `config.yml` and generated the `wazuh-install-files.tar` in the installation of another Wazuh component, you can skip directly to step 4.

1. Edit the `config.yml` file with the desired configuration for each of the Wazuh components.
2. Create the necessary files for installation that will be stored in `wazuh-install-files.tar` with the following command:

    ```bash
    sudo bash wazuh-install-5.0.0.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -g
    ```

3. The `wazuh-install-files.tar` file will be necessary for the installation of each component that will be part of the distributed installation as it includes the certificates for each of the components specified in the `config.yml` file. Therefore, copy this file to each of the machines where you will install a Wazuh component.
4. Once you have the `wazuh-install-files.tar` file on the machine where you will install the component, you just need to run the installation command for the desired component:

    4.1 To install the Wazuh Manager:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-manager
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wm
    ```

    4.2 To install the Wazuh Indexer:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-indexer
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wi
    ```

    4.3 To install the Wazuh Dashboard:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-dashboard
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wd
    ```

### Change the default passwords

The installation assistant is designed to facilitate the initial installation of Wazuh, so a freshly completed installation leaves several Wazuh indexer internal users with their password set to the same value as their username, some of them with high privileges. Therefore, it is highly recommended to change them to more secure ones right after installation.

The recommended procedure is to change all default passwords in a single command using the `--change-all` option of the passwords tool. See the [Change all default passwords](#change-all-default-passwords) section for details.

This same command also rotates the Wazuh server API users (`wazuh` and `wazuh-wui`) on the host where the Wazuh manager is installed, so there is no need to change them separately. The new passwords are saved in `/etc/wazuh/credentials.env`, never printed.

After changing the passwords, remember to use the new `admin` password to log in to the Wazuh dashboard.

### Offline Installation

You can install Wazuh even without an Internet connection. Installing the solution offline involves first downloading the Wazuh central components on a system with Internet access, then transferring and installing them on the offline system. Wazuh supports both all-in-one and distributed deployments.

#### Download packages necessary for offline installation

1. On a system with Internet access, download the packages of the central components you want to install on the offline system. Note that you also need to have the `wazuh-install-5.0.0.sh` on the system with Internet access.
See the [Installation Assistant Installation](../../installation/installation-assistant/ia-installation.md) section to learn how to download `wazuh-install-5.0.0.sh`.

    To download the packages necessary for offline installation, run the following command:

    ```bash
    sudo bash wazuh-install-5.0.0.sh --download-wazuh <TYPE> --download-arch <ARCH>
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -dw <TYPE> -da <ARCH>
    ```

    Where `<TYPE>` is the Linux distribution of the offline system (`deb` or `rpm`) and `<ARCH>` is the architecture of the offline system (`x86_64` or `arm64`).

    This command will generate the `wazuh-offline.tar.gz` file which contains all the packages necessary to install Wazuh on the offline system.

2. Next, create the necessary certificates that will be used in the offline installation. To do this, modify the `config.yml` file with the desired configuration for each of the Wazuh components and run the following command:

  If you need DNS-based configurations, see [Other `config.yml` examples](../configuration/configuration-files.md#other-configyml-examples).

    ```bash
    sudo bash wazuh-install-5.0.0.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -g
    ```

    This command will generate the `wazuh-install-files.tar` file which contains the necessary certificates for offline installation.

3. Transfer all files (`wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install-5.0.0.sh`) to the offline system where you want to install Wazuh using your preferred method (USB, SCP, etc).

#### Perform the offline installation

Once you have the `wazuh-offline.tar.gz`, `wazuh-install-files.tar` and `wazuh-install-5.0.0.sh` files on the offline system, the installation is done the same way as a normal Wazuh installation (you can see how it's done in the `AIO Installation` and `Specific Component Installation` sections found above in this document), but by specifying the `-of, --offline-installation` option to the installation command.
For example, to perform an offline AIO installation, the command would be:

```bash
sudo bash wazuh-install-5.0.0.sh --all-in-one --offline-installation
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a -of
```

If you want to install a specific Wazuh component, the command would be similar to the following (depending on the component you are going to install):

```bash
sudo bash wazuh-install-5.0.0.sh --wazuh-manager --offline-installation
# or use the short form
sudo bash wazuh-install-5.0.0.sh -wm -of
```

### Use development packages in the installation

When you use the installation assistant to install Wazuh, the official Wazuh packages are downloaded by default. However, if you are developing or testing new features or want to try the `pre-release` version instead of the official ones, you can do so by specifying the `-d [pre-release|local], --development` option to the installation command.

#### Use pre-release packages

If you want to use Wazuh `pre-release` packages instead of the official ones, simply add the `-d pre-release, --development pre-release` option to the installation command. For example, to perform an AIO installation using `pre-release` packages, the command would be:

```bash
sudo bash wazuh-install-5.0.0.sh --all-in-one --development pre-release
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a -d pre-release
```

#### Use development packages

To use packages that are in development, it is necessary to have an `artifact_urls.yml` file located in the same path as the `wazuh-install-5.0.0.sh` script. This file must contain the URLs of the development packages that will be used in the installation. It must have the following format:

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
sudo bash wazuh-install-5.0.0.sh --all-in-one --development local
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a -d local
```

This command will automatically detect the `artifact_urls.yml` file in the same path as the `wazuh-install-5.0.0.sh` script and will use the URLs specified in it to download the necessary packages for the installation.

## Wazuh certs tool

The certs-tool is used by running the previously downloaded `wazuh-certs-tool-5.0.0.sh` script along with the `config.yml` configuration file. The certs tool generates the necessary certificates for the nodes specified in the configuration file.

### Options list

| Option | Description |
| -------- | ------------- |
| `-a`, `--admin-certificates` | Creates the admin certificates. |
| `-A`, `--all` | Creates certificates specified in config.yml and admin certificates. If there is no root CA in the CA directory, a new one is created there. Includes the `load_balancer` entries when the section is present. |
| `-as`, `--agent-san <ip\|dns>` | Adds an extra address to the subject alternative name of every agent listener certificate. Repeat it for more than one. Must be used along with `-A` or `-wm`. |
| `-ca`, `--root-ca-certificates` | Creates the root CA in the CA directory, if it does not exist yet. |
| `-lb`, `--load-balancer-certificates` | Creates the certificates of the `load_balancer` entries of config.yml. Only needed by a proxy that terminates TLS. |
| `-v`, `--verbose` | Enables verbose mode. |
| `-wd`, `--wazuh-dashboard-certificates` | Creates the Wazuh dashboard certificates. |
| `-wi`, `--wazuh-indexer-certificates` | Creates the Wazuh indexer certificates. |
| `-wm`, `--wazuh-manager-certificates` | Creates the Wazuh manager certificates. |
| `-tmp`, `--cert_tmp_path </path/to/tmp_dir>` | Modifies the default tmp directory (/tmp/wazuh-ceritificates) to the specified one. Must be used along with one of these options: -a, -A, -ca, -wi, -wd, -wm, -lb |

### Root CA

The certs tool creates and reads the root CA through the shared `wazuh-credentials.sh` library, the same one the Wazuh packages use. The root CA lives in `/etc/wazuh/ca/`, or in the directory set in the `WAZUH_CA_DIR` environment variable:

- `root-ca.pem` (mode `0644`) is copied to the `wazuh-certificates` directory with the new certificates.
- `root-ca.key` (mode `0400`) stays in the CA directory. It is never copied to the `wazuh-certificates` directory, so it does not travel to the other nodes.

The tool must be run as root. An existing root CA is validated and reused, never replaced. To use a root CA created elsewhere, place `root-ca.pem` and `root-ca.key` in a `root:root` directory with mode `0700`, with the modes above, and point `WAZUH_CA_DIR` at it:

```bash
sudo WAZUH_CA_DIR=/path/to/ca bash wazuh-certs-tool-5.0.0.sh -A
```

### config.yml configuration

The `config.yml` file is a YAML format configuration file that contains the necessary information to generate certificates for Wazuh nodes.
It is very important to ensure that the `config.yml` file is correctly configured with both the name of each node and the IP address, as they will be used to generate the corresponding certificate.

Here is a basic example of how this file should be structured:

```yaml
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: indexer
      ip: "<indexer-node-ip>"
    #- name: indexer-2
    #  ip: "<indexer-node-ip>"
    #- name: indexer-3
    #  ip: "<indexer-node-ip>"

  # Wazuh manager nodes
  # If there is more than one Wazuh manager
  # node, each one must have a node_type
  manager:
    - name: manager
      ip: "<wazuh-manager-ip>"
    #  node_type: master
    #- name: manager-2
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
    #- name: manager-3
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "<dashboard-node-ip>"
```

Each node must have a unique name and an associated IP address. In the case of Wazuh server nodes, if there is more than one node, it is necessary to specify the node type (master or worker) using the `node_type` field.

For the certs-tool to detect the file, it must be located in the same path as the `wazuh-certs-tool-5.0.0.sh` script.

### Create certificates

#### Create all certificates

To create all the certificates specified in the `config.yml` file, run the following command:

```bash
sudo bash wazuh-certs-tool-5.0.0.sh --all
# or use the short version
sudo bash wazuh-certs-tool-5.0.0.sh -A
```

This will generate all the necessary certificates for the nodes defined in the configuration file. If there is no root CA in the CA directory yet, it is created first. See [Root CA](#root-ca).

#### Create specific certificates

You can create only the certificates for a component as well as the CA or admin certificates (used in the indexer) using the following options:

- Create root CA:

    ```bash
    sudo bash wazuh-certs-tool-5.0.0.sh --root-ca-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0.sh -ca
    ```

- Create Wazuh indexer certificates:

    ```bash
    sudo bash wazuh-certs-tool-5.0.0.sh --wazuh-indexer-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0.sh -wi
    ```

- Create Wazuh manager certificates:

    ```bash
    sudo bash wazuh-certs-tool-5.0.0.sh --wazuh-manager-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0.sh -wm
    ```

- Create Wazuh dashboard certificates:

    ```bash
    sudo bash wazuh-certs-tool-5.0.0.sh --wazuh-dashboard-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0.sh -wd
    ```

- Create admin certificates:

    ```bash
    sudo bash wazuh-certs-tool-5.0.0.sh --admin-certificates
    # or use the short version
    sudo bash wazuh-certs-tool-5.0.0.sh -a
    ```

#### Name the address agents dial

An agent checks the manager's listener certificate against the address it dialled before
enrolling, so that address has to be in the certificate. The `ip` and `dns` fields of each
manager node cover the case where agents dial the node itself. When they dial an address
no single node owns, add it with `-as`, `--agent-san`, repeated once per value:

```bash
sudo bash wazuh-certs-tool-5.0.0.sh -A --agent-san wazuh.example.com --agent-san 203.0.113.10
```

Each value reaches the subject alternative name of the listener certificate of **every**
manager node, which is what a cluster behind a single address needs, and of no other
certificate. Use it for a layer 4 (passthrough) load balancer, a published name, or a NAT
address.

`wazuh-install-5.0.0.sh` takes the same option with `-a` and `-g`. An all-in-one install
adds the addresses of the host on its own, so `--agent-san` is only needed there when the
address agents dial is one the host cannot see, such as a NAT or a cloud balancer:

```bash
sudo bash wazuh-install-5.0.0.sh -a --agent-san wazuh.example.com
```

#### Create the certificate of a TLS-terminating load balancer

When a proxy terminates the agents' TLS session, it is the proxy's certificate that agents
validate. Declare it in the `load_balancer` section of `config.yml` and issue it from the
same root-ca, so the agents' pinned anchor still verifies it:

```bash
sudo bash wazuh-certs-tool-5.0.0.sh --load-balancer-certificates
# or use the short version
sudo bash wazuh-certs-tool-5.0.0.sh -lb
```

This produces `<name>.pem` and `<name>-key.pem`, the leaf followed by the CA, so the proxy
serves the full chain. A passthrough balancer needs `--agent-san` instead: it terminates
nothing, and a certificate of its own would never be presented.

All these certificates will be generated in the `wazuh-certificates` directory within the current directory where the script is executed.

## Wazuh password tool

### Options

The `wazuh-passwords-tool-5.0.0.sh` script provides the following options for managing the passwords of the Wazuh indexer and Wazuh server API users:

| Options | Purpose |
| --------- | --------- |
| `-a\|--change-all` | Changes the password of all the Wazuh indexer and Wazuh server API users installed on the host, generating a random password for each one. Incompatible with `-u\|--user` and `-p\|--password`. |
| `-u\|--user <USER>` | Indicates the name of the user whose password will be changed. If `-p\|--password` is not used, a random password is generated. Either `-u\|--user` or `-a\|--change-all` is required. |
| `-p\|--password` | Reads the new password from the standard input. Must be used with option `-u\|--user <USER>`. |
| `-v\|--verbose` | Shows the complete script execution output. |
| `-h\|--help` | Shows help. |

The tool manages the users of the Wazuh packages only:

| User | Component | Key in `credentials.env` |
| ---- | --------- | ------------------------ |
| `admin` | Wazuh indexer | `WAZUH_INDEXER_ADMIN_PASSWORD` |
| `kibanaserver` | Wazuh indexer | `WAZUH_INDEXER_KIBANASERVER_PASSWORD` |
| `wazuh-manager` | Wazuh indexer | `WAZUH_INDEXER_MANAGER_PASSWORD` |
| `wazuh` | Wazuh server API | `WAZUH_MANAGER_API_PASSWORD` |
| `wazuh-wui` | Wazuh server API | `WAZUH_MANAGER_WUI_PASSWORD` |

The tool requires root privileges to run.

### Password rules

The tool uses the same rules as the Wazuh packages, through the shared `wazuh-credentials.sh` library:

- Between 12 and 64 characters.
- At least one letter and one digit.
- Only these characters: `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`
- It cannot be a number, such as `123456789e10`, because the Wazuh dashboard keystore would store it as a number.

A generated password has 32 characters, with at least one lower case letter, one upper case letter and one digit.

### Where the passwords are saved

The tool never prints a password. The passwords are saved in the credentials file, `/etc/wazuh/credentials.env` (or `<WAZUH_BASE_DIR>/credentials.env`), inside the block that the Wazuh packages manage:

- A generated password is always saved there, and the tool prints the file and the key. If the file does not exist, it is created with mode `0600`.
- A password you give with `-p` updates the file only when it already exists.

Read the new password in the file, for example:

```bash
sudo grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env
```

Remove the file when you no longer need it. Editing a value in the file does not change the deployment: use the tool to change a password.

### Change all default passwords

The `-a`, `--change-all` option rotates, in a single execution, the password of every user of the table above that is installed on the host: the Wazuh indexer users when the Wazuh indexer is installed, and the Wazuh server API users when the Wazuh manager is installed. No Wazuh server API admin credentials are needed. A different random password is generated for each user.

```bash
sudo ./wazuh-passwords-tool-5.0.0.sh -a
```

The command output will be similar to the following:

```bash
INFO: The new password of user admin was saved in /etc/wazuh/credentials.env as WAZUH_INDEXER_ADMIN_PASSWORD.
INFO: The new password of user kibanaserver was saved in /etc/wazuh/credentials.env as WAZUH_INDEXER_KIBANASERVER_PASSWORD.
INFO: The new password of user wazuh-manager was saved in /etc/wazuh/credentials.env as WAZUH_INDEXER_MANAGER_PASSWORD.
INFO: The password of the Wazuh API user wazuh was changed.
INFO: The new password of user wazuh was saved in /etc/wazuh/credentials.env as WAZUH_MANAGER_API_PASSWORD.
INFO: The password of the Wazuh API user wazuh-wui was changed.
INFO: The new password of user wazuh-wui was saved in /etc/wazuh/credentials.env as WAZUH_MANAGER_WUI_PASSWORD.
```

The tool updates the keystore of the Wazuh manager (`wazuh-manager` user) and the keystore of the Wazuh dashboard (`kibanaserver` and `wazuh-wui` users), and restarts both services once the new passwords have been applied, so the connectivity between components is preserved on the node where the tool runs.

If a service is stopped when the tool runs, it is not started: the new credentials are already in its keystore and are applied the next time the service starts. The tool reports it:

```bash
WARNING: The Wazuh manager keystore was updated, but the wazuh-manager service is not running. The restart is pending: the new Wazuh indexer credentials will be applied when the service starts.
```

### Multi-node deployments

The tool only reaches the keystore of the node it runs on, whichever option is used. It cannot tell a single-node deployment from a multi-node one, so it prints the note below on every run. Every other Wazuh manager node keeps its previous Wazuh indexer credentials and loses the connection to the Wazuh indexer, which the tool reports:

```bash
WARNING: If this is a multi-node deployment, update the keystore of every other Wazuh manager node and restart them.
```

On each of the remaining Wazuh manager nodes, write the new credentials into the keystore and restart the service:

```bash
echo 'wazuh-manager' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
echo '<WAZUH_MANAGER_PASSWORD>' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
systemctl restart wazuh-manager
```

Where `<WAZUH_MANAGER_PASSWORD>` is the `WAZUH_INDEXER_MANAGER_PASSWORD` value saved in `/etc/wazuh/credentials.env` on the node where the tool ran.

The same applies to any additional Wazuh dashboard node: its `opensearch.password` keystore entry holds the `kibanaserver` password, and its `wazuh_core.hosts.default.password` entry holds the `wazuh-wui` password.

### Change a Wazuh indexer password

To change the password of a Wazuh indexer user, use the following syntax:

```bash
sudo ./wazuh-passwords-tool-5.0.0.sh -u <USER> [-p]
```

Where `<USER>` is `admin`, `kibanaserver` or `wazuh-manager`. With `-p`, the tool asks for the new password twice, without showing it, or reads it from the standard input when it is not a terminal. Without `-p`, the tool generates a random password and saves it in the credentials file.

For example, to change the password of the `admin` user to a password saved in a file:

```bash
sudo ./wazuh-passwords-tool-5.0.0.sh -u admin -p < /root/new-admin-password.txt
```

The command output will be similar to the following:

```bash
INFO: Generating password hash
WARNING: Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services.
```

### Change a Wazuh server API password

The Wazuh server API passwords are changed with `rbac_control change-password` on the Wazuh manager, so no Wazuh server API admin credentials are needed. Run the tool on the Wazuh manager node:

```bash
sudo ./wazuh-passwords-tool-5.0.0.sh -u <USER> [-p]
```

Where `<USER>` is `wazuh` or `wazuh-wui`. `-p` works as for the Wazuh indexer users.

The command output will be similar to the following:

```bash
INFO: The password of the Wazuh API user wazuh was changed.
```

When the user is `wazuh-wui` and the Wazuh dashboard is installed on the same host, the tool also writes the new password into the `wazuh_core.hosts.default.password` entry of the Wazuh dashboard keystore and restarts the Wazuh dashboard.
