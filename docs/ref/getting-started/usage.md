# Usage

## Wazuh installation assistant

The Wazuh Installation Assistant is used by running the previously downloaded `wazuh-install-5.0.0.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

### Option list

| Option | Description |
| -------- | ------------- |
| `-a`, `--all-in-one` | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard. |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If local is specified, it will use a local `artifact_urls.yaml` file located in the same path as the wazuh-install-5.0.0.sh. See [Use development packages](#use-development-packages). |
| `-dw`, `--download-wazuh <deb\|rpm>` | Download all the packages necessary for offline installation. Type of packages to download for offline installation (rpm, deb) |
| `-da`, `--download-arch <amd64\|arm64\|x86_64\|aarch64>` | Define the architecture of the packages to download for offline installation. |
| `-g`, `--generate-config-files` | Generate wazuh-install-files.tar file containing the files that will be needed for installation from config.yml. In distributed deployments you will need to copy this file to all hosts. |
| `-h`, `--help` | Display this help and exit. |
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

### AIO Installation

To perform an AIO (All In One) installation, simply run the following command:

```bash
sudo bash wazuh-install-5.0.0.sh --all-in-one
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a
```

This command will download, install, and configure all Wazuh components on the same machine automatically without the need to configure anything else.

The assistant stops if a package it needs, such as `apt-transport-https`, is missing, and names it. Install it, or add `-id|--install-dependencies` to the command to install it automatically. The same applies to every installation command.

### Specific Component Installation

If you want to install a specific Wazuh component, first make sure you have the `config.yml` file downloaded.

The `config.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [config.yml configuration](#configyml-configuration) section.

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
4. Once you have the `wazuh-install-files.tar` file on the machine where you will install the component, you just need to run the installation command for the desired component, with the name of the node in `config.yml`:

    4.1 To install the Wazuh Manager:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-manager <manager-node-name>
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wm <manager-node-name>
    ```

    4.2 To install the Wazuh Indexer:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-indexer <indexer-node-name>
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wi <indexer-node-name>
    ```

    4.3 To install the Wazuh Dashboard:

    ``` bash
    sudo bash wazuh-install-5.0.0.sh --wazuh-dashboard <dashboard-node-name>
    # or use the short form
    sudo bash wazuh-install-5.0.0.sh -wd <dashboard-node-name>
    ```

### Change the default passwords

A freshly completed installation has no default passwords: the passwords of the Wazuh indexer and Wazuh server API users are generated during the installation and saved in `/etc/wazuh/credentials.env`. To rotate them, for example if that file was exposed, the recommended procedure is to change all the passwords in a single command using the `--change-all` option of the passwords tool. See the [Change all default passwords](#change-all-default-passwords) section for details.

This same command also rotates the Wazuh server API users (`wazuh` and `wazuh-wui`) on the host where the Wazuh manager is installed, so there is no need to change them separately. The new passwords are saved in `/etc/wazuh/credentials.env`, never printed.

After changing the passwords, remember to use the new `admin` password to log in to the Wazuh dashboard.

### Offline Installation

You can install Wazuh even without an Internet connection. Installing the solution offline involves first downloading the Wazuh central components on a system with Internet access, then transferring and installing them on the offline system. Wazuh supports both all-in-one and distributed deployments.

#### Download packages necessary for offline installation

1. On a system with Internet access, download the packages of the central components you want to install on the offline system. Note that you also need to have the `wazuh-install-5.0.0.sh` on the system with Internet access.
See the [Installation Assistant Installation](../installation/installation-assistant/ia-installation.md) section to learn how to download `wazuh-install-5.0.0.sh`.

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

To use packages that are in development, create an `artifact_urls.yaml` file in the same directory as the `wazuh-install-5.0.0.sh` script. It holds one `<key>: "<URL>"` line per package. The key is `wazuh_<component>_<architecture>_<package type>`, and the architecture is named as each package type names it:

| Package type | x86_64 host | aarch64 host |
| ------------ | ----------- | ------------ |
| DEB | `amd64` | `arm64` |
| RPM | `x86_64` | `aarch64` |

Only the keys of the host where the assistant runs, and of the components it installs, are required. For example, for an all-in-one installation on an x86_64 RPM host:

``` yaml
wazuh_indexer_x86_64_rpm: "https://example.com/wazuh-indexer-5.0.0-1.x86_64.rpm"
wazuh_manager_x86_64_rpm: "https://example.com/wazuh-manager-5.0.0-1.x86_64.rpm"
wazuh_dashboard_x86_64_rpm: "https://example.com/wazuh-dashboard-5.0.0-1.x86_64.rpm"
```

And on an x86_64 DEB host:

``` yaml
wazuh_indexer_amd64_deb: "https://example.com/wazuh-indexer_5.0.0-1_amd64.deb"
wazuh_manager_amd64_deb: "https://example.com/wazuh-manager_5.0.0-1_amd64.deb"
wazuh_dashboard_amd64_deb: "https://example.com/wazuh-dashboard_5.0.0-1_amd64.deb"
```

A file with the keys of every architecture and package type works on any host. A missing key stops the installation with `Missing required artifact key: <key>`.

Then add the `-d local, --development local` option to every installation command, including the ones of a distributed deployment. For example, to perform an AIO installation using development packages:

```bash
sudo bash wazuh-install-5.0.0.sh --all-in-one --development local
# or use the short form
sudo bash wazuh-install-5.0.0.sh -a -d local
```

The assistant reads `artifact_urls.yaml` from the directory of the script and downloads the packages from the URLs in it. Without the file, it stops with `Cannot find artifact_urls.yaml in <directory>`.

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

### Certificate subjects

The Wazuh indexer node and admin certificates have the same subject as the ones the Wazuh indexer package creates, so the `plugins.security.nodes_dn` and `plugins.security.authcz.admin_dn` values it writes in `opensearch.yml` keep their format:

```yaml
plugins.security.authcz.admin_dn:
- "C=US,L=California,O=Wazuh,OU=Wazuh,CN=admin"
plugins.security.nodes_dn:
- "C=US,L=California,O=Wazuh,OU=Wazuh,CN=<indexer node name>"
```

`nodes_dn` lists every Wazuh indexer node by its name. A renewed certificate of a node with the same name needs no change; if a node name changes, update `nodes_dn` on every Wazuh indexer node.

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

### Renew and deploy certificates

To renew the certificates of a deployment, run the certs tool again on the node that holds the root CA and copy the new certificates to each node.

1. Go to the node whose `/etc/wazuh/ca` holds `root-ca.key`: in a deployment installed with the Wazuh installation assistant, the node where `--generate-config-files` was run. The tool must run as root, in a directory with the `config.yml` of the deployment, which is also inside `wazuh-install-files.tar`:

    ```bash
    mkdir -p ~/certs-tool && cd ~/certs-tool
    cp /path/to/wazuh-certs-tool-5.0.0.sh .
    sudo tar -xf ~/wazuh-install-files.tar --strip-components 1 wazuh-install-files/config.yml
    ```

2. Remove the `wazuh-certificates` directory of a previous run (the tool does not write in one that is not empty) and create the certificates you need, for example the Wazuh indexer ones:

    ```bash
    sudo rm -rf wazuh-certificates
    sudo bash wazuh-certs-tool-5.0.0.sh -wi
    ```

    Use `-wd` for the Wazuh dashboard, `-wm` for the Wazuh manager nodes, `-a` for the admin certificate, or `-A` for all of them. The existing root CA is reused, so every node keeps trusting the others, and agents keep trusting the Wazuh manager.

3. Copy each file to its node, with the name, owner and mode the component expects:

    | Node | File in `wazuh-certificates` | Destination | Owner and mode |
    | ---- | ---------------------------- | ----------- | -------------- |
    | Wazuh indexer | `<node>.pem`, `<node>-key.pem` | `/etc/wazuh-indexer/certs/indexer.pem`, `indexer-key.pem` | `wazuh-indexer:wazuh-indexer`, `0400` |
    | Wazuh indexer | `admin.pem`, `admin-key.pem` | `/etc/wazuh-indexer/certs/admin.pem`, `admin-key.pem` | `wazuh-indexer:wazuh-indexer`, `0400` |
    | Wazuh manager | `<node>.pem`, `<node>-key.pem` | `/var/wazuh-manager/etc/certs/indexer-connector.pem`, `indexer-connector-key.pem` | `root:wazuh-manager`, `0640` |
    | Wazuh manager | `<node>-remoted.pem`, `<node>-remoted-key.pem` | `/var/wazuh-manager/etc/certs/remoted.pem`, `remoted-key.pem` | `wazuh-manager:wazuh-manager`, `0640` |
    | Wazuh dashboard | `<node>.pem`, `<node>-key.pem` | `/etc/wazuh-dashboard/certs/dashboard.pem`, `dashboard-key.pem` | `wazuh-dashboard:wazuh-dashboard`, `0400` |

    For example, on a Wazuh indexer node, with the files of that node copied to the current directory:

    ```bash
    sudo install -o wazuh-indexer -g wazuh-indexer -m 0400 <node>.pem /etc/wazuh-indexer/certs/indexer.pem
    sudo install -o wazuh-indexer -g wazuh-indexer -m 0400 <node>-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    ```

4. Restart the services:

    - Wazuh indexer: restart one node at a time, and wait until the cluster is `green` with every node before the next one. The certificates keep the subject format of `nodes_dn`, so it does not change as long as the node names do not.
    - Admin certificate: no restart is needed. It is only used to load the security configuration, for example by `wazuh-passwords-tool-5.0.0.sh`.
    - Wazuh manager: restart every node. Agents keep their connection: the new agent listener certificate is signed by the same root CA.
    - Wazuh dashboard: restart the service.

5. Remove the `wazuh-certificates` directory, and every copy of it, once the certificates are in place: it holds private keys.

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
- Only these characters: `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`
- At least one upper case letter, one lower case letter, one digit and one symbol from `. , _ + : @ % ^ = ~ -`.

A generated password has 32 characters and follows the same rules.

### Where the passwords are saved

The tool never prints a password. The passwords are saved in the credentials file, `/etc/wazuh/credentials.env` (or `<WAZUH_BASE_DIR>/credentials.env`), inside the block that the Wazuh packages manage:

- A generated password is always saved there, and the tool prints the file and the key. If the file does not exist, it is created with mode `0600`.
- A password you give with `-p` updates the file only when it already exists.

Read the new password in the file, for example:

```bash
sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-
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

> [!NOTE]
> In a distributed deployment, `-a` only changes the users of the components installed on the host where it runs. Run it on a Wazuh indexer node to change the Wazuh indexer users, and on the Wazuh manager master node to change the Wazuh server API users. Then update the other nodes as described in [Multi-node and distributed deployments](#multi-node-and-distributed-deployments).

If a service is stopped when the tool runs, it is not started: the new credentials are already in its keystore and are applied the next time the service starts. The tool reports it:

```bash
WARNING: The Wazuh manager keystore was updated, but the wazuh-manager service is not running. The restart is pending: the new Wazuh indexer credentials will be applied when the service starts.
```

### Multi-node and distributed deployments

The tool only updates the keystores of the node it runs on, and only the `/etc/wazuh/credentials.env` of that node gets the new value. When the Wazuh manager or the Wazuh dashboard run on other hosts, their keystores keep the previous password until you update them. The tool warns about each of them, for example:

```bash
WARNING: The Wazuh dashboard is not installed on this host. Update opensearch.password in the keystore of every Wazuh dashboard node and restart them.
WARNING: If this is a multi-node deployment, update the keystore of every other Wazuh manager node and restart them.
```

Run the tool on the node given below for each user, then update the nodes of the last column:

| User | Run the tool on | Then update, on every node of | Restart |
| ---- | --------------- | ----------------------------- | ------- |
| `admin` | a Wazuh indexer node (it needs the admin certificate) | nothing | nothing |
| `kibanaserver` | a Wazuh indexer node | Wazuh dashboard: keystore entry `opensearch.password` | `wazuh-dashboard` |
| `wazuh-manager` | a Wazuh indexer node | Wazuh manager (master and workers): keystore `-f indexer -k password` | `wazuh-manager` |
| `wazuh` | the Wazuh manager master node | nothing | nothing |
| `wazuh-wui` | the Wazuh manager master node | Wazuh dashboard: keystore entry `wazuh_core.hosts.default.password` | `wazuh-dashboard` |

The Wazuh dashboard steps are needed even with a single Wazuh dashboard, when it is not on the node where the tool runs.

#### Get the new password

Read it in `/etc/wazuh/credentials.env` of the node where the tool ran. The file on the other nodes, and the one inside `wazuh-install-files.tar`, keep the previous values:

```bash
sudo grep '^WAZUH_INDEXER_MANAGER_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-
```

The keys are `WAZUH_INDEXER_ADMIN_PASSWORD`, `WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD`, `WAZUH_MANAGER_API_PASSWORD` and `WAZUH_MANAGER_WUI_PASSWORD`.

Change the Wazuh server API users on the master node. The tool also works on a worker node, but then the new value is saved in the `credentials.env` of that worker, not of the master.

#### Update the Wazuh manager nodes

After changing `wazuh-manager`, on every Wazuh manager node:

```bash
echo 'wazuh-manager' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
echo '<WAZUH_MANAGER_PASSWORD>' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
systemctl restart wazuh-manager
```

Where `<WAZUH_MANAGER_PASSWORD>` is the `WAZUH_INDEXER_MANAGER_PASSWORD` value. Until the keystore is updated and the service restarted, the Wazuh manager logs `Unauthorized - Check indexer credentials`. After the restart it logs `The indexer is reachable`:

```bash
grep 'indexer is reachable' /var/wazuh-manager/logs/wazuh-manager.log | tail -1
```

#### Update the Wazuh dashboard nodes

After changing `kibanaserver` or `wazuh-wui`, on every Wazuh dashboard node. The keystore belongs to the `wazuh-dashboard` user, so write it as that user:

```bash
echo '<KIBANASERVER_PASSWORD>' | runuser -u wazuh-dashboard -- /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore add opensearch.password --stdin --force
echo '<WAZUH_WUI_PASSWORD>' | runuser -u wazuh-dashboard -- /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore add wazuh_core.hosts.default.password --stdin --force
systemctl restart wazuh-dashboard
```

Only write the entry of the user that changed. After `-a`, write both and restart once.

> [!NOTE]
> The Wazuh dashboard login does not show a wrong `kibanaserver` password: it sends the credentials of the user who logs in to the Wazuh indexer. The Wazuh dashboard server itself uses `kibanaserver`, so check its state instead. It is `red` (`Unable to retrieve version information from OpenSearch nodes`) until `opensearch.password` is updated:
>
> ```bash
> curl -k -u admin https://<WAZUH_DASHBOARD_IP_ADDRESS>/api/status
> ```
>
> A wrong `wazuh-wui` password shows as an error of the Wazuh server API connection in the Wazuh dashboard.

#### Pass the password without typing it

`echo '<PASSWORD>'` leaves the password in the shell history. You can pipe it from the node where the tool ran instead, for example from a host that reaches both nodes over SSH:

```bash
ssh <WAZUH_INDEXER_NODE> "sudo grep '^WAZUH_INDEXER_MANAGER_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-" \
  | ssh <WAZUH_MANAGER_NODE> 'sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password'
```

#### Change all passwords in a distributed deployment

1. On a Wazuh indexer node, run `-a`. It changes `admin`, `kibanaserver` and `wazuh-manager`.
2. On the Wazuh manager master node, run `-a`. It changes `wazuh` and `wazuh-wui`.
3. On every Wazuh manager node, update the keystore with the `WAZUH_INDEXER_MANAGER_PASSWORD` of the Wazuh indexer node, and restart the service.
4. On every Wazuh dashboard node, write `opensearch.password` with the `WAZUH_INDEXER_KIBANASERVER_PASSWORD` of the Wazuh indexer node and `wazuh_core.hosts.default.password` with the `WAZUH_MANAGER_WUI_PASSWORD` of the master node, and restart the service once.

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
INFO: The password of the Wazuh indexer user admin was changed.
INFO: WAZUH_INDEXER_ADMIN_PASSWORD was updated in /etc/wazuh/credentials.env.
```

The tool only warns about what it cannot do on this host: after changing `wazuh-manager`, `kibanaserver` or `wazuh-wui`, it reminds you to update the keystore of the Wazuh manager or Wazuh dashboard nodes on other hosts.

### Change a Wazuh server API password

The Wazuh server API passwords are changed with `rbac_control change-password` on the Wazuh manager, so no Wazuh server API admin credentials are needed. Run the tool on the Wazuh manager node, the master node in a cluster:

```bash
sudo ./wazuh-passwords-tool-5.0.0.sh -u <USER> [-p]
```

Where `<USER>` is `wazuh` or `wazuh-wui`. `-p` works as for the Wazuh indexer users.

The command output will be similar to the following:

```bash
INFO: The password of the Wazuh API user wazuh was changed.
```

When the user is `wazuh-wui` and the Wazuh dashboard is installed on the same host, the tool also writes the new password into the `wazuh_core.hosts.default.password` entry of the Wazuh dashboard keystore and restarts the Wazuh dashboard. Otherwise, update the Wazuh dashboard nodes as described in [Multi-node and distributed deployments](#multi-node-and-distributed-deployments).
