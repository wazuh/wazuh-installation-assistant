# Command line options

## Wazuh installation assistant

The Wazuh Installation Assistant is used by running the previously downloaded `wazuh-install-5.1.0.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

### Option list

| Option | Description |
| -------- | ------------- |
| `-a`, `--all-in-one` | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard. |
| `-as`, `--agent-san <ip\|dns>` | Adds an extra address to the subject alternative name of the agent listener certificate of every Wazuh manager node. Repeat it for more than one. Use it for the address agents dial when the host cannot know it: a load balancer shared by a cluster, a published name, a NAT address. Must be used along with `-a` or `-g`. |
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

## Wazuh certs tool

The certs-tool is used by running the previously downloaded `wazuh-certs-tool-5.1.0.sh` script along with the `config.yml` configuration file. The certs tool generates the necessary certificates for the nodes specified in the configuration file.

For DNS-based or mixed address configurations, see [Other `config.yml` examples](configuration-files.md#other-configyml-examples).

### Options list

| Option | Description |
| -------- | ------------- |
| `-a`, `--admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the admin certificates, add root-ca.pem and root-ca.key. |
| `-A`, `--all </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates certificates specified in config.yml and admin certificates. Add a root-ca.pem and root-ca.key or leave it empty so a new one will be created. Includes the `load_balancer` entries when the section is present. |
| `-as`, `--agent-san <ip\|dns>` | Adds an extra address to the subject alternative name of every agent listener certificate, on top of the `ip` and `dns` entries of each manager node in config.yml. Repeat it for more than one. It names an address agents dial that no single node owns, such as a load balancer shared by every node of a cluster. Must be used along with `-A` or `-wm`. |
| `-ca`, `--root-ca-certificates` | Creates the root-ca certificates. |
| `-lb`, `--load-balancer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the certificates of the `load_balancer` entries of config.yml, add root-ca.pem and root-ca.key. Only needed by a proxy that terminates TLS. |
| `-v`, `--verbose` | Enables verbose mode. |
| `-wd`, `--wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh dashboard certificates, add root-ca.pem and root-ca.key. |
| `-wi`, `--wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh indexer certificates, add root-ca.pem and root-ca.key. |
| `-ws`, `--wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh server certificates, add root-ca.pem and root-ca.key. |
| `-tmp`, `--cert_tmp_path </path/to/tmp_dir>` | Modifies the default tmp directory (/tmp/wazuh-ceritificates) to the specified one. Must be used along with one of these options: -a, -A, -ca, -wi, -wd, -ws, -lb |

## Wazuh password tool

### Options

The `wazuh-passwords-tool-5.1.0.sh` script provides the following options for managing Wazuh internal user passwords:

| Options | Purpose |
| --------- | --------- |
| `-A\|--api` | Change the Wazuh server API password given the current password. Requires `-u\|--user <USER>`, `-p\|--password <PASSWORD>`, `-au\|--admin-user <ADMIN_USER>`, and `-ap\|--admin-password <ADMIN_PASSWORD>`. |
| `-au\|--admin-user <ADMIN_USER>` | Admin user for the Wazuh server API. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-ap\|--admin-password <ADMIN_PASSWORD>` | Password for the Wazuh server API admin user. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-u\|--user <USER>` | Indicates the name of the user whose password will be changed. If no password is specified, it will generate a random one. |
| `-p\|--password <PASSWORD>` | Indicates the new password. Must be used with option `-u\|--user <USER>`. |
| `-v\|--verbose` | Shows the complete script execution output. |
| `-h\|--help` | Shows help. |

### The address agents dial

In Wazuh 5.0 an agent pins the CA, opens a verified connection to the manager and checks
the certificate against the address it actually dialled before enrolling. An address
missing from the subject alternative name is not a warning, it is a failed enrollment,
and the same address is checked again when an enrollment token is minted.

Cover that address in one of three ways, depending on who terminates TLS:

| Deployment | What terminates the agent's TLS session | How to name the address |
| -------- | -------- | ------------- |
| Single manager, or one address per manager | The manager | The `ip` and `dns` fields of the node in config.yml |
| Cluster behind a layer 4 (passthrough) load balancer | The manager | `-as`, `--agent-san` with the load balancer address, so it reaches the listener certificate of every node |
| Cluster behind a proxy that terminates TLS | The proxy | The `load_balancer` section of config.yml plus `-lb`, so the proxy serves a certificate signed by the same root-ca agents pin |

A passthrough load balancer terminates nothing: the agent's session ends at the manager,
the manager's own listener certificate is what the agent validates, and a certificate of
the balancer's own would never be presented.
