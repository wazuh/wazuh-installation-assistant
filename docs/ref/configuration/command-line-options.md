# Command line options

## Wazuh installation assistant

The Wazuh Installation Assistant is used by running the previously downloaded `wazuh-install-5.0.0.sh` script. Depending on the type of installation you want to perform (AIO or a specific component), the steps vary.

### Option list

| Option | Description |
| -------- | ------------- |
| `-a`, `--all-in-one` | Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard. |
| `-as`, `--agent-san <ip\|dns>` | Adds an extra address to the subject alternative name of the agent listener certificate of every Wazuh manager node. Repeat it for more than one. Use it for the address agents dial when the host cannot know it: a load balancer shared by a cluster, a published name, a NAT address. Must be used along with `-a` or `-g`. |
| `-d [pre-release\|local]`, `--development` | Use development repositories. By default it uses the pre-release package repository. If local is specified, it will use a local `artifact_urls.yaml` file located in the same path as the wazuh-install-5.0.0.sh. See [Use development packages](../getting-started/usage.md#use-development-packages). |
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

## Wazuh certs tool

The certs-tool is used by running the previously downloaded `wazuh-certs-tool-5.0.0.sh` script along with the `config.yml` configuration file. The certs tool generates the necessary certificates for the nodes specified in the configuration file.

For DNS-based or mixed address configurations, see [Other `config.yml` examples](configuration-files.md#other-configyml-examples).

### Options list

| Option | Description |
| -------- | ------------- |
| `-a`, `--admin-certificates` | Creates the admin certificates, signed by the root CA of the CA directory. |
| `-A`, `--all` | Creates certificates specified in config.yml and admin certificates. If there is no root CA in the CA directory, a new one is created there. Includes the `load_balancer` entries when the section is present. |
| `-as`, `--agent-san <ip\|dns>` | Adds an extra address to the subject alternative name of every agent listener certificate, on top of the `ip` and `dns` entries of each manager node in config.yml. Repeat it for more than one. It names an address agents dial that no single node owns, such as a load balancer shared by every node of a cluster. Must be used along with `-A` or `-wm`. |
| `-ca`, `--root-ca-certificates` | Creates the root CA in the CA directory, if it does not exist yet. |
| `-lb`, `--load-balancer-certificates` | Creates the certificates of the `load_balancer` entries of config.yml. Only needed by a proxy that terminates TLS. |
| `-v`, `--verbose` | Enables verbose mode. |
| `-wd`, `--wazuh-dashboard-certificates` | Creates the Wazuh dashboard certificates. |
| `-wi`, `--wazuh-indexer-certificates` | Creates the Wazuh indexer certificates. |
| `-wm`, `--wazuh-manager-certificates` | Creates the Wazuh manager certificates. Each manager node also gets `<name>-remoted.pem` and `<name>-remoted-key.pem`, the certificate of the agent listener. |
| `-tmp`, `--cert_tmp_path </path/to/tmp_dir>` | Uses this directory to create the certificates, instead of a new one with a random name in `/tmp`. The directory must not exist, or must be an empty directory owned by root. Symbolic links are not allowed. Must be used along with one of these options: -a, -A, -ca, -wi, -wd, -wm, -lb |

The tool must be run as root. The root CA is read from `/etc/wazuh/ca`, or from the directory set in `WAZUH_CA_DIR`. Its private key, `root-ca.key`, stays there and is never copied to the `wazuh-certificates` directory. See [Root CA](../getting-started/usage.md#root-ca).

## Wazuh password tool

### Options

The `wazuh-passwords-tool-5.0.0.sh` script provides the following options for managing Wazuh internal user passwords:

| Options | Purpose |
| --------- | --------- |
| `-a\|--change-all` | Changes the passwords of all the Wazuh indexer and Wazuh server API users installed on the host. The new passwords are generated and saved in `/etc/wazuh/credentials.env`. |
| `-u\|--user <USER>` | Indicates the name of the user whose password will be changed: a Wazuh indexer user (`admin`, `kibanaserver`, `wazuh-manager`) or a Wazuh server API user (`wazuh`, `wazuh-wui`). If `-p\|--password` is not used, a random password is generated and saved in `/etc/wazuh/credentials.env`. |
| `-p\|--password` | Reads the new password from the standard input. Takes no value. Must be used with option `-u\|--user <USER>`. For example: `printf '%s\n' "$NEW_PASSWORD" \| sudo bash wazuh-passwords-tool-5.0.0.sh -u admin -p`. |
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
