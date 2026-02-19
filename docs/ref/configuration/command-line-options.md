# Command line options

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
