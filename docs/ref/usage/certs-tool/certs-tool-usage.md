# Certs Tool usage

The certs-tool is used by running the previously downloaded `wazuh-certs-tool.sh` script along with the `config.yml` configuration file. The certs tool generates the necessary certificates for the nodes specified in the configuration file.

## Options list

| Option | Description |
|--------|-------------|
| `-a`, `--admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the admin certificates, add root-ca.pem and root-ca.key. |
| `-A`, `--all </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates certificates specified in config.yml and admin certificates. Add a root-ca.pem and root-ca.key or leave it empty so a new one will be created. |
| `-ca`, `--root-ca-certificates` | Creates the root-ca certificates. |
| `-v`, `--verbose` | Enables verbose mode. |
| `-wd`, `--wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh dashboard certificates, add root-ca.pem and root-ca.key. |
| `-wi`, `--wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh indexer certificates, add root-ca.pem and root-ca.key. |
| `-ws`, `--wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>` | Creates the Wazuh server certificates, add root-ca.pem and root-ca.key. |
| `-tmp`, `--cert_tmp_path </path/to/tmp_dir>` | Modifies the default tmp directory (/tmp/wazuh-ceritificates) to the specified one. Must be used along with one of these options: -a, -A, -ca, -wi, -wd, -ws |

## config.yml configuration

The `config.yml` file is a YAML format configuration file that contains the necessary information to generate certificates for Wazuh nodes.
It is very important to ensure that the `config.yml` file is correctly configured with both the name of each node and the IP address, as they will be used to generate the corresponding certificate.

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

For the certs-tool to detect the file, it must be located in the same path as the `wazuh-certs-tool.sh` script.

## Create certificates

### Create all certificates

To create all the certificates specified in the `config.yml` file, run the following command:

```bash
sudo bash wazuh-certs-tool.sh --all
# or use the short version
sudo bash wazuh-certs-tool.sh -A
```

This will generate all the necessary certificates for the nodes defined in the configuration file, as well as the CA.

If you already had a CA created previously, you can use it to generate the certificates by running the following command:

```bash
sudo bash wazuh-certs-tool.sh -A </path/to/root-ca.pem> </path/to/root-ca.key>
```

### Create specific certificates

You can create only the certificates for a component as well as the CA or admin certificates (used in the indexer) using the following options:
- Create root CA:
    ```bash
    sudo bash wazuh-certs-tool.sh --root-ca-certificates
    # or use the short version
    sudo bash wazuh-certs-tool.sh -ca
    ```
- Create Wazuh indexer certificates:
    ```bash
    sudo bash wazuh-certs-tool.sh --wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool.sh -wi </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create Wazuh server certificates:
    ```bash
    sudo bash wazuh-certs-tool.sh --wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool.sh -ws </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create Wazuh dashboard certificates:
    ```bash
    sudo bash wazuh-certs-tool.sh --wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool.sh -wd </path/to/root-ca.pem> </path/to/root-ca.key>
    ```
- Create admin certificates:
    ```bash
    sudo bash wazuh-certs-tool.sh --admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>
    # or use the short version
    sudo bash wazuh-certs-tool.sh -a </path/to/root-ca.pem> </path/to/root-ca.key>
    ```


All these certificates will be generated in the `wazuh-certificates` directory within the current directory where the script is executed.