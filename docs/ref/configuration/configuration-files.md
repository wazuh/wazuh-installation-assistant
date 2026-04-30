# Configuration files

## Wazuh installation assistant

The installation assistant needs the certificates and the `config.yml` to perform distributed installations:

If you want to install a specific Wazuh component, first make sure you have the `config.yml` file downloaded.

The `config.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [certs-tool-usage](../getting-started/usage.md#wazuh-certs-tool) section.

The steps to perform the installation are as follows:
> **note**: If you have already configured the `config.yml` and generated the `wazuh-install-files.tar` in the installation of another Wazuh component, you can skip directly to step 4.

1. Edit the `config.yml` file with the desired configuration for each of the Wazuh components.
2. Create the necessary files for installation that will be stored in `wazuh-install-files.tar` with the following command:

    ```bash
    sudo bash wazuh-install-5.9.9.sh --generate-config-files
    # or use the short form
    sudo bash wazuh-install-5.9.9.sh -g
    ```

3. The `wazuh-install-files.tar` file will be necessary for the installation of each component that will be part of the distributed installation as it includes the certificates for each of the components specified in the `config.yml` file. Therefore, copy this file to each of the machines where you will install a Wazuh component.
4. Once you have the `wazuh-install-files.tar` file on the machine where you will install the component, you just need to run the installation command for the desired component:

    4.1 To install the Wazuh Manager:

    ``` bash
    sudo bash wazuh-install-5.9.9.sh --wazuh-manager
    # or use the short form
    sudo bash wazuh-install-5.9.9.sh -wm
    ```

    4.2 To install the Wazuh Indexer:

    ``` bash
    sudo bash wazuh-install-5.9.9.sh --wazuh-indexer
    # or use the short form
    sudo bash wazuh-install-5.9.9.sh -wi
    ```

    4.3 To install the Wazuh Dashboard:

    ``` bash
    sudo bash wazuh-install-5.9.9.sh --wazuh-dashboard
    # or use the short form
    sudo bash wazuh-install-5.9.9.sh -wd
    ```

> **note**: The installation assistant is designed to facilitate the initial installation of Wazuh, so the passwords for each Wazuh internal user are set to default. Therefore, it is highly recommended to change them to more secure ones using this tool. You can see how to use this tool in the [Passwords Tool Usage](../getting-started/usage.md#wazuh-password-tool) section.

## Wazuh certs tool

The `config.yml` file is a YAML format configuration file that contains the necessary information to generate certificates for Wazuh nodes.
It is very important to ensure that the `config.yml` file is correctly configured with both the name of each node and the IP address, as they will be used to generate the corresponding certificate.

Here is the default example of how this file should be structured (using only `ip`):

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

### Other `config.yml` examples

Each node must have a unique name and at least one network identifier (`ip` or `dns`). In the case of Wazuh manager nodes, if there is more than one node, it is necessary to specify the node type (master or worker) using the `node_type` field.

#### Example 1: using only `dns` values

```yaml
nodes:
  indexer:
    - name: indexer-1
      dns: "indexer-1.example.org"

  manager:
    - name: manager-1
      dns: "manager-1.example.org"
      node_type: master
    - name: manager-2
      dns: "manager-2.example.org"
      node_type: worker

  dashboard:
    - name: dashboard-1
      dns: "dashboard.example.org"
```

#### Example 2: using only DNS lists

```yaml
nodes:
  indexer:
    - name: indexer-1
      dns:
        - "indexer-1.example.org"
        - "indexer-1.internal.local"

  manager:
    - name: manager-1
      dns:
        - "manager-1.example.org"
        - "manager-1.internal.local"
      node_type: master
    - name: manager-2
      dns:
        - "manager-2.example.org"
        - "manager-2.internal.local"
      node_type: worker

  dashboard:
    - name: dashboard-1
      dns:
        - "dashboard.example.org"
        - "dashboard.internal.local"
```

#### Example 3: combining `ip`, `dns`, and DNS lists

```yaml
nodes:
  indexer:
    - name: indexer-by-ip
      ip: "10.0.0.11"
    - name: indexer-by-dns
      dns: "indexer.example.org"
    - name: indexer-by-dns-list
      dns:
        - "indexer.example.org"
        - "indexer.internal.local"
    - name: indexer-combined
      ip: "10.0.0.12"
      dns:
        - "indexer-alt.example.org"

  manager:
    - name: manager-by-ip
      ip: "10.0.0.21"
      node_type: master
    - name: manager-combined
      ip: "10.0.0.22"
      dns: "manager.example.org"
      node_type: worker

  dashboard:
    - name: dashboard-by-dns
      dns: "dashboard.example.org"
```

By default, documentation examples use only `ip` values for simplicity.

For the wazuh certs tool to detect the file, it must be located in the same path as the `wazuh-certs-tool-5.9.9.sh` script.

## Wazuh passwords tool

The wazuh passwords tool does not accept configuration files for use.
