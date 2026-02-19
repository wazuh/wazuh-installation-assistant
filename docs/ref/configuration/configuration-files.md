# Configuration files

## Wazuh installation assistant

El asistente de instalación necesita los ceritificados y el archivo `config-5.0.0-1.yml` para realizar intalaciones distribuidas:

If you want to install a specific Wazuh component, first make sure you have the `config-5.0.0-1.yml` file downloaded.

The `config-5.0.0-1.yml` file is a YAML format configuration file that contains the name and IP of each component to be installed in the distributed installation. This file is used to generate the necessary certificates for secure communication between the different Wazuh components. For more information on how to configure this file, see the [certs-tool-usage](../getting-started/usage.md#wazuh-certs-tool) section.


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

> **note**: The installation assistant is designed to facilitate the initial installation of Wazuh, so the passwords for each Wazuh internal user are set to default. Therefore, it is highly recommended to change them to more secure ones using this tool. You can see how to use this tool in the [Passwords Tool Usage](../getting-started/usage.md#wazuh-password-tool) section.

## Wazuh certs tool

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

## Wazuh password tool

The wazuh password tool does not accept configuration files for use.
