# Clusterized

Install and configure the Wazuh indexer as a multi-node cluster on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. The Wazuh indexer is a highly scalable full-text search engine. It offers advanced security, alerting, index management, deep performance analysis, and several other features.

## Wazuh indexer

### Wazuh indexer cluster installation

The installation process is divided into three stages.

  1. Initial configuration
  2. Wazuh indexer nodes installation
  3. Cluster initialization

> [!NOTE]
> You need root user privileges to run all the commands described below.

### Initial configuration

Follow these steps to configure your Wazuh deployment, create SSL certificates to encrypt communications between the Wazuh central components, and generate random passwords to secure your installation.

  1. Download the Wazuh installation assistant and the configuration file.

   ```BASH
    curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-certs-tool-5.0.0.sh
    curl -s -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.0.0.yml
   ```

  2. Edit `./config.yml` and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh manager, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

  For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../ref/configuration/configuration-files.md#other-configyml-examples).

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

  3. Run the Wazuh installation assistant with the option `--generate-config-files` to generate the Wazuh cluster key, certificates, and passwords necessary for installation. You can find these files in `./wazuh-install-files.tar`.

  ```BASH
    bash wazuh-install-5.0.0.sh --generate-config-files
  ```

  4. Copy the `wazuh-install-files.tar` file to all the servers of the distributed deployment, including the Wazuh manager, the Wazuh indexer, and the Wazuh dashboard nodes. This can be done by using the `scp` utility.

### Wazuh indexer node installation

Follow these steps to install and configure a multi-node Wazuh indexer.

  1. Download the Wazuh installation assistant. Skip this step if you performed the initial configuration on the same server and the Wazuh installation assistant is already in your working directory:

  ```BASH
    curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh
  ```

  2. Run the Wazuh installation assistant with the option `--wazuh-indexer` and the node name to install and configure the Wazuh indexer. The node name must be the same one used in `config.yml` for the initial configuration, for example, `indexer`.

  > [!NOTE]
  > Make sure that a copy of `wazuh-install-files.tar`, created during the initial configuration step, is placed in your working directory.

  ```bash
      bash wazuh-install-5.0.0.sh --wazuh-indexer indexer
  ```

Repeat this stage of the installation process for every Wazuh indexer node in your cluster. Then proceed with initializing your multi-node cluster in the next stage.

> [!NOTE]
> For Wazuh indexer installation on hardened endpoints with `noexec` flag on the `/tmp` directory, additional setup is required. See the Wazuh indexer configuration on hardened endpoints section for necessary configuration.

MISSING LINK HERE

## Cluster initialization

The final stage of installing the Wazuh indexer multi-node cluster consists of running the security admin script.

Run the Wazuh installation assistant with option `--start-cluster` on any Wazuh indexer node to load the new certificates information and start the cluster.

```BASH
      bash wazuh-install-5.0.0.sh --start-cluster
```

> [!NOTE]
> You only have to initialize the cluster once, there is no need to run this command on every node.

### Testing the cluster installation

Verify that the Wazuh indexer installed correctly and the Wazuh indexer cluster is functioning as expected by following the steps below.

  1. Run the following command to confirm that the installation is successful. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer and use the password gotten from the output of the previous command:

  ```bash
        curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200
  ```

```json
  {
    "name" : "indexer",
    "cluster_name" : "wazuh-cluster",
    "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
    "version" : {
      "number" : "7.10.2",
      "build_type" : "rpm",
      "build_hash" : "db90a415ff2fd428b4f7b3f800a51dc229287cb4",
      "build_date" : "2023-06-03T06:24:25.112415503Z",
      "build_snapshot" : false,
      "lucene_version" : "9.6.0",
      "minimum_wire_compatibility_version" : "7.10.0",
      "minimum_index_compatibility_version" : "7.0.0"
    },
    "tagline" : "The OpenSearch Project: https://opensearch.org/"
  }
```

  2. Run the following command to check if the cluster is working correctly. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer and enter the password for the Wazuh indexer admin user when it prompts for password:

    ```bash
        curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    ```

    ```bash
        ip              heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                               cluster_manager name
        192.168.107.240           19          94   4    0.22    0.21     0.20 dimr      data,ingest,master,remote_cluster_client *               indexer
    ```

## Wazuh manager

Install the Wazuh manager as a multi-node cluster on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. The Wazuh manager analyzes the data received from the Wazuh agents, triggering alerts when it detects threats and anomalies.

### Wazuh manager cluster installation

  1. Download the Wazuh installation assistant. Skip this step if you installed Wazuh indexer on the same server and the Wazuh installation assistant is already in your working directory:

  ```BASH
        curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh
  ```

  2. Run the Wazuh installation assistant with the option `--wazuh-manager` followed by the node name to install the Wazuh manager. The node name must be the same one used in `config.yml` for the initial configuration, for example, `manager`:

  > [!NOTE]
  > Make sure that a copy of `wazuh-install-files.tar`, created during the initial configuration step, is placed in your working directory.

  ```BASH
        bash wazuh-install-5.0.0.sh --wazuh-manager manager
  ```

Your Wazuh manager is now successfully installed, repeat this process on every Wazuh manager node.

## Wazuh dashboard

Install and configure the Wazuh dashboard on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. Wazuh dashboard is a flexible and intuitive web interface for mining and visualizing security events and archives.

### Wazuh dashboard installation

  1. Download the Wazuh installation assistant. You can skip this step if you have already installed Wazuh indexer on the same server.

  ```BASH
        curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh
  ```

  2. Run the Wazuh installation assistant with the option `--wazuh-dashboard` and the node name to install and configure the Wazuh dashboard. The node name must be the same one used in `config.yml` for the initial configuration, for example, `dashboard`:

  > [!NOTE]
  > Make sure that a copy of `wazuh-install-files.tar` created during the Wazuh indexer installation is placed in your working directory.

  ```BASH
        bash wazuh-install-5.0.0.sh --wazuh-dashboard dashboard
  ```

  Once the Wazuh installation is completed, the output shows the access credentials and a message that confirms that the installation was successful.

```bash
  INFO: --- Summary ---
  INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
  User: admin
  Password: admin

  INFO: Installation finished.

```

  3. Access the Wazuh web interface with your `admin` user credentials. This is the default administrator account for the Wazuh indexer and it allows you to access the Wazuh dashboard.

- URL: `https://<WAZUH_DASHBOARD_IP_ADDRESS>`
- Username: `admin`
- Password: `admin`

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, the `root-ca.pem` file previously generated can be imported to the certificate manager of the browser instead. Alternatively, you can configure a certificate from a trusted authority.
