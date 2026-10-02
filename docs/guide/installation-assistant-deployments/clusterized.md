# Clusterized

Install and configure the Wazuh indexer as a multi-node cluster on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. The Wazuh indexer is a highly scalable full-text search engine. It offers advanced security, alerting, index management, deep performance analysis, and several other features.

> [!NOTE]
> The assistant stops if a package it needs, such as `apt-transport-https`, is missing, and names it. Install it, or add `-id` to the installation commands of this guide to install it automatically. To install packages that are not published yet, add `-d local` and list them in `artifact_urls.yaml`, as described in [Use development packages](../../ref/getting-started/usage.md#use-development-packages).

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

      ```bash
      curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh
      curl -s -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.0.0.yml
      ```

      To use `pre-release` packages instead, use the following commands:

      ```bash
      curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-install-5.0.0-<STAGE>.sh
      curl -s -o config.yml https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/config-5.0.0-<STAGE>.yml
      ```

  2. Edit `./config.yml` and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh manager, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed. Use the IP addresses the nodes use to reach each other.

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

  3. On the first Wazuh indexer node, run the Wazuh installation assistant with the option `--generate-config-files` to generate the Wazuh cluster key, certificates, and passwords necessary for installation. You can find these files in `./wazuh-install-files.tar`. The root CA and its private key stay in `/etc/wazuh/ca` of this node and are not added to the file; back them up in a safe place, they are needed to add nodes or renew certificates later.

      ```bash
      bash wazuh-install-5.0.0.sh --generate-config-files
      ```

      If agents will connect to a Wazuh manager through a different address, such as a public IP, a NAT address, or a load balancer, add it with `-as|--agent-san <address>`. Agent enrollment tokens can only be created for an address that is in the listener certificate of the Wazuh manager. See [Name the address agents dial](../../ref/getting-started/usage.md#name-the-address-agents-dial).

      ```bash
      bash wazuh-install-5.0.0.sh --generate-config-files -as <address>
      ```

  4. Copy the `wazuh-install-files.tar` file and the `wazuh-install-5.0.0.sh` script to all the servers of the distributed deployment, including the Wazuh manager, the Wazuh indexer, and the Wazuh dashboard nodes. This can be done by using the `scp` utility.

      > [!NOTE]
      > The file holds the passwords generated with it. If a password is changed later, update the file before using it to add or reinstall a node. See [Security](../security.md).

### Wazuh indexer node installation

Follow these steps to install and configure a multi-node Wazuh indexer.

  1. Run the Wazuh installation assistant with the option `--wazuh-indexer` and the node name to install and configure the Wazuh indexer. The node name must be the same one used in `config.yml` for the initial configuration, for example, `indexer`.

      > [!NOTE]
      > Make sure that a copy of `wazuh-install-files.tar` and `wazuh-install-5.0.0.sh`, created during the initial configuration step, is placed in your working directory.

      ```bash
      bash wazuh-install-5.0.0.sh --wazuh-indexer indexer
      ```

      To install `pre-release` packages instead, use:

      ```bash
      bash wazuh-install-5.0.0-<STAGE>.sh --wazuh-indexer indexer -d pre-release
      ```

Repeat this stage of the installation process for every Wazuh indexer node in your cluster. Then proceed with initializing your multi-node cluster in the next stage.

> [!NOTE]
> For Wazuh indexer installation on hardened endpoints with `noexec` flag on the `/tmp` directory, additional setup is required. See the Wazuh indexer configuration on hardened endpoints section for necessary configuration.

## Cluster initialization

The final stage of installing the Wazuh indexer multi-node cluster consists of running the security admin script.

Run the Wazuh installation assistant with option `--start-cluster` on any Wazuh indexer node to load the new certificates information and start the cluster.

```bash
bash wazuh-install-5.0.0.sh --start-cluster
```

> [!NOTE]
> You only have to initialize the cluster once, there is no need to run this command on every node.

### Testing the cluster installation

Verify that the Wazuh indexer installed correctly and the Wazuh indexer cluster is functioning as expected by following the steps below.

  1. Run the following command to confirm that the installation is successful. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer. When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh/credentials.env` (`sudo grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env`).

      ```bash
      curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200
      ```

      ```json
      {
        "name" : "indexer",
        "cluster_name" : "wazuh-cluster",
        "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
        "version" : {
          "number" : "3.6.0",
          ...
        },
        "tagline" : "The OpenSearch Project: https://opensearch.org/"
      }
      ```

  2. Run the following command to check if the cluster is working correctly. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer. When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh/credentials.env` (`sudo grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env`).

      ```bash
      curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
      ```

      ```bash
      ip              heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                               cluster_manager name
      192.168.107.240           19          94   4    0.22    0.21     0.20 dimr      cluster_manager,data,ingest,remote_cluster_client *               indexer
      ```

## Wazuh manager

Install the Wazuh manager as a multi-node cluster on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. The Wazuh manager analyzes the data received from the Wazuh agents, triggering alerts when it detects threats and anomalies.

### Wazuh manager cluster installation

  1. Run the Wazuh installation assistant with the option `--wazuh-manager` followed by the node name to install the Wazuh manager. The node name must be the same one used in `config.yml` for the initial configuration, for example, `manager`:

      > [!NOTE]
      > Make sure that a copy of `wazuh-install-files.tar` and `wazuh-install-5.0.0.sh`, created during the initial configuration step, is placed in your working directory.

        ```bash
        bash wazuh-install-5.0.0.sh --wazuh-manager manager
        ```

        To install `pre-release` packages instead, use:

        ```bash
        bash wazuh-install-5.0.0-<STAGE>.sh --wazuh-manager manager -d pre-release
        ```

Your Wazuh manager is now successfully installed, repeat this process on every Wazuh manager node.

  2. On the master node, check that every Wazuh manager node is listed in the cluster:

      ```bash
      /var/wazuh-manager/bin/cluster_control -l
      ```

  3. Check that the Wazuh server API answers. Replace `<MASTER_IP>` with the IP address of the master node and `<WAZUH_MANAGER_API_PASSWORD>` with the `WAZUH_MANAGER_API_PASSWORD` value of `/etc/wazuh/credentials.env`:

      ```bash
      curl -k -u wazuh:<WAZUH_MANAGER_API_PASSWORD> -X POST "https://<MASTER_IP>:55000/security/user/authenticate?raw=true"
      ```

The Wazuh server API only runs on the master node. The Wazuh dashboard connects to the master.

## Wazuh dashboard

Install and configure the Wazuh dashboard on a 64-bit (x86_64/AMD64 or AARCH64/ARM64) architecture using the assisted installation method. Wazuh dashboard is a flexible and intuitive web interface for mining and visualizing security events and archives.

### Wazuh dashboard installation

  1. Run the Wazuh installation assistant with the option `--wazuh-dashboard` and the node name to install and configure the Wazuh dashboard. The node name must be the same one used in `config.yml` for the initial configuration, for example, `dashboard`:

      > [!NOTE]
      > Make sure that a copy of `wazuh-install-files.tar` and `wazuh-install-5.0.0.sh`, created during the initial configuration step, is placed in your working directory.

        ```bash
        bash wazuh-install-5.0.0.sh --wazuh-dashboard dashboard
        ```

      To install `pre-release` packages instead, use:

      ```bash
      bash wazuh-install-5.0.0-<STAGE>.sh --wazuh-dashboard dashboard -d pre-release
      ```

      Once the Wazuh installation is completed, the output shows the access credentials and a message that confirms that the installation was successful. There is one `You can access` line per address of the Wazuh dashboard certificate, and the line after `Password:` is the command that prints the `admin` password. Run it in the directory that holds `wazuh-install-files.tar`.

      ```bash
        INFO: Wazuh dashboard web application initialized.
        INFO: --- Summary ---
        INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>:443
        INFO:     User: admin
        INFO:     Password: to read it from wazuh-install-files.tar, run:
        INFO:         sudo tar -xOf wazuh-install-files.tar wazuh-install-files/credentials.env | grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' | cut -d= -f2-
        INFO: Installation finished.
      ```

  2. Access the Wazuh web interface with your `admin` user credentials. This is the default administrator account for the Wazuh indexer and it allows you to access the Wazuh dashboard.

- URL: `https://<WAZUH_DASHBOARD_IP_ADDRESS>`
- Username: `admin`
- Password: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in the `credentials.env` file of `wazuh-install-files.tar`, or in `/etc/wazuh/credentials.env` of a Wazuh indexer node. The Wazuh dashboard node does not receive it.

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, the `root-ca.pem` file previously generated can be imported to the certificate manager of the browser instead. Alternatively, you can configure a certificate from a trusted authority.

> [!NOTE]
> `/etc/wazuh/credentials.env` holds the passwords of the Wazuh users, generated during the installation. Each node only receives the passwords of the components installed on it; the node where `wazuh-install-files.tar` was generated keeps all of them. Once you have stored them in a safe place, remove the file from every node: the Wazuh components do not read it after the installation. To change a password later, see [Multi-node and distributed deployments](../../ref/getting-started/usage.md#multi-node-and-distributed-deployments).
>
> Remove `wazuh-install-files.tar` from every node too: it holds the private keys and the passwords of the deployment. Keep a copy in a safe place if you plan to add nodes later, and update its passwords first if you change them, as described in [Security](../security.md).

## Next step: enroll the Wazuh agents

Agents enroll with an enrollment token created on the master node. Replace `<MANAGER_ADDRESS>` with the address agents use to reach the Wazuh manager. It must be in the listener certificate of the Wazuh manager.

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <MANAGER_ADDRESS>
```

Then install the agent with the token in `WAZUH_ENROLLMENT_TOKEN`, for example:

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='<NAME>' dpkg -i wazuh-agent_*.deb
```

The package does not start the agent. Start it and enable it at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

To check the enrollment, look for `Token bootstrap: enrollment succeeded` in `/var/ossec/logs/ossec.log` on the endpoint. The agent then shows as `active` in the Wazuh server API (`GET /agents`) and in the Wazuh dashboard.

See the [Wazuh agent installation](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/getting-started/installation.md#agent) for the other platforms and options.
