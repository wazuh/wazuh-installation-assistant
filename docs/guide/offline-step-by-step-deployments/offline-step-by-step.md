# Offline install step by step

## Decompress necessary installation files

In the working directory where you placed `wazuh-offline.tar.gz` and `wazuh-install-files.tar`, execute the following command to decompress the installation files:

```bash
tar xf wazuh-offline.tar.gz
tar xf wazuh-install-files.tar
```

## Installing the Wazuh indexer

The following dependencies must be installed on the Wazuh indexer nodes:

- **coreutils**

1. Run the following commands to install the Wazuh indexer.

    **RPM-based systems:**

    ```bash
    rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm
    ```

    **DEB-based systems:**

    ```bash
    dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb
    ```

2. Run the following commands replacing `<INDEXER_NODE_NAME>` with the name of the Wazuh indexer node you are configuring as defined in `config.yml`. For example, `indexer`. This deploys the SSL certificates to encrypt communications between the Wazuh central components.

    ```bash
    NODE_NAME=<INDEXER_NODE_NAME>
    mkdir /etc/wazuh-indexer/certs
    mv -n wazuh-install-files/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
    mv -n wazuh-install-files/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    mv wazuh-install-files/admin-key.pem /etc/wazuh-indexer/certs/
    mv wazuh-install-files/admin.pem /etc/wazuh-indexer/certs/
    cp wazuh-install-files/root-ca.pem /etc/wazuh-indexer/certs/
    chmod 500 /etc/wazuh-indexer/certs
    chmod 400 /etc/wazuh-indexer/certs/*
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
    ```

    Here you move the node certificate and key files, such as `indexer.pem` and `indexer-key.pem`, to their corresponding certs folder. They are specific to each node and are not required on other nodes. The `root-ca.pem` certificate is copied so it can be reused in the next component configuration steps.

3. Edit `/etc/wazuh-indexer/opensearch.yml` and replace the following values:

   - `network.host`: Address of this node for HTTP and transport traffic. Use the same node address set in `config.yml`.
   - `node.name`: Name of the Wazuh indexer node as defined in `config.yml` (for example, `indexer`).
   - `cluster.initial_master_nodes`: List of master-eligible node names.

        ```yaml
        cluster.initial_master_nodes:
            - "indexer"
            - "indexer-2"
            - "indexer-3"
        ```

   - `discovery.seed_hosts`: List of the addresses of the master-eligible nodes. For multi-node deployments, uncomment and set these values.

        ```yaml
        discovery.seed_hosts:
            - "10.0.0.1"
            - "10.0.0.2"
            - "10.0.0.3"
        ```

   - `plugins.security.nodes_dn`: List of Distinguished Names of the certificates of all Wazuh indexer cluster nodes. Uncomment the lines for `indexer-2` and `indexer-3` and change the common names (CN) and values according to your settings and your `config.yml` definitions.

        ```yaml
        plugins.security.nodes_dn:
        - "CN=indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
        - "CN=indexer-2,OU=Wazuh,O=Wazuh,L=California,C=US"
        - "CN=indexer-3,OU=Wazuh,O=Wazuh,L=California,C=US"
        ```

4. Enable and start the Wazuh indexer service.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```

5. For multi-node clusters, repeat the previous steps on every Wazuh indexer node.

6. When all Wazuh indexer nodes are running, run the Wazuh indexer `indexer-security-init.sh` script on any Wazuh indexer node to load the new certificates information and start the cluster.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    ```

7. Run the following command to check that the installation is successful. This command uses `127.0.0.1`; set your Wazuh indexer address if necessary.

    ```bash
    curl -XGET https://127.0.0.1:9200 -u admin:admin -k
    ```

    Example output:

    ```json
    {
        "name": "indexer",
        "cluster_name": "wazuh-cluster",
        "cluster_uuid": "095jEW-oRJSFKLz5wmo5PA",
        "version": {
            "number": "7.10.2",
            "build_type": "rpm",
            "build_hash": "db90a415ff2fd428b4f7b3f800a51dc229287cb4",
            "build_date": "2023-06-03T06:24:25.112415503Z",
            "build_snapshot": false,
            "lucene_version": "9.6.0",
            "minimum_wire_compatibility_version": "7.10.0",
            "minimum_index_compatibility_version": "7.0.0"
        },
        "tagline": "The OpenSearch Project: https://opensearch.org/"
    }
    ```

## Installing the Wazuh manager

On systems with apt as package manager, the following dependencies must be installed on the Wazuh manager nodes:

- **gnupg**
- **apt-transport-https**

1. Run the following commands to import the Wazuh key and install the Wazuh manager.

    **RPM-based systems:**

    ```bash
    rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm
    ```

    **DEB-based systems:**

    ```bash
    dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb
    ```

2. Deploy the SSL certificates for secure communication between the Wazuh manager and indexer. These certificates should be extracted from the `wazuh-certificates/` directory generated during the certificate creation process.

    ```BASH
    NODE_NAME=<MANAGER_NODE_NAME>
    ```

    ```BASH
    mkdir -p /var/ossec/etc/certs
    cp ./wazuh-certificates/root-ca.pem /var/wazuh-manager/etc/certs/root-ca.pem
    mv ./wazuh-certificates/$NODE_NAME.pem /var/wazuh-manager/etc/certs/manager.pem
    mv ./wazuh-certificates/$NODE_NAME-key.pem /var/wazuh-manager/etc/certs/manager-key.pem
    chmod 500 /var/wazuh-manager/etc/certs
    chmod 400 /var/wazuh-manager/etc/certs/*
    chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc/certs
    ```

    > [!NOTE]
    > Replace `<MANAGER_NODE_NAME>` with the name you used when generating the certificates.

3. Save the Wazuh indexer username and password into the Wazuh manager keystore using the `wazuh-keystore` tool:

    ```bash
    echo '<INDEXER_USERNAME>' | /var/ossec/bin/wazuh-keystore -f indexer -k username
    echo '<INDEXER_PASSWORD>' | /var/ossec/bin/wazuh-keystore -f indexer -k password
    ```

    > Note: The default offline-installation credentials are `admin:admin`.

    Update the indexer configuration in `/var/wazuh-manager/etc/wazuh-manager.conf` to specify the indexer IP address:

    ```xml
    <indexer>
    <hosts>
        <host>https://127.0.0.1:9200</host>
    </hosts>
    <ssl>
        <certificate_authorities>
        <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
        </certificate_authorities>
        <certificate>/var/wazuh-manager/etc/certs/manager.pem</certificate>
        <key>/var/wazuh-manager/etc/certs/manager-key.pem</key>
    </ssl>
    </indexer>
    ```

4. Enable and start the Wazuh manager service.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    ```

5. Run the following command to verify that the Wazuh manager status is active.

    ```bash
    systemctl status wazuh-manager
    ```

### Wazuh cluster configuration for multi-node deployment

After completing the installation of the Wazuh manager on every node, configure one manager node as master and the rest as workers.

#### Configuring the Wazuh manager master node

1. Edit the following settings in `/var/ossec/etc/ossec.conf`:

    ```xml
    <cluster>
        <name>wazuh</name>
        <node_name>master-node</node_name>
        <node_type>master</node_type>
        <key>c98b62a9b6169ac5f67dae55ae4a9088</key>
        <port>1516</port>
        <bind_addr>0.0.0.0</bind_addr>
        <nodes>
            <node><WAZUH_MASTER_ADDRESS></node>
        </nodes>
        <hidden>no</hidden>
        <disabled>no</disabled>
    </cluster>
    ```

    Replace `MASTER_NODE_IP` with the actual IP address of the master node.

2. On each worker node, edit `/var/wazuh-manager/etc/wazuh-manager.conf`

    ```xml
    <cluster>
    <name>wazuh</name>
    <node_name>worker-node-01</node_name>
    <node_type>worker</node_type>
    <key>fd3350b86d239654e34866ab3c4988a8</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>MASTER_NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    </cluster>
    ```

    Replace `MASTER_NODE_IP` with the actual IP address of the master node, and use a unique `node_name` for each worker.

3. Restart the Wazuh manager service on all nodes after making configuration changes:

    ```BASH
    systemctl restart wazuh-manager
    ```

4. Verify the cluster status from any node:

    ```BASH
    /var/wazuh-manager/bin/cluster_control -l
    ```

Repeat these configuration steps for every Wazuh manager worker node in your cluster.

#### Testing Wazuh manager cluster

To verify that the Wazuh cluster is enabled and all the nodes are connected, run:

```bash
/var/wazuh-manager/bin/cluster_control -l
```

Example output:

```text
NAME     TYPE    VERSION  ADDRESS
manager  master  4.12.0   10.0.0.3
manager-2  worker  4.12.0   10.0.0.5
manager-3  worker  4.12.0   10.0.0.4
```

## Installing the Wazuh dashboard

The following dependencies must be installed on the Wazuh dashboard node:

- **libcap**

1. Run the following commands to install the Wazuh dashboard.

    **RPM-based systems:**

    ```bash
    rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm
    ```

    **DEB-based systems:**

    ```bash
    dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb
    ```

2. Edit `/etc/wazuh-dashboard/opensearch_dashboards.yml` and replace the following values:

   - `server.host`: This setting specifies the host of the Wazuh dashboard server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard server. The value 0.0.0.0 will accept all the available IP addresses of the host.
   - `opensearch.hosts`: The URLs of the Wazuh indexer instances to use for all your queries. The Wazuh dashboard can be configured to connect to multiple Wazuh indexer nodes in the same cluster. The addresses of the nodes can be separated by commas. For example, ["https://10.0.0.2:9200", "https://10.0.0.3:9200","https://10.0.0.4:9200"]
   - `wazuh_core.hosts`: The Wazuh manager hosts that the dashboard will use to query the Wazuh manager API. At least one host is required. Each host entry defined with an unique ID and must include:
   - `url`: The URL to the server API including the protocol and address (DNS or IP).
   - `port`: The port where is served.
   - `username`: The user that runs the requests.
   - `password`: The password for the user.
   - `run_as`: This defines how the dashboard requests the data, using the default configured account (false) or the current user's context (true).

    ```yaml
    server.host: 0.0.0.0
    server.port: 443
    opensearch.hosts: https://127.0.0.1:9200
    opensearch.ssl.verificationMode: certificate
    ---
    wazuh_core.hosts:
    default:
        url: https://127.0.0.1
        port: 55000
        username: wazuh-wui
        password: wazuh-wui
        run_as: false
    ```

3. Replace `<DASHBOARD_NODE_NAME>` with your Wazuh dashboard node name used in `config.yml` (for example, `dashboard`) and move the certificates.

    ```bash
    NODE_NAME=<DASHBOARD_NODE_NAME>
    mkdir /etc/wazuh-dashboard/certs
    mv -n wazuh-install-files/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
    mv -n wazuh-install-files/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    cp wazuh-install-files/root-ca.pem /etc/wazuh-dashboard/certs/
    chmod 500 /etc/wazuh-dashboard/certs
    chmod 400 /etc/wazuh-dashboard/certs/*
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
    ```

4. Enable and start the Wazuh dashboard.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-dashboard
    systemctl start wazuh-dashboard
    ```

5. Access the Wazuh web interface.

   - URL: `https://<WAZUH_DASHBOARD_IP_ADDRESS>:443`
   - Username: `admin`
   - Password: `admin`

Upon first access, the browser may show a certificate warning. You can add an exception in the browser advanced options, import `root-ca.pem` into the browser certificate manager, or configure a certificate signed by a trusted authority.
