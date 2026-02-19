# All in one

Install and configure the Wazuh indexer as a single-node cluster following step-by-step instructions. Wazuh indexer is a highly scalable full-text search engine and offers advanced security, alerting, index management, deep performance analysis, and several other features.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Certificate creation

Wazuh uses certificates to establish confidentiality and encrypt communications between its central components. Follow these steps to create certificates for the Wazuh central components.

  1. Download the `wazuh-certs-tool-5.0.0-1.sh` script and the `config-5.0.0-1.yml` configuration file. This creates the certificates that encrypt communications between the Wazuh central components.

  ```BASH
      curl -sO https://packages.wazuh.com/5.0/wazuh-certs-tool-5.0.0-1.sh
      curl -sO https://packages.wazuh.com/5.0/config-5.0.0-1.yml
   ```

  2. Edit `config-5.0.0-1.yml` and replace the node names and IP values with the corresponding names and IP addresses. In this case, the IP to configure can be `127.0.0.1` since we are performing an All-In-One installation.

  ```
  nodes:
  # Wazuh indexer node
  indexer:
    - name: node-1
      ip: "127.0.0.1"

  # Wazuh manager node
  manager:
    - name: wazuh-1
      ip: "127.0.0.1"

  # Wazuh dashboard node
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
   ```

  3. Run `wazuh-certs-tool-5.0.0-1.sh` to create the certificates.

  ```BASH
      bash wazuh-certs-tool-5.0.0-1.sh -A
  ```

## Wazuh indexer

Follow these steps to install and configure a single-node Wazuh indexer.

### Installing package dependencies

#### APT

```BASH
dpkg -i debconf adduser procps
```

#### YUM

```BASH
yum install coreutils
```

### Download and install Wazuh indexer package

#### DEB amd64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-1_amd64.deb
dpkg -i ./wazuh-indexer_5.0.0-1_amd64.deb
```

#### DEB arm64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-1_arm64.deb
dpkg -i ./wazuh-indexer_5.0.0-1_arm64.deb
```

#### RPM x86_64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-indexer-5.0.0-1.x86_64.rpm
yum install -y ./wazuh-indexer-5.0.0-1.x86_64.rpm
```

#### RPM aarch64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-indexer-5.0.0-1.aarch64.rpm
yum install -y ./wazuh-indexer-5.0.0-1.aarch64.rpm
```

### Configuring the Wazuh indexer

Edit `/etc/wazuh-indexer/opensearch.yml` and replace the following values:

  1. `network.host`: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in `config-5.0.0-1.yml` to create the SSL certificates.

  2. `node.name`: Name of the Wazuh indexer node as defined in the `config-5.0.0-1.yml` file. For example, `node-1`.

  3. `cluster.initial_master_nodes`: List of the names of the master-eligible nodes. These names are defined in the `config-5.0.0-1.yml` file.

  ```
        cluster.initial_master_nodes:
        - "node-1"
  ```

  3. `discovery.seed_hosts`: List of the addresses of the master-eligible nodes. Each element can be either an IP address or a hostname. You may leave this setting commented if you are configuring the Wazuh indexer as a single node.

  ```
            discovery.seed_hosts:
              - "10.0.0.1"
  ```

  4. `plugins.security.nodes_dn`: List of the Distinguished Names of the certificates of all the Wazuh indexer cluster nodes.

  ```
        plugins.security.nodes_dn:
        - "CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US"
  ```

> [!NOTE]
> Firewalls can block communication between Wazuh components on different hosts. Refer to the Required ports section and ensure the necessary ports are open.

### Deploying certificates

Run the following commands, replacing `<INDEXER_NODE_NAME>` with the name of the Wazuh indexer node you are configuring as defined in `config-5.0.0-1.yml`. For example, `node-1`. This deploys the SSL certificates to encrypt communications between the Wazuh central components.

```BASH
NODE_NAME=<INDEXER_NODE_NAME>
```

```BASH
mkdir /etc/wazuh-indexer/certs
cp ./wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem
cp ./wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
cp ./wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
mv -n ./wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n ./wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

> [!NOTE]
> For Wazuh indexer installation on hardened endpoints with `noexec` flag on the `/tmp` directory, additional setup is required. See the Wazuh indexer configuration on hardened endpoints section for necessary configuration.

### Starting the service

Enable and start the Wazuh indexer service.

#### Systemd

```BASH
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```

#### SysV init

Choose one option according to the operating system used.

##### RPM-based operating system:

```BASH
chkconfig --add wazuh-indexer
service wazuh-indexer start
```

##### Debian-based operating system:

```BASH
update-rc.d wazuh-indexer defaults 95 10
service wazuh-indexer start
```

### Cluster initialization

The final stage of installing the Wazuh indexer cluster consists of running the security admin script.
Run the Wazuh `indexer indexer-security-init.sh` script to load the new certificates information and start the single-node cluster.

```BASH
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

### Testing the cluster installation

  1. Run the following commands to confirm that the installation is successful. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer:

  ```BASH
    curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200
  ```

  ```
  {
    "name" : "node-1",
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

  2. Run the following command to check if the cluster is working correctly. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of the Wazuh indexer:

  ```BASH
    curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
  ```

  ```
    ip              heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                               cluster_manager name
    192.168.107.240           19          94   4    0.22    0.21     0.20 dimr      data,ingest,master,remote_cluster_client *               node-1
  ```

## Wazuh manager

Install and configure the Wazuh manager following step-by-step instructions. The Wazuh manager collects and analyzes data from the deployed Wazuh agents. It triggers alerts when threats or anomalies are detected. Wazuh manager securely forwards alerts and archived events to the Wazuh indexer.

> [!NOTE]
> You need root user privileges to run all the commands described below.

### Download and install Wazuh manager package

#### DEB amd64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-1_amd64.deb
dpkg -i ./wazuh-manager_5.0.0-1_amd64.deb
```

#### DEB arm64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-1_arm64.deb
dpkg -i ./wazuh-manager_5.0.0-1_arm64.deb
```

#### RPM x86_64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-manager-5.0.0-1.x86_64.rpm
yum install -y ./wazuh-manager-5.0.0-1.x86_64.rpm
```

#### RPM aarch64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-manager-5.0.0-1.aarch64.rpm
yum install -y ./wazuh-manager-5.0.0-1.aarch64.rpm
```

### Deploying certificates

Deploy the SSL certificates for secure communication between the Wazuh manager and indexer. These certificates should be extracted from the `wazuh-certificates/` dir generated during the certificate creation process.

```BASH
NODE_NAME=<MANAGER_NODE_NAME>
```

```BASH
mkdir -p /var/ossec/etc/certs
cp ./wazuh-certificates/root-ca.pem /var/ossec/etc/certs/root-ca.pem
mv ./wazuh-certificates/$NODE_NAME.pem /var/ossec/etc/certs/manager.pem
mv ./wazuh-certificates/$NODE_NAME-key.pem /var/ossec/etc/certs/manager-key.pem
chmod 500 /var/ossec/etc/certs
chmod 400 /var/ossec/etc/certs/*
chown -R wazuh:wazuh /var/ossec/etc/certs
```

> [!NOTE]
> Replace `<MANAGER_NODE_NAME>` with the name you used when generating the certificates.

### Configure indexer connection

Configure the Wazuh manager to connect to the Wazuh indexer using the secure keystore:

```BASH
/var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
/var/ossec/bin/wazuh-keystore -f indexer -k password -v admin
```

Update the indexer configuration in `/var/ossec/etc/ossec.conf` to specify the indexer IP address:

```
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/ossec/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/ossec/etc/certs/manager.pem</certificate>
    <key>/var/ossec/etc/certs/manager-key.pem</key>
  </ssl>
</indexer>
```

### Start the Wazuh manager service

Start and enable the Wazuh manager service:

```BASH
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

Verify the Wazuh manager service is running:

```BASH
systemctl status wazuh-manager
```

## Wazuh dashboard

Follow these steps to install the Wazuh dashboard.

### Installing package dependencies

#### APT

```BASH
dpkg -i debhelper tar curl libcap2-bin # debhelper version 9 or later
```

#### YUM

```BASH
yum install libcap
```

### Download and install Wazuh dashboard package

#### DEB amd64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-1_amd64.deb
dpkg -i ./wazuh-dashboard_5.0.0-1_amd64.deb
```

#### DEB arm64

```BASH
curl -sO https://packages.wazuh.com/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-1_arm64.deb
dpkg -i ./wazuh-dashboard_5.0.0-1_arm64.deb
```

#### RPM x86_64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-dashboard-5.0.0-1.x86_64.rpm
yum install -y ./wazuh-dashboard-5.0.0-1.x86_64.rpm
```

#### RPM aarch64

```BASH
curl -sO https://packages.wazuh.com/5.x/yum/wazuh-dashboard-5.0.0-1.aarch64.rpm
yum install -y ./wazuh-dashboard-5.0.0-1.aarch64.rpm
```

### Configuring the Wazuh dashboard

Edit the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file and replace the following values:

  - `server.host`: This setting specifies the host of the Wazuh dashboard server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard server. The value 0.0.0.0 will accept all the available IP addresses of the host.
  - `opensearch.hosts`: The URLs of the Wazuh indexer instances to use for all your queries. For example, ["https://127.0.0.1:9200"]
  - `wazuh_core.hosts`: The Wazuh manager hosts that the dashboard will use to query the Wazuh manager API.
    - `url`: The URL to the server API including the protocol and address (DNS or IP).
    - `port`: The port where is served.
    - `username`: The user that runs the requests.
    - `password`: The password for the user.
    - `run_as`: This defines how the dashboard requests the data, using the default configured account (false) or the current user's context (true).

```
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
opensearch.ssl.verificationMode: certificate
---
wazuh_core.hosts:
  default:
    url: https://localhost
    port: 55000
    username: wazuh-wui
    password: wazuh-wui
    run_as: false
```

### Deploying certificates

```BASH
NODE_NAME=<DASHBOARD_NODE_NAME>
```

```BASH
mkdir -p /etc/wazuh-dashboard/certs
cp ./wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
mv ./wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv ./wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh:wazuh /etc/wazuh-dashboard/certs
```

### Starting the Wazuh dashboard service

#### Systemd

```BASH
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```

#### SysV init

##### RPM-based operating system

```BASH
chkconfig --add wazuh-dashboard
service wazuh-dashboard start
```

##### Debian-based operating system

```BASH
update-rc.d wazuh-dashboard defaults 95 10
service wazuh-dashboard start
```

### Access the Wazuh web interface

Access the Wazuh web interface with your `admin` user credentials. This is the default administrator account for the Wazuh indexer and it allows you to access the Wazuh dashboard.

  - URL: https://<WAZUH_DASHBOARD_IP_ADDRESS>
  - Username: admin
  - Password: admin

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, the `root-ca.pem` file previously generated can be imported to the certificate manager of the browser. Alternatively, you can configure a certificate from a trusted authority.
