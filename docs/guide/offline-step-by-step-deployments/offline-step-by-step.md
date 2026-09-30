# Offline install step by step

Install the Wazuh central components on hosts without Internet access, from the files prepared in [Offline download packages](../offline-download-packages/offline-download-packages.md): `wazuh-offline.tar.gz`, with the packages, and `wazuh-install-files.tar`, with the certificates and the passwords of a distributed deployment.

> [!NOTE]
> You need root user privileges to run all the commands described below.

Check the hardware and operating system requirements in [Hardware and operating system](../../ref/getting-started/requirements.md#hardware-and-operating-system). Firewalls can block communication between Wazuh components on different hosts: open the ports listed in [Required ports](../../ref/getting-started/requirements.md#required-ports).

## All-in-one deployment

An all-in-one deployment does not need `wazuh-install-files.tar`: the Wazuh packages create the root CA, the certificates and the passwords on the host. Decompress the packages and follow the [All in one](../step-by-step-deployments/all-in-one.md) guide, skipping the steps that add the Wazuh repository, and installing each package from `./wazuh-offline/wazuh-packages/`:

```bash
tar xf wazuh-offline.tar.gz
```

**RPM-based systems:**

```bash
yum install ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm
yum install ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm
yum install ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm
```

**DEB-based systems:**

```bash
apt install ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb
apt install ./wazuh-offline/wazuh-packages/wazuh-manager*.deb
apt install ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb
```

Install one package at a time, in the order and at the step of the guide where it is installed.

When you configure the Wazuh indexer, also disable the tasks that need Internet access, as described in [Installing the Wazuh indexer](#installing-the-wazuh-indexer), step 5.

> [!IMPORTANT]
> Without access to Wazuh CTI, the Wazuh indexer gets no vulnerability content, so vulnerability detection has no CVE feed and scans nothing. There is no offline feed in Wazuh 5.x. See [Migrating Vulnerability Detection to CTI-Based Feeds](https://github.com/wazuh/wazuh/blob/5.0.0/docs/guide/migration/vulnerability-detection-cti-feeds.md).

## Distributed deployment

> [!IMPORTANT]
> Without access to Wazuh CTI, the Wazuh indexer gets no vulnerability content, so vulnerability detection has no CVE feed and scans nothing. There is no offline feed in Wazuh 5.x. See [Migrating Vulnerability Detection to CTI-Based Feeds](https://github.com/wazuh/wazuh/blob/5.0.0/docs/guide/migration/vulnerability-detection-cti-feeds.md).

### How the passwords and certificates are shared

`wazuh-install-files.tar` holds the root CA certificate (`root-ca.pem`), the certificates of every node of `config.yml`, and `credentials.env`, with the five passwords of the deployment, generated once. Place them on every node **before** installing its package: the package then uses them, and generates nothing.

- The three Wazuh indexer passwords must be the same on every Wazuh indexer node. Only the node where you run `indexer-security-init.sh` counts: the script loads the users of that node into the Wazuh indexer security index, which replaces the users of every other node.
- The two Wazuh server API passwords must be the same on the master node and on every worker node.
- The Wazuh manager and the Wazuh dashboard consume the passwords of the Wazuh indexer and of the Wazuh server API, so they must be given the same values.

Each host needs these keys in `/etc/wazuh/credentials.env`:

| Host | Keys |
| ---- | ---- |
| Wazuh indexer nodes | `WAZUH_INDEXER_ADMIN_PASSWORD`, `WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD` |
| Wazuh manager nodes, master and workers | `WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD` |
| Wazuh dashboard nodes | `WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD` |

A host that runs more than one component needs the keys of all of them: the commands of this guide only add the keys that are not in the file yet.

The private key of the root CA, `root-ca.key`, is not in `wazuh-install-files.tar`: it stays in `/etc/wazuh/ca` of the host where you ran `wazuh-install-5.0.0.sh -g`. Back it up in a safe place: you need it to add nodes or renew certificates later. See [Security](../security.md).

### Decompress necessary installation files

On every node, in the working directory where you placed `wazuh-offline.tar.gz` and `wazuh-install-files.tar`, execute the following commands to decompress the installation files:

```bash
umask 022
tar xf wazuh-offline.tar.gz
tar xf wazuh-install-files.tar
```

### Installing the Wazuh indexer

Follow these steps on every Wazuh indexer node.

1. Install the following dependencies, if missing.

    **RPM-based systems:** `coreutils diffutils hostname iproute openssl procps-ng util-linux`

    **DEB-based systems:** `debconf adduser procps diffutils iproute2 openssl`

2. Place the passwords, the root CA certificate and the certificates of this node, replacing `<INDEXER_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `indexer-1`.

    ```bash
    NODE_NAME=<INDEXER_NODE_NAME>
    ```

    ```bash
    install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
    install -m 0644 wazuh-install-files/root-ca.pem /etc/wazuh/ca/root-ca.pem
    [ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
    for key in WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
        grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-install-files/credentials.env >> /etc/wazuh/credentials.env
    done
    install -d -m 0750 /etc/wazuh-indexer
    install -d -m 0500 /etc/wazuh-indexer/certs
    install -m 0400 wazuh-install-files/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
    install -m 0400 wazuh-install-files/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    install -m 0400 wazuh-install-files/admin.pem /etc/wazuh-indexer/certs/admin.pem
    install -m 0400 wazuh-install-files/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
    ```

3. Install the Wazuh indexer. The package uses the passwords and the certificates you placed, and gives the certificates to the `wazuh-indexer` user. Do not install it before placing them: placing them afterwards does not configure the node.

    **RPM-based systems:**

    ```bash
    yum install ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm
    ```

    **DEB-based systems:**

    ```bash
    apt install ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb
    ```

4. Edit `/etc/wazuh-indexer/opensearch.yml` and replace the following values:

   - `network.host`: Address of this node for HTTP and transport traffic. Use the same node address set in `config.yml`.
   - `node.name`: Name of the Wazuh indexer node as defined in `config.yml` (for example, `indexer-1`).
   - `cluster.initial_cluster_manager_nodes`: List of master-eligible node names.

        ```yaml
        cluster.initial_cluster_manager_nodes:
        - "indexer-1"
        - "indexer-2"
        ```

   - `discovery.seed_hosts`: List of the addresses of the master-eligible nodes. Uncomment this setting and set these values.

        ```yaml
        discovery.seed_hosts:
          - "10.0.0.1"
          - "10.0.0.2"
        ```

   - `plugins.security.nodes_dn`: List of Distinguished Names of the certificates of all Wazuh indexer cluster nodes. The package only writes the Distinguished Name of its own node: replace the list with one line per Wazuh indexer node of `config.yml`, in this format. Leave `plugins.security.authcz.admin_dn` as the package wrote it.

        ```yaml
        plugins.security.nodes_dn:
        - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer-1"
        - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer-2"
        ```

5. Disable the tasks that need Internet access. Add these settings to `/etc/wazuh-indexer/opensearch.yml`:

    ```yaml
    plugins.content_manager.catalog.update_on_start: false
    plugins.content_manager.catalog.update_on_schedule: false
    plugins.content_manager.telemetry.enabled: false
    ```

    See the [offline configuration of the Wazuh indexer](https://github.com/wazuh/wazuh-indexer-plugins/blob/5.0.0/docs/ref/modules/content-manager/configuration.md#offline-configuration--disabling-automatic-updates).

6. Set the Java heap of the Wazuh indexer. The package sets 1 GB, which is not enough: the Wazuh dashboard fails on its first start with `circuit_breaking_exception`. On a host dedicated to the Wazuh indexer, use half of the memory of the host:

    ```bash
    HEAP_MB=$(( $(free -m | awk 'NR == 2 {print $2}') / 2 ))
    sed -i -e "s/^-Xms.*/-Xms${HEAP_MB}m/" -e "s/^-Xmx.*/-Xmx${HEAP_MB}m/" /etc/wazuh-indexer/jvm.options
    ```

7. Enable and start the Wazuh indexer service.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```

8. When every Wazuh indexer node is running, run the Wazuh indexer `indexer-security-init.sh` script on one of them. It loads the security configuration, including the users and their passwords, and starts the cluster. Run it only once.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    ```

9. Check that every Wazuh indexer node joined the cluster and that its status is `green`. When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh/credentials.env` (`grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env`). The value is quoted in the file; the quotes are not part of the password.

    ```bash
    curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cluster/health?pretty
    ```

### Installing the Wazuh manager

Follow these steps on the master node and on every worker node.

1. Place the passwords, the root CA certificate and the certificates of this node, replacing `<MANAGER_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `master`.

    ```bash
    NODE_NAME=<MANAGER_NODE_NAME>
    ```

    ```bash
    install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
    install -m 0644 wazuh-install-files/root-ca.pem /etc/wazuh/ca/root-ca.pem
    [ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
    for key in WAZUH_MANAGER_API_PASSWORD WAZUH_MANAGER_WUI_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
        grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-install-files/credentials.env >> /etc/wazuh/credentials.env
    done
    mkdir -p /var/wazuh-manager/etc/certs
    install -m 0640 wazuh-install-files/$NODE_NAME.pem /var/wazuh-manager/etc/certs/indexer-connector.pem
    install -m 0640 wazuh-install-files/$NODE_NAME-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem
    install -m 0640 wazuh-install-files/$NODE_NAME-remoted.pem /var/wazuh-manager/etc/certs/remoted.pem
    install -m 0640 wazuh-install-files/$NODE_NAME-remoted-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem
    ```

2. Install the Wazuh manager. The package uses the files you placed instead of issuing its own, and gives each one its owner.

    **RPM-based systems:**

    ```bash
    yum install ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm
    ```

    **DEB-based systems:**

    ```bash
    apt install ./wazuh-offline/wazuh-packages/wazuh-manager*.deb
    ```

3. In the `<indexer>` block of `/var/wazuh-manager/etc/wazuh-manager.conf`, replace `127.0.0.1` with the addresses of the Wazuh indexer nodes, one `<host>` per node. Do it on every node: the cluster does not synchronize this block. Leave the `<ssl>` settings as the package wrote them. The credentials are not configured here: the package stored them in the keystore of the Wazuh manager.

    ```xml
    <indexer>
      <hosts>
        <host>https://<WAZUH_INDEXER_1_IP_ADDRESS>:9200</host>
        <host>https://<WAZUH_INDEXER_2_IP_ADDRESS>:9200</host>
      </hosts>
    ```

4. Edit the `<cluster>` block of `/var/wazuh-manager/etc/wazuh-manager.conf`. Use the key in `wazuh-install-files/clusterkey` on every node (`cat wazuh-install-files/clusterkey`), `master` as `node_type` on the master node and `worker` on the rest, and a unique `node_name` for each node, such as its name in `config.yml`. Replace `<MASTER_NODE_IP>` with the IP address of the master node. The package writes a `<cluster>` block with a random key of its own, `node_type` `master` and `bind_addr` `127.0.0.1` on every node, so replace the whole block on each of them.

    ```xml
    <cluster>
      <name>wazuh</name>
      <node_name>master</node_name>
      <node_type>master</node_type>
      <key><CLUSTER_KEY></key>
      <port>1516</port>
      <bind_addr>0.0.0.0</bind_addr>
      <nodes>
          <node><MASTER_NODE_IP></node>
      </nodes>
      <hidden>no</hidden>
    </cluster>
    ```

5. Enable and start the Wazuh manager service, first on the master node and then on the worker nodes.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    ```

6. Check that the Wazuh manager reaches the Wazuh indexer and, on the master node, that every node joined the cluster.

    ```bash
    grep 'indexer is reachable' /var/wazuh-manager/logs/wazuh-manager.log | tail -1
    /var/wazuh-manager/bin/cluster_control -l
    ```

    ```text
    NAME    TYPE    VERSION  ADDRESS
    master  master  5.0.0    10.0.0.3
    worker  worker  5.0.0    10.0.0.4
    ```

### Installing the Wazuh dashboard

1. Install the following dependencies, if missing.

    **RPM-based systems:** `libcap openssl diffutils util-linux`

    **DEB-based systems:** `tar curl libcap2-bin openssl`

2. Place the passwords, the root CA certificate and the certificate of this node, replacing `<DASHBOARD_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `dashboard`.

    ```bash
    NODE_NAME=<DASHBOARD_NODE_NAME>
    ```

    ```bash
    install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
    install -m 0644 wazuh-install-files/root-ca.pem /etc/wazuh/ca/root-ca.pem
    [ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
    for key in WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_MANAGER_WUI_PASSWORD; do
        grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-install-files/credentials.env >> /etc/wazuh/credentials.env
    done
    mkdir -p /etc/wazuh-dashboard/certs
    install -m 0400 wazuh-install-files/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
    install -m 0400 wazuh-install-files/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    ```

3. Install the Wazuh dashboard.

    **RPM-based systems:**

    ```bash
    yum install ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm
    ```

    **DEB-based systems:**

    ```bash
    apt install ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb
    ```

4. Give the certificates to the service user and restrict their directory. Some versions of the package leave a pair placed before installing as `root`, and the Wazuh dashboard then fails to start with `EACCES`:

    ```bash
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
    chmod 500 /etc/wazuh-dashboard/certs
    ```

5. Edit `/etc/wazuh-dashboard/opensearch_dashboards.yml` and replace the following values:

   - `server.host`: This setting specifies the host of the Wazuh dashboard server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard server. The value `0.0.0.0` will accept all the available IP addresses of the host.
   - `opensearch.hosts`: The URLs of the Wazuh indexer nodes.
   - `wazuh_core.hosts`: The Wazuh server API that the dashboard queries. `url` must be the Wazuh server API of the **master node**: it only runs there. Do not set a `password`: the package stored the `wazuh-wui` password in the keystore of the Wazuh dashboard, and a value in the file takes precedence over it. Leave `run_as` as the package wrote it.

    ```yaml
    server.host: 0.0.0.0
    server.port: 443
    opensearch.hosts: ["https://<WAZUH_INDEXER_1_IP_ADDRESS>:9200", "https://<WAZUH_INDEXER_2_IP_ADDRESS>:9200"]
    opensearch.ssl.verificationMode: certificate
    wazuh_core.hosts:
      default:
        url: https://<MASTER_NODE_IP>
        port: 55000
        username: wazuh-wui
    ```

6. Enable and start the Wazuh dashboard.

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-dashboard
    systemctl start wazuh-dashboard
    ```

7. Access the Wazuh web interface.

   - URL: `https://<WAZUH_DASHBOARD_IP_ADDRESS>`
   - Username: `admin`
   - Password: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `wazuh-install-files/credentials.env`

    Upon first access, the browser may show a certificate warning. You can add an exception in the browser advanced options, import `/etc/wazuh-dashboard/certs/root-ca.pem` into the browser certificate manager, or configure a certificate signed by a trusted authority.

### Removing the installation files

Once every component is installed and running, check the accounts, enroll agents, and troubleshoot as described in the [Clusterized](../step-by-step-deployments/clusterized.md#removing-the-credentials-files) guide. Then copy the passwords to your password manager and, on every node, remove the credentials file and the installation files:

```bash
rm -rf /etc/wazuh/credentials.env ./wazuh-install-files ./wazuh-install-files.tar
```
