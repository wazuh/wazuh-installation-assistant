# Clusterized

Install and configure a distributed Wazuh deployment following step-by-step instructions: a Wazuh indexer cluster, a Wazuh manager cluster with one master node and one or more worker nodes, and the Wazuh dashboard.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Before you start

Firewalls can block communication between Wazuh components on different hosts: open the ports listed in [Required ports](../../ref/getting-started/requirements.md#required-ports).

### How the passwords and certificates are shared

There are no default passwords and no default certificates. Each Wazuh package reads the passwords it needs from `/etc/wazuh/credentials.env` when it is installed, generates any password it owns that is not there, and issues its own certificates from the root CA in `/etc/wazuh/ca`. On a single host that is all it takes. In a distributed deployment, the nodes must share one root CA and one set of passwords, so you create them once, on the first Wazuh indexer node, and place them on every node **before** installing its package:

- The three Wazuh indexer passwords must be the same on every Wazuh indexer node. Only the node where you run `indexer-security-init.sh` counts: the script loads the users of that node into the Wazuh indexer security index, which replaces the users of every other node. A Wazuh indexer node installed with different values would keep passwords that do not work.
- The two Wazuh server API passwords must be the same on the master node and on every worker node.
- The Wazuh manager and the Wazuh dashboard only consume passwords that other components own, so they must be given the values the Wazuh indexer and the Wazuh manager use.

This is what the Wazuh installation assistant does with `wazuh-install-files.tar` in a [distributed deployment](../installation-assistant-deployments/clusterized.md).

Each host needs these keys in `/etc/wazuh/credentials.env`:

| Host | Keys |
| ---- | ---- |
| Wazuh indexer nodes | `WAZUH_INDEXER_ADMIN_PASSWORD`, `WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD` |
| Wazuh manager nodes, master and workers | `WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD` |
| Wazuh dashboard nodes | `WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD` |

A host that runs more than one component needs the keys of all of them: the commands of this guide only add the keys that are not in the file yet. The file has one `KEY="value"` line per password, belongs to `root:root` with mode `0600`, and lives in `/etc/wazuh`, which belongs to `root:root` with mode `0700`.

## Wazuh indexer

Follow these steps to install and configure a multi-node Wazuh indexer. Start with the first Wazuh indexer node: it is where you create the passwords and the certificates of the whole deployment, and where the root CA stays.

### Installing package dependencies

Install the following packages on every Wazuh indexer node, if missing.

#### APT

```bash
apt install debconf adduser procps diffutils iproute2 openssl
```

#### YUM

```bash
yum install coreutils diffutils hostname iproute openssl procps-ng util-linux
```

> [!NOTE]
> You can install Wazuh by adding the Wazuh repository or by downloading the packages directly.

### Adding the Wazuh repository

#### APT

```bash
apt install gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg apt-transport-https
curl -s https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/ unstable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

#### YUM

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/production/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

To use `pre-release` packages instead, run the following commands:

```bash
rpm --import https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

### Creating the passwords

On the first Wazuh indexer node, before installing its package:

1. Create the five passwords of the deployment in `credentials.env`, in your working directory. A password must be 12 to 64 characters long, use only `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`, and contain at least one uppercase letter, one lowercase letter, one digit and one symbol. You can choose them yourself, or generate them:

    ```bash
    wazuh_generate_password() {
        local password
        while :; do
            password=$(LC_ALL=C tr -dc 'A-Za-z0-9.,_+:@%^=~-' < /dev/urandom | head -c 32)
            [[ $password =~ [A-Z] && $password =~ [a-z] && $password =~ [0-9] && $password =~ [.,_+:@%^=~-] ]] && break
        done
        printf '%s\n' "$password"
    }
    ```

    ```bash
    install -m 0600 /dev/null credentials.env
    cat > credentials.env <<EOF
    WAZUH_INDEXER_ADMIN_PASSWORD="$(wazuh_generate_password)"
    WAZUH_INDEXER_KIBANASERVER_PASSWORD="$(wazuh_generate_password)"
    WAZUH_INDEXER_MANAGER_PASSWORD="$(wazuh_generate_password)"
    WAZUH_MANAGER_API_PASSWORD="$(wazuh_generate_password)"
    WAZUH_MANAGER_WUI_PASSWORD="$(wazuh_generate_password)"
    EOF
    ```

2. Give the Wazuh indexer passwords to the package of this node:

    ```bash
    install -d -m 0700 -o root -g root /etc/wazuh
    install -m 0600 /dev/null /etc/wazuh/credentials.env
    grep '^WAZUH_INDEXER_' credentials.env > /etc/wazuh/credentials.env
    ```

### Installing Wazuh indexer

> [!NOTE]
> Install the package on the first Wazuh indexer node now. On every other Wazuh indexer node, install it after [Deploying certificates and passwords](#deploying-certificates-and-passwords).

#### APT

```bash
apt -y install wazuh-indexer
```

#### YUM

```bash
yum -y install wazuh-indexer
```

### Download and install Wazuh indexer package

#### DEB amd64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0_amd64.deb
apt -y install ./wazuh-indexer_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-indexer_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0_arm64.deb
apt -y install ./wazuh-indexer_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-indexer_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.0.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.0.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.0-<STAGE>.aarch64.rpm
```

### Creating the certificates

The certificates tool ships with the Wazuh indexer package. On the first Wazuh indexer node, after installing the package:

1. Edit `/usr/share/wazuh-indexer/tools/config.yml` and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh manager, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed. The Wazuh manager nodes need a `node_type`: one `master`, and `worker` for the rest.

    The file that ships with the package is a template, with other node names and commented examples: replace its nodes with yours, as in this example.

    For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../ref/configuration/configuration-files.md#other-configyml-examples).

    ```yaml
    nodes:
      # Wazuh indexer nodes
      indexer:
        - name: indexer-1
          ip: "<indexer-node-ip>"
        - name: indexer-2
          ip: "<indexer-node-ip>"
        #- name: indexer-3
        #  ip: "<indexer-node-ip>"

      # Wazuh manager nodes
      # If there is more than one Wazuh manager
      # node, each one must have a node_type
      manager:
        - name: master
          ip: "<wazuh-manager-ip>"
          node_type: master
        - name: worker
          ip: "<wazuh-manager-ip>"
          node_type: worker

      # Wazuh dashboard nodes
      dashboard:
        - name: dashboard
          ip: "<dashboard-node-ip>"
    ```

    Agents connect to the Wazuh manager nodes at the addresses of this file. If they reach them at another address, such as a public IP address, a DNS name or a load balancer, add it with `--agent-san`, as described in [Name the address agents dial](../../ref/getting-started/usage.md#name-the-address-agents-dial).

2. Create the certificates. The tool signs them with the root CA that the package created in `/etc/wazuh/ca`, and writes them to `wazuh-certificates/`, beside the tool:

    ```bash
    bash /usr/share/wazuh-indexer/tools/wazuh-certs-tool.sh -A
    ```

3. Add the passwords and compress all the necessary files:

    ```bash
    install -m 0600 credentials.env /usr/share/wazuh-indexer/tools/wazuh-certificates/credentials.env
    tar -cvf ./wazuh-certificates.tar -C /usr/share/wazuh-indexer/tools/wazuh-certificates/ .
    chmod 600 ./wazuh-certificates.tar
    rm -rf /usr/share/wazuh-indexer/tools/wazuh-certificates
    ```

4. Copy `wazuh-certificates.tar` to the working directory of every other node, including the Wazuh indexer, Wazuh manager, and Wazuh dashboard nodes. This can be done by using the `scp` utility. The file holds the private keys and the passwords of the deployment: keep it only until the installation is finished.

> [!IMPORTANT]
> The private key of the root CA, `root-ca.key`, stays in `/etc/wazuh/ca` of the first Wazuh indexer node, and it is not in `wazuh-certificates.tar`. Anyone holding it can issue a certificate that the Wazuh indexer accepts as its administrator. Back up `/etc/wazuh/ca` in a safe place: you need it to add nodes or renew certificates later. See [Security](../security.md).

### Deploying certificates and passwords

On every Wazuh indexer node, run the following commands in the directory that holds `wazuh-certificates.tar`, replacing `<INDEXER_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `indexer-1`.

```bash
NODE_NAME=<INDEXER_NODE_NAME>
```

```bash
umask 022
mkdir wazuh-certificates
tar -xf wazuh-certificates.tar -C wazuh-certificates
```

1. On every Wazuh indexer node except the first one, place the passwords and the root CA certificate. The first node already has both.

    ```bash
    install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
    install -m 0644 wazuh-certificates/root-ca.pem /etc/wazuh/ca/root-ca.pem
    [ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
    for key in WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
        grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-certificates/credentials.env >> /etc/wazuh/credentials.env
    done
    ```

2. Place the certificates of this node, with the names the package uses:

    ```bash
    install -d -m 0750 /etc/wazuh-indexer
    install -d -m 0500 /etc/wazuh-indexer/certs
    install -m 0400 wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
    install -m 0400 wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    install -m 0400 wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem
    install -m 0400 wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
    rm -rf wazuh-certificates
    ```

    On the first Wazuh indexer node, these files replace the certificates the package issued. Give them to the service user:

    ```bash
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
    ```

3. On every Wazuh indexer node except the first one, install the Wazuh indexer package now, as described in [Installing Wazuh indexer](#installing-wazuh-indexer). The package uses the passwords and the certificates you placed, generates nothing, and gives the certificates to the `wazuh-indexer` user.

    Do not install the package before placing the certificates: without the root CA private key and without a pair, the node cannot obtain a certificate, and placing one later does not configure it.

4. **Recommended action**: If no other Wazuh components will be installed on this node, remove the `wazuh-certificates.tar` file.

    ```bash
    rm -f ./wazuh-certificates.tar
    ```

> [!NOTE]
> For Wazuh indexer installation on hardened endpoints with `noexec` flag on the `/tmp` directory, additional setup is required. See the Wazuh indexer configuration on hardened endpoints section for necessary configuration.

### Configuring the Wazuh indexer

On every Wazuh indexer node, edit `/etc/wazuh-indexer/opensearch.yml` and replace the following values:

  1. `network.host`: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.

        Use the same node address set in `config.yml` to create the SSL certificates.

  2. `node.name`: Name of the Wazuh indexer node as defined in the `config.yml` file. For example, `indexer-1`.

  3. `cluster.initial_cluster_manager_nodes`: List of the names of the master-eligible nodes. These names are defined in the `config.yml` file.

      ```yaml
      cluster.initial_cluster_manager_nodes:
      - "indexer-1"
      - "indexer-2"
      ```

  4. `discovery.seed_hosts`: List of the addresses of the master-eligible nodes. Each element can be either an IP address or a hostname. Uncomment this setting and set the address of each master-eligible node.

      ```yaml
      discovery.seed_hosts:
        - "10.0.0.1"
        - "10.0.0.2"
      ```

  5. `plugins.security.nodes_dn`: List of the Distinguished Names of the certificates of all the Wazuh indexer cluster nodes. The package only writes the Distinguished Name of its own node: replace the list with one line per Wazuh indexer node of `config.yml`, in this format.

      ```yaml
      plugins.security.nodes_dn:
      - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer-1"
      - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer-2"
      ```

      Leave `plugins.security.authcz.admin_dn` as the package wrote it.

  6. Set the Java heap of the Wazuh indexer. The package sets 1 GB, which is not enough: the Wazuh dashboard fails on its first start with `circuit_breaking_exception`. On a host dedicated to the Wazuh indexer, use half of the memory of the host:

      ```bash
      HEAP_MB=$(( $(free -m | awk 'NR == 2 {print $2}') / 2 ))
      sed -i -e "s/^-Xms.*/-Xms${HEAP_MB}m/" -e "s/^-Xmx.*/-Xmx${HEAP_MB}m/" /etc/wazuh-indexer/jvm.options
      ```

### Starting the service

Enable and start the Wazuh indexer service.

#### Systemd

```bash
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```

#### SysV init

Choose one option according to the operating system used.

##### RPM-based operating system

```bash
chkconfig --add wazuh-indexer
service wazuh-indexer start
```

##### Debian-based operating system

```bash
update-rc.d wazuh-indexer defaults 95 10
service wazuh-indexer start
```

> [!NOTE]
> Repeat this stage of the installation process for every Wazuh indexer node in your multi-node cluster. Then proceed with initializing your multi-node cluster in the next stage.

### Cluster initialization

When every Wazuh indexer node is running, run the Wazuh indexer `indexer-security-init.sh` script on one of them. It loads the security configuration, including the users and their passwords, and starts the multi-node cluster.

```bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

> [!NOTE]
> You only have to initialize the cluster once, there is no need to run this command on every node.

### Testing the cluster installation

When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh/credentials.env` (`grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env`). The value is quoted in the file; the quotes are not part of the password.

  1. Run the following command to confirm that the installation is successful. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the IP address of a Wazuh indexer node.

      ```bash
      curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200
      ```

      ```json
      {
        "name" : "indexer-1",
        "cluster_name" : "wazuh-cluster",
        "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
        "version" : {
          "number" : "3.6.0",
          ...
        },
        "tagline" : "The OpenSearch Project: https://opensearch.org/"
      }
      ```

  2. Run the following commands to check that every Wazuh indexer node joined the cluster and that its status is `green`.

      ```bash
      curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
      curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cluster/health?pretty
      ```

      ```bash
      ip       heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                               cluster_manager name
      10.0.0.1           19          94   4    0.22    0.21     0.20 dimr      cluster_manager,data,ingest,remote_cluster_client *               indexer-1
      10.0.0.2           17          93   3    0.18    0.20     0.19 dimr      cluster_manager,data,ingest,remote_cluster_client -               indexer-2
      ```

## Wazuh manager

Install and configure the Wazuh manager following step-by-step instructions. The Wazuh manager collects and analyzes data from the deployed Wazuh agents. It triggers alerts when threats or anomalies are detected. Wazuh manager securely forwards alerts and archived events to the Wazuh indexer.

Follow these steps on the master node and on every worker node.

> [!NOTE]
> You can install Wazuh by adding the Wazuh repository or by downloading the packages directly.

### Adding the Wazuh repository

> [!NOTE]
> If you added the repository on any previous step you can skip this step.

#### APT

```bash
apt install gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg apt-transport-https
curl -s https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/ unstable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

#### YUM

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/production/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

To use `pre-release` packages instead, run the following commands:

```bash
rpm --import https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

### Deploying certificates and passwords

Before installing the package, run the following commands in the directory that holds `wazuh-certificates.tar`, replacing `<MANAGER_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `master`.

```bash
NODE_NAME=<MANAGER_NODE_NAME>
```

```bash
umask 022
mkdir wazuh-certificates
tar -xf wazuh-certificates.tar -C wazuh-certificates
install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
install -m 0644 wazuh-certificates/root-ca.pem /etc/wazuh/ca/root-ca.pem
[ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
for key in WAZUH_MANAGER_API_PASSWORD WAZUH_MANAGER_WUI_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
    grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-certificates/credentials.env >> /etc/wazuh/credentials.env
done
mkdir -p /var/wazuh-manager/etc/certs
install -m 0640 wazuh-certificates/$NODE_NAME.pem /var/wazuh-manager/etc/certs/indexer-connector.pem
install -m 0640 wazuh-certificates/$NODE_NAME-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem
install -m 0640 wazuh-certificates/$NODE_NAME-remoted.pem /var/wazuh-manager/etc/certs/remoted.pem
install -m 0640 wazuh-certificates/$NODE_NAME-remoted-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem
rm -rf wazuh-certificates
```

The package uses these files instead of issuing its own, copies `root-ca.pem` to `/var/wazuh-manager/etc/certs`, and gives each file its owner. `remoted.pem` is served to the agents by `wazuh-manager-remoted` on port 1517 and reused by `wazuh-manager-authd` on port 1515.

**Recommended action**: If no other Wazuh components will be installed on this node, remove the `wazuh-certificates.tar` file.

```bash
rm -f ./wazuh-certificates.tar
```

### Installing Wazuh manager

#### APT

```bash
apt -y install wazuh-manager
```

#### YUM

```bash
yum -y install wazuh-manager
```

### Download and install Wazuh manager package

#### DEB amd64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0_amd64.deb
apt -y install ./wazuh-manager_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-manager_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0_arm64.deb
apt -y install ./wazuh-manager_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-manager_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.0.x86_64.rpm
yum -y install ./wazuh-manager-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-manager-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.0.aarch64.rpm
yum -y install ./wazuh-manager-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-manager-5.0.0-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh manager

1. In the `<indexer>` block of `/var/wazuh-manager/etc/wazuh-manager.conf`, replace `127.0.0.1` with the addresses of the Wazuh indexer nodes, one `<host>` per node. Do it on the master node and on every worker node: the cluster does not synchronize this block. Leave the `<ssl>` settings as the package wrote them. The credentials are not configured here: the package stored them in the keystore of the Wazuh manager.

    ```xml
    <indexer>
      <hosts>
        <host>https://<WAZUH_INDEXER_1_IP_ADDRESS>:9200</host>
        <host>https://<WAZUH_INDEXER_2_IP_ADDRESS>:9200</host>
      </hosts>
    ```

2. Configure the cluster. Create a key on the master node, and use the same one on every worker node. It must be 32 characters long:

    ```bash
    openssl rand -hex 16
    ```

    On the master node, edit the `<cluster>` block of `/var/wazuh-manager/etc/wazuh-manager.conf`:

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

    On each worker node:

    ```xml
    <cluster>
      <name>wazuh</name>
      <node_name>worker</node_name>
      <node_type>worker</node_type>
      <key><CLUSTER_KEY></key>
      <port>1516</port>
      <bind_addr>0.0.0.0</bind_addr>
      <nodes>
          <node><MASTER_NODE_IP></node>
      </nodes>
      <hidden>no</hidden>
    </cluster>
    ```

    The package writes a `<cluster>` block with a random key of its own, `node_type` `master` and `bind_addr` `127.0.0.1` on every node, so replace the whole block on each of them. Replace `<CLUSTER_KEY>` with the key, `<MASTER_NODE_IP>` with the IP address of the master node, and use a unique `node_name` for each node, such as its name in `config.yml`.

### Starting the Wazuh manager service

Enable and start the Wazuh manager service, first on the master node and then on the worker nodes:

```bash
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

Verify the Wazuh manager service is running:

```bash
systemctl status wazuh-manager
```

Check that the Wazuh manager reaches the Wazuh indexer:

```bash
grep 'indexer is reachable' /var/wazuh-manager/logs/wazuh-manager.log | tail -1
```

On the master node, check that every node joined the cluster:

```bash
/var/wazuh-manager/bin/cluster_control -l
```

```text
NAME    TYPE    VERSION  ADDRESS
master  master  5.0.0    10.0.0.3
worker  worker  5.0.0    10.0.0.4
```

## Wazuh dashboard

Follow these steps to install the Wazuh dashboard.

### Installing package dependencies

Install the following packages, if missing.

#### APT

```bash
apt install tar curl libcap2-bin openssl
```

#### YUM

```bash
yum install libcap openssl diffutils util-linux
```

> [!NOTE]
> You can install Wazuh by adding the Wazuh repository or by downloading the packages directly.

### Adding the Wazuh repository

> [!NOTE]
> If you added the repository on any previous step you can skip this step.

#### APT

```bash
apt install gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg apt-transport-https
curl -s https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/ unstable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

#### YUM

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/production/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

To use `pre-release` packages instead, run the following commands:

```bash
rpm --import https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo
```

### Deploying certificates and passwords

Before installing the package, run the following commands in the directory that holds `wazuh-certificates.tar`, replacing `<DASHBOARD_NODE_NAME>` with the name of the node as defined in `config.yml`. For example, `dashboard`.

```bash
NODE_NAME=<DASHBOARD_NODE_NAME>
```

```bash
umask 022
mkdir wazuh-certificates
tar -xf wazuh-certificates.tar -C wazuh-certificates
install -d -m 0700 -o root -g root /etc/wazuh /etc/wazuh/ca
install -m 0644 wazuh-certificates/root-ca.pem /etc/wazuh/ca/root-ca.pem
[ -e /etc/wazuh/credentials.env ] || install -m 0600 /dev/null /etc/wazuh/credentials.env
for key in WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_MANAGER_WUI_PASSWORD; do
    grep -q "^${key}=" /etc/wazuh/credentials.env || grep "^${key}=" wazuh-certificates/credentials.env >> /etc/wazuh/credentials.env
done
mkdir -p /etc/wazuh-dashboard/certs
install -m 0400 wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
install -m 0400 wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
rm -rf wazuh-certificates
```

**Recommended action**: If no other Wazuh components will be installed on this node, remove the `wazuh-certificates.tar` file.

```bash
rm -f ./wazuh-certificates.tar
```

### Installing Wazuh dashboard

#### APT

```bash
apt -y install wazuh-dashboard
```

#### YUM

```bash
yum -y install wazuh-dashboard
```

### Download and install Wazuh dashboard package

#### DEB amd64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0_amd64.deb
apt -y install ./wazuh-dashboard_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-dashboard_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -sO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0_arm64.deb
apt -y install ./wazuh-dashboard_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-dashboard_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.0.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.0.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.0-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh dashboard

1. After installing the package, give the certificates to the service user and restrict their directory. Some versions of the package leave a pair placed before installing as `root`, and the Wazuh dashboard then fails to start with `EACCES`:

    ```bash
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
    chmod 500 /etc/wazuh-dashboard/certs
    ```

2. Edit the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file and replace the following values:

    - `server.host`: This setting specifies the host of the Wazuh dashboard server. To allow remote users to connect, set the value to the IP address or DNS name of the Wazuh dashboard server. The value `0.0.0.0` will accept all the available IP addresses of the host.
    - `opensearch.hosts`: The URLs of the Wazuh indexer nodes. For example, `["https://10.0.0.1:9200", "https://10.0.0.2:9200"]`.
    - `wazuh_core.hosts`: The Wazuh server API that the dashboard queries. Each host entry is defined with a unique ID and must include:
      - `url`: The URL of the Wazuh server API of the **master node**, including the protocol and address (DNS or IP). The Wazuh server API only runs on the master node.
      - `port`: The port where it is served.
      - `username`: The user that runs the requests.
      - `run_as`: Leave the value the package wrote.

    These settings are already in the file: change their values, and do not paste the block over it. Do not set a `password` in this file. The package stored the `wazuh-wui` password in the keystore of the Wazuh dashboard, and a value in the file takes precedence over it.

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

### Starting the Wazuh dashboard service

#### Systemd

```bash
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```

#### SysV init

##### RPM-based operating system

```bash
chkconfig --add wazuh-dashboard
service wazuh-dashboard start
```

##### Debian-based operating system

```bash
update-rc.d wazuh-dashboard defaults 95 10
service wazuh-dashboard start
```

### Access the Wazuh web interface

Access the Wazuh web interface with your `admin` user credentials. This is the administrator account of the Wazuh indexer and it allows you to access the Wazuh dashboard.

- URL: `https://<WAZUH_DASHBOARD_IP_ADDRESS>`
- Username: `admin`
- Password: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `/etc/wazuh/credentials.env` of a Wazuh indexer node, or in the `credentials.env` you created on the first Wazuh indexer node.

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, import the `/etc/wazuh-dashboard/certs/root-ca.pem` file into the certificate manager of the browser. Alternatively, you can configure a certificate from a trusted authority.

## Enrolling agents

Agents register with an enrollment token. Create it on the master node, replacing `<MANAGER_ADDRESS>` with the address the agents use to reach the Wazuh manager. It must be one of the addresses of `remoted.pem`, that is, the address of the node in `config.yml` or one given with `--agent-san`:

```bash
/var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <MANAGER_ADDRESS>
```

Then install the agent with the token. For example, on a Debian-based endpoint:

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='<AGENT_NAME>' dpkg -i wazuh-agent_*.deb
```

See the [Wazuh agent installation](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/getting-started/installation.md#agent) for the other platforms and options.

## Removing the credentials files

Once every component is installed and running, the passwords are stored in the keystores and databases of each component, and nothing reads `/etc/wazuh/credentials.env` again.

1. Check that the accounts work. When `curl` asks for a password, enter the value of the key given for each account.

    ```bash
    # Wazuh indexer: admin (WAZUH_INDEXER_ADMIN_PASSWORD), kibanaserver (WAZUH_INDEXER_KIBANASERVER_PASSWORD) and wazuh-manager (WAZUH_INDEXER_MANAGER_PASSWORD)
    curl -k -u admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cluster/health?pretty
    curl -k -u kibanaserver https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_plugins/_security/authinfo?pretty
    curl -k -u wazuh-manager https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_plugins/_security/authinfo?pretty
    # Wazuh server API on the master node: wazuh (WAZUH_MANAGER_API_PASSWORD) and wazuh-wui (WAZUH_MANAGER_WUI_PASSWORD)
    curl -k -u wazuh -X POST "https://<MASTER_NODE_IP>:55000/security/user/authenticate?raw=true"
    curl -k -u wazuh-wui -X POST "https://<MASTER_NODE_IP>:55000/security/user/authenticate?raw=true"
    ```

    Log in to the Wazuh dashboard, and check that it reaches the Wazuh server API: the dashboard shows an error of the Wazuh server API connection otherwise.

2. Copy the passwords to your password manager. `credentials.env` on the first Wazuh indexer node holds all five.

3. Remove the credentials file on every node, the `credentials.env` you created on the first Wazuh indexer node, and `wazuh-certificates.tar` wherever it is left:

    ```bash
    rm -f /etc/wazuh/credentials.env ./credentials.env ./wazuh-certificates.tar
    ```

4. Only the first Wazuh indexer node must hold the root CA private key. On every other node, `/etc/wazuh/ca` must only hold `root-ca.pem`. If it holds `root-ca.key`, remove it:

    ```bash
    ls /etc/wazuh/ca
    ```

To add a node later, recreate its `/etc/wazuh/credentials.env` with the current passwords, as described in [Deploying certificates and passwords](#deploying-certificates-and-passwords). To change a password, see [Security](../security.md).

## Troubleshooting

- A service does not start: check its journal, for example `journalctl -u wazuh-dashboard -e`. When a password is missing, the service refuses to start and names the key, for example `MISSING WAZUH_MANAGER_WUI_PASSWORD`. Add it to `/etc/wazuh/credentials.env` and start the service again.
- The Wazuh manager logs `Unauthorized - Check indexer credentials`: `WAZUH_INDEXER_MANAGER_PASSWORD` on the Wazuh manager node is not the one of the Wazuh indexer. Update the keystore of the Wazuh manager as described in [Update the Wazuh manager nodes](../../ref/getting-started/usage.md#update-the-wazuh-manager-nodes).
- The Wazuh dashboard shows an error of the Wazuh server API connection: check that `url` is the master node, that there is no `password` under `wazuh_core.hosts` in `opensearch_dashboards.yml`, and that `WAZUH_MANAGER_WUI_PASSWORD` was the one of the master node.
- The Wazuh indexer nodes do not join the cluster, or log TLS errors: check that every node has the pair from `wazuh-certificates.tar`, and that `plugins.security.nodes_dn` lists every node.
- The Wazuh dashboard logs `EACCES` on its certificates: run the `chown` of [Configuring the Wazuh dashboard](#configuring-the-wazuh-dashboard).
