# All in one

Install and configure the Wazuh indexer, the Wazuh manager and the Wazuh dashboard on a single host following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Before you start

Check the hardware and operating system requirements in [Hardware and operating system](../../ref/getting-started/requirements.md#hardware-and-operating-system). Open the ports listed in [Required ports](../../ref/getting-started/requirements.md#required-ports) that the agents and the users of the Wazuh dashboard must reach.

There are no default passwords and no default certificates, and there is nothing to create by hand. When they are installed on the same host, the Wazuh packages share what they generate through `/etc/wazuh`:

- The Wazuh indexer package creates a root CA in `/etc/wazuh/ca`, issues its own certificates, and generates the passwords of the Wazuh indexer users.
- The Wazuh manager package issues its certificates from that root CA, generates the passwords of the Wazuh server API users, and reads the password of its Wazuh indexer user.
- The Wazuh dashboard package issues its certificate from that root CA and reads the passwords it needs.

Every password is written to `/etc/wazuh/credentials.env`, readable only by root. Install the components in the order of this guide, and keep the file until the end of the installation.

## Wazuh indexer

Follow these steps to install and configure a single-node Wazuh indexer.

### Installing package dependencies

Install the following packages, if missing.

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

### Installing Wazuh indexer

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
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.1.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.1.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.1-<STAGE>.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.1-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.1.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.1.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.1-<STAGE>.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.1-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh indexer

The package configures a single node with its own certificates. Only two settings need a change:

1. Keep the Wazuh indexer off the network. The other components reach it on this host. In `/etc/wazuh-indexer/opensearch.yml`, set `network.host` to `127.0.0.1`:

    ```bash
    sed -i 's|^network.host:.*|network.host: "127.0.0.1"|' /etc/wazuh-indexer/opensearch.yml
    ```

2. Set the Java heap of the Wazuh indexer. The package sets 1 GB, which is not enough: the Wazuh dashboard fails on its first start with `circuit_breaking_exception`. On a host shared with the other components, use a quarter of the memory of the host:

    ```bash
    HEAP_MB=$(( $(free -m | awk 'NR == 2 {print $2}') / 4 ))
    sed -i -e "s/^-Xms.*/-Xms${HEAP_MB}m/" -e "s/^-Xmx.*/-Xmx${HEAP_MB}m/" /etc/wazuh-indexer/jvm.options
    ```

> [!NOTE]
> For Wazuh indexer installation on hardened endpoints with `noexec` flag on the `/tmp` directory, additional setup is required. See the Wazuh indexer configuration on hardened endpoints section for necessary configuration.

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

### Cluster initialization

Run the Wazuh indexer `indexer-security-init.sh` script. It loads the security configuration, including the users and their passwords, and starts the single-node cluster.

```bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

### Testing the cluster installation

When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh/credentials.env` (`grep WAZUH_INDEXER_ADMIN_PASSWORD /etc/wazuh/credentials.env`). The value is quoted in the file; the quotes are not part of the password.

  1. Run the following command to confirm that the installation is successful.

      ```bash
      curl -k -u admin https://127.0.0.1:9200
      ```

      ```json
      {
        "name" : "node-1",
        "cluster_name" : "wazuh-cluster",
        "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
        "version" : {
          "number" : "3.6.0",
          ...
        },
        "tagline" : "The OpenSearch Project: https://opensearch.org/"
      }
      ```

  2. Run the following command to check that the cluster is working correctly and that its status is `green`.

      ```bash
      curl -k -u admin https://127.0.0.1:9200/_cluster/health?pretty
      ```

## Wazuh manager

Install and configure the Wazuh manager following step-by-step instructions. The Wazuh manager collects and analyzes data from the deployed Wazuh agents. It triggers alerts when threats or anomalies are detected. Wazuh manager securely forwards alerts and archived events to the Wazuh indexer.

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
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.1.x86_64.rpm
yum -y install ./wazuh-manager-5.0.1.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.1-<STAGE>.x86_64.rpm
yum -y install ./wazuh-manager-5.0.1-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.1.aarch64.rpm
yum -y install ./wazuh-manager-5.0.1.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.1-<STAGE>.aarch64.rpm
yum -y install ./wazuh-manager-5.0.1-<STAGE>.aarch64.rpm
```

The package issues the certificate that the agents verify, `remoted.pem`, for the addresses it finds on the host. If the agents reach this host at another address, such as a public IP address behind NAT or a DNS name, set `WAZUH_MANAGER_REMOTED_CERT_SANS` when installing the package. It replaces the addresses the package finds, so include those too. For example:

```bash
WAZUH_MANAGER_REMOTED_CERT_SANS='IP:<HOST_IP_ADDRESS>,IP:203.0.113.10,DNS:wazuh.example.com' apt -y install wazuh-manager
```

```bash
WAZUH_MANAGER_REMOTED_CERT_SANS='IP:<HOST_IP_ADDRESS>,IP:203.0.113.10,DNS:wazuh.example.com' yum -y install wazuh-manager
```

The same applies when you install a downloaded package, for example `yum -y install ./wazuh-manager-5.0.1.x86_64.rpm`.

### Configuring the Wazuh manager

There is nothing to configure. The package connects the Wazuh manager to the Wazuh indexer on `127.0.0.1`, with the certificates it issued and the password of its Wazuh indexer user, which it stored in its keystore.

### Starting the Wazuh manager service

Enable and start the Wazuh manager service:

```bash
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

Verify the Wazuh manager service is running and that it reaches the Wazuh indexer:

```bash
systemctl status wazuh-manager
grep 'indexer is reachable' /var/wazuh-manager/logs/wazuh-manager.log | tail -1
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
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.1.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.1.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.1-<STAGE>.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.1-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -sO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.1.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.1.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.1-<STAGE>.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.1-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh dashboard

The package connects the Wazuh dashboard to the Wazuh indexer and to the Wazuh server API on this host, and stores their passwords in its keystore. There is nothing to change in `/etc/wazuh-dashboard/opensearch_dashboards.yml`, except:

- `server.host`: This setting specifies the host of the Wazuh dashboard server. The package sets `0.0.0.0`, which accepts all the available IP addresses of the host. To restrict it, set the IP address or DNS name of the Wazuh dashboard server.
- Do not add a `password` under `wazuh_core.hosts`. The package stored the `wazuh-wui` password in the keystore of the Wazuh dashboard, and a value in the file takes precedence over it.

The file already holds these values, among others:

```yaml
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
wazuh_core.hosts:
  default:
    url: https://localhost
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
- Password: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `/etc/wazuh/credentials.env`

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, import the `/etc/wazuh-dashboard/certs/root-ca.pem` file into the certificate manager of the browser. Alternatively, you can configure a certificate from a trusted authority.

## Enrolling agents

Agents register with an enrollment token. Create it on this host, replacing `<MANAGER_ADDRESS>` with the address the agents use to reach the Wazuh manager. It must be one of the addresses of `remoted.pem`:

```bash
/var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <MANAGER_ADDRESS>
```

Then install the agent with the token. For example, on a Debian-based endpoint:

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='<AGENT_NAME>' dpkg -i wazuh-agent_*.deb
```

See the [Wazuh agent installation](https://github.com/wazuh/wazuh/blob/5.0.1/docs/ref/getting-started/installation.md#agent) for the other platforms and options.

## Removing the credentials file

Once the three components are installed and running, the passwords are stored in the keystores and databases of each component, and nothing reads `/etc/wazuh/credentials.env` again.

1. Check that the accounts work. When `curl` asks for a password, enter the value of the key given for each account.

    ```bash
    # Wazuh indexer: admin (WAZUH_INDEXER_ADMIN_PASSWORD), kibanaserver (WAZUH_INDEXER_KIBANASERVER_PASSWORD) and wazuh-manager (WAZUH_INDEXER_MANAGER_PASSWORD)
    curl -k -u admin https://127.0.0.1:9200/_cluster/health?pretty
    curl -k -u kibanaserver https://127.0.0.1:9200/_plugins/_security/authinfo?pretty
    curl -k -u wazuh-manager https://127.0.0.1:9200/_plugins/_security/authinfo?pretty
    # Wazuh server API: wazuh (WAZUH_MANAGER_API_PASSWORD) and wazuh-wui (WAZUH_MANAGER_WUI_PASSWORD)
    curl -k -u wazuh -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"
    curl -k -u wazuh-wui -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"
    ```

    Log in to the Wazuh dashboard, and check that it reaches the Wazuh server API: the dashboard shows an error of the Wazuh server API connection otherwise.

2. Copy the passwords to your password manager.

3. Remove the file:

    ```bash
    rm -f /etc/wazuh/credentials.env
    ```

The root CA private key stays in `/etc/wazuh/ca`. Back it up in a safe place: you need it to add nodes or renew certificates later. See [Security](../security.md). To change a password, see [Change the passwords of a step-by-step deployment](../security.md#change-the-passwords-of-a-step-by-step-deployment).

## Troubleshooting

- A service does not start: check its journal, for example `journalctl -u wazuh-dashboard -e`. When a password is missing, the service refuses to start and names the key, for example `MISSING WAZUH_MANAGER_WUI_PASSWORD`. Check that the component that owns it, the Wazuh indexer or the Wazuh manager, was installed before, and that `/etc/wazuh/credentials.env` was not removed. Then start the service again.
- The Wazuh manager logs `Unauthorized - Check indexer credentials`: run `indexer-security-init.sh`, as described in [Cluster initialization](#cluster-initialization), and restart the Wazuh manager.
- The Wazuh dashboard shows an error of the Wazuh server API connection: check that there is no `password` under `wazuh_core.hosts` in `opensearch_dashboards.yml`.
