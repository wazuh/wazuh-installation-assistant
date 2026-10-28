# All in one

Install and configure the Wazuh indexer, the Wazuh manager and the Wazuh dashboard on a single host following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Before you start

Check the hardware and operating system requirements in [Hardware and operating system](../../ref/getting-started/requirements.md#hardware-and-operating-system). Open the ports listed in [Required ports](../../ref/getting-started/requirements.md#required-ports) that the agents and the users of the Wazuh dashboard must reach.

There are no default passwords and no default certificates, and there is nothing to create by hand. Each Wazuh package has its own configuration directory, with its own CA. When they are installed on the same host, the packages share what they need through the `export/` directory of each package:

- The Wazuh indexer package creates its CA in `/etc/wazuh-indexer/ca`, issues its own certificates, and generates the passwords of the Wazuh indexer users. It publishes its CA and these passwords in `/etc/wazuh-indexer/export/`.
- The Wazuh manager package creates its CA in `/etc/wazuh-manager/ca`, issues its own certificates, and generates the passwords of the Wazuh server API users. It takes the Wazuh indexer CA and the password of its Wazuh indexer user from `/etc/wazuh-indexer/export/`, and publishes its CA and its passwords in `/etc/wazuh-manager/export/`.
- The Wazuh dashboard package creates its CA in `/etc/wazuh-dashboard/ca`, issues its own certificate, and takes the CAs and the passwords it needs from the `export/` directories of the Wazuh indexer and the Wazuh manager.

The passwords are in `/etc/wazuh-indexer/export/credentials.env` and `/etc/wazuh-manager/export/credentials.env`, readable only by root. Install the components in the order of this guide.

## Wazuh indexer

Follow these steps to install and configure a single-node Wazuh indexer.

### Installing package dependencies

Install the following packages, if missing. These are the lists the Wazuh installation assistant installs for each component: they include what the assistant itself uses to place the files, such as `cmp` from `diffutils`.

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
apt install gnupg
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg
curl -fsS https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
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
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0_amd64.deb
apt -y install ./wazuh-indexer_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-indexer_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0_arm64.deb
apt -y install ./wazuh-indexer_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-indexer_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.0.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-indexer-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-indexer-5.0.0.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-indexer-5.0.0-<STAGE>.aarch64.rpm
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
> On hardened endpoints with the `noexec` flag on the `/tmp` directory, the Wazuh indexer needs no additional setup: the package sets `OPENSEARCH_TMPDIR=/var/lib/wazuh-indexer/tmp` in `/etc/sysconfig/wazuh-indexer` (RPM) or `/etc/default/wazuh-indexer` (DEB), so the service does not use `/tmp`. That directory must allow execution.

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

The Wazuh indexer publishes its CA certificate in `/etc/wazuh-indexer/export/ca.pem`. Only `root` and the `wazuh-indexer` group can read it, so run `curl` with `sudo`. When `curl` asks for the password, enter the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh-indexer/export/credentials.env` (`sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-`).

  1. Run the following command to confirm that the installation is successful.

      ```bash
      sudo curl --cacert /etc/wazuh-indexer/export/ca.pem -u admin https://127.0.0.1:9200
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
      sudo curl --cacert /etc/wazuh-indexer/export/ca.pem -u admin https://127.0.0.1:9200/_cluster/health?pretty
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
apt install gnupg
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg
curl -fsS https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
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

### Setting the certificate addresses (optional)

The package issues the certificate that the agents verify, `remoted.pem`, for the addresses it finds on the host. If the agents reach this host at another address, such as a public IP address behind NAT or a DNS name, add `WAZUH_MANAGER_REMOTED_CERT_SANS` to `/etc/wazuh-manager/local.env` now, before installing the package. It replaces the addresses the package finds, so include those too. For example:

```bash
install -d -m 0750 -o root -g root /etc/wazuh-manager
[ -e /etc/wazuh-manager/local.env ] || install -m 0600 /dev/null /etc/wazuh-manager/local.env
echo 'WAZUH_MANAGER_REMOTED_CERT_SANS=IP:<HOST_IP_ADDRESS>,IP:203.0.113.10,DNS:wazuh.example.com' >> /etc/wazuh-manager/local.env
```

The package also issues the certificate of the Server API, `apid.pem`, for the addresses it finds on the host plus `localhost`, `127.0.0.1` and `::1`. To add an address API clients dial, add `WAZUH_MANAGER_APID_CERT_SANS` to the same file, for example `WAZUH_MANAGER_APID_CERT_SANS=IP:<HOST_IP_ADDRESS>,DNS:api.example.com`. It is independent from `WAZUH_MANAGER_REMOTED_CERT_SANS`.

The Wazuh indexer and the Wazuh dashboard packages work the same way with `WAZUH_INDEXER_CERT_SANS` in `/etc/wazuh-indexer/local.env` and `WAZUH_DASHBOARD_CERT_SANS` in `/etc/wazuh-dashboard/local.env`, set before installing each package. Without it, the Wazuh dashboard certificate names the host name, its FQDN and the addresses of the default-route interfaces, so set `WAZUH_DASHBOARD_CERT_SANS` when browsers reach it by another name or address. Each list replaces the addresses the package finds, so include those too.

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
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0_amd64.deb
apt -y install ./wazuh-manager_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-manager_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0_arm64.deb
apt -y install ./wazuh-manager_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-manager_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.0.x86_64.rpm
yum -y install ./wazuh-manager-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-manager-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-manager-5.0.0.aarch64.rpm
yum -y install ./wazuh-manager-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-manager-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-manager-5.0.0-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh manager

There is nothing to configure. The package connects the Wazuh manager to the Wazuh indexer on `127.0.0.1`. It imports the indexer CA and the client pair the Wazuh indexer issued for it from `/etc/wazuh-indexer/export/` (`ca.pem` and `manager-client.pem` with its key), and stores the password of its Wazuh indexer user in its keystore.

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

Install the following packages, if missing. The Wazuh dashboard package only needs the account tools (`passwd`, `useradd`, `userdel`), which it declares itself; `tar` and `curl` are used in the steps below.

#### APT

```bash
apt install tar curl
```

#### YUM

```bash
yum install tar curl
```

> [!NOTE]
> You can install Wazuh by adding the Wazuh repository or by downloading the packages directly.

### Adding the Wazuh repository

> [!NOTE]
> If you added the repository on any previous step you can skip this step.

#### APT

```bash
apt install gnupg
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/production/5.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
```

To use `pre-release` packages instead, run the following commands:

```bash
apt install gnupg
curl -fsS https://packages-staging.xdrsiem.wazuh.info/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
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
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0_amd64.deb
apt -y install ./wazuh-dashboard_5.0.0_amd64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-<STAGE>_amd64.deb
apt -y install ./wazuh-dashboard_5.0.0-<STAGE>_amd64.deb
```

#### DEB arm64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0_arm64.deb
apt -y install ./wazuh-dashboard_5.0.0_arm64.deb
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_5.0.0-<STAGE>_arm64.deb
apt -y install ./wazuh-dashboard_5.0.0-<STAGE>_arm64.deb
```

#### RPM x86_64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.0.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.0.x86_64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.0-<STAGE>.x86_64.rpm
yum -y install ./wazuh-dashboard-5.0.0-<STAGE>.x86_64.rpm
```

#### RPM aarch64

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/yum/wazuh-dashboard-5.0.0.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.0.aarch64.rpm
```

To use `pre-release` packages instead, run the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-dashboard-5.0.0-<STAGE>.aarch64.rpm
yum -y install ./wazuh-dashboard-5.0.0-<STAGE>.aarch64.rpm
```

### Configuring the Wazuh dashboard

The package connects the Wazuh dashboard to the Wazuh indexer and to the Wazuh server API on this host, and stores their passwords in its keystore. There is nothing to change in `/etc/wazuh-dashboard/opensearch_dashboards.yml`, except:

- `server.host`: This setting specifies the host of the Wazuh dashboard server. The package sets `0.0.0.0`, which accepts all the available IP addresses of the host. To restrict it, set the IP address or DNS name of the Wazuh dashboard server.
- Do not add a `password` under `wazuh_core.hosts`. The package stored the `wazuh-internal-client` password in the keystore of the Wazuh dashboard, and a value in the file takes precedence over it.

The file already holds these values, among others:

```yaml
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
wazuh_core.hosts:
  default:
    url: https://localhost
    port: 55000
    username: wazuh-internal-client
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
- Password: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `/etc/wazuh-indexer/export/credentials.env`

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, import the `/etc/wazuh-dashboard/export/ca.pem` file into the certificate manager of the browser. The `export/` directory is readable by `root` only, so copy the file first with `sudo cp /etc/wazuh-dashboard/export/ca.pem ~/wazuh-dashboard-ca.pem && sudo chown "$USER" ~/wazuh-dashboard-ca.pem`, and then bring it to the machine of the browser (for example with `scp`). Alternatively, you can configure a certificate from a trusted authority.

## Enrolling agents

Agents register with an enrollment token. Create it on this host, replacing `<MANAGER_ADDRESS>` with the address the agents use to reach the Wazuh manager. It must be one of the addresses of `remoted.pem`:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <MANAGER_ADDRESS>
```

Then install the agent with the token. For example, on a Debian-based endpoint:

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='<AGENT_NAME>' dpkg -i wazuh-agent_*.deb
```

The package does not start the agent. Start it and enable it at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

To check the enrollment, look for `Token bootstrap: enrollment succeeded` in `/var/ossec/logs/ossec.log` on the endpoint. The agent then shows as `active` in the Wazuh server API (`GET /agents`) and in the Wazuh dashboard.

See the [Wazuh agent installation](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/getting-started/installation.md#agent) for the other platforms and options.

## Checking the accounts

Once the three components are installed and running, check the accounts and store the passwords in a safe place.

1. Check that the accounts work. Each package has its own CA, published in its `export/` directory, and `curl` verifies the certificate with the CA of the service it connects to. Only `root` can read the `export/` directory of the Wazuh manager, so run `curl` with `sudo`. When `curl` asks for a password, enter the value of the key given for each account.

    ```bash
    # Wazuh indexer: admin (WAZUH_INDEXER_ADMIN_PASSWORD), kibanaserver (WAZUH_INDEXER_KIBANASERVER_PASSWORD) and wazuh-manager (WAZUH_INDEXER_MANAGER_PASSWORD)
    sudo curl --cacert /etc/wazuh-indexer/export/ca.pem -u admin https://127.0.0.1:9200/_cluster/health?pretty
    sudo curl --cacert /etc/wazuh-indexer/export/ca.pem -u kibanaserver https://127.0.0.1:9200/_plugins/_security/authinfo?pretty
    sudo curl --cacert /etc/wazuh-indexer/export/ca.pem -u wazuh-manager https://127.0.0.1:9200/_plugins/_security/authinfo?pretty
    # Wazuh server API: wazuh (WAZUH_MANAGER_API_PASSWORD) and wazuh-internal-client (WAZUH_MANAGER_WUI_PASSWORD)
    sudo curl --cacert /etc/wazuh-manager/export/ca.pem -u wazuh -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"
    sudo curl --cacert /etc/wazuh-manager/export/ca.pem -u wazuh-internal-client -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"
    ```

    Log in to the Wazuh dashboard, and check that it reaches the Wazuh server API: the dashboard shows an error of the Wazuh server API connection otherwise.

2. Copy the passwords to your password manager. They are in `/etc/wazuh-indexer/export/credentials.env` and `/etc/wazuh-manager/export/credentials.env`.

Each package keeps its CA and the private key of that CA in its `ca/` directory: `/etc/wazuh-indexer/ca`, `/etc/wazuh-manager/ca` and `/etc/wazuh-dashboard/ca`. Back them up in a safe place: you need them to renew certificates later. See [Security](../security.md). To change a password, see [Change the passwords of a step-by-step deployment](../security.md#change-the-passwords-of-a-step-by-step-deployment).

## Troubleshooting

- A service does not start: check its journal, for example `journalctl -u wazuh-dashboard -e`. When a password is missing, the service refuses to start and names the key, for example `MISSING WAZUH_MANAGER_WUI_PASSWORD`. Check that the component that owns it, the Wazuh indexer or the Wazuh manager, was installed before, and that its `export/credentials.env` file was not removed. Then start the service again.
- The Wazuh manager logs `Unauthorized - Check indexer credentials`: run `indexer-security-init.sh`, as described in [Cluster initialization](#cluster-initialization), and restart the Wazuh manager.
- The Wazuh dashboard shows an error of the Wazuh server API connection: check that there is no `password` under `wazuh_core.hosts` in `opensearch_dashboards.yml`.
