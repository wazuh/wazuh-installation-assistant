# Offline download packages

## Prerequisites

There are some packages that need to be installed in the target system where the offline installation will be done. These are:

- `curl`
- `tar`
- `openssl`
- `gnupg` (`gnupg2` on RPM-based systems)
- `setcap`

Each Wazuh component also needs other packages. See the required dependencies in [Offline install using the installation assistant](../offline-installation-assistant-deployments/offline-assisted-install.md).

---

## Download the packages

### 1. Download the Wazuh Installation Assistant

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh
chmod 744 wazuh-install-5.0.0.sh
```

To use `pre-release` packages instead, use the following commands:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-install-5.0.0-<STAGE>.sh
chmod 744 wazuh-install-5.0.0-<STAGE>.sh
```

### 2. Download packages by architecture using the installation assistant

#### For RPM

##### x86_64

```bash
./wazuh-install-5.0.0.sh -dw rpm -da x86_64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.0.0-<STAGE>.sh -dw rpm -da x86_64 -d pre-release
```

##### aarch64

```bash
./wazuh-install-5.0.0.sh -dw rpm -da aarch64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.0.0-<STAGE>.sh -dw rpm -da aarch64 -d pre-release
```

#### For DEB

##### amd64

```bash
./wazuh-install-5.0.0.sh -dw deb -da amd64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.0.0-<STAGE>.sh -dw deb -da amd64 -d pre-release
```

##### arm64

```bash
./wazuh-install-5.0.0.sh -dw deb -da arm64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.0.0-<STAGE>.sh -dw deb -da arm64 -d pre-release
```

### 3. Download the certificates configuration file

> **Note:** Steps 3 to 5 are only needed for a distributed deployment. In an all-in-one deployment, the Wazuh packages create the root CA, the certificates and the passwords during the installation, so `config.yml` and `wazuh-install-files.tar` are not used. Go to [step 6](#6-copy-the-necessary-files-to-the-final-host).

```bash
curl -fsS -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.0.0.yml
```

To download `pre-release` configuration file instead, use:

```bash
curl -fsS -o config.yml https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/config-5.0.0-<STAGE>.yml
```

### 4. Edit `config.yml` to prepare the certificates creation

Replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all the Wazuh server, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

The Wazuh manager nodes need an address that the agents can reach. Do not use `127.0.0.1` for them: the agent listener certificate would only name loopback addresses, no agent could verify it, and the next step fails.

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../ref/configuration/configuration-files.md#other-configyml-examples).

### 5. Create the certificates

Run the following command in order to create the certificates using the installation assistant script.

```bash
./wazuh-install-5.0.0.sh -g
```

If agents will connect to a Wazuh manager through a different address, such as a public IP, a NAT address, or a load balancer, add it with `-as|--agent-san <address>`. See [Name the address agents dial](../../ref/getting-started/usage.md#name-the-address-agents-dial).

```bash
./wazuh-install-5.0.0.sh -g -as <address>
```

### 6. Copy the necessary files to the final host

Copy the packages, the installation assistant and, in a distributed deployment, the certificates to the final host where the offline installation will be carried out.
You can use `scp` to complete this task.

- `wazuh-install-5.0.0.sh`
- `wazuh-offline.tar.gz`
- `wazuh-install-files.tar` (only for a distributed deployment)

---

## Next steps

Now, you can continue with the installation of the Wazuh components:

- Installing using the [installation assistant](../offline-installation-assistant-deployments/offline-assisted-install.md).
- Installing [step-by-step](../offline-step-by-step-deployments/offline-step-by-step.md).
