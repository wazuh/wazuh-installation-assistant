# Offline download packages

## Prerequisites

There are some packages that need to be installed in the target system where the offline installation will be done. These are:

- `curl`
- `tar`
- `setcap`
- `gnupg` (for some Debian-based systems)

---

## Download the packages

### 1. Download the Wazuh Installation Assistant

```bash
curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.9.9.sh
chmod 744 wazuh-install-5.9.9.sh
```

To use `pre-release` packages instead, use the following commands:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-install-5.9.9-<STAGE>.sh
chmod 744 wazuh-install-5.9.9-<STAGE>.sh
```

### 2. Download packages by architecture using the installation assistant

#### For RPM

##### x86_64

```bash
./wazuh-install-5.9.9.sh -dw rpm -da x86_64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.9.9-<STAGE>.sh -dw rpm -da x86_64 -d pre-release
```

##### aarch64

```bash
./wazuh-install-5.9.9.sh -dw rpm -da aarch64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.9.9-<STAGE>.sh -dw rpm -da aarch64 -d pre-release
```

#### For DEB

##### amd64

```bash
./wazuh-install-5.9.9.sh -dw deb -da amd64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.9.9-<STAGE>.sh -dw deb -da amd64 -d pre-release`
```

##### arm64

```bash
./wazuh-install-5.9.9.sh -dw deb -da arm64
```

To install `pre-release` packages instead, use:

```bash
./wazuh-install-5.9.9-<STAGE>.sh -dw deb -da arm64 -d pre-release`
```

### 3. Download the certificates configuration file

```bash
curl -s -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.9.9.yml
```

To download `pre-release` configuration file instead, use:

```bash
curl -s -o config.yml https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/config-5.9.9-<STAGE>.yml
```

### 4. Edit `config.yml` to prepare the certificates creation

- If you are performning an all-in-one deployment, replace the `"<indexer-node-ip>"`, `"<wazuh-manager-ip>"`, and `"<dashboard-node-ip>"` with `127.0.0.1`.
- If you are performing a distributed deployment, replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all the Wazuh server, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../ref/configuration/configuration-files.md#other-configyml-examples).

### 5. Create the certificates

Run the following command in order to create the certificates using the installation assistant script.

```bash
./wazuh-install-5.9.9.sh -g
```

### 6. Copy the necessary files to the final host

Copy the certificates, the packages and the installation assistant to the final host where the offline installation will be carried out.
You can use `scp` to complete this task.

- `wazuh-install-5.9.9.sh`
- `wazuh-offline.tar.gz`
- `wazuh-install-files.tar`

---

## Next steps

Now, you can continue with the installation of the Wazuh components:

- Installing using the [installation assistant](/docs/guide/offline-installation-assistant-deployments/offline-assisted-install.md).
- Installing [step-by-step](/docs/guide/offline-step-by-step-deployments/offline-step-by-step.md).
