# Offline install using the installation assistant

## Single-node offline installation

Install and configure the single-node server on a 64-bit (**x86_64/AMD64** or **AARCH64/ARM64**) architecture with the aid of the Wazuh assisted installation method.

### Prerequisites

> **Note:** You need root user privileges to run all the commands described below. Please make sure that a copy of the `wazuh-install-files.tar` and `wazuh-offline.tar.gz` files, created during the initial configuration step, is placed in your working directory.

#### Required dependencies

The following dependencies must be installed on the Wazuh single node:

**RPM-based systems:**

- coreutils
- libcap

**DEB-based systems:**

- coreutils
- libcap

#### Files needed

For the single-node offline installation, you need to have the following files in your working directory:

- `wazuh-install-files.tar`
- `wazuh-offline.tar.gz`
- `wazuh-install-5.0.0-1.sh`

### Installation

To perform the offline installation with the `--offline-installation` flag of Wazuh manager on a single-node using the assisted method, run:

```bash
bash wazuh-install-5.0.0-1.sh --offline-installation -a
```

Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful:

```shell
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh_dashboard_ip>:443
   User: admin
   Password: admin

INFO: Installation finished.
```

### Accessing the Wazuh Dashboard

You now have installed and configured Wazuh.

Access the Wazuh web interface with your admin user credentials. This is the default administrator account for the Wazuh indexer and it allows you to access the Wazuh dashboard.

- **URL:** `https://<WAZUH_DASHBOARD_IP_ADDRESS>:443`
- **Username:** `admin`
- **Password:** `admin`

---

## Multi-node offline installation

### Installing the Wazuh indexer

Install and configure the Wazuh indexer nodes on a 64-bit (**x86_64/AMD64** or **AARCH64/ARM64**) architecture.

#### Required dependencies

The following dependencies must be installed on the Wazuh indexer nodes:

**RPM-based systems:**

- coreutils

**DEB-based systems:**

- coreutils

#### Installation Steps

1. Run the multi-node assisted method with the `--offline-installation` flag to perform an offline installation. Use the option `--wazuh-indexer` and the node name to install and configure the Wazuh indexer. The node name must be the same one used in `config.yml` for the initial configuration, for example, `indexer`.

```bash
    bash wazuh-install-5.0.0-1.sh --offline-installation --wazuh-indexer indexer
```

    Repeat this step for every Wazuh indexer node in your cluster. Then proceed with initializing your multi-node cluster in the next step.

2. Run the Wazuh assisted installation option `--start-cluster` on any Wazuh indexer node to load the new certificates information and start the cluster.

```bash
    bash wazuh-install-5.0.0-1.sh --offline-installation --start-cluster
```

    > **Note:** You only have to initialize the cluster once. There is no need to run this command on every node.

### Testing the cluster installation

1. Run the following command to confirm that the installation is successful. Replace `<WAZUH_INDEXER_IP_ADDRESS>` with the configured Wazuh indexer IP address:

```bash
    curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200
```

    **Output example:**

```json
    {
    "name" : "indexer",
    "cluster_name" : "wazuh-cluster",
    "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
    "version" : {
        "distribution" : "opensearch",
        "number" : "3.5.0",
        "build_type" : "deb",
        "build_hash" : "0688bb0c0d4d2384772311ab88edcd2a18a67774",
        "build_date" : "2026-04-09T01:00:23.398850475Z",
        "build_snapshot" : false,
        "lucene_version" : "10.3.2",
        "minimum_wire_compatibility_version" : "2.19.0",
        "minimum_index_compatibility_version" : "2.0.0"
    },
    "tagline" : "The OpenSearch Project: https://opensearch.org/"
    }
```

2. Verify that the cluster is running correctly. Replace `<WAZUH_INDEXER_IP_ADDRESS>` in the following command, then execute it:

```bash
    curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
```

### Installing the Wazuh manager

#### Required dependencies

**RPM-based systems (with yum package manager):**

- libcap

**DEB-based systems:**

- libcap

#### Installation Steps

Run the assisted method with `--offline-installation` to perform an offline installation. Use the option `--wazuh-manager` followed by the node name to install the Wazuh manager. The node name must be the same one used in `config.yml` for the initial configuration, for example, `manager`.

```bash
bash wazuh-install-5.0.0-1.sh --offline-installation --wazuh-manager manager
```

Your Wazuh manager is now successfully installed. Repeat this step on every Wazuh manager node.

### Installing the Wazuh dashboard

#### Required dependencies

The following dependencies must be installed on the Wazuh dashboard node:

**RPM-based systems:**

- libcap

**DEB-based systems:**

- libcap

#### Installation Steps

1. Run the assisted method with `--offline-installation` to perform an offline installation. Use the option `--wazuh-dashboard` and the node name to install and configure the Wazuh dashboard. The node name must be the same one used in `config.yml` for the initial configuration, for example, `dashboard`.

```bash
    bash wazuh-install-5.0.0-1.sh --offline-installation --wazuh-dashboard dashboard
```

The TCP port for the Wazuh web user interface (dashboard) is 443.

#### Installation Summary

Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful:

```shell
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh_dashboard_ip>:443
   User: admin
   Password: admin

INFO: Installation finished.
```

### Accessing the Wazuh Dashboard

You now have installed and configured Wazuh.

Access the Wazuh web interface with your admin user credentials. This is the default administrator account for the Wazuh indexer and it allows you to access the Wazuh dashboard.

- **URL:** `https://<WAZUH_DASHBOARD_IP_ADDRESS>`
- **Username:** `admin`
- **Password:** `admin`

#### Certificate Notice

When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. An exception can be added in the advanced options of the web browser. For increased security, the `root-ca.pem` file previously generated can be imported to the certificate manager of the browser instead. Alternatively, a certificate from a trusted authority can be configured.
