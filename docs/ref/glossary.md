# Glossary

This glossary provides definitions for key terms, components, and concepts used throughout the Wazuh Installation Assistant repository.

---

## Core Tools

### Wazuh Installation Assistant

The main tool (`wazuh-install-<version>.sh`) that automates the deployment and configuration of Wazuh central components. It guides users through the process of installing Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard. The assistant supports both All-In-One (AIO) installations and distributed deployments, includes system requirements checking and automated configuration, and embeds the certificate functions of the Certificate Tool.

### Wazuh Certs Tool

A utility script (`wazuh-certs-tool.sh`) for generating and managing SSL/TLS certificates required for secure communication between Wazuh components. It uses OpenSSL to create 2048-bit SHA-256 certificates for each node specified in the `config.yml` file. The tool can generate root CA certificates, admin certificates, Wazuh Indexer certificates, Wazuh Manager certificates, and Wazuh Dashboard certificates.

### Wazuh Password Tool

A script (`wazuh-passwords-tool.sh`) for securely generating, managing, and resetting passwords for Wazuh internal users. It can create random secure passwords, update passwords in the different Wazuh components, modify Wazuh API passwords, and update the `internal_users.yml` file using Wazuh Indexer's hashing tool to obfuscate passwords.

### Builder Script

The `builder.sh` script used to build the installation assistant and tools. It combines multiple source files into single, distributable shell scripts (`wazuh-install.sh`, `wazuh-certs-tool.sh`, and `wazuh-passwords-tool.sh`). Accepts options to build the installer (`-i`), certificate tool (`-c`), or password tool (`-p`). The version suffix seen on the published files (for example `wazuh-install-5.0.0.sh`) is added later, when `5_builder_installation_assistant.yml` publishes them.

---

## Wazuh Components

### Wazuh Indexer

The search and analytics engine for Wazuh, responsible for indexing and storing security events and alerts. It is based on OpenSearch and runs on ports 9200 (REST API) and 9300 (cluster communication). Requires certificates for secure communication and forms clusters with multiple nodes for high availability and scalability.

### Wazuh Manager

Also referred to as **Wazuh Manager**, this is the core component that analyzes data received from agents, triggers alerts, and manages agent communication. It uses port 1517 for agent communication over HTTPS, 1515 for agent enrollment, 1516 for cluster communication between Wazuh manager nodes, and 55000 for the API. Port 1514 is the legacy agent channel. It is optional and disabled by default. Can be deployed in cluster mode with master and worker nodes for load balancing and redundancy.

### Wazuh Dashboard

The web-based user interface for visualizing and analyzing Wazuh data. Built on OpenSearch Dashboards, it connects to the Wazuh Indexer to retrieve data and to the Wazuh Manager API for management operations. Runs on port 443 (HTTPS) by default and requires SSL/TLS certificates.

---

## Installation Types

### All-In-One (AIO)

An installation type where all Wazuh central components (Indexer, Manager, and Dashboard) are installed and configured on a single machine. Best suited for testing, development, or small deployments. Can be deployed using the `-a` option with the installation assistant.

### Distributed Deployment

An installation architecture where Wazuh components are installed on separate machines or nodes. Allows for better resource distribution, scalability, and high availability. Requires proper network configuration and certificate management across nodes.

### Offline Installation

An installation method for environments without internet access. Requires downloading a compressed tar file (`wazuh-offline.tar.gz`) containing all necessary packages and dependencies beforehand. The offline package includes Wazuh components for the target operating system (DEB or RPM packages).

---

## Cluster Concepts

### Cluster

A group of nodes (Wazuh Indexers or Wazuh Managers) working together to provide high availability, load balancing, and fault tolerance. Requires proper network connectivity and shared configuration between nodes.

### Node

A single machine or instance in a Wazuh deployment. Each node has a unique name and is identified in the `config.yml` file. Nodes can be of different types depending on their role.

### Master Node

In a Wazuh Manager cluster, the master node is the primary node that coordinates cluster operations and synchronizes agent data and configuration across worker nodes. Only one master node is active at a time in a cluster.

### Worker Node

In a Wazuh Manager cluster, worker nodes receive synchronized information from the master node and can process agent connections and events. Multiple worker nodes can exist in a cluster for load distribution.

### Cluster Key

A shared secret key used to authenticate and secure communication between nodes in a Wazuh Manager cluster. Generated during installation and must be identical across all cluster members.

---

## Configuration

### config.yml

The main configuration file that defines the deployment architecture, including node names, IP addresses or DNS names, and node types for each component. Required for generating certificates and for distributed deployments. Should be customized before installation.

For supported `config.yml` formats using `ip`, `dns`, DNS lists, or mixed values, see [Other `config.yml` examples](configuration/configuration-files.md#other-configyml-examples).

### internal_users.yml

A configuration file in Wazuh Indexer that defines internal users and their hashed passwords. Modified by the Wazuh Password Tool when updating user credentials.

---

## Security Components

### SSL/TLS Certificates

Digital certificates used to establish encrypted communication between Wazuh components. Required for securing connections between the Dashboard, Indexer, and Manager. Generated using the Wazuh Certs Tool.

### Root CA (Certificate Authority)

The top-level certificate authority used to sign all other certificates in the Wazuh deployment. The root CA consists of a certificate (`root-ca.pem`) and private key (`root-ca.key`). All component certificates are signed by this CA.

### Admin Certificates

Special certificates with elevated privileges used for performing administrative operations on the Wazuh Indexer, such as initializing the security configuration. Consists of `admin.pem` and `admin-key.pem`.

### Node Certificates

Individual SSL/TLS certificates generated for each node in the deployment. Each node has its own certificate and private key file for secure communication.

---

## Package Management

### Dependencies

Software packages required for Wazuh components to function properly. The installation assistant automatically checks for and installs necessary dependencies, which vary by component and operating system (YUM/APT).

### tar File

An archive file (`wazuh-install-files.tar`) containing the generated certificates, `root-ca.pem` (never `root-ca.key`), the passwords (`credentials.env`), the `config.yml` it was generated from and, when there is more than one Wazuh manager node, the cluster key. Created by `-g` and required for distributed deployments.

### Repository

The package repository hosted at `packages.wazuh.com` containing Wazuh component packages, GPG keys, and installation scripts for various versions and distributions.

---

## System Components

### System Type

The package management system used by the operating system, either `yum` (for Red Hat-based distributions like CentOS, RHEL, Amazon Linux) or `apt-get` (for Debian-based distributions like Ubuntu, Debian).

### Logfile

The installation log file located at `/var/log/wazuh-install.log` that records all operations performed by the installation assistant, useful for troubleshooting and auditing.

---

## Wazuh Users

### Internal Users

Built-in user accounts used by Wazuh components for internal operations and API access. The Wazuh Password Tool manages the Wazuh indexer users `admin`, `kibanaserver` and `wazuh-manager`, and the Wazuh server API users `wazuh` and `wazuh-internal-client`.

### Wazuh API User

User accounts for accessing the Wazuh Manager REST API, used for management and configuration operations. API user passwords can be changed using the Wazuh Password Tool with `-u wazuh` or `-u wazuh-internal-client`, or with `-a` together with the other users.

---

## Installation Phases

### System Requirements Check

The initial validation phase that verifies the system meets minimum requirements, including memory, CPU cores, supported operating system, required ports availability, and necessary permissions.

### Certificate Generation

The process of creating SSL/TLS certificates for all nodes using the Wazuh Certs Tool. Performed with the `-g` option for a distributed installation. In an AIO installation the packages create their own CA and certificates.

### Password Generation

The process of creating secure random passwords for Wazuh internal users. Performed with the `-g` option for a distributed installation. In an AIO installation the packages generate them.

### Component Installation

The process of downloading (or using offline packages), installing, and configuring Wazuh components on target nodes.

### Cluster Initialization

The process of starting and configuring the Wazuh Indexer cluster security settings using the `/usr/share/wazuh-indexer/bin/indexer-security-init.sh` script of the Wazuh indexer package with admin certificates. Required after all Indexer nodes are installed.

---

## Common Options and Flags

### --wazuh-indexer <NODE_NAME>

Command-line option to install only the Wazuh Indexer component on the current machine, using the node name specified in `config.yml`.

### --wazuh-dashboard <NODE_NAME>

Command-line option to install only the Wazuh Dashboard component on the current machine, using the node name specified in `config.yml`.

### --wazuh-manager <NODE_NAME>

Command-line option to install only the Wazuh Manager (server) component on the current machine, using the node name specified in `config.yml`.

### -a, --all-in-one

Option to install all Wazuh central components (Indexer, Manager, and Dashboard) on the local machine in All-In-One configuration.

### -g, --generate-config-files

Option to generate certificates and passwords for all nodes defined in `config.yml`. Creates the `wazuh-install-files.tar` archive. The root CA, its private key and the passwords are kept in the `wazuh-ca` directory, so a new run reuses them. A new run also generates a new cluster key, so it is only for adding Wazuh indexer or Wazuh dashboard nodes, and it stops if `wazuh-install-files.tar` already exists.

### -u, --uninstall

Option to uninstall all Wazuh central components from the system.

### --start-cluster

Option to initialize security settings for the Wazuh Indexer cluster. Must be run after all Indexer nodes are installed. It waits up to 300 seconds for the cluster to form. If it is cancelled or fails, it does not remove the Wazuh indexer.

### --offline-installation

Option to perform installation using pre-downloaded offline packages instead of fetching from online repositories.

---

## File Paths

### /etc/wazuh-indexer/certs

Directory containing SSL/TLS certificates for the Wazuh Indexer, including the node certificate, key, root CA, and admin certificates.

### /etc/wazuh-dashboard/certs

Directory containing SSL/TLS certificates for the Wazuh Dashboard, including the node certificate, key, and the CAs of the indexer (`indexer-ca.pem`) and the manager (`manager-ca.pem`).

### /etc/wazuh-manager/certs

Directory containing SSL/TLS certificates for the Wazuh Manager (server), including the root CA, the agent listener and Server API certificates, the indexer CA (`indexer-ca.pem`), and the certificate used to connect to the indexer.

### local.env

A file in the configuration directory of each package (`/etc/wazuh-indexer/local.env`, `/etc/wazuh-manager/local.env`, `/etc/wazuh-dashboard/local.env`). It holds the values given before the package is installed, such as passwords. It only has the keys that package uses. Owned by root, mode 0600.

### export/credentials.env

A file the Wazuh indexer and the Wazuh manager packages publish after install (`/etc/wazuh-indexer/export/credentials.env`, `/etc/wazuh-manager/export/credentials.env`). It holds the passwords of the users that package owns. The `export/` directory also has the CA of the package, `ca.pem`.

### wazuh-ca

The directory where the `-g` option and the Wazuh Certs Tool keep the deployment root CA (`root-ca.pem` and `root-ca.key`). The `-g` option also keeps the passwords there, in `credentials.env`. It is next to the script, or in the directory set in the `WAZUH_CA_DIR` environment variable. Back it up.

### /etc/wazuh-manager/wazuh-manager.conf

Main configuration file for the Wazuh Manager, containing settings for cluster configuration, agent communication, and log analysis.
