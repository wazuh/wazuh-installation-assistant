# Glossary

This glossary provides definitions for key terms, components, and concepts used throughout the Wazuh Installation Assistant repository.

---

## Core Tools

### Wazuh Installation Assistant

The main tool (`wazuh-install-5.0.0-1.sh`) that automates the deployment and configuration of Wazuh central components. It guides users through the process of installing Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard. The assistant supports both All-In-One (AIO) installations and distributed deployments, includes system requirements checking, automated configuration, and embeds both the Certificate Tool and Password Tool for complete setup automation.

### Wazuh Certs Tool

A utility script (`wazuh-certs-tool-5.0.0-1.sh`) for generating and managing SSL/TLS certificates required for secure communication between Wazuh components. It uses OpenSSL to create 2048-bit SHA-256 certificates for each node specified in the `config-5.0.0-1.yml` file. The tool can generate root CA certificates, admin certificates, Wazuh Indexer certificates, Wazuh Manager certificates, and Wazuh Dashboard certificates.

### Wazuh Password Tool

A script (`wazuh-passwords-tool-5.0.0-1.sh`) for securely generating, managing, and resetting passwords for Wazuh internal users. It can create random secure passwords, update passwords in the different Wazuh components, modify Wazuh API passwords, and update the `internal_users.yml` file using Wazuh Indexer's hashing tool to obfuscate passwords.

### Builder Script

The `builder.sh` script used to build the installation assistant and tools. It combines multiple source files into single, distributable shell scripts (`wazuh-install-5.0.0-1.sh`, `wazuh-certs-tool-5.0.0-1.sh`, and `wazuh-passwords-tool-5.0.0-1.sh`). Accepts options to build the installer (`-i`), certificate tool (`-c`), or password tool (`-p`).

---

## Wazuh Components

### Wazuh Indexer

The search and analytics engine for Wazuh, responsible for indexing and storing security events and alerts. It is based on OpenSearch and runs on ports 9200 (REST API) and 9300 (cluster communication). Requires certificates for secure communication and forms clusters with multiple nodes for high availability and scalability.

### Wazuh Manager

Also referred to as **Wazuh Manager**, this is the core component that analyzes data received from agents, triggers alerts, and manages agent communication. It runs on ports 1514, 1515, 1516 (agent communication), and 55000 (API). Can be deployed in cluster mode with master and worker nodes for load balancing and redundancy.

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

A single machine or instance in a Wazuh deployment. Each node has a unique name and is identified in the `config-5.0.0-1.yml` file. Nodes can be of different types depending on their role.

### Master Node

In a Wazuh Manager cluster, the master node is the primary node that coordinates cluster operations and synchronizes agent data and configuration across worker nodes. Only one master node is active at a time in a cluster.

### Worker Node

In a Wazuh Manager cluster, worker nodes receive synchronized information from the master node and can process agent connections and events. Multiple worker nodes can exist in a cluster for load distribution.

### Cluster Key

A shared secret key used to authenticate and secure communication between nodes in a Wazuh Manager cluster. Generated during installation and must be identical across all cluster members.

---

## Configuration

### config-5.0.0-1.yml

The main configuration file that defines the deployment architecture, including node names, IP addresses or DNS names, and node types for each component. Required for generating certificates and for distributed deployments. Should be customized before installation.

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

A compressed archive file (`wazuh-install-files.tar`) containing generated certificates, passwords, and cluster keys. Created during the certificate and password generation process and required for distributed deployments.

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

Built-in user accounts used by Wazuh components for internal operations and API access. Include users like `admin`, `kibanaserver`, `kibanaro`, and `logstash`. Passwords for these users are managed by the Wazuh Password Tool.

### Wazuh API User

User accounts for accessing the Wazuh Manager REST API, used for management and configuration operations. API user passwords can be changed using the Wazuh Password Tool with the `-A` option.

---

## Installation Phases

### System Requirements Check

The initial validation phase that verifies the system meets minimum requirements, including available disk space, memory, supported operating system, required ports availability, and necessary permissions.

### Certificate Generation

The process of creating SSL/TLS certificates for all nodes using the Wazuh Certs Tool. Performed with the `-g` option or automatically during AIO installation.

### Password Generation

The process of creating secure random passwords for Wazuh internal users. Performed with the `-g` option or automatically during AIO installation.

### Component Installation

The process of downloading (or using offline packages), installing, and configuring Wazuh components on target nodes.

### Cluster Initialization

The process of starting and configuring the Wazuh Indexer cluster security settings using the `securityadmin.sh` script with admin certificates. Required after all Indexer nodes are installed.

---

## Common Options and Flags

### --wazuh-indexer <NODE_NAME>

Command-line option to install only the Wazuh Indexer component on the current machine, using the node name specified in `config-5.0.0-1.yml`.

### --wazuh-dashboard <NODE_NAME>

Command-line option to install only the Wazuh Dashboard component on the current machine, using the node name specified in `config-5.0.0-1.yml`.

### --wazuh-server <NODE_NAME>

Command-line option to install only the Wazuh Manager (server) component on the current machine, using the node name specified in `config-5.0.0-1.yml`.

### -a, --all

Option to install all Wazuh central components (Indexer, Manager, and Dashboard) on the local machine in All-In-One configuration.

### -g, --generate

Option to generate certificates and passwords for all nodes defined in `config-5.0.0-1.yml`. Creates the `wazuh-install-files.tar` archive.

### -u, --uninstall

Option to uninstall all Wazuh central components from the system.

### --start-cluster

Option to initialize security settings for the Wazuh Indexer cluster. Must be run after all Indexer nodes are installed.

### --offline-installation

Option to perform installation using pre-downloaded offline packages instead of fetching from online repositories.

---

## File Paths

### /etc/wazuh-indexer/certs

Directory containing SSL/TLS certificates for the Wazuh Indexer, including the node certificate, key, root CA, and admin certificates.

### /etc/wazuh-dashboard/certs

Directory containing SSL/TLS certificates for the Wazuh Dashboard, including the node certificate, key, and root CA.

### /var/ossec/etc/certs

Directory containing SSL/TLS certificates for the Wazuh Manager (server), including the node certificate, key, and root CA.

### /var/ossec/etc/ossec.conf

Main configuration file for the Wazuh Manager, containing settings for cluster configuration, agent communication, and log analysis.
