## Description

### Wazuh installation assistant

The Wazuh Installation Assistant is a tool designed to simplify the deployment of Wazuh. It guides users through the process of installing Wazuh components. With the Wazuh Installation Assistant, you can perform AIO (All In One) installations where you download and configure all components on the same machine, or distributed installations where you can install only the specified component.

The script is written in Bash to facilitate its implementation on Linux systems (x86_64/AMD64 or AARCH64/ARM64). It includes the Wazuh Password Tool and the Wazuh Certs Tool, which are used in the all-in-one installation process.


### Wazuh password tool

Wazuh central components use different types of users for their operation, such as Wazuh indexer users, Wazuh manager users, the `wazuh-passwords-tool-5.0.0-1.sh` script is used to manage passwords related to Wazuh internal users. This tool allows users to create, update, and manage passwords securely for the different Wazuh internal users.

The script is written in bash and creates secure passwords for different users, updates these passwords in the different components, and also updates the `internal_users.yml` file of Wazuh indexer using Wazuh indexer's own hashing tool to obfuscate the passwords.


### Wazuh certs tool
The `wazuh-certs-tool-5.0.0-1.sh` script simplifies certificate generation for Wazuh central components and creates all the certificates required for installation.You need to create or edit the configuration file config-5.0.0-1.yml. This file references the node details like node types and IP addresses or DNS names which are used to generate certificates for each of the nodes specified in it.

The script is written in bash and creates all certificates needed for deploy Wazuh central components. Use openssl to create 2048-bit and sha256 certificates.
