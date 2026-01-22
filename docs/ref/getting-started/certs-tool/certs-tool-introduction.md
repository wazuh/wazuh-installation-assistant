# Certs Tool introduction

The `wazuh-certs-tool.sh` script simplifies certificate generation for Wazuh central components and creates all the certificates required for installation. You need to create or edit the configuration file config.yml. This file references the node details like node types and IP addresses or DNS names which are used to generate certificates for each of the nodes specified in it. A template could be downloaded from our [repository](https://packages.wazuh.com/5.0/config.yml). These certificates are created with the following additional information:

- C: US
- L: California
- O: Wazuh
- OU: Wazuh
- CN: Name of the node

To learn how to install the certs tool, see the [Certs Tool Installation](../../installation/certs-tool/certs-tool-installation.md) section.
For more information on how to use this tool, see the [Certs Tool Usage](../../usage/certs-tool/certs-tool-usage.md) section.