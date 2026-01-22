# Passwords Tool Introduction

The `wazuh-passwords-tool.sh` script is used to manage passwords related to Wazuh internal users. This tool allows users to create, update, and manage passwords securely for the different Wazuh internal users.

Among the Wazuh indexer users, it is worth mentioning the following:

- `admin`: is the default administrator account of the Wazuh indexer. It's used to log in to the Wazuh dashboard and for communications between Filebeat and the Wazuh indexer. If you change the admin password, you must update it in Filebeat and the Wazuh server.

- `kibanaserver`: is used for communications between the Wazuh dashboard and the Wazuh indexer. If you change the kibanaserver password, you must update it in the Wazuh dashboard.

On the other hand, the Wazuh server API has two default users:

- `wazuh`: is the default Wazuh server API administrator user.
- `wazuh-wui`: is an admin user used for communications between Wazuh dashboard and the Wazuh server API. If you change the wazuh-wui password, you must ensure it updates in the Wazuh dashboard.

> **note** By default, in all Wazuh installations, Wazuh users have default passwords, so it is highly recommended to change them to more secure ones using this tool.

To learn how to download the tool, see the [Passwords Tool Installation](../../installation/passwords-tool/passwords-tool-installation.md) section.
To see how to use this tool, see the [Passwords Tool Usage](../../usage/passwords-tool/passwords-tool-usage.md) section.
