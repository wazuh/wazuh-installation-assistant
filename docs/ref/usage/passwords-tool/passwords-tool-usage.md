# Passwords Tool usage

## Options

The `wazuh-passwords-tool.sh` script provides the following options for managing Wazuh internal user passwords:

| Options | Purpose |
|---------|---------|
| `-A\|--api` | Change the Wazuh server API password given the current password. Requires `-u\|--user <USER>`, `-p\|--password <PASSWORD>`, `-au\|--admin-user <ADMIN_USER>`, and `-ap\|--admin-password <ADMIN_PASSWORD>`. |
| `-au\|--admin-user <ADMIN_USER>` | Admin user for the Wazuh server API. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-ap\|--admin-password <ADMIN_PASSWORD>` | Password for the Wazuh server API admin user. Required for changing the Wazuh server API passwords. Requires `-A\|--api`. |
| `-u\|--user <USER>` | Indicates the name of the user whose password will be changed. If no password is specified, it will generate a random one. |
| `-p\|--password <PASSWORD>` | Indicates the new password. Must be used with option `-u\|--user <USER>`. |
| `-v\|--verbose` | Shows the complete script execution output. |
| `-h\|--help` | Shows help. |

The passwords tool changes passwords by specifying the user whose password you want to change and the new password. The password must have a length between 8 and 64 characters and contain at least one upper case letter, one lower case letter, a number and one of the following symbols: `.*+?-` If no password is specified, the tool will generate a random one.

There are two types of users whose passwords can be changed with this tool: Wazuh indexer users and Wazuh server API users. For the latter, it is necessary to provide an administrator user and their password to authenticate the password change request.

## Change Wazuh indexer password

Wazuh Indexer users are defined in `/etc/wazuh-indexer/opensearch-security/internal_users.yml`. To change the password of a Wazuh indexer user, use the following syntax:

```bash
sudo ./wazuh-passwords-tool.sh -u <USER> [-p <PASSWORD>]
```
Where `<USER>` is the name of the user whose password you want to change and `<PASSWORD>` is the new password. If `<PASSWORD>` is not specified, the tool will generate a random password.

For example, to change the password of the `admin` user to `Secr3tP4ssw*rd`, run the following command:

```bash
sudo ./wazuh-passwords-tool.sh -u admin -p Secr3tP4ssw*rd
```

El output del comando será similar al siguiente:

```bash
INFO: Generating password hash
WARNING: Password changed. Remember to update the password in the Wazuh dashboard node if necessary, and restart the services.
```

## Change Wazuh server API password

To change the password of a Wazuh server API user, use the following syntax:

```bash
sudo ./wazuh-passwords-tool.sh -A -au <ADMIN_USER> -ap <ADMIN_PASSWORD> -u <USER> [-p <PASSWORD>] 
```

Where `<ADMIN_USER>` is the Wazuh server API administrator user, `<ADMIN_PASSWORD>` is the administrator user's password, `<USER>` is the name of the user whose password you want to change, and `<PASSWORD>` is the new password. If `<PASSWORD>` is not specified, the tool will generate a random password.
For example, to change the password of the `wazuh` user to `N3wS3cr3tP4ss*`, run the following command:

```bash
sudo ./wazuh-passwords-tool.sh -A -au wazuh -ap wazuh -u wazuh -p N3wS3cr3tP4ss*
```

The command output will be similar to the following:

```bash
INFO: The password for Wazuh API user wazuh is N3wS3cr3tP4ss*
```
