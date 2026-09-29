# Security

This section describes the security mechanisms used by the Wazuh installation tools and the recommended practices to keep your deployment secure.

## SSL/TLS certificates

All communication between Wazuh components (Indexer, Manager, and Dashboard) is encrypted using SSL/TLS certificates. Certificates are generated with the `wazuh-certs-tool-5.0.0.sh` script based on the node information in `config.yml`.

For DNS-based or mixed address configurations in `config.yml`, see [Other `config.yml` examples](../ref/configuration/configuration-files.md#other-configyml-examples).

The installation bundle (`wazuh-install-files.tar`) is created once with `wazuh-install-5.0.0.sh --generate-config-files` on the first Wazuh indexer node and then distributed to each node. It contains:

- The root CA certificate (`root-ca.pem`)
- The passwords of the Wazuh users (`credentials.env`), which each node places in `/etc/wazuh/credentials.env` before its package is installed
- An admin certificate (`admin.pem` and `admin-key.pem`) for cluster security initialization
- Individual node certificates for each Wazuh Indexer, Manager, and Dashboard node
- For each Wazuh Manager node, the certificate of the agent listener (`<node>-remoted.pem` and `<node>-remoted-key.pem`), deployed as `remoted.pem` and `remoted-key.pem`

The Wazuh manager does not generate certificates: it will not start until `remoted.pem` and `remoted-key.pem` are present in `/var/wazuh-manager/etc/certs`. That pair is served by `wazuh-manager-remoted` on port 1517 and reused by `wazuh-manager-authd` on port 1515, so agents can verify the manager they dial by pinning `root-ca.pem`. `<node>-remoted.pem` is a chain: the leaf followed by the root CA, and its `notBefore` is backdated one day so an agent whose clock lags does not reject a freshly issued certificate. Unlike the rest of the trust material, which is read as `root`, the listener pair is opened after dropping privileges and is therefore owned by `wazuh-manager:wazuh-manager` with mode `640`.

The root CA private key (`root-ca.key`) is not in the bundle: it stays in `/etc/wazuh/ca` of the node where the bundle was generated. Anyone holding it can issue a certificate with `CN=admin`, which the Wazuh indexer accepts as its superuser without a password, and a certificate issued that way cannot be revoked. Keeping it on one node, instead of on every node, limits that exposure to a single host. Back up `/etc/wazuh/ca` of that node in a safe place: the key is only needed to add nodes or renew certificates with `wazuh-certs-tool-5.0.0.sh`.

The passwords in the bundle are the ones generated with it. After a password is changed with `wazuh-passwords-tool-5.0.0.sh`, the bundle no longer matches the deployment: a node installed or reinstalled from it gets the previous password and cannot connect. Before adding or reinstalling a node, update `credentials.env` inside the bundle with the current passwords, or install the node and then write the current passwords into its keystores as described in [Change all default passwords](../ref/getting-started/usage.md#change-all-default-passwords). Keep in mind what removing a component with `-u|--uninstall` does to the credentials of that node: the package takes its own keys out of `/etc/wazuh/credentials.env`, and when it is the last Wazuh component of the node it also deletes `root-ca.pem` and `root-ca.key` from `/etc/wazuh/ca`. On the node where the bundle was generated, that is the only copy of the root CA private key, so back up `/etc/wazuh/ca` before uninstalling there.

Certificate files are stored in the following paths on each node:

| Component | Certificate path |
| ----------- | ------------------ |
| Wazuh Indexer | `/etc/wazuh-indexer/certs/` |
| Wazuh Dashboard | `/etc/wazuh-dashboard/certs/` |
| Wazuh Manager | `/var/wazuh-manager/etc/certs/` |

## Password management

There are no default passwords. The Wazuh packages generate random passwords for the internal Wazuh users when they are installed, or use the ones in `wazuh-install-files.tar` in a distributed deployment, and publish them in `/etc/wazuh/credentials.env` (mode `0600`). Once you have stored them in a safe place, remove that file from every node: the Wazuh components do not read it after the installation.

To change all passwords at once, use the `--change-all` option. See the [Change all default passwords](../ref/getting-started/usage.md#change-all-default-passwords) section for details.

```bash
bash wazuh-passwords-tool-5.0.0.sh --change-all
```

To change a specific user's password, reading the new one from the standard input so it never shows up in the process list:

```bash
bash wazuh-passwords-tool-5.0.0.sh -u <USER> -p
```

`<USER>` is a Wazuh indexer user (`admin`, `kibanaserver`, `wazuh-manager`) or a Wazuh API user (`wazuh`, `wazuh-wui`). The Wazuh API passwords are changed with `rbac_control`, so no admin credentials are needed. Without `-p`, a random password is generated.

The tool never prints a password. Generated passwords are saved in `/etc/wazuh/credentials.env` (mode `0600`), the same file the Wazuh packages use.

Passwords for internal users are stored hashed in `/etc/wazuh-indexer/opensearch-security/internal_users.yml`.

## Least privilege

- Run installation scripts with `sudo` or as root only when required.
- Restrict read access to certificate files and the `wazuh-install-files.tar` archive.
- After installation, remove the `wazuh-install-files.tar` file from every node, as it contains private keys and the passwords of the Wazuh users.
- After storing the passwords in a safe place, remove `/etc/wazuh/credentials.env` from every node.

## Recommendations

- Keep the root CA private key only on the node where it was generated, and back it up.
- Keep all Wazuh components updated to receive security patches.
- Store certificates and backups in secure, access-controlled locations.
- Rotate certificates and passwords periodically.
