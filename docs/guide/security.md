# Security

This section describes the security mechanisms used by the Wazuh installation tools and the recommended practices to keep your deployment secure.

## SSL/TLS certificates

All communication between Wazuh components (Indexer, Manager, and Dashboard) is encrypted using SSL/TLS certificates. Certificates are generated with the `wazuh-certs-tool-5.0.0.sh` script based on the node information in `config.yml`.

For DNS-based or mixed address configurations in `config.yml`, see [Other `config.yml` examples](../ref/configuration/configuration-files.md#other-configyml-examples).

The certificate bundle (`wazuh-install-files.tar`) is created once and then distributed to each node. It contains:

- A root CA certificate (`root-ca.pem` and `root-ca.key`)
- An admin certificate (`admin.pem` and `admin-key.pem`) for cluster security initialization
- Individual node certificates for each Wazuh Indexer, Manager, and Dashboard node
- For each Wazuh Manager node, the certificate of the agent listener (`<node>-remoted.pem` and `<node>-remoted-key.pem`), deployed as `remoted.pem` and `remoted-key.pem`

The Wazuh manager does not generate certificates: it will not start until `remoted.pem` and `remoted-key.pem` are present in `/var/wazuh-manager/etc/certs`. That pair is served by `wazuh-manager-remoted` on port 1517 and reused by `wazuh-manager-authd` on port 1515, so agents can verify the manager they dial by pinning `root-ca.pem`. `<node>-remoted.pem` is a chain: the leaf followed by the root CA, and its `notBefore` is backdated one day so an agent whose clock lags does not reject a freshly issued certificate. Unlike the rest of the trust material, which is read as `root`, the listener pair is opened after dropping privileges and is therefore owned by `wazuh-manager:wazuh-manager` with mode `640`.

Certificate files are stored in the following paths on each node:

| Component | Certificate path |
| ----------- | ------------------ |
| Wazuh Indexer | `/etc/wazuh-indexer/certs/` |
| Wazuh Dashboard | `/etc/wazuh-dashboard/certs/` |
| Wazuh Manager | `/var/wazuh-manager/etc/certs/` |

## Password management

The installation assistant sets default passwords for internal Wazuh users during installation. It is strongly recommended to change these passwords after installation using the `wazuh-passwords-tool-5.0.0.sh` script.

To change a specific user's password:

```bash
bash wazuh-passwords-tool-5.0.0.sh -u <USER> -p <NEW_PASSWORD>
```

To change the Wazuh API password:

```bash
bash wazuh-passwords-tool-5.0.0.sh -A -u <API_USER> -p <NEW_PASSWORD> -au <ADMIN_USER> -ap <ADMIN_PASSWORD>
```

Passwords for internal users are stored hashed in `/etc/wazuh-indexer/opensearch-security/internal_users.yml`.

## Least privilege

- Run installation scripts with `sudo` or as root only when required.
- Restrict read access to certificate files and the `wazuh-install-files.tar` archive.
- After installation, remove or secure the `wazuh-install-files.tar` file as it contains private keys.

## Recommendations

- Change all default passwords immediately after installation.
- Keep all Wazuh components updated to receive security patches.
- Store certificates and backups in secure, access-controlled locations.
- Rotate certificates and passwords periodically.
