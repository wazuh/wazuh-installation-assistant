# Security

This section describes the security mechanisms used by the Wazuh installation tools and the recommended practices to keep your deployment secure.

## SSL/TLS certificates

All communication between Wazuh components (Indexer, Manager, and Dashboard) is encrypted using SSL/TLS certificates. Certificates are generated with the `wazuh-certs-tool-5.0.0.sh` script based on the node information in `config.yml`.

For DNS-based or mixed address configurations in `config.yml`, see [Other `config.yml` examples](../ref/configuration/configuration-files.md#other-configyml-examples).

The installation bundle (`wazuh-install-files.tar`) is created once with `wazuh-install-5.0.0.sh --generate-config-files`, on any host, and then distributed to each node. That host keeps the root CA and its private key in `wazuh-ca/`, next to the script. It contains:

- The root CA certificate (`root-ca.pem`)
- The passwords of the Wazuh users (`credentials.env`). Before a package is installed, the node writes in the `local.env` file of that package only the passwords it uses: `WAZUH_INDEXER_ADMIN_PASSWORD`, `WAZUH_INDEXER_KIBANASERVER_PASSWORD` and `WAZUH_INDEXER_MANAGER_PASSWORD` in `/etc/wazuh-indexer/local.env`, `WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD` and `WAZUH_INDEXER_MANAGER_PASSWORD` in `/etc/wazuh-manager/local.env`, and `WAZUH_INDEXER_KIBANASERVER_PASSWORD` and `WAZUH_MANAGER_WUI_PASSWORD` in `/etc/wazuh-dashboard/local.env`. The `wazuh-ca` directory of the node where the bundle was generated keeps all of them
- An admin certificate (`admin.pem` and `admin-key.pem`) for cluster security initialization
- Individual node certificates for each Wazuh Indexer, Manager, and Dashboard node
- For each Wazuh Manager node, the certificate of the agent listener (`<node>-remoted.pem` and `<node>-remoted-key.pem`), deployed as `remoted.pem` and `remoted-key.pem`
- For each Wazuh Manager node, the certificate of the Server API (`<node>-apid.pem` and `<node>-apid-key.pem`), deployed as `apid.pem` and `apid-key.pem`

The Wazuh manager package creates its own CA and issues its certificates when it is installed without them, as in an all-in-one installation. In a distributed deployment the node receives them in the bundle instead, and the Wazuh manager does not start until `remoted.pem` and `remoted-key.pem` are present in `/etc/wazuh-manager/certs`. That pair is served by `wazuh-manager-remoted` on port 1517 and reused by `wazuh-manager-authd` on port 1515, so agents can verify the manager they dial by pinning `root-ca.pem`. `<node>-remoted.pem` is a chain: the leaf followed by the root CA, and its `notBefore` is backdated one day so an agent whose clock lags does not reject a freshly issued certificate. Unlike the rest of the trust material, which is read as `root`, the listener pair is opened after dropping privileges, so the daemons read it through the `wazuh-manager` group: it is owned by `root:wazuh-manager` with mode `640`. The Wazuh manager refuses to start when a certificate is owned by another user, such as `wazuh-manager`. The Server API pair, `apid.pem` and `apid-key.pem`, has the same profile, owner and mode, and is served by `wazuh-manager-apid` on port 55000. The Wazuh manager does not self-sign it: when the pair is missing, the Server API does not start.

The root CA private key (`root-ca.key`) is not in the bundle: it stays in the `wazuh-ca` directory of the node where the bundle was generated. This directory is next to `wazuh-install-5.0.0.sh`, or in the directory set in the `WAZUH_CA_DIR` environment variable. It also keeps the passwords (`credentials.env`), so running `--generate-config-files` again reuses the same CA and passwords to add nodes. Anyone holding the key can issue a certificate with `CN=admin`, which the Wazuh indexer accepts as its superuser without a password, and a certificate issued that way cannot be revoked. Keeping it on one node, instead of on every node, limits that exposure to a single host. Back up the `wazuh-ca` directory of that node in a safe place: the key is only needed to add nodes or renew certificates with `wazuh-certs-tool-5.0.0.sh`.

The passwords in the bundle are the ones generated with it. After a password is changed with `wazuh-passwords-tool-5.0.0.sh`, the bundle no longer matches the deployment: a node installed or reinstalled from it gets the previous password and cannot connect. Before adding or reinstalling a node, update `credentials.env` inside the bundle with the current passwords (and `credentials.env` in the `wazuh-ca` directory, so a new bundle gets them too), or install the node and then write the current passwords into its keystores as described in [Multi-node and distributed deployments](../ref/getting-started/usage.md#multi-node-and-distributed-deployments). Keep in mind what removing a component with `-u|--uninstall` does: it deletes the configuration directory of that package (`/etc/wazuh-indexer`, `/etc/wazuh-manager` or `/etc/wazuh-dashboard`), with its `local.env`, `ca/`, `certs/` and `export/`. The `wazuh-ca` directory is not removed. If the deployment no longer needs it to add nodes or renew certificates, remove it by hand.

Certificate files are stored in the following paths on each node:

| Component | Certificate path |
| ----------- | ------------------ |
| Wazuh Indexer | `/etc/wazuh-indexer/certs/` |
| Wazuh Dashboard | `/etc/wazuh-dashboard/certs/` |
| Wazuh Manager | `/etc/wazuh-manager/certs/` |

## Password management

There are no default passwords. The Wazuh packages generate random passwords for the internal Wazuh users when they are installed, or use the ones in `wazuh-install-files.tar` in a distributed deployment. The Wazuh indexer publishes the passwords of its users in `/etc/wazuh-indexer/export/credentials.env`, and the Wazuh manager publishes the passwords of the API users in `/etc/wazuh-manager/export/credentials.env`. Both files are owned by root. The values given before the install are in the `local.env` file of each package (root, mode `0600`).

To change all passwords at once, use the `--change-all` option. See the [Change all default passwords](../ref/getting-started/usage.md#change-all-default-passwords) section for details.

```bash
bash wazuh-passwords-tool-5.0.0.sh --change-all
```

To change a specific user's password, reading the new one from the standard input so it never shows up in the process list:

```bash
bash wazuh-passwords-tool-5.0.0.sh -u <USER> -p
```

`<USER>` is a Wazuh indexer user (`admin`, `kibanaserver`, `wazuh-manager`) or a Wazuh API user (`wazuh`, `wazuh-internal-client`). The Wazuh API passwords are changed with `rbac_control`, so no admin credentials are needed. Without `-p`, a random password is generated.

The tool never prints a password. A new password is saved in every credential file of the host that holds that user: the `export/credentials.env` file of the package that owns the user, the `local.env` file of each package that uses it, and the `credentials.env` file that `--generate-config-files` keeps in `wazuh-ca/` when the tool runs next to it. See [Where the new passwords are saved](../ref/configuration/command-line-options.md#where-the-new-passwords-are-saved).

Passwords for internal users are stored hashed in `/etc/wazuh-indexer/opensearch-security/internal_users.yml`.

### Change the passwords of a step-by-step deployment

A deployment installed step by step does not need the Wazuh installation assistant to change a password: the Wazuh packages ship the tools.

- **Wazuh indexer users** (`admin`, `kibanaserver`, `wazuh-manager`): on a Wazuh indexer node, run the passwords tool that ships with the package. It reads the new password from the standard input:

    ```bash
    /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u <USER> -p
    ```

- **Wazuh server API users** (`wazuh`, `wazuh-internal-client`): on the master node, run `rbac_control`. Every node keeps its own `rbac.db` and the cluster does not synchronize it, so repeat the change on any node that may become the master:

    ```bash
    /var/wazuh-manager/bin/rbac_control change-password
    ```

- **The nodes that use the changed password** keep the previous one in their keystores until you update them and restart the service:
  - After changing `wazuh-manager`, on every Wazuh manager node, as described in [Update the Wazuh manager nodes](../ref/getting-started/usage.md#update-the-wazuh-manager-nodes).
  - After changing `kibanaserver` or `wazuh-internal-client`, on every Wazuh dashboard node (keystore entries `opensearch.password` and `wazuh_core.hosts.default.password`), as described in [Update the Wazuh dashboard nodes](../ref/getting-started/usage.md#update-the-wazuh-dashboard-nodes).

## Least privilege

- Run installation scripts with `sudo` or as root only when required.
- Restrict read access to certificate files and the `wazuh-install-files.tar` archive.
- After installation, remove the `wazuh-install-files.tar` file from every node, as it contains private keys and the passwords of the Wazuh users.
- Do not give other users read access to the `local.env` and `export/credentials.env` files.

## Recommendations

- Keep the root CA private key only in the `wazuh-ca` directory of the node where it was generated, and back it up.
- Keep all Wazuh components updated to receive security patches.
- Store certificates and backups in secure, access-controlled locations.
- Rotate certificates and passwords periodically.
