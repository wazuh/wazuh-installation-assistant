# All in one

Upgrade all Wazuh central components (Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard) on a single host following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

> [!NOTE]
> This documentation assumes you are already provisioned with a wazuh-indexer package through any of the possible methods.
> Check the wazuh-indexer documentation for more information about downloading packages.

### Preparing the upgrade

Perform the following steps on any of the Wazuh indexer nodes replacing `$WAZUH_INDEXER_IP_ADDRESS`, `$USERNAME`, and `$PASSWORD`.

1. Disable shard replication to prevent shard replicas from being created while Wazuh indexer nodes are being taken offline for the upgrade.

    ```bash
    curl -X PUT "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cluster/settings" \
    -u $USERNAME:$PASSWORD -k -H "Content-Type: application/json" -d '
    {
        "persistent": {
            "cluster.routing.allocation.enable": "primaries"
        }
    }'
    ```

    **Output**

    ```json
    {
        "acknowledged" : true,
        "persistent" : {
          "cluster" : {
            "routing" : {
              "allocation" : {
                "enable" : "primaries"
              }
            }
          }
        },
        "transient" : {}
        }
    ```

1. Perform a flush operation on the cluster to commit transaction log entries to the index.

    ```bash
    curl -X POST "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_flush" -u $USERNAME:$PASSWORD -k
    ```

    **Output**

    ```json
    {
    "_shards" : {
        "total" : 19,
        "successful" : 19,
        "failed" : 0
       }
    }
    ```

### Upgrading the Wazuh indexer nodes

1. Stop the Wazuh indexer service.

    **Systemd**

    ```bash
    systemctl stop wazuh-indexer
    ```

    **SysV**

    ```bash
    service wazuh-indexer stop
    ```

2. Upgrade the Wazuh indexer to the latest version.

    **rpm**

    ```bash
    rpm -ivh --replacepkgs wazuh-indexer-<VERSION>.rpm
    ```

    **dpkg**

    ```bash
    dpkg -i wazuh-indexer-<VERSION>.deb
    ```

3. Restart the Wazuh indexer service.

    **Systemd**

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```

    **SysV**

    Choose one option according to the operating system used.

    a. RPM-based operating system:

    ```bash
    chkconfig --add wazuh-indexer
    service wazuh-indexer start
    ```

    b. Debian-based operating system:

    ```bash
    update-rc.d wazuh-indexer defaults 95 10
    service wazuh-indexer start
    ```

Repeat steps 1 to 3 above on all Wazuh indexer nodes before proceeding to the [post-upgrade actions](#post-upgrade-actions).

### Post-upgrade actions

Perform the following steps on any of the Wazuh indexer nodes replacing `$WAZUH_INDEXER_IP_ADDRESS`, `$USERNAME`, and `$PASSWORD`.

1. Check that the newly upgraded Wazuh indexer nodes are in the cluster.

    ```bash
    curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

2. Re-enable shard allocation.

    ```bash
    curl -X PUT "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cluster/settings" \
    -u $USERNAME:$PASSWORD -k -H "Content-Type: application/json" -d '
    {
        "persistent": {
            "cluster.routing.allocation.enable": "all"
        }
    }
    '
    ```

    **Output**

    ```json
    {
        "acknowledged" : true,
        "persistent" : {
            "cluster" : {
            "routing" : {
                "allocation" : {
                "enable" : "all"
                }
            }
            }
        },
        "transient" : {}
    }
    ```

3. Check the status of the Wazuh indexer cluster again to see if the shard allocation has finished.

    ```bash
    curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

    **Output**

    ```bash
    ip         heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                                        cluster_manager name
    172.18.0.3           34          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh2.indexer
    172.18.0.4           21          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client *               wazuh1.indexer
    172.18.0.2           16          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh3.indexer
    ```

## Wazuh Manager

**Important**: Upgrading the Wazuh **manager** from version 4.x to 10.x is **not supported**. For manager major version upgrades, a fresh installation is required. However, Wazuh **agents** support upgrades from 4.x to 10.x and can connect to a 10.x manager.

### Pre-Upgrade Requirements

Before upgrading, ensure you:

1. Review release notes for breaking changes and new features
2. Verify system meets requirements for the new version
3. Create a backup following the [backup procedures](backup-restore.md#manager-backup-and-restore)
4. Plan maintenance window for the upgrade
5. Notify relevant stakeholders

### Backup

Create a backup before upgrading:

```bash
# Create backup directory
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR/db

# Backup configuration and database
sudo tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Verify backup integrity
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null && echo "Backup successful"
sudo sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check"
```

### Download package

Download the Wazuh manager package for your platform and version. Check the wazuh-manager documentation for more information about downloading packages.

### Upgrade

Install the downloaded Wazuh manager package for your platform:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

The package manager will automatically:

- Stop the current service
- Preserve your configuration files
- Install the new binaries
- Start the service

### Verify upgrade

Verify the manager is running:

```bash
# Check service status
sudo systemctl status wazuh-manager

# Check logs for errors
sudo tail -50 /var/wazuh-manager/logs/wazuh-manager.log

# Check database integrity
sudo sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"
```

## Wazuh Dashboard

### Pre-Upgrade Requirements

Before upgrading, ensure you:

1. Review release notes for breaking changes and new features
2. Verify system meets requirements for the new version
3. Create a backup following the [backup procedures](./backup-restore.md)

### Upgrading the Wazuh dashboard

1. Stop the Wazuh dashboard service:

**Systemd**

```bash
systemctl stop wazuh-dashboard
```

**SysV init**

```bash
service wazuh-dashboard stop
```

2. Backup

It is recommended to take a backup before proceding the upgrade. See [backup](./backup-restore.md).

Backup the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file to save your settings at least, this could be required to redefine the configuration changes. Create a copy of the file using the following command:

```bash
cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.old
```

3. Download the new package and install it

Check the wazuh-dashboard documentation for more information about downloading packages.

**Debian-based:**

```bash
dpkg -i wazuh-dashboard_<VERSION>-<REVISION>_<ARCHITECTURE>.deb
```

**RHEL/CentOS-based:**

```bash
yum localinstall wazuh-dashboard-<VERSION>-<REVISION>.<ARCHITECTURE>.rpm
```

**RHEL/CentOS-based (DNF):**

```bash
dnf localinstall wazuh-dashboard-<VERSION>-<REVISION>.<ARCHITECTURE>.rpm
```

> **Note:** When prompted, choose to replace the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file with the updated version.

1. Reapply the configuration changes.

If the configuration file was replaced when the package was installed, follow the next steps:

4.1. Manually reapply any configuration changes to the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file. Ensure that the values of `server.ssl.key` and `server.ssl.certificate` match the files located in `/etc/wazuh-dashboard/certs/`.

4.2. Ensure the value of `uiSettings.overrides.defaultRoute` in the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file is set to `/app/wz-home` as shown below:

```yaml
uiSettings.overrides.defaultRoute: /app/wz-home
```

5. Restart the Wazuh dashboard:

   **Systemd:**

   ```bash
   systemctl daemon-reload
   systemctl enable wazuh-dashboard
   systemctl start wazuh-dashboard
   ```

   **SysV init:**
   Choose one option according to your operating system:

   - RPM-based operating system:

   ```bash
   chkconfig --add wazuh-dashboard
   service wazuh-dashboard start
   ```

   - Debian-based operating system:

   ```bash
   update-rc.d wazuh-dashboard defaults 95 10
   service wazuh-dashboard start
    ```

    You can now access the Wazuh dashboard via: `https://<DASHBOARD_IP_ADDRESS>`.

6. Import the saved objects customizations exported while preparing the upgrade if required.

- Navigate to **Dashboard management** > **Dashboard Management** > **Saved objects** on the Wazuh dashboard.
- Click **Import**, add the ndjson file and click **Import**.

> **Note:**
> Note that the upgrade process doesn't update plugins installed manually. Outdated plugins might cause the upgrade to fail.
>
> - Run the following command on the Wazuh dashboard server to list installed plugins and identify those that require an update:
>
>   ```bash
>   sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list
>   ```
>
>   In the output, plugins that require an update will be labeled as "outdated".
>
> - Remove the outdated plugins and reinstall the latest version replacing `<PLUGIN_NAME>` with the name of the plugin:
>
>   ```bash
>   sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove <PLUGIN_NAME>
>   sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install <PLUGIN_NAME>
>   ```

7. Check the upgrade status

**Systemd:**

```bash
systemctl status wazuh-dashboard
```

**SysV init:**

```bash
service wazuh-dashboard status
```
