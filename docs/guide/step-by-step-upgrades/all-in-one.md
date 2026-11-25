# All in one

Upgrade all Wazuh central components (Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard) on a single host following step-by-step instructions.

These steps upgrade a 5.x deployment to a later 5.x version. A 4.x deployment cannot be upgraded to 5.x, neither the Wazuh manager nor the Wazuh indexer and the Wazuh dashboard. Migrate it instead: install 5.0 and carry the agents, the configuration and the data across, as described in [Migration from 4.x](../migration/all-in-one.md).

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

> [!NOTE]
> This documentation assumes you are already provisioned with a wazuh-indexer package through any of the possible methods.
> Check the wazuh-indexer documentation for more information about downloading packages.

### Preparing the upgrade

Perform the following steps on any of the Wazuh indexer nodes replacing `$WAZUH_INDEXER_IP_ADDRESS`, `$USERNAME`, and `$PASSWORD`. `$USERNAME` is `admin`, and `$PASSWORD` is the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh-indexer/export/credentials.env`:

```bash
sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-
```

The commands check the Wazuh indexer certificate against `/etc/wazuh-indexer/certs/root-ca.pem`. In an all-in-one installation, use `127.0.0.1` (not `localhost`) as `$WAZUH_INDEXER_IP_ADDRESS`: by default the Wazuh indexer listens on that address only, and its certificate names only that IP address.

1. Disable shard replication to prevent shard replicas from being created while Wazuh indexer nodes are being taken offline for the upgrade.

    ```bash
    sudo curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -X PUT "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cluster/settings" \
    -u $USERNAME:$PASSWORD -H "Content-Type: application/json" -d '
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
    sudo curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -X POST "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_flush" -u $USERNAME:$PASSWORD
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
    yum install -y ./wazuh-indexer-<VERSION>.rpm
    ```

    **dpkg**

    ```bash
    apt install -y ./wazuh-indexer-<VERSION>.deb
    ```

    Keep your `/etc/wazuh-indexer/opensearch.yml`. The installation changed it, so on Debian-based systems `apt` asks about the file: keep the installed version. The new one is saved as `/etc/wazuh-indexer/opensearch.yml.dpkg-dist`. Without a terminal, `apt` cannot ask and the package is left half-configured; pass `-o Dpkg::Options::=--force-confold` to keep your file without the question. On RPM-based systems there is no question: the package keeps your file and, when the packaged file changed, installs the new one as `opensearch.yml.rpmnew`. Settings added to the packaged file, such as new plugin settings, do not reach an upgraded node until you bring them over. Compare the new file with yours, for example:

    ```bash
    diff /etc/wazuh-indexer/opensearch.yml /etc/wazuh-indexer/opensearch.yml.dpkg-dist   # Debian-based
    diff /etc/wazuh-indexer/opensearch.yml /etc/wazuh-indexer/opensearch.yml.rpmnew      # RPM-based
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

The commands check the Wazuh indexer certificate against `/etc/wazuh-indexer/certs/root-ca.pem`. In an all-in-one installation, use `127.0.0.1` (not `localhost`) as `$WAZUH_INDEXER_IP_ADDRESS`: by default the Wazuh indexer listens on that address only, and its certificate names only that IP address.

1. Check that the newly upgraded Wazuh indexer nodes are in the cluster.

    ```bash
    sudo curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

2. Re-enable shard allocation.

    ```bash
    sudo curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -X PUT "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cluster/settings" \
    -u $USERNAME:$PASSWORD -H "Content-Type: application/json" -d '
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

3. Check the health of the Wazuh indexer cluster again, until the shard allocation has finished and the status is `green`.

    ```bash
    sudo curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u $USERNAME:$PASSWORD "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cluster/health?pretty"
    ```

    Wait until `status` is `green` and `relocating_shards`, `initializing_shards` and `unassigned_shards` are `0`.

## Wazuh Manager

A 4.x Wazuh manager cannot be upgraded to 5.x: see [Migration from 4.x](../migration/all-in-one.md). The 4.x agents connect to the Wazuh manager 5.x, and can be upgraded to 5.x later.

Follow the upgrade procedure of the Wazuh manager package: [Upgrade](https://github.com/wazuh/wazuh/blob/5.0.1/docs/ref/upgrade.md) in the `wazuh/wazuh` repository. It covers the backup to take first (including the Server API database `rbac.db` and the keystore), the upgrade itself, the files the package preserves, and the checks afterwards. The package restarts the Wazuh manager after the upgrade only if it was running before.

## Wazuh Dashboard

### Pre-Upgrade Requirements

Before upgrading, ensure you:

1. Review release notes for breaking changes and new features
2. Verify system meets requirements for the new version
3. Create a backup following the [backup procedures](../backup-and-restore.md)
4. Export the saved objects you customized, if any: on the Wazuh dashboard, navigate to **Dashboard management** > **Dashboards Management** > **Saved objects**, select them and click **Export**.

### Upgrading the Wazuh dashboard

1. Back up the configuration file. The upgrade keeps your settings, but you need this copy if you replace the file:

    ```bash
    cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.old
    ```

2. Download the new package and install it. Check the wazuh-dashboard documentation for more information about downloading packages. The package stops the Wazuh dashboard before the upgrade and starts it again afterwards, if it was running.

    **Debian-based:**

    ```bash
    apt install ./wazuh-dashboard_<VERSION>-<REVISION>_<ARCHITECTURE>.deb
    ```

    **RHEL/CentOS-based:**

    ```bash
    yum localinstall wazuh-dashboard-<VERSION>-<REVISION>.<ARCHITECTURE>.rpm
    ```

    **RHEL/CentOS-based (DNF):**

    ```bash
    dnf localinstall wazuh-dashboard-<VERSION>-<REVISION>.<ARCHITECTURE>.rpm
    ```

3. Keep your `/etc/wazuh-dashboard/opensearch_dashboards.yml`.

    - On Debian-based systems, when `apt` asks about the file, keep the installed version. The new one is saved as `/etc/wazuh-dashboard/opensearch_dashboards.yml.dpkg-dist`.
    - On RPM-based systems there is no question: the package keeps your file and, when the packaged file changed between the two versions, installs the new one as `/etc/wazuh-dashboard/opensearch_dashboards.yml.rpmnew`. When it did not change, there is no `.rpmnew` file and nothing to compare.

    The packaged file points `opensearch.hosts` and `wazuh_core.hosts.default.url` to `localhost`, and has the default `opensearch.ssl.certificateAuthorities`, `username` and `ca` settings. If you take it, copy back from `opensearch_dashboards.yml.old` every setting of your deployment, not only `server.ssl.key` and `server.ssl.certificate`, or a distributed Wazuh dashboard loses its connection to the Wazuh indexer and to the Server API. Compare the new file with yours to bring over new settings, for example:

    ```bash
    diff /etc/wazuh-dashboard/opensearch_dashboards.yml.old /etc/wazuh-dashboard/opensearch_dashboards.yml.dpkg-dist   # Debian-based
    diff /etc/wazuh-dashboard/opensearch_dashboards.yml.old /etc/wazuh-dashboard/opensearch_dashboards.yml.rpmnew      # RPM-based
    ```

    Ensure the value of `uiSettings.overrides.defaultRoute` is `/app/wz-home`:

    ```yaml
    uiSettings.overrides.defaultRoute: /app/wz-home
    ```

    If you changed the file, restart the Wazuh dashboard: `systemctl restart wazuh-dashboard`, or `service wazuh-dashboard restart` with SysV init.

    You can now access the Wazuh dashboard via: `https://<DASHBOARD_IP_ADDRESS>`.

4. Import the saved objects you exported before the upgrade, if any.

    - Navigate to **Dashboard management** > **Dashboards Management** > **Saved objects** on the Wazuh dashboard.
    - Click **Import**, add the ndjson file and click **Import**.

    > **Note:**
    > The upgrade process doesn't update plugins installed manually. Outdated plugins might cause the upgrade to fail. The plugin directory belongs to `root`, so run these commands as root.
    >
    > - List installed plugins and identify those that require an update. In the output, plugins that require an update are labeled as "outdated":
    >
    >   ```bash
    >   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list
    >   ```
    >
    > - Remove the outdated plugins and reinstall the latest version replacing `<PLUGIN_NAME>` with the name of the plugin:
    >
    >   ```bash
    >   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin remove <PLUGIN_NAME>
    >   sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install <PLUGIN_NAME>
    >   ```

5. Check the upgrade status

    **Systemd:**

    ```bash
    systemctl status wazuh-dashboard
    ```

    **SysV init:**

    ```bash
    service wazuh-dashboard status
    ```
