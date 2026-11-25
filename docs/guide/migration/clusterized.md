# Clusterized

Migrate a distributed deployment installed with the 4.x installation assistant to 5.0: one or more Wazuh indexer nodes, a Wazuh manager cluster with a master node and worker nodes, and a Wazuh dashboard. Read [Migration from 4.x](./migration.md) first: it lists what is kept and the differences between the two paths. The steps are the ones of [All in one](./all-in-one.md), which explains each of them, with these differences:

- The agents are exported from the 4.x master node and imported on the 5.0 master node. The 5.0 worker nodes receive the agent keys and the groups from the master node.
- The Server API users live in the master node, so the passwords are set back on the master node.
- Every 4.x Wazuh manager node is stopped, so no agent stays connected to 4.x.

> [!NOTE]
> You need root user privileges to run all the commands described below.

The steps use `wazuh-migrate-identity.py` with `--with-rbac`, which also carries the Server API users, roles and policies. Leave it out on both commands if you don't need them. If 4.x agents must still enroll after the migration with the 4.x enrollment password, add `--with-password` to both commands too.

## New hosts

1. **Install 5.0 on the new hosts.** Follow [Clusterized](../installation-assistant-deployments/clusterized.md). If the agents will reach the Wazuh manager nodes through a load balancer or a DNS name, add it with `-as|--agent-san` when you run `-g`, so it is in the certificate of every Wazuh manager node. Do not point any agent to the new hosts yet.

2. **Stop the 4.x Wazuh manager nodes and export the agents.** Stop and disable the Wazuh manager on every 4.x Wazuh manager node, workers first:

    ```bash
    systemctl stop wazuh-manager
    systemctl disable wazuh-manager
    ```

    On the 4.x master node, download the tool and export the agents, first with `--dry-run`:

    ```bash
    curl -fsSLo /root/wazuh-migrate-identity.py https://raw.githubusercontent.com/wazuh/wazuh/5.0.1/tools/migration/wazuh-migrate-identity.py
    /var/ossec/framework/python/bin/python3 /root/wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/ossec/framework/python/bin/python3 /root/wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac
    ```

    Copy `/root/wazuh-4x-bundle` and `/root/wazuh-migrate-identity.py` to `/root` of the 5.0 master node. The bundle holds the agent keys and the password hashes of the Server API users: handle it like a password.

3. **Import the agents** on the 5.0 master node, first with `--dry-run`:

    ```bash
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac
    ```

4. **Restart the master node and check the import.** On the 5.0 master node, restart the Wazuh manager, set the `wazuh` and `wazuh-internal-client` users back to the passwords of the 5.0 installation, and compare it with the bundle:

    ```bash
    systemctl restart wazuh-manager
    sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh -p -
    sed -n 's/^WAZUH_MANAGER_WUI_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh-internal-client -p -
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py check /root/wazuh-4x-bundle
    ```

    The output ends with `The target matches the bundle.`

5. **Point the agents to the new hosts.** Change the DNS name or the load balancer the agents use, or edit `<client><server><address>` in the `ossec.conf` of each agent and restart it. For a few seconds after the import, a worker node can log that an agent `is not registered`, until it receives the keys from the master node. See [Check the migration](./all-in-one.md#check-the-migration), on the master node.

6. **Migrate the configuration** of every Wazuh manager node, as described in the Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.0.1/docs/guide/migration/manager-4x-to-5x.md#4-migrate-the-configuration). The 4.x files are still in `/var/ossec` on the 4.x nodes. To keep the rootcheck files of the `default` group for the 4.x agents, copy the `*.txt` files of `/var/ossec/etc/shared/default/` on the 4.x master node to `/etc/wazuh-manager/shared/default/` on the 5.0 master node, with owner `wazuh-manager:wazuh-manager` and mode `0660`.

To roll back, stop the 5.0 Wazuh manager nodes, start the 4.x ones again with `systemctl enable --now wazuh-manager`, master first, and point the agents back to them. This works only for agents that still run 4.x. When you no longer need the 4.x deployment, remove it with `bash wazuh-install.sh -u` on every 4.x node.

## Same hosts

On the same hosts, 4.x is removed from every node before 5.0 is installed. Check the costs of this path in [All in one](./all-in-one.md#same-host): downtime, no simple rollback, an operating system that 5.0 supports on every node, and the 4.x data lost without a snapshot.

1. **Back up the 4.x deployment.** See [Before you start](./migration.md#before-you-start).

2. **Take a snapshot of the 4.x indices.** Skip this step if you don't need the 4.x alerts and inventory in 5.0. With one Wazuh indexer node, create `/var/backups/wazuh-4x-snapshots` on it as in step 2 of [All in one](./all-in-one.md#same-host). With more than one, every Wazuh indexer node writes its own part of the snapshot, so all of them must reach the same directory at the same path: mount a shared file system, such as NFS, at `/var/backups/wazuh-4x-snapshots` on every Wazuh indexer node, outside the directories that the uninstall removes. Then, on every Wazuh indexer node, add it to `path.repo` and restart the Wazuh indexer, one node at a time. Before you restart the next node, wait until the restarted one is ready, with the wait command of step 2 of [All in one](./all-in-one.md#same-host) and the address of the node instead of `127.0.0.1`:

    ```bash
    chown wazuh-indexer:wazuh-indexer /var/backups/wazuh-4x-snapshots
    printf '\npath.repo: ["/var/backups/wazuh-4x-snapshots"]\n' >> /etc/wazuh-indexer/opensearch.yml
    systemctl restart wazuh-indexer
    ```

    On one Wazuh indexer node, register the directory and take the snapshot as in step 2 of [All in one](./all-in-one.md#same-host), with the address of that node instead of `127.0.0.1`. The `admin` password is in the `wazuh-install-files.tar` file of the 4.x deployment.

3. **Stop the 4.x Wazuh manager nodes and export the agents.** Stop the Wazuh manager on every 4.x Wazuh manager node, workers first, with `systemctl stop wazuh-manager`. On the 4.x master node, export the agents as in step 2 of [New hosts](#new-hosts). On every Wazuh manager node, keep the 4.x files you need to rewrite the configuration, because the uninstall removes `/var/ossec`:

    ```bash
    tar -czf /root/wazuh-4x-config.tar.gz -C /var/ossec etc/ossec.conf etc/local_internal_options.conf etc/rules etc/decoders etc/lists etc/shared api/configuration/api.yaml
    ```

4. **Remove 4.x** from every node with the 4.x installation assistant: `bash wazuh-install.sh -u`. If you no longer have `wazuh-install.sh`, download it again with `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh`.

5. **Install 5.0 with the agent ports closed.** Follow [Clusterized](../installation-assistant-deployments/clusterized.md), with a new 5.0 `config.yml`. On every Wazuh manager node, master and workers, run the installation assistant with the two variables that keep the agents away until the import:

    ```bash
    sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='127.0.0.1' WAZUH_REMOTE_LEGACY_ENABLED='no' bash ./wazuh-install-5.0.1.sh -wm <MANAGER_NODE_NAME>
    ```

6. **Import the agents** on the 5.0 master node, as in step 3 of [New hosts](#new-hosts).

7. **Open the agent ports and check the import.** On every Wazuh manager node, master first, set `<bind_addr>` of the `<https>` block back to `0.0.0.0` and `<enabled>` of the `<legacy>` block to `yes` in `/etc/wazuh-manager/wazuh-manager.conf`, as in step 7 of [All in one](./all-in-one.md#same-host), and restart the Wazuh manager:

    ```bash
    sed -i -e '/<https>/,/<\/https>/s|<bind_addr>.*</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|' \
    -e '/<legacy>/,/<\/legacy>/s|<enabled>.*</enabled>|<enabled>yes</enabled>|' /etc/wazuh-manager/wazuh-manager.conf
    /var/wazuh-manager/bin/wazuh-manager-conf validate
    systemctl restart wazuh-manager
    ```

    Then, on the master node, set the `wazuh` and `wazuh-internal-client` passwords back and compare it with the bundle, as in step 4 of [New hosts](#new-hosts), without the restart.

8. **Restore the snapshot.** Skip this step if you did not take the snapshot of step 2. The Wazuh indexer 5.0 lists `/var/lib/wazuh-indexer/backup` in `path.repo`. Do not add another `path.repo` line: the Wazuh indexer refuses to start with `Duplicate field 'path.repo'`. With one Wazuh indexer node, move the snapshot to `/var/lib/wazuh-indexer/backup/wazuh-4x` as in step 8 of [All in one](./all-in-one.md#same-host), and restore it from there.

    With more than one, the shared file system of step 2 is still mounted at `/var/backups/wazuh-4x-snapshots` on every Wazuh indexer node. Keep it there: the Wazuh indexer [backup guide](https://github.com/wazuh/wazuh-indexer-plugins/blob/5.0.1/docs/ref/backup-restore.md#backing-up-the-data) asks for a shared repository outside the directories of the Wazuh indexer package. Make sure the `wazuh-indexer` user of every node can read it. Then, on every Wazuh indexer node, add it to the existing `path.repo` line and restart the Wazuh indexer, one node at a time, waiting until each one is ready as in step 2, with the 5.0 `admin` password:

    ```bash
    sed -i 's|^path.repo:.*|path.repo: ["/var/lib/wazuh-indexer/backup", "/var/backups/wazuh-4x-snapshots"]|' /etc/wazuh-indexer/opensearch.yml
    systemctl restart wazuh-indexer
    ```

    On one Wazuh indexer node, register the directory as read-only and restore the indices as in step 8 of [All in one](./all-in-one.md#same-host), with `/var/backups/wazuh-4x-snapshots` as `location` and the address of that node instead of `127.0.0.1`. The `admin` password is the `WAZUH_INDEXER_ADMIN_PASSWORD` value of `/etc/wazuh-indexer/export/credentials.env`.

9. **Migrate the configuration** of every Wazuh manager node, as described in the Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.0.1/docs/guide/migration/manager-4x-to-5x.md#4-migrate-the-configuration). The 4.x files are in `/root/wazuh-4x-config.tar.gz` of each node. To keep the rootcheck files of the `default` group for the 4.x agents, copy them on the master node as in step 9 of [All in one](./all-in-one.md#same-host).

Then continue with [After the migration](./all-in-one.md#after-the-migration).
