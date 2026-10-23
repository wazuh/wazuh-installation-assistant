# Back up and restore

This section describes how to back up and restore the configuration, certificates, and data of the Wazuh central components.

> [!NOTE]
> You need root user privileges to run all the commands described below.

Each Wazuh component keeps its credentials and certificates in its own configuration directory: `/etc/wazuh-indexer`, `/etc/wazuh-manager` and `/etc/wazuh-dashboard`. Back up these files of each directory:

- `local.env`: the passwords and values given before the package was installed.
- `ca/`: the CA of the package.
- `certs/`: the certificates the service uses, and the CAs of the other components.
- `export/`: the CA and the passwords the Wazuh indexer and the Wazuh manager publish.

## Deployment root CA

If you ran `wazuh-install-5.0.1.sh -g`, also back up the `wazuh-ca` directory of that host. It is next to `wazuh-install-5.0.1.sh`, or in the directory set in the `WAZUH_CA_DIR` environment variable. It holds the root CA of the deployment, its private key and the passwords. You need it to add nodes or renew certificates. Keep the backup in a safe place.

```bash
tar -czf wazuh-ca-backup.tar.gz -C <DIRECTORY_OF_WAZUH_INSTALL> wazuh-ca
```

## Wazuh Indexer

In this section you can find instructions on how to create and restore a backup of your Wazuh Indexer key files, preserving file permissions, ownership, and path. Later, you can move this folder contents back to the corresponding location to restore your certificates and configurations. Backing up these files is useful in cases such as moving your Wazuh installation to another system.

> **Note**: This backup only restores the configuration files, not the data. To back up data stored in the indexer, use [snapshots](https://docs.opensearch.org/3.3/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/).

### Creating a backup

To create a backup of the Wazuh indexer, follow these steps. Repeat them on every cluster node you want to back up.

> **Note**: You need root user privileges to run all the commands described below.

#### Preparing the backup

1. Backup the existing Wazuh indexer security configuration files.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-backup /etc/wazuh-indexer/opensearch-security -icl -nhnv"
    ```

2. Create the destination folder to store the files. For version control, add the date and time of the backup to the name of the folder.

    ```bash
    backup_folder=~/wazuh_files_backup/$(date +%F_%H:%M)
    mkdir -p $backup_folder && echo $backup_folder
    ```

3. Save the host information.

    ```bash
    cat /etc/*release* > $backup_folder/host-info.txt
    echo -e "\n$(hostname): $(hostname -I)" >> $backup_folder/host-info.txt
    ```

#### Backing up the Wazuh indexer

Back up the Wazuh indexer certificates and configuration

```bash
rsync -aREz \
/etc/wazuh-indexer/local.env \
/etc/wazuh-indexer/ca/ \
/etc/wazuh-indexer/certs/ \
/etc/wazuh-indexer/export/ \
/etc/wazuh-indexer/jvm.options \
/etc/wazuh-indexer/jvm.options.d \
/etc/wazuh-indexer/log4j2.properties \
/etc/wazuh-indexer/opensearch.yml \
/etc/wazuh-indexer/opensearch.keystore \
/etc/wazuh-indexer/opensearch-observability/ \
/etc/wazuh-indexer/opensearch-security/ \
/etc/wazuh-indexer/wazuh-indexer-reports-scheduler/ \
/etc/wazuh-indexer/wazuh-indexer-notifications/ \
/etc/wazuh-indexer/wazuh-indexer-notifications-core/ \
/usr/lib/sysctl.d/wazuh-indexer.conf $backup_folder
```

Compress the files and transfer them to the new server:

```bash
tar -cvzf wazuh-indexer-backup.tar.gz $backup_folder
```

### Restoring Wazuh indexer from backup

This guide explains how to restore a backup of your configuration files.

>**Note**: This guide is designed specifically for restoration from a backup of the same version.

---

>**Note**: For a multi-node setup, there should be a backup file for each node within the cluster. You need root user privileges to execute the commands below.

#### Preparing the data restoration

1. In the new node, move the compressed backup file to the root `/` directory:

    ```bash
    mv wazuh-indexer-backup.tar.gz /
    cd /
    ```

2. Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files:

    ```bash
    tar -xzvf wazuh-indexer-backup.tar.gz
    cd $backup_folder
    ```

#### Restoring Wazuh indexer files

Perform the following steps to restore the Wazuh indexer files on the new server.

1. Stop the Wazuh indexer to prevent any modifications to the Wazuh indexer files during the restoration process:

    ```bash
    systemctl stop wazuh-indexer
    ```

2. Restore the Wazuh indexer configuration files and change the file permissions and ownership accordingly:

    ```bash
    cp -a etc/wazuh-indexer/local.env /etc/wazuh-indexer/local.env
    cp -a etc/wazuh-indexer/ca etc/wazuh-indexer/export /etc/wazuh-indexer/
    cp -r etc/wazuh-indexer/certs/. /etc/wazuh-indexer/certs/
    cp etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options
    cp -r etc/wazuh-indexer/jvm.options.d/. /etc/wazuh-indexer/jvm.options.d/
    cp etc/wazuh-indexer/log4j2.properties /etc/wazuh-indexer/log4j2.properties
    cp etc/wazuh-indexer/opensearch.yml /etc/wazuh-indexer/opensearch.yml
    cp etc/wazuh-indexer/opensearch.keystore /etc/wazuh-indexer/opensearch.keystore
    cp -r etc/wazuh-indexer/opensearch-observability/. /etc/wazuh-indexer/opensearch-observability/
    cp -r etc/wazuh-indexer/opensearch-security/. /etc/wazuh-indexer/opensearch-security/
    cp -r etc/wazuh-indexer/wazuh-indexer-reports-scheduler/. /etc/wazuh-indexer/wazuh-indexer-reports-scheduler/
    cp -r etc/wazuh-indexer/wazuh-indexer-notifications/. /etc/wazuh-indexer/wazuh-indexer-notifications/
    cp -r etc/wazuh-indexer/wazuh-indexer-notifications-core/. /etc/wazuh-indexer/wazuh-indexer-notifications-core/
    cp usr/lib/sysctl.d/wazuh-indexer.conf /usr/lib/sysctl.d/wazuh-indexer.conf

    chown -R root:wazuh-indexer /etc/wazuh-indexer/certs/
    chown root:root /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
    chmod 600 /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
    chown root:wazuh-indexer /etc/wazuh-indexer/jvm.options
    chown -R root:wazuh-indexer /etc/wazuh-indexer/jvm.options.d
    chown root:wazuh-indexer /etc/wazuh-indexer/log4j2.properties
    chown root:wazuh-indexer /etc/wazuh-indexer/opensearch.yml
    chown root:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore
    chown -R root:wazuh-indexer /etc/wazuh-indexer/opensearch-observability/
    chown -R root:wazuh-indexer /etc/wazuh-indexer/opensearch-security/
    chown -R root:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-reports-scheduler/
    chown -R root:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-notifications/
    chown -R root:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-notifications-core/
    chown root:root /usr/lib/sysctl.d/wazuh-indexer.conf
    ```

    The configuration directory belongs to `root`, and the Wazuh indexer reads it through its group and writes nothing in it. Do not give the files to the `wazuh-indexer` user: the Wazuh indexer refuses to start when a certificate is not owned by `root` or is writable by its group or others. The admin pair is `root`'s alone, with mode `0600`.

3. Start the Wazuh indexer service:

    ```bash
    systemctl start wazuh-indexer
    ```

4. Clear the backup files to free up space:

    ```bash
    rm -rf $backup_folder
    rm -rf /wazuh-indexer-backup.tar.gz
    ```

## Wazuh Manager

The Wazuh manager package documents its own backup and restore: [Back Up and Restore](https://github.com/wazuh/wazuh/blob/5.0.1/docs/ref/backup-restore.md) in the `wazuh/wazuh` repository. Follow it. It covers what this guide cannot keep up to date: besides `/etc/wazuh-manager` (`local.env`, `ca/`, `certs/`, `export/`, `client.keys`) and `global.db`, it includes the Server API database `rbac.db`, the keystore with the Wazuh indexer credential, `tasks.db`, the cluster differences between master and worker nodes, and the restore order.

### Manager backup procedures

Back up these files together. Restored alone on a freshly installed node, part of them would not match the rest:

- `rbac.db` holds the Server API passwords that `export/credentials.env` and the `local.env` of the Wazuh dashboard name. Without it, the new installation keeps the passwords it generated, and the Wazuh dashboard cannot log in to the Server API.
- The keystore in `/var/wazuh-manager/queue/keystore/` holds the password of the `wazuh-manager` Wazuh indexer user. Without it, the Wazuh manager cannot authenticate to the Wazuh indexer.

What the Wazuh installation assistant adds to that procedure:

- The `wazuh-ca` directory of the host where `-g` ran, described in [Deployment root CA](#deployment-root-ca). The manager backup does not include it.
- `wazuh-install-files.tar`, if you keep it to add nodes. Its `credentials.env` must have the current passwords: after restoring a node with other passwords, or after changing them, update it as described in [Security](security.md).

## Wazuh Dashboard

This guide focuses on the assets managed by the Wazuh dashboard itself.

### What to back up

- Dashboard configuration: `/etc/wazuh-dashboard/opensearch_dashboards.yml`
- Dashboard NodeJS options: `/etc/wazuh-dashboard/node.options`
- Dashboard keystore: `/etc/wazuh-dashboard/opensearch_dashboards.keystore`
- Passwords given before the install: `/etc/wazuh-dashboard/local.env`
- CA of the Wazuh dashboard, when the package created one: `/etc/wazuh-dashboard/ca/`
- TLS certificates: `/etc/wazuh-dashboard/certs/`
- Saved objects exported from the UI (dashboards, visualizations, index patterns)
- Custom assets

### Creating a backup

To create a backup of the Wazuh dashboard, follow these steps:

1. Create the backup directory

```bash
backup_folder=~/wazuh_dashboard_backup/$(date +%Y%m%d-%H%M%S)
mkdir -p $backup_folder && echo $backup_folder
```

2. Back up the configuration and certificates

```bash
rsync -aREz \
/etc/wazuh-dashboard/opensearch_dashboards.yml \
/etc/wazuh-dashboard/node.options \
/etc/wazuh-dashboard/opensearch_dashboards.keystore \
/etc/wazuh-dashboard/local.env \
/etc/wazuh-dashboard/certs/ \
$backup_folder
[ -d /etc/wazuh-dashboard/ca ] && rsync -aREz /etc/wazuh-dashboard/ca/ $backup_folder
```

3. Export the saved objects

3.1. Create the **saved_objects** directory

```bash
mkdir -p "$backup_folder/saved_objects"
```

> Note: if multitenancy is used, export the saved objects of each tenant repeating the following steps, consider separating in directories by tenant.

3.2. Open **Dashboard management** > **Dashboards Management** > **Saved objects**.

3.3. Export the required objects, or use **Export all objects**. Choose as destination the **saved_objects** directory.

4. Custom assets

If the dashboard is serving custom assets (i.e. images for UI customization), copy these files to the $backup_folder directory.

```bash
rsync -aREz \
<PATH_TO_FILE> \
$backup_folder
```

5. Archive the files

```bash
tar -cvzf wazuh-dashboard-backup.tar.gz $backup_folder
```

### Restore

1. Stop the target Wazuh dashboard

**Systemd:**

```bash
systemctl stop wazuh-dashboard
```

**SysV init:**

```bash
service wazuh-dashboard stop
```

2. Decompress the files

Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files:

```bash
tar -xzvf wazuh-dashboard-backup.tar.gz
cd $backup_destination_folder
```

3. Restore the files:

```bash
cp etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml
cp etc/wazuh-dashboard/node.options /etc/wazuh-dashboard/node.options
cp etc/wazuh-dashboard/opensearch_dashboards.keystore /etc/wazuh-dashboard/opensearch_dashboards.keystore
cp -r etc/wazuh-dashboard/certs/. /etc/wazuh-dashboard/certs/
cp -a etc/wazuh-dashboard/local.env /etc/wazuh-dashboard/local.env
[ -d etc/wazuh-dashboard/ca ] && cp -a etc/wazuh-dashboard/ca /etc/wazuh-dashboard/
chown root:wazuh-dashboard /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/node.options /etc/wazuh-dashboard/opensearch_dashboards.keystore
chmod 640 /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/node.options /etc/wazuh-dashboard/opensearch_dashboards.keystore
chown -R root:wazuh-dashboard /etc/wazuh-dashboard/certs
chmod 750 /etc/wazuh-dashboard/certs
chmod 640 /etc/wazuh-dashboard/certs/*
```

The configuration belongs to `root`, and the Wazuh dashboard reads it through its group. Do not give these files to the `wazuh-dashboard` user: the Wazuh dashboard refuses to start when a file in `/etc/wazuh-dashboard/certs` is not owned by `root` or is writable by its group or others.

4. Restore the custom assets files

If some custom asset was backed, then for each one:

```bash
cp <path/to/asset/> <destination_path>
chown wazuh-dashboard:wazuh-dashboard <destination_path>
```

5. Restart the service:

**Systemd:**

```bash
systemctl restart wazuh-dashboard
```

**SysV init:**

```bash
service wazuh-dashboard restart
```

6. Import saved objects from **Dashboard management** > **Dashboards Management** > **Saved objects**.

Import the saved object stored in `$backup_folder`. If using multitenancy, import the related saved objects into each tenant.
