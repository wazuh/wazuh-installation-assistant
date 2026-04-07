# Back up and restore

This section describes how to back up and restore the configuration, certificates, and data of the Wazuh central components.

> [!NOTE]
> You need root user privileges to run all the commands described below.

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
/etc/wazuh-indexer/certs/ \
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
    cp etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options
    cp -r etc/wazuh-indexer/jvm.options.d/ /etc/wazuh-indexer/jvm.options.d/
    cp etc/wazuh-indexer/log4j2.properties /etc/wazuh-indexer/log4j2.properties
    cp etc/wazuh-indexer/opensearch.keystore /etc/wazuh-indexer/opensearch.keystore
    cp -r etc/wazuh-indexer/opensearch-observability/ /etc/wazuh-indexer/opensearch-observability/
    cp -r etc/wazuh-indexer/wazuh-indexer-reports-scheduler/ /etc/wazuh-indexer/wazuh-indexer-reports-scheduler/
    cp -r etc/wazuh-indexer/wazuh-indexer-notifications/ /etc/wazuh-indexer/wazuh-indexer-notifications/
    cp -r etc/wazuh-indexer/wazuh-indexer-notifications-core/ /etc/wazuh-indexer/wazuh-indexer-notifications-core/
    cp usr/lib/sysctl.d/wazuh-indexer.conf /usr/lib/sysctl.d/wazuh-indexer.conf

    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/jvm.options
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/jvm.options.d
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/log4j2.properties
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-observability/
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-reports-scheduler/
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-notifications/
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/wazuh-indexer-notifications-core/
    chown wazuh-indexer:wazuh-indexer /usr/lib/sysctl.d/wazuh-indexer.conf
    ```

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

The following components should be included in your Wazuh manager backup strategy:

### Essential Data

- **Configuration files**: `/var/wazuh-manager/etc/`
  - `wazuh-manager.conf` - Main configuration file
  - `wazuh-manager-internal-options.conf` - Internal configuration overrides

- **Agent keys**: `/var/wazuh-manager/etc/client.keys`
  - Contains encryption keys for registered agents
  - Critical for agent communication

- **SSL/TLS certificates**: `/var/wazuh-manager/etc/certs/`
  - Manager certificates and keys
  - Root CA certificates

- **Global database**: `/var/wazuh-manager/var/db/global.db`
  - Agent information (registration, metadata)
  - Agent group assignments
  - Group membership data

- **Agent groups**: `/var/wazuh-manager/etc/shared/`
  - Group-specific configurations and files
  - Shared files distributed to agents in each group

### Optional Data

- **Logs**: `/var/wazuh-manager/logs/`
  - Historical logs for audit and troubleshooting
  - Can be large; consider retention policies

### Manager Backup Procedures

#### Pre-Backup Checklist

Before creating a backup, verify:

1. Sufficient disk space for backup files
2. Backup destination is accessible
3. You have appropriate permissions
4. Consider stopping the manager for consistent backups (optional)

#### Creating a Full Manager Backup

**Option 1: Backup while manager is running** (recommended for production)

This method allows the manager to continue operating during the backup:

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Backup configuration files
sudo tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/

# Backup global database (use SQLite backup for consistency)
sudo mkdir -p $BACKUP_DIR/db
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Set proper permissions
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

**Option 2: Backup with manager stopped** (recommended for critical operations)

This method ensures complete data consistency:

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Stop the Wazuh manager
sudo systemctl stop wazuh-manager

# Backup essential directories
sudo tar -czf $BACKUP_DIR/wazuh-manager-backup.tar.gz \
    -C /var/wazuh-manager \
    etc/ \
    var/db/global.db

# Start the Wazuh manager
sudo systemctl start wazuh-manager

# Verify manager is running
sudo systemctl status wazuh-manager

# Set proper permissions
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

#### Creating Selective Manager Backups

**Configuration only:**

```bash
sudo tar -czf wazuh-manager-config-$(date +%Y%m%d).tar.gz -C /var/wazuh-manager etc/
```

**Agent keys only:**

```bash
sudo cp /var/wazuh-manager/etc/client.keys wazuh-client-keys-$(date +%Y%m%d).backup
```

**Global database only:**

```bash
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup 'wazuh-global-db-$(date +%Y%m%d).db'"
```

#### Backup Verification

After creating a backup, verify its integrity:

```bash
# Verify tar archive integrity
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null && echo "Configuration backup verified" || echo "Backup verification failed"

# Check database integrity
sudo sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check" && echo "Database backup verified" || echo "Database verification failed"

# Check backup size
du -sh $BACKUP_DIR

# List backup contents
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz | head -20
```

#### Automated Manager Backup Script

Create a script for regular automated backups:

```bash
#!/bin/bash
# /usr/local/bin/wazuh-manager-backup.sh

BACKUP_BASE="/backup/wazuh-manager"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE/backup-$TIMESTAMP"

# Create backup directory
mkdir -p $BACKUP_DIR/db

# Perform backup
tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/
sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Verify backup
if tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null 2>&1 && \
   sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check" > /dev/null 2>&1; then
    echo "$(date): Manager backup completed successfully to $BACKUP_DIR" >> /var/log/wazuh-backup.log

    # Remove old backups
    find $BACKUP_BASE -type d -name "backup-*" -mtime +$RETENTION_DAYS -exec rm -rf {} \;
else
    echo "$(date): Manager backup FAILED - verification error" >> /var/log/wazuh-backup.log
    exit 1
fi
```

Schedule with cron:

```bash
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/wazuh-manager-backup.sh
```

### Manager Restore Procedures

#### Pre-Restore Checklist

Before restoring from a backup:

1. Verify backup file integrity
2. Ensure compatible Wazuh version
3. Check available disk space
4. Plan for service downtime
5. Notify relevant stakeholders

#### Full Manager Restore

**Step 1: Stop the Wazuh manager**

```bash
sudo systemctl stop wazuh-manager
```

**Step 2: Backup current data (optional but recommended)**

```bash
sudo mv /var/wazuh-manager/etc /var/wazuh-manager/etc.old.$(date +%Y%m%d)
sudo mv /var/wazuh-manager/var/db/global.db /var/wazuh-manager/var/db/global.db.old.$(date +%Y%m%d)
```

**Step 3: Restore from backup**

```bash
# Restore configuration
sudo tar -xzf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager

# Restore global database
sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/var/db/global.db
```

**Step 4: Set proper permissions**

```bash
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/var/db
sudo chmod 640 /var/wazuh-manager/etc/client.keys
sudo chmod 500 /var/wazuh-manager/etc/certs
sudo chmod 400 /var/wazuh-manager/etc/certs/*
```

**Step 5: Start the Wazuh manager**

```bash
sudo systemctl start wazuh-manager
```

**Step 6: Verify the restore**

```bash
# Check manager status
sudo systemctl status wazuh-manager

# Check database integrity
sudo sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"

# Check logs for errors
sudo tail -f /var/wazuh-manager/logs/wazuh-manager.log
```

#### Selective Manager Restore

**Restore configuration only:**

```bash
sudo systemctl stop wazuh-manager
sudo tar -xzf wazuh-manager-config-YYYYMMDD.tar.gz -C /var/wazuh-manager
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc
sudo systemctl start wazuh-manager
```

**Restore agent keys only:**

```bash
sudo systemctl stop wazuh-manager
sudo cp wazuh-client-keys-YYYYMMDD.backup /var/wazuh-manager/etc/client.keys
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/client.keys
sudo chmod 640 /var/wazuh-manager/etc/client.keys
sudo systemctl start wazuh-manager
```

**Restore global database only:**

```bash
sudo systemctl stop wazuh-manager
sudo cp wazuh-global-db-YYYYMMDD.db /var/wazuh-manager/var/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/var/db/global.db
sudo chmod 640 /var/wazuh-manager/var/db/global.db
sudo systemctl start wazuh-manager
```

### Cluster-Specific Manager Backup

In a cluster deployment, backup procedures differ slightly:

**Master node:**

- Backup all data as described above
- The master node contains authoritative agent registration and group assignment data

**Worker nodes:**

- Configuration backup is sufficient
- The global database is synchronized from master
- Shared files are synchronized from master

**Recommended approach:**

1. Always backup the master node completely
2. Backup worker node configurations
3. Store backups separately for each node
4. Document cluster topology and node roles

#### Master Node Backup

```bash
BACKUP_DIR="/backup/wazuh-master-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR/db

# Full backup of master node
sudo tar -czf $BACKUP_DIR/wazuh-master-etc.tar.gz -C /var/wazuh-manager etc/
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"
```

#### Worker Node Backup

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Configuration only for worker nodes
sudo tar -czf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager/etc wazuh-manager.conf wazuh-manager-internal-options.conf
```

### Cluster Restore Procedures

#### Restore Master Node

1. Follow the full manager restore procedure
2. Verify cluster configuration in `/var/wazuh-manager/etc/wazuh-manager.conf`
3. Start the manager service
4. Verify cluster status: `sudo /var/wazuh-manager/bin/cluster_control -l`

#### Restore Worker Node

1. Restore configuration files
2. Ensure cluster settings point to correct master
3. Start the manager service
4. Verify connection to master node
5. Allow time for synchronization from master

#### Cluster Restore Verification

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check synchronization status
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

## Wazuh Dashboard

This guide focuses on the assets managed by the Wazuh dashboard itself.

### What to back up

- Dashboard configuration: `/etc/wazuh-dashboard/opensearch_dashboards.yml`
- Dashboard NodeJS options: `/etc/wazuh-dashboard/node.options`
- Dashboard keystore: `/etc/wazuh-dashboard/opensearch_dashboards.keystore`
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
/etc/wazuh-dashboard/certs/ \
$backup_folder
```

3. Export the saved objects

3.1. Create the **saved_objects** directory

```bash
mkdir -p "$backup_folder/saved_objects"
```

> Note: if multitenancy is used, exportthe saved objects of each tenant repeating the following steps, consider separating in directories by tenant.

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
cp -r etc/wazuh-dashboard/certs/ /etc/wazuh-dashboard/certs/
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/opensearch_dashboards.yml
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/node.options
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/opensearch_dashboards.keystore
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
```

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
