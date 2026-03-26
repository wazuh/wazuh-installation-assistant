# Clusterized

Upgrade a distributed Wazuh deployment (separate Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard nodes) following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

Follow the Wazuh Indexer upgrade steps described in the [all-in-one](./all-in-one.md#wazuh-indexer) guide. Those steps apply to both all-in-one and distributed deployments, and in a clusterized environment you must run them on each Wazuh Indexer node.

## Wazuh Manager

### Cluster upgrade

For cluster deployments, upgrade nodes in this order:

1. Worker nodes (one at a time)
2. Master node (last)

This approach minimizes service disruption as agents can connect to other worker nodes while individual nodes are being upgraded.

#### Backup all nodes

**On the master node:**

```bash
BACKUP_DIR="/backup/wazuh-master-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR/db

# Full backup of master
sudo tar -czf $BACKUP_DIR/wazuh-master-etc.tar.gz -C /var/wazuh-manager etc/
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Verify backup
tar -tzf $BACKUP_DIR/wazuh-master-etc.tar.gz > /dev/null && echo "Master backup successful"
```

**On each worker node:**

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Configuration backup only
sudo tar -czf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager/etc wazuh-manager.conf local_internal_options.conf

# Verify backup
tar -tzf $BACKUP_DIR/wazuh-worker-config.tar.gz > /dev/null && echo "Worker backup successful"
```

#### Upgrade worker nodes

Upgrade worker nodes one at a time to maintain service availability.

**On each worker node:**

1. Check cluster status before upgrading:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
```

2. Upgrade the package:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

3. Verify the upgrade:

```bash
# Check service status
sudo systemctl status wazuh-manager

# Check cluster connectivity
sudo /var/wazuh-manager/bin/cluster_control -l

# Monitor cluster synchronization
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

4. Wait for synchronization before upgrading the next worker:

```bash
# Monitor synchronization status
sudo /var/wazuh-manager/bin/cluster_control -i

# Check cluster logs
sudo tail -50 /var/wazuh-manager/logs/cluster.log | grep -i sync
```

**Repeat for each remaining worker node**, ensuring each worker is fully synchronized before upgrading the next one.

#### Upgrade master node

Upgrade the master node last to ensure worker nodes can continue operating during their individual upgrades.

**On the master node:**

1. Verify all workers are upgraded and healthy:

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify all workers are connected
sudo /var/wazuh-manager/bin/cluster_control -i
```

2. Upgrade the package:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

3. Verify the upgrade:

```bash
# Check service status
sudo systemctl status wazuh-manager

# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check logs
sudo tail -50 /var/wazuh-manager/logs/wazuh-manager.log
sudo tail -50 /var/wazuh-manager/logs/cluster.log
```

4. Verify cluster synchronization:

```bash
# Check that all workers are synchronized with the master
sudo /var/wazuh-manager/bin/cluster_control -l

# Monitor cluster logs on master
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

#### Verify cluster upgrade

After upgrading all nodes, perform comprehensive verification:

**On the master node:**

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Check cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check database integrity
sudo sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"

# Monitor logs for errors
sudo tail -100 /var/wazuh-manager/logs/wazuh-manager.log | grep -i error
sudo tail -100 /var/wazuh-manager/logs/cluster.log | grep -i error
```

**On each worker node:**

```bash
# Check cluster connectivity
sudo /var/wazuh-manager/bin/cluster_control -l

# Monitor logs
sudo tail -50 /var/wazuh-manager/logs/cluster.log
```

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
