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
mkdir -p $BACKUP_DIR/db

# Full backup of master
tar -czf $BACKUP_DIR/wazuh-master-etc.tar.gz -C /var/wazuh-manager etc/
sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Verify backup
tar -tzf $BACKUP_DIR/wazuh-master-etc.tar.gz > /dev/null && echo "Master backup successful"
```

**On each worker node:**

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR

# Configuration backup only
tar -czf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager/etc wazuh-manager.conf local_internal_options.conf

# Verify backup
tar -tzf $BACKUP_DIR/wazuh-worker-config.tar.gz > /dev/null && echo "Worker backup successful"
```

### Download package

Check the wazuh-manager documentation for more information about downloading packages.

#### Upgrade worker nodes

Upgrade worker nodes one at a time to maintain service availability.

**On each worker node:**

1. Check cluster status before upgrading:

```bash
/var/wazuh-manager/bin/cluster_control -l
```

1. Download the package. Check the wazuh-manager documentation for more information about downloading packages.

2. Upgrade the package:

**Debian-based platforms:**

```bash
apt install ./wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
yum install ./wazuh-manager-*.rpm
```

4. Verify the upgrade:

```bash
# Check service status
systemctl status wazuh-manager

# Check cluster connectivity
/var/wazuh-manager/bin/cluster_control -l

# Monitor cluster synchronization
tail -f /var/wazuh-manager/logs/cluster.log
```

5. Wait for synchronization before upgrading the next worker:

```bash
# Monitor synchronization status
/var/wazuh-manager/bin/cluster_control -i

# Check cluster logs
tail -50 /var/wazuh-manager/logs/cluster.log | grep -i sync
```

**Repeat for each remaining worker node**, ensuring each worker is fully synchronized before upgrading the next one.

#### Upgrade master node

Upgrade the master node last to ensure worker nodes can continue operating during their individual upgrades.

**On the master node:**

1. Verify all workers are upgraded and healthy:

```bash
# Check cluster status
/var/wazuh-manager/bin/cluster_control -l

# Verify all workers are connected
/var/wazuh-manager/bin/cluster_control -i
```

1. Download the package. Check the wazuh-manager documentation for more information about downloading packages.

2. Upgrade the package:

**Debian-based platforms:**

```bash
apt install ./wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
yum install ./wazuh-manager-*.rpm
```

4. Verify the upgrade:

```bash
# Check service status
systemctl status wazuh-manager

# Check cluster status
/var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
/var/wazuh-manager/bin/cluster_control -i

# Check logs
tail -50 /var/wazuh-manager/logs/wazuh-manager.log
tail -50 /var/wazuh-manager/logs/cluster.log
```

5. Verify cluster synchronization:

```bash
# Check that all workers are synchronized with the master
/var/wazuh-manager/bin/cluster_control -l

# Monitor cluster logs on master
tail -f /var/wazuh-manager/logs/cluster.log
```

#### Verify cluster upgrade

After upgrading all nodes, perform comprehensive verification:

**On the master node:**

```bash
# Check cluster status
/var/wazuh-manager/bin/cluster_control -l

# Check cluster health
/var/wazuh-manager/bin/cluster_control -i

# Check database integrity
sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"

# Monitor logs for errors
tail -100 /var/wazuh-manager/logs/wazuh-manager.log | grep -i error
tail -100 /var/wazuh-manager/logs/cluster.log | grep -i error
```

**On each worker node:**

```bash
# Check cluster connectivity
/var/wazuh-manager/bin/cluster_control -l

# Monitor logs
tail -50 /var/wazuh-manager/logs/cluster.log
```

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
