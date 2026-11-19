# Clusterized

Upgrade a distributed Wazuh deployment (separate Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard nodes) following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

Follow the Wazuh Indexer upgrade steps described in the [all-in-one](./all-in-one.md#wazuh-indexer) guide. Those steps apply to both all-in-one and distributed deployments, and in a clusterized environment you must run them on each Wazuh Indexer node.

The [all-in-one](./all-in-one.md#wazuh-indexer) steps stop every Wazuh indexer node before upgrading them, so the cluster is unavailable until the last node is back. To keep the cluster available, upgrade one node at a time instead:

1. Run [Preparing the upgrade](./all-in-one.md#preparing-the-upgrade) against a node that keeps running.
2. On the node to upgrade, run steps 1 to 3 of [Upgrading the Wazuh indexer nodes](./all-in-one.md#upgrading-the-wazuh-indexer-nodes).
3. Run the [post-upgrade actions](./all-in-one.md#post-upgrade-actions): check that the node is back in the cluster, re-enable shard allocation, and wait until the status is `green`.
4. Repeat steps 1 to 3 on the next node.

## Wazuh Manager

**Important**: Upgrading the Wazuh **manager** from version 4.x to 5.x is **not supported**. For manager major version upgrades, a fresh installation is required. However, Wazuh **agents** support upgrades from 4.x to 5.x and can connect to a 5.x manager.

Follow the cluster upgrade procedure of the Wazuh manager package: [Cluster upgrade](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/ref/upgrade.md#cluster-upgrade) in the `wazuh/wazuh` repository. It covers the backup of the master and the worker nodes, the upgrade order and the checks on each node.

The master node accepts a worker node only when both run exactly the same Wazuh version, and refuses any other with error `3031`. From the first node upgraded until the master is upgraded too, the nodes on different versions are not connected to each other: each upgraded worker node stays out of the cluster, and only rejoins and synchronizes once the master node runs the same version. Do not wait for an upgraded worker node to synchronize before upgrading the next one, and keep that window short.

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
