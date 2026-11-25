# Clusterized

Upgrade a distributed Wazuh deployment (separate Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard nodes) following step-by-step instructions.

These steps upgrade a 5.x deployment to a later 5.x version. A 4.x deployment cannot be upgraded to 5.x, neither the Wazuh manager nor the Wazuh indexer and the Wazuh dashboard. Migrate it instead: install 5.0 and carry the agents, the configuration and the data across, as described in [Migration from 4.x](../migration/clusterized.md).

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

Follow the Wazuh Indexer upgrade steps described in the [all-in-one](./all-in-one.md#wazuh-indexer) guide. Those steps apply to both all-in-one and distributed deployments, and in a clusterized environment you must run them on each Wazuh Indexer node.

The [all-in-one](./all-in-one.md#wazuh-indexer) steps upgrade the nodes one after another, but keep shard allocation limited to primaries until the last node is upgraded, so replicas are not rebuilt in between. To re-enable allocation and let the cluster recover after each node instead, upgrade one node at a time:

1. Run [Preparing the upgrade](./all-in-one.md#preparing-the-upgrade) against a node that keeps running.
2. On the node to upgrade, run steps 1 to 3 of [Upgrading the Wazuh indexer nodes](./all-in-one.md#upgrading-the-wazuh-indexer-nodes).
3. Run the [post-upgrade actions](./all-in-one.md#post-upgrade-actions): check that the node is back in the cluster, re-enable shard allocation, and wait until the status is `green`. When the new version bundles a newer OpenSearch version, the cluster cannot place a replica on a node that still runs the older version, so it can stay `yellow` until the last node is upgraded: wait until no shard is initializing or relocating (`_cluster/health` shows `initializing_shards` and `relocating_shards` at `0`) and continue. After the last node, wait for `green`.
4. Repeat steps 1 to 3 on the next node.

## Wazuh Manager

A 4.x Wazuh manager cannot be upgraded to 5.x: see [Migration from 4.x](../migration/clusterized.md). The 4.x agents connect to the Wazuh manager 5.x, and can be upgraded to 5.x later.

Follow the cluster upgrade procedure of the Wazuh manager package: [Cluster upgrade](https://github.com/wazuh/wazuh/blob/5.1.0/docs/ref/upgrade.md#cluster-upgrade) in the `wazuh/wazuh` repository. It covers the backup of the master and the worker nodes, the upgrade order and the checks on each node.

The master node accepts a worker node only when both run exactly the same Wazuh version, and refuses any other with error `3031`. From the first node upgraded until the master is upgraded too, the nodes on different versions are not connected to each other: each upgraded worker node stays out of the cluster, and only rejoins and synchronizes once the master node runs the same version. Do not wait for an upgraded worker node to synchronize before upgrading the next one, and keep that window short.

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
