# Clusterized

Upgrade a distributed Wazuh deployment (separate Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard nodes) following step-by-step instructions.

These steps upgrade a 5.x deployment to a later 5.x version. A 4.x deployment cannot be upgraded to 5.x, neither the Wazuh manager nor the Wazuh indexer and the Wazuh dashboard. Migrate it instead: install 5.0 and carry the agents, the configuration and the data across, as described in [Migration from 4.x](../migration/clusterized.md).

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

Follow the Wazuh Indexer upgrade steps described in the [all-in-one](./all-in-one.md#wazuh-indexer) guide. Those steps apply to both all-in-one and distributed deployments, and in a clusterized environment you must run them on each Wazuh Indexer node.

## Wazuh Manager

A 4.x Wazuh manager cannot be upgraded to 5.x: see [Migration from 4.x](../migration/clusterized.md). The 4.x agents connect to the Wazuh manager 5.x, and can be upgraded to 5.x later.

Follow the cluster upgrade procedure of the Wazuh manager package: [Cluster upgrade](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/ref/upgrade.md#cluster-upgrade) in the `wazuh/wazuh` repository. It covers the backup of the master and the worker nodes, the upgrade order and the checks on each node.

The master node accepts a worker node only when both run exactly the same Wazuh version, and refuses any other with error `3031`. From the first node upgraded until the master is upgraded too, the nodes on different versions are not connected to each other: each upgraded worker node stays out of the cluster, and only rejoins and synchronizes once the master node runs the same version. Do not wait for an upgraded worker node to synchronize before upgrading the next one, and keep that window short.

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
