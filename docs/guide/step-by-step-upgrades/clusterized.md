# Clusterized

Upgrade a distributed Wazuh deployment (separate Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard nodes) following step-by-step instructions.

> [!NOTE]
> You need root user privileges to run all the commands described below.

## Wazuh Indexer

Follow the Wazuh Indexer upgrade steps described in the [all-in-one](./all-in-one.md#wazuh-indexer) guide. Those steps apply to both all-in-one and distributed deployments, and in a clusterized environment you must run them on each Wazuh Indexer node.

## Wazuh Manager

> [!WARNING]
> Upgrading the Wazuh manager from 5.1.0 RC 1 or an earlier pre-release is not supported ([wazuh/wazuh#40338](https://github.com/wazuh/wazuh/issues/40338)), and the package does not block it. RC 1 kept its configuration in `/var/wazuh-manager/etc`, and the RC 2 package only preserves `/etc/wazuh-manager`: the upgrade regenerates `wazuh-manager.conf`, leaves `client.keys` empty and, with no `certs/remoted.pem` in place, mints a new CA. The agents lose their keys and stop trusting the manager. Install the Wazuh manager again instead.

Follow the cluster upgrade procedure of the Wazuh manager package: [Cluster upgrade](https://github.com/wazuh/wazuh/blob/5.1.0/docs/ref/upgrade.md#cluster-upgrade) in the `wazuh/wazuh` repository. It covers the backup of the master and the worker nodes, the upgrade order and the checks on each node.

The master node accepts a worker node only when both run exactly the same Wazuh version, and refuses any other with error `3031`. From the first node upgraded until the master is upgraded too, the nodes on different versions are not connected to each other: each upgraded worker node stays out of the cluster, and only rejoins and synchronizes once the master node runs the same version. Do not wait for an upgraded worker node to synchronize before upgrading the next one, and keep that window short.

## Wazuh Dashboard

The Wazuh Dashboard can't be clusterized. Refer to the [all-in-one](./all-in-one.md#wazuh-dashboard) upgrade guide.
