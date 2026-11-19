# Migration from 4.x

A Wazuh 4.x deployment cannot be upgraded in place to 5.0. The Wazuh manager 5.0 is a new installation, with other paths (`/var/wazuh-manager` and `/etc/wazuh-manager` instead of `/var/ossec`), a new configuration format and a new agent protocol. The Wazuh indexer and the Wazuh dashboard are not upgraded either: they are installed new, and Filebeat is gone because the Wazuh manager 5.0 writes to the Wazuh indexer directly.

To move a deployment installed with the 4.x installation assistant to 5.0, install 5.0 with the 5.0 installation assistant, and then carry across what you need from 4.x:

- The agents, with [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/v5.0.0/tools/migration/wazuh-migrate-identity.py). It keeps the agent IDs, names and keys, the custom groups and the group of each agent, so the 4.x agents connect to 5.0 without enrolling again.
- The Server API users, roles and policies, if you want them. The same tool carries them.
- The configuration of the Wazuh manager, the rules, the decoders and the CDB lists. You rewrite them for 5.0.
- The alerts and the inventory stored in the Wazuh indexer, if you want them in 5.0, with a snapshot.

The Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-4x-to-5x.md) is the reference for the Wazuh manager part: what the tool does, the configuration, the agent upgrade and the historical data. The pages of this section are the installation assistant part of it:

- [All in one](./all-in-one.md)
- [Clusterized](./clusterized.md)

## What is kept

| Data | In 5.0 | How |
| ---- | ------ | --- |
| Agent IDs, names and keys | Kept. The agents connect without enrolling again. | `wazuh-migrate-identity.py` |
| Custom groups, their `agent.conf` and the group of each agent | Kept, also the groups given from the Wazuh manager or the Server API. | `wazuh-migrate-identity.py` |
| Registration date of the agents | Not kept. It is the date of the import. | |
| Server API users, roles and policies | Kept if you ask for them. | `wazuh-migrate-identity.py --with-rbac` |
| Enrollment password (`authd.pass`) | Kept if you ask for it. Only 4.x agents that still have to enroll need it. | `wazuh-migrate-identity.py --with-password` |
| Configuration of the Wazuh manager (`ossec.conf`, `local_internal_options.conf`, `api.yaml`) | Rewritten by hand. | [Manager configuration migration](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/manager-configuration-migration.md) |
| Custom rules, decoders and CDB lists | Rewritten by hand. | [Rules](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/rules-4x-to-5x.md), [decoders](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/xml-decoders-migration.md), [CDB lists](https://github.com/wazuh/wazuh/blob/v5.0.0/docs/guide/migration/cdb-to-kvdb-migration.md) |
| Certificates and passwords of the Wazuh components | Not kept. The 5.0 installation creates new ones. | |
| Wazuh indexer users and roles you created, and the Wazuh dashboard objects you saved | Not kept. Create them again in 5.0. | |
| Alerts and inventory in the Wazuh indexer | Not read by 5.0. Keep the 4.x Wazuh indexer to consult them, or restore a snapshot of them in 5.0. | [Historical data](#historical-data) |

The 5.0 agents rebuild their inventory, file integrity, SCA and vulnerability data in the 5.0 indices once they run 5.0. The 4.x agents keep sending events to the Wazuh manager 5.0 on port `1514`, with the limits listed in the Wazuh manager guide.

## Choose a path

There are two ways to migrate. Both install 5.0 with the installation assistant and carry the same data.

| | New hosts (recommended) | Same hosts |
| - | ----------------------- | ---------- |
| The 4.x deployment | Stays. Only its Wazuh manager is stopped. | Removed. |
| Rollback | Start the 4.x Wazuh manager again and point the agents back to it. | Only by installing 4.x again and restoring your backups. |
| 4.x alerts and inventory | Stay in the 4.x Wazuh indexer, which you can keep running to consult them. | Lost when 4.x is removed, unless you take a snapshot first and restore it in 5.0. |
| Downtime | From the stop of the 4.x Wazuh manager until the agents point to 5.0. | From the stop of the 4.x Wazuh manager until 5.0 is installed and the agents are imported. |
| Operating system | The new hosts run an operating system that 5.0 supports. | The hosts must already run an operating system that 5.0 supports. |
| Agent address | Point the agents to the new hosts: change the DNS name, move the address, or edit each agent. | Stays the same. |

While no Wazuh manager accepts them, the agents keep their events in a buffer of limited size. When the downtime is long, the oldest events are lost.

An agent upgraded to 5.0 connects to the Wazuh manager on port `1517`, which the 4.x Wazuh manager does not have, so it cannot go back to 4.x. Upgrade the agents only once the migration is checked and you no longer need the rollback.

## Before you start

- **Operating system and hardware.** The recommended operating systems for 5.0 are Amazon Linux 2023, Ubuntu 24.04 and 26.04, and Red Hat Enterprise Linux 9 and 10. An all-in-one host needs 8 GB of RAM, 4 CPU cores and 20 GB of free disk space. See [Requirements](../../ref/getting-started/requirements.md).
- **Ports.** The 4.x agents connect on `1514/tcp`, and enroll on `1515/tcp`. The agents upgraded to 5.0 connect and enroll on `1517/tcp`. Open the three ports to the agents on the 5.0 Wazuh manager nodes.
- **Agent address.** Every 4.x agent connects to the address in `<client><server><address>` of its `ossec.conf`. The Wazuh manager 5.0 must be reachable at that address, or you edit it on every agent. Once upgraded, a 5.0 agent also checks that this address is in the certificate of the Wazuh manager. On an all-in-one host, the certificate has the addresses of the network interfaces of the host. On a cluster, it has the `ip` and `dns` values of each Wazuh manager node in `config.yml`. Add a DNS name, a public or NAT address, or a load balancer with `-as|--agent-san` when you install 5.0. See [The address agents dial](../../ref/configuration/command-line-options.md#the-address-agents-dial).
- **The migration tool.** Download [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/v5.0.0/tools/migration/wazuh-migrate-identity.py) on the 4.x Wazuh manager host and on the 5.0 one. Run it with the Python that each Wazuh manager includes: `/var/ossec/framework/python/bin/python3` on 4.x and `/var/wazuh-manager/framework/python/bin/python3` on 5.0. Its options are in its [README](https://github.com/wazuh/wazuh/blob/v5.0.0/tools/migration/README.md).

    ```bash
    curl -fsSLo wazuh-migrate-identity.py https://raw.githubusercontent.com/wazuh/wazuh/v5.0.0/tools/migration/wazuh-migrate-identity.py
    ```

- **Backup.** Back up the 4.x deployment as described in the 4.x [Backup guide](https://documentation.wazuh.com/4.14/migration-guide/creating/wazuh-central-components.html). If the hosts are virtual machines, a snapshot of each one is the simplest rollback.

## Historical data

The Wazuh indexer 5.0 does not read the 4.x indices, and the Wazuh manager 5.0 writes to other ones: events to `wazuh-events-v5-*` and findings, the 5.0 replacement for alerts, to `wazuh-findings-v5-*`. The 4.x alerts (`wazuh-alerts-4.x-*`) and inventory (`wazuh-states-*`, with the name of the 4.x cluster or host at the end) stay where they are:

- On new hosts, they stay in the 4.x Wazuh indexer. Keep the 4.x Wazuh indexer and Wazuh dashboard running for as long as you need to consult them.
- On the same hosts, removing 4.x removes them. To keep them, take a snapshot before you remove 4.x and restore it in the Wazuh indexer 5.0, as described in [All in one](./all-in-one.md#same-host).

A restored index keeps the 4.x format. The steps of this guide restore it with the `restored-` prefix, so it does not mix with the 5.0 indices. To see it in the Wazuh dashboard 5.0, create an index pattern for it in **Dashboards Management** > **Index patterns**, for example `restored-wazuh-alerts-4.x-*` with `timestamp` as the time field.
