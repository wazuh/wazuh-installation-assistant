# Requirements

The Wazuh installation assistant, Wazuh password tool, and Wazuh certs tools work on Linux systems, both x86_64/AMD64 and AARCH64/ARM64. For the Wazuh installation assistant and all associated tools to work, you must have the packages `systemd`, `grep`, `tar`, `coreutils`, `sed`, `procps`, `gawk`, and `curl` installed on the system.

## Hardware and operating system

Minimum and recommended hardware of each node, from the installation guides of the [Wazuh indexer](https://github.com/wazuh/wazuh-indexer-plugins/blob/5.0.0/docs/ref/getting-started/requirements.md), the [Wazuh manager](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/getting-started/requirements.md) and the [Wazuh dashboard](https://github.com/wazuh/wazuh-dashboard-plugins/blob/5.0.0/docs/ref/getting-started/requirements.md):

| Component | Minimum | Recommended |
| --------- | ------- | ----------- |
| Wazuh indexer | 8 GB RAM, 4 CPU cores | 16 GB RAM, 8 CPU cores |
| Wazuh manager | 8 GB RAM, 4 CPU cores | |
| Wazuh dashboard | 4 GB RAM, 2 CPU cores, 2 GB of free disk space | 8 GB RAM, 4 CPU cores, 10 GB of free disk space |

A host that runs several components needs 8 GB of RAM and 4 CPU cores, the minimum the installation assistant checks for an all-in-one installation, instead of the sum of the components. A host that only runs the Wazuh dashboard needs the dashboard figures above. The assistant warns below these figures and continues the installation.

An all-in-one installation needs at least 20 GB of free disk space. Right after the installation it uses about 12 GB: the Wazuh manager takes about 8.5 GB, 7.7 GB of them the vulnerability detection feed, which grows as the feed does.

The events stored by the Wazuh indexer have a limit: each category of events that receives data keeps up to 20 GB, plus the events of the last hour. For an all-in-one that monitors Linux and Windows endpoints, which use a single category of events, plan about 65 GB of free disk space: the installation, 20 GB of events, 20 GB of findings, and a margin so that the disk does not reach 85 % of use. Add about 25 GB for each other category of events that receives data. The findings are kept for at least 90 days, so plan more space if you expect many of them.

On a cluster of two or more Wazuh indexer nodes every index has a replica, which doubles the disk space of the Wazuh indexer.

The recommended operating systems for Wazuh 5.x are Amazon Linux 2023, Ubuntu 24.04 and 26.04, and Red Hat Enterprise Linux 9 and 10.

## Required ports

| Port | Component | Used by |
| ---- | --------- | ------- |
| 9200/tcp | Wazuh indexer | Other nodes |
| 9300/tcp | Wazuh indexer | Other Wazuh indexer nodes |
| 1516/tcp | Wazuh manager cluster | Other Wazuh manager nodes |
| 55000/tcp | Wazuh server API, on the master node | Wazuh dashboard |
| 443/tcp | Wazuh dashboard | Users |
| 1515/tcp | Wazuh manager (enrollment) | Wazuh agents |
| 1517/tcp | Wazuh manager (agent connection) | Wazuh agents |
