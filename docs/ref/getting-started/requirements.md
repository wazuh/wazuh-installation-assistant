# Requirements

The Wazuh installation assistant, Wazuh password tool, and Wazuh certs tools work on Linux systems, both x86_64/AMD64 and AARCH64/ARM64. For the Wazuh installation assistant and all associated tools to work, you must have the packages `systemd`, `grep`, `tar`, `coreutils`, `sed`, `procps`, `gawk`, and `curl` installed on the system.

## Hardware and operating system

Minimum and recommended hardware of each node, from the installation guides of the [Wazuh indexer](https://github.com/wazuh/wazuh-indexer-plugins/blob/5.0.0/docs/ref/getting-started/requirements.md), the [Wazuh manager](https://github.com/wazuh/wazuh/blob/5.0.0/docs/ref/getting-started/requirements.md) and the [Wazuh dashboard](https://github.com/wazuh/wazuh-dashboard-plugins/blob/5.0.0/docs/ref/getting-started/requirements.md):

| Component | Minimum | Recommended |
| --------- | ------- | ----------- |
| Wazuh indexer | 8 GB RAM, 4 CPU cores | 16 GB RAM, 8 CPU cores |
| Wazuh manager | 8 GB RAM, 4 CPU cores | |
| Wazuh dashboard | 4 GB RAM, 2 CPU cores, 2 GB of free disk space | 8 GB RAM, 4 CPU cores, 10 GB of free disk space |

A host that runs several components, such as an all-in-one installation, needs the resources of all of them.

The disk space of the Wazuh indexer depends on the events per second (EPS) of the monitored endpoints. To store 90 days of events, estimate 3.7 GB per server (0.25 EPS), 1.5 GB per workstation (0.1 EPS) and 7.4 GB per network device (0.5 EPS). The disk space of the Wazuh manager depends on the alert rate and the retention period.

The recommended operating systems for Wazuh 5.x are Amazon Linux 2023, Ubuntu 24.04 and 26.04, and Red Hat Enterprise Linux 9 and 10.

## Required ports

| Port | Component | Used by |
| ---- | --------- | ------- |
| 9200/tcp | Wazuh indexer | Other nodes |
| 9300/tcp | Wazuh indexer | Other Wazuh indexer nodes |
| 1516/tcp | Wazuh manager cluster | Other Wazuh manager nodes |
| 55000/tcp | Wazuh server API, on the master node | Wazuh dashboard |
| 443/tcp | Wazuh dashboard | Users |
| 1517/tcp | Wazuh manager (agent enrollment and connection) | Wazuh agents |
| 1514/tcp | Wazuh manager (legacy agent connection) | Wazuh 4.x agents |
| 1515/tcp | Wazuh manager (legacy agent enrollment) | Wazuh 4.x agents |

Wazuh 5.x agents only use port 1517. The Wazuh manager package opens ports 1514 and 1515 by default, so Wazuh 4.x agents can connect, enroll and be upgraded remotely. If no Wazuh agent runs 4.x, you can close them. The Wazuh server API listens on all network interfaces, except on an all-in-one installation, where it only listens on the local host. See [Network exposure](../../guide/security.md#network-exposure).
