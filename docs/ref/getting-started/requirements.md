# Requirements

The Wazuh installation assistant, Wazuh password tool, and Wazuh certs tools work on Linux systems, both x86_64/AMD64 and AARCH64/ARM64. For the Wazuh installation assistant and all associated tools to work, you must have the packages `systemd`, `grep`, `tar`, `coreutils`, `sed`, `procps`, `gawk`, and `curl` installed on the system.

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
