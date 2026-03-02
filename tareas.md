
## Description

Review all changes made to the Wazuh manager package to avoid installation problems in the assisted installation.

---

### 1. Installation Directory

| Before | After |
|--------|-------|
| `/var/ossec` | `/var/wazuh-manager` |

---

### 2. Manager Daemon Binaries

All manager-side daemons/tools/scripts have been renamed from `wazuh-*` to `wazuh-manager-*`:

| Before | After |
|--------|-------|
| `wazuh-analysisd` | `wazuh-manager-analysisd` |
| `wazuh-apid` | `wazuh-manager-apid` |
| `wazuh-authd` | `wazuh-manager-authd` |
| `wazuh-clusterd` | `wazuh-manager-clusterd` |
| `wazuh-db` | `wazuh-manager-db` |
| `wazuh-modulesd` | `wazuh-manager-modulesd` |
| `wazuh-monitord` | `wazuh-manager-monitord` |
| `wazuh-remoted` | `wazuh-manager-remoted` |
| `wazuh-control` | `wazuh-manager-control` |
| `wazuh-keystore` | `wazuh-manager-keystore` |

> **Note:** Agent-side binaries (`wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-execd`, `wazuh-modulesd`) are now exclusively agent binaries and are no longer installed with the manager.

---

### 3. Python Scripts (Framework / API)

| Before | After |
|--------|-------|
| `api/scripts/wazuh_apid.py` | `api/scripts/wazuh_manager_apid.py` |
| `framework/scripts/wazuh_clusterd.py` | `framework/scripts/wazuh_manager_clusterd.py` |

---

### 4. Configuration Files

| Before | After |
|--------|-------|
| `etc/ossec.conf` | `etc/wazuh-manager.conf` |
| `etc/ossec-server.conf` | `etc/ossec-server.conf` (updated internally) |
| `api/tools/env/wazuh-manager/xml/master_ossec_conf.xml` | `api/tools/env/wazuh-manager/xml/master_wazuh-manager_conf.xml` |
| `api/tools/env/wazuh-manager/xml/worker_ossec_conf.xml` | `api/tools/env/wazuh-manager/xml/worker_wazuh-manager_conf.xml` |
| `framework/wazuh/core/tests/data/configuration/ossec.conf` | `framework/wazuh/core/tests/data/configuration/wazuh-manager.conf` |

---

### 5. XML Configuration Root Tag

Manager-scoped config files now use a different root tag. Agent config files remain unchanged.

| Before | After | Scope |
|--------|-------|-------|
| `<ossec_config>` | `<wazuh_config>` | Manager only |
| `<ossec_config>` | `<ossec_config>` | Agent (no change) |
| `<client><server>` | `<client><manager>` | Agent |


---

### 6. Certificate Files

| Before | After |
|--------|-------|
| `etc/certs/server.pem` | `etc/certs/manager.pem` |
| `etc/certs/server-key.pem` | `etc/certs/manager-key.pem` |

---

### 7. Log Files

| Before | After |
|--------|-------|
| `ossec.log` | `wazuh-manager.log` |
| `ossec.json` | `wazuh-manager.json` |

---

### 8. System User and Group

| Before | After |
|--------|-------|
| User: `wazuh` | User: `wazuh-manager` |
| Group: `wazuh` | Group: `wazuh-manager` |

---

### 9. Files and directories permissions

Manager binaries under `/var/wazuh-manager/bin/` have been hardened:


| Path (relative to `/var/wazuh-manager/`) | Owner:Group | Mode | Rule | Notes |
|------------------------------------------|-------------|------|------|-------|
| **Binaries and executables** | | | | |
| `bin/wazuh-manager-analysisd` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-authd` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-remoted` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-db` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-modulesd` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-monitord` | `root:root` | `750` | Rule 1 | Root-launched daemon binary |
| `bin/wazuh-manager-apid` | `root:wazuh-manager` | `750` | **Exception** | See [exception 6](#exception-6-apid-and-clusterd-binaries) |
| `bin/wazuh-manager-clusterd` | `root:wazuh-manager` | `750` | **Exception** | See [exception 6](#exception-6-apid-and-clusterd-binaries) |
| `bin/wazuh-manager-control` | `root:root` | `750` | Rule 1 | Main control entry point |
| `bin/wazuh-manager-keystore` | `root:root` | `750` | Rule 1 | Admin tool |
| `bin/agent_groups` | `root:wazuh-manager` | `750` | Rule 2 | Wrapper used by framework/API runtime |
| `bin/agent_upgrade` | `root:wazuh-manager` | `750` | Rule 2 | Wrapper used by framework/API runtime |
| `bin/cluster_control` | `root:wazuh-manager` | `750` | Rule 2 | Wrapper used by framework/API runtime |
| `bin/rbac_control` | `root:wazuh-manager` | `750` | Rule 2 | Wrapper used by framework/API runtime |
| `bin/verify-agent-conf` | `root:wazuh-manager` | `750` | **Exception** | See [exception 1](#exception-1-verify-agent-conf) |
| **Active response scripts shipped with manager** | | | | |
| `active-response/bin/restart.sh` | `root:wazuh-manager` | `750` | Rule 2 | Required by active-response restart flow |
| `active-response/bin/kaspersky.py` | `root:wazuh-manager` | `750` | Rule 2 | Kept as executable script artifact |
| **Shared libraries** | | | | |
| `lib/*.so` | `root:wazuh-manager` | `750` | **Exception** | See [exception 2](#exception-2-shared-libraries) |
| **Framework and API scripts** | | | | |
| `framework/**/*.py` | `root:wazuh-manager` | `640` | **Exception** | See [exception 3](#exception-3-python-framework-and-api-scripts) |
| `api/scripts/*.py` | `root:wazuh-manager` | `640` | **Exception** | See [exception 3](#exception-3-python-framework-and-api-scripts) |
| **Static configuration (not expected to be service-writable)** | | | | |
| `etc/internal_options.conf` | `root:wazuh-manager` | `640` | Rule 1 | Runtime read-only configuration |
| `etc/local_internal_options.conf` | `root:wazuh-manager` | `640` | Rule 1 | Runtime read-only configuration |
| `etc/sslmanager.cert` | `root:root` | `640` | Rule 1 | Certificate material |
| `etc/sslmanager.key` | `root:root` | `640` | Rule 1 | Private key material |
| `etc/localtime` | `root:root` | `640` | Rule 1 | Local timezone copy |
| `VERSION.json` | `root:wazuh-manager` | `440` | **Exception** | See [exception 4](#exception-4-versionjson) |
| **Runtime-writable configuration/data files** | | | | |
| `etc/wazuh-manager.conf` | `root:wazuh-manager` | `660` | **Exception** | See [exception 5](#exception-5-runtime-written-root-owned-files) |
| `etc/client.keys` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Updated at enrollment/runtime |
| `etc/shared/agent-template.conf` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Group config template |
| `etc/shared/default/agent.conf` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Group agent configuration |
| `api/configuration/api.yaml` | `root:wazuh-manager` | `660` | **Exception** | See [exception 5](#exception-5-runtime-written-root-owned-files) |
| `var/db/mitre.db` | `root:wazuh-manager` | `660` | **Exception** | See [exception 5](#exception-5-runtime-written-root-owned-files) |
| **Engine runtime data** | | | | |
| `engine/` | `root:root` | `755` | **Exception** | Traversal path for engine binaries and store trees |
| `engine/kvdb/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Runtime KV storage |
| `engine/mmdb/` | `root:wazuh-manager` | `770` | Rule 2 | Container dir for GeoIP files |
| `engine/mmdb/*.mmdb` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Replaced/updated at runtime |
| `engine/outputs/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Runtime-managed outputs |
| `engine/outputs/*.yml` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Runtime-generated/updated output config |
| `engine/store/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Runtime store root |
| `engine/store/**` (directories) | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Runtime-created/updated store dirs |
| `engine/store/**` (files) | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Runtime-created/updated store files |
| `engine/store/geo/` | `root:root` | `755` | **Exception** | Preserved traversal path |
| `engine/store/geo/mmdb/` | `root:wazuh-manager` | `770` | Rule 2 | Managed mmdb subdirectory |
| **Queue and sockets** | | | | |
| `queue/` (base dir) | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Service runtime root |
| `queue/alerts/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Alert event queue |
| `queue/sockets/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | UNIX socket directory |
| `queue/rids/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Agent counters |
| `queue/cluster/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Cluster runtime queue |
| `queue/tasks/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Modules task queue |
| `queue/vd/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Vulnerability detector runtime |
| `queue/indexer/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Indexer queue |
| `queue/router/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Router queue |
| `queue/db/` | `wazuh-manager:wazuh-manager` | `750` | Rule 2 | DB runtime files/sockets |
| `queue/keystore/` | `wazuh-manager:wazuh-manager` | `750` | Rule 2 | Keystore runtime data |
| `queue/tzdb/` | `wazuh-manager:wazuh-manager` | `750` | Rule 2 | Timezone DB runtime assets |
| `queue/agents-timestamp` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Updated by enrollment/runtime |
| **Logs** | | | | |
| `logs/` (base dir) | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Runtime log root |
| `logs/*.log`, `logs/*.json` | `wazuh-manager:wazuh-manager` | `660` | Rule 2 | Daemon log files |
| `logs/api/`, `logs/alerts/`, `logs/archives/`, `logs/cluster/`, `logs/firewall/`, `logs/wazuh/` | `wazuh-manager:wazuh-manager` | `750` | Rule 2 | Log subdirectories |
| **Temporary and variable data** | | | | |
| `tmp/` | `root:wazuh-manager` | `1770` | **Exception** | Sticky bit (`+t`) required |
| `var/run/` | `root:wazuh-manager` | `770` | **Exception** | PID/runtime files created early |
| `var/multigroups/` | `wazuh-manager:wazuh-manager` | `770` | Rule 2 | Cluster/group merge runtime |
| `var/upgrade/` | `root:wazuh-manager` | `770` | **Exception** | Upgrade staging area |
| `var/db/` | `root:wazuh-manager` | `770` | Rule 2 | Runtime DB parent directory |
| `var/download/` | `root:wazuh-manager` | `770` | Rule 2 | Runtime download directory |
| `var/selinux/` | `root:wazuh-manager` | `770` | Rule 2 | SELinux policy assets |
| `var/selinux/wazuh.pp` | `root:wazuh-manager` | `640` | Rule 1 | Policy file |
| **Backup** | | | | |
| `backup/db/`, `backup/agents/` | `wazuh-manager:wazuh-manager` | `750` | Rule 2 | Runtime backup content |
| `backup/shared/` | `root:wazuh-manager` | `750` | Rule 1 | Shared backup path |


---

### 10. Terminology: "server" → "manager"

All user-facing references to `server` (as a synonym for manager) have been renamed to `manager`:

- Installation type prompt: previously `server`, now `manager`
- Build system output: `Done building manager` (was `server`)
- `TARGET=server` in `src/Makefile` is still accepted but internally remapped to `TARGET=manager`
- `USER_AGENT_SERVER_IP` → `USER_AGENT_MANAGER_IP` (in `preloaded-vars.conf`)
- Engine config keys renamed from `server` to `manager`
- All multilingual installation templates (`etc/templates/*/messages.txt`) updated across: `br`, `cn`, `de`, `el`, `en`, `es`, `fr`, `hu`, `it`, `jp`, `nl`, `pl`, `ru`, `sr`, `tr`

---


## Tasks
- [ ] Implement the necessary changes to the Wazuh installation assistant
- [ ] Implement the necessary changes to the Wazuh installation assistant tests
- [ ] Verify the complete deployment of the core components in 5.0.0


