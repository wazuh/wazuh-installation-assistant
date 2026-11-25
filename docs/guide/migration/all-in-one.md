# All in one

Migrate an all-in-one deployment installed with the 4.x installation assistant to 5.0. Read [Migration from 4.x](./migration.md) first: it lists what is kept and the differences between the two paths.

> [!NOTE]
> You need root user privileges to run all the commands described below.

The steps use `wazuh-migrate-identity.py` with `--with-rbac`, which also carries the Server API users, roles and policies. Leave it out on both commands if you don't need them. If 4.x agents must still enroll after the migration with the 4.x enrollment password, add `--with-password` to both commands too.

## New host

The 4.x host keeps running until you remove it. Only its Wazuh manager is stopped.

1. **Install 5.0 on the new host.** Follow [All in one](../installation-assistant-deployments/all-in-one.md). If the agents will reach the new host through a DNS name, or through an address that is not on its network interfaces, add it with `-as|--agent-san`:

    ```bash
    curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.1.0.sh && sudo bash ./wazuh-install-5.1.0.sh -a -as <AGENT_ADDRESS>
    ```

    Do not point any agent to the new host yet: the Wazuh manager does not know them until the import of step 3. The 4.x agents that reach it before try to enroll again, and an agent that enrolls in that time, such as a new agent, takes an ID that the import needs.

2. **Stop the 4.x Wazuh manager and export the agents.** On the 4.x host, stop the Wazuh manager and disable it, so it does not start again after a reboot. The Wazuh indexer and the Wazuh dashboard keep running, so you can still consult the 4.x data. From now on, the agents cannot send events until step 5.

    ```bash
    systemctl stop wazuh-manager
    systemctl disable wazuh-manager
    ```

    Download [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/5.1.0/tools/migration/wazuh-migrate-identity.py) and run the export first with `--dry-run`. It ends with a **Review before going on** list: the `agent.conf` settings that 5.0 agents ignore, the files the tool leaves behind, and the features of the 4.x `ossec.conf` that stop with the migration, each one with the guide that rebuilds it. Then run the export:

    ```bash
    curl -fsSLo wazuh-migrate-identity.py https://raw.githubusercontent.com/wazuh/wazuh/5.1.0/tools/migration/wazuh-migrate-identity.py
    /var/ossec/framework/python/bin/python3 wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/ossec/framework/python/bin/python3 wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac
    ```

    Copy the `/root/wazuh-4x-bundle` directory and `wazuh-migrate-identity.py` to `/root` of the new host, for example with `scp`. The bundle holds the agent keys and the password hashes of the Server API users: handle it like a password.

3. **Import the agents.** On the new host, run the import first with `--dry-run`, then for real. The tool connects to the Server API on `localhost` with the `wazuh` user, and reads its password from `/etc/wazuh-manager/export/credentials.env`.

    ```bash
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac
    ```

    The import ends with `Inserted N of N agent(s)`, where `N` is the number of agents.

4. **Restart the Wazuh manager and check the import.** With `--with-rbac`, the Server API loads the 4.x users when it starts again. From then on, the `wazuh` and `wazuh-internal-client` users have their 4.x passwords, and the Wazuh dashboard, which uses the password in `/etc/wazuh-manager/export/credentials.env`, cannot log in. Set both back to the passwords of the 5.0 installation:

    ```bash
    systemctl restart wazuh-manager
    sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh -p -
    sed -n 's/^WAZUH_MANAGER_WUI_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh-internal-client -p -
    ```

    The Server API users you created keep their 4.x passwords. Then compare the Wazuh manager with the bundle:

    ```bash
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py check /root/wazuh-4x-bundle
    ```

    The output ends with `The target matches the bundle.`

5. **Point the agents to the new host.** Change the DNS name the agents use, move the address to the new host, or edit `<client><server><address>` in the `ossec.conf` of each agent and restart it. Do not remove `client.keys` on the agents. Each agent connects on port `1514` with its key, without enrolling again. See [Check the migration](#check-the-migration).

6. **Migrate the configuration.** Rewrite the 4.x configuration of the Wazuh manager, your rules, decoders and CDB lists for 5.0, as described in the Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.1.0/docs/guide/migration/manager-4x-to-5x.md#4-migrate-the-configuration). The 4.x files are still in `/var/ossec` on the 4.x host. If the review list of the export asks you to keep the rootcheck files of the `default` group, copy the `*.txt` files of `/var/ossec/etc/shared/default/` on the 4.x host to `/etc/wazuh-manager/shared/default/` on the new host, with owner `wazuh-manager:wazuh-manager` and mode `0660`.

To roll back, stop the Wazuh manager 5.0, start the 4.x one again with `systemctl enable --now wazuh-manager`, and point the agents back to the 4.x host. This works only for agents that still run 4.x.

When you no longer need the 4.x data or the rollback, remove the 4.x deployment with the 4.x installation assistant: `bash wazuh-install.sh -u` on the 4.x host.

## Same host

On the same host, 4.x is removed before 5.0 is installed. Before you choose this path, check its costs:

- The downtime lasts from the stop of the 4.x Wazuh manager until the agents are imported in 5.0.
- There is no simple rollback: removing 4.x removes its configuration and its data. To go back, you install 4.x again and restore your backups.
- The host must already run an operating system that 5.0 supports. See [Before you start](./migration.md#before-you-start).
- The 4.x alerts and inventory are lost unless you take the snapshot of step 2.

The steps below keep the 4.x files in `/root` and the snapshot in `/var/backups/wazuh-4x-snapshots`, outside the directories that the uninstall removes.

1. **Back up the 4.x deployment.** See [Before you start](./migration.md#before-you-start).

2. **Take a snapshot of the 4.x indices.** Skip this step if you don't need the 4.x alerts and inventory in 5.0. If the 4.x deployment was first installed with Wazuh 4.3 or earlier, read [Historical data](./migration.md#historical-data) first: the Wazuh indexer 5.0 cannot restore the indices created back then. The Wazuh indexer can only write snapshots to a directory listed in `path.repo`, so add it and restart the Wazuh indexer:

    ```bash
    mkdir -p /var/backups/wazuh-4x-snapshots
    chown wazuh-indexer:wazuh-indexer /var/backups/wazuh-4x-snapshots
    printf '\npath.repo: ["/var/backups/wazuh-4x-snapshots"]\n' >> /etc/wazuh-indexer/opensearch.yml
    systemctl restart wazuh-indexer
    ```

    The 4.x `admin` password is in the `wazuh-install-files.tar` file that the 4.x installation assistant created:

    ```bash
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
    ```

    Wait until the Wazuh indexer is ready after the restart, replacing `<ADMIN_PASSWORD>`. Before that, it answers `OpenSearch Security not initialized` and the snapshot fails. If the command does not end after a few minutes, check the password:

    ```bash
    until curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -u admin:<ADMIN_PASSWORD> "https://127.0.0.1:9200/_cluster/health" | grep -q '"status"'; do sleep 5; done
    ```

    Register the directory and take the snapshot:

    ```bash
    curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u admin:<ADMIN_PASSWORD> -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x" \
    -H 'Content-Type: application/json' -d '{"type":"fs","settings":{"location":"/var/backups/wazuh-4x-snapshots"}}'
    curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u admin:<ADMIN_PASSWORD> -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x/wazuh-4x?wait_for_completion=true" \
    -H 'Content-Type: application/json' -d '{"indices":"wazuh-alerts-4.x-*,wazuh-archives-4.x-*,wazuh-states-*","include_global_state":false}'
    ```

    The snapshot is complete when the output shows `"state":"SUCCESS"`.

3. **Stop the 4.x Wazuh manager and export the agents.** From now on, the agents cannot send events until step 7. Download [`wazuh-migrate-identity.py`](https://github.com/wazuh/wazuh/blob/5.1.0/tools/migration/wazuh-migrate-identity.py) and run the export first with `--dry-run`. It ends with a **Review before going on** list: the `agent.conf` settings that 5.0 agents ignore, the files the tool leaves behind, and the features of the 4.x `ossec.conf` that stop with the migration, each one with the guide that rebuilds it. Then run the export:

    ```bash
    systemctl stop wazuh-manager
    curl -fsSLo /root/wazuh-migrate-identity.py https://raw.githubusercontent.com/wazuh/wazuh/5.1.0/tools/migration/wazuh-migrate-identity.py
    /var/ossec/framework/python/bin/python3 /root/wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/ossec/framework/python/bin/python3 /root/wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-rbac
    ```

    The bundle holds the agent keys and the password hashes of the Server API users: handle it like a password. Also keep the 4.x files you need in step 9, because the uninstall removes `/var/ossec`:

    ```bash
    tar -czf /root/wazuh-4x-config.tar.gz -C /var/ossec etc/ossec.conf etc/local_internal_options.conf etc/rules etc/decoders etc/lists etc/shared api/configuration/api.yaml
    ```

4. **Remove 4.x.** Run the 4.x installation assistant with `-u`. It removes the Wazuh manager, the Wazuh indexer with its data, Filebeat and the Wazuh dashboard. If you no longer have `wazuh-install.sh`, download it again with `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh`.

    ```bash
    bash wazuh-install.sh -u
    ```

    The Wazuh manager 5.0 package refuses to install while a 4.x Wazuh manager is on the host.

5. **Install 5.0 with the agent ports closed.** Follow [All in one](../installation-assistant-deployments/all-in-one.md), with two variables that keep the agents away from the Wazuh manager until the import. `WAZUH_REMOTE_HTTPS_BIND_ADDR='127.0.0.1'` makes the agent listener on port `1517` listen on the local host only, and `WAZUH_REMOTE_LEGACY_ENABLED='no'` closes the ports `1514` and `1515` of the 4.x agents. With `sudo`, write the variables after `sudo`, so they reach the Wazuh manager package:

    ```bash
    curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.1.0.sh
    sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='127.0.0.1' WAZUH_REMOTE_LEGACY_ENABLED='no' bash ./wazuh-install-5.1.0.sh -a
    ```

    Meanwhile, the agents log `(1216): Unable to connect` and `(1208): Unable to connect to enrollment service`, and keep trying. Without the variables, the Wazuh manager accepts agents before the import: the 4.x agents try to enroll again, and an agent that enrolls in that time, such as a new agent, takes an ID that the import needs.

6. **Import the agents.** Run the import first with `--dry-run`, then for real. The tool connects to the Server API on `localhost` with the `wazuh` user, and reads its password from `/etc/wazuh-manager/export/credentials.env`.

    ```bash
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac --dry-run
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-rbac
    ```

    The import ends with `Inserted N of N agent(s)`, where `N` is the number of agents.

7. **Open the agent ports and check the import.** In `/etc/wazuh-manager/wazuh-manager.conf`, set `<bind_addr>` of the `<https>` block back to `0.0.0.0`, and `<enabled>` of the `<legacy>` block to `yes`:

    ```xml
    <remote>
      <https>
        <bind_addr>0.0.0.0</bind_addr>
        ...
      </https>
      <legacy>
        <enabled>yes</enabled>
        ...
      </legacy>
    </remote>
    ```

    This command changes only these two values:

    ```bash
    sed -i -e '/<https>/,/<\/https>/s|<bind_addr>.*</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|' \
    -e '/<legacy>/,/<\/legacy>/s|<enabled>.*</enabled>|<enabled>yes</enabled>|' /etc/wazuh-manager/wazuh-manager.conf
    ```

    Check the file and restart the Wazuh manager:

    ```bash
    /var/wazuh-manager/bin/wazuh-manager-conf validate
    systemctl restart wazuh-manager
    ```

    With `--with-rbac`, the Server API loads the 4.x users when it starts again. From then on, the `wazuh` and `wazuh-internal-client` users have their 4.x passwords, and the Wazuh dashboard, which uses the password in `/etc/wazuh-manager/export/credentials.env`, cannot log in. Set both back to the passwords of the 5.0 installation:

    ```bash
    sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh -p -
    sed -n 's/^WAZUH_MANAGER_WUI_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env | /var/wazuh-manager/bin/rbac_control change-password -u wazuh-internal-client -p -
    ```

    The Server API users you created keep their 4.x passwords. Then compare the Wazuh manager with the bundle:

    ```bash
    /var/wazuh-manager/framework/python/bin/python3 /root/wazuh-migrate-identity.py check /root/wazuh-4x-bundle
    ```

    The output ends with `The target matches the bundle.` The agents connect again on port `1514` with their keys, without enrolling again. See [Check the migration](#check-the-migration).

8. **Restore the snapshot.** Skip this step if you did not take the snapshot of step 2. The Wazuh indexer 5.0 is ready for snapshots in `/var/lib/wazuh-indexer/backup`, the directory that its `opensearch.yml` lists in `path.repo`. Do not add another `path.repo` line: the Wazuh indexer refuses to start with `Duplicate field 'path.repo'`. Move the snapshot into that directory and give it to the Wazuh indexer:

    ```bash
    mv /var/backups/wazuh-4x-snapshots /var/lib/wazuh-indexer/backup/wazuh-4x
    chown -R wazuh-indexer:wazuh-indexer /var/lib/wazuh-indexer/backup/wazuh-4x
    ```

    Register the directory as read-only and restore the indices with the `restored-` prefix, so they do not mix with the 5.0 indices:

    ```bash
    ADMIN_PASSWORD=$(grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-)
    curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "admin:${ADMIN_PASSWORD}" -X PUT "https://127.0.0.1:9200/_snapshot/wazuh-4x" \
    -H 'Content-Type: application/json' -d '{"type":"fs","settings":{"location":"/var/lib/wazuh-indexer/backup/wazuh-4x","readonly":true}}'
    curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "admin:${ADMIN_PASSWORD}" -X POST "https://127.0.0.1:9200/_snapshot/wazuh-4x/wazuh-4x/_restore?wait_for_completion=true" \
    -H 'Content-Type: application/json' -d '{"indices":"*","include_global_state":false,"rename_pattern":"(.+)","rename_replacement":"restored-$1"}'
    curl --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "admin:${ADMIN_PASSWORD}" "https://127.0.0.1:9200/_cat/indices/restored-*?v&h=health,index,docs.count"
    ```

    The last command lists the restored indices, `green`, with their number of documents. To see them in the Wazuh dashboard, see [Historical data](./migration.md#historical-data).

9. **Migrate the configuration.** Rewrite the 4.x configuration of the Wazuh manager, your rules, decoders and CDB lists for 5.0, as described in the Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.1.0/docs/guide/migration/manager-4x-to-5x.md#4-migrate-the-configuration). The 4.x files are in `/root/wazuh-4x-config.tar.gz`:

    ```bash
    mkdir -p /root/wazuh-4x-config && tar -xzf /root/wazuh-4x-config.tar.gz -C /root/wazuh-4x-config
    ```

    The review list of the export says what stops with the migration. For example, the 4.x agents lose the rootcheck files of the `default` group, and log `No rootcheck_files file`. To keep them until the agents are upgraded, copy them to the `default` group of 5.0:

    ```bash
    install -m 0660 -o wazuh-manager -g wazuh-manager /root/wazuh-4x-config/etc/shared/default/*.txt /etc/wazuh-manager/shared/default/
    ```

## Check the migration

On the 5.0 host, list the agents with the Server API. Use the `WAZUH_MANAGER_API_PASSWORD` value of `/etc/wazuh-manager/export/credentials.env` as `<WAZUH_PASSWORD>`:

```bash
TOKEN=$(curl -s --cacert /etc/wazuh-manager/certs/root-ca.pem -u wazuh:<WAZUH_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s --cacert /etc/wazuh-manager/certs/root-ca.pem "https://localhost:55000/agents?select=id,name,status,group,version&pretty=true" -H "Authorization: Bearer ${TOKEN}"
```

Every agent has its 4.x ID, name and groups. It is `never_connected` until it connects, and `active` with its version once it does. The log of the Wazuh manager shows how many agent keys it loaded:

```bash
grep 'agent key' /var/wazuh-manager/logs/wazuh-manager.log
```

If you carried the Server API users with `--with-rbac`, log in with one of your own users the same way, with its 4.x password.

## After the migration

Continue with the Wazuh manager guide [Migrating a Wazuh manager from 4.x to 5.0](https://github.com/wazuh/wazuh/blob/5.1.0/docs/guide/migration/manager-4x-to-5x.md):

- [Upgrade the agents to 5.0](https://github.com/wazuh/wazuh/blob/5.1.0/docs/guide/migration/manager-4x-to-5x.md#7-upgrade-the-agents-to-50). Until then, the 4.x agents send events, but get no active response, inventory, file integrity state or vulnerability detection. An agent upgraded with its Linux package needs the CA of the Wazuh manager: give it an enrollment token in `WAZUH_ENROLLMENT_TOKEN`, as that guide describes. The agent keeps its ID and groups, does not enroll again, and connects on port `1517`.
- Once no 4.x agent is left, retire the legacy channel and close ports `1514` and `1515`, as described in [Close the legacy ports 1514 and 1515](../security.md#close-the-legacy-ports-1514-and-1515).
- Enroll new agents with an enrollment token, as the summary of the installation assistant shows.

The 4.x Wazuh manager monitored its own host as agent `000`. Wazuh 5.0 has no agent `000`: to monitor the host of the Wazuh manager, install a 5.0 agent on it.
