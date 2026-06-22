# Passwords Tool installation

The passwords tool is embedded in the Wazuh indexer under `/usr/share/wazuh-indexer/plugins/opensearch-security/tools/`. You can use the embedded version or download it with the following command:

```bash
curl -so wazuh-passwords-tool-5.0.0.sh https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-passwords-tool-5.0.0.sh
```

To use `pre-release` packages instead, use the following command:

```bash
curl -so wazuh-passwords-tool-5.0.0.sh https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-passwords-tool-5.0.0-<STAGE>.sh
```

To see how to use this tool, see the [Passwords Tool Usage](../../usage/passwords-tool/passwords-tool-usage.md) section.
