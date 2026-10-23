# Certs Tool installation

The Certs Tool can be installed by downloading the `wazuh-certs-tool-5.1.0.sh` script from the Wazuh packages repository. You can do this by running the following command:

```bash
curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-certs-tool-5.1.0.sh
```

To use `pre-release` packages instead, use the following command:

```bash
curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-certs-tool-5.1.0-<STAGE>.sh
```

For the certs-tool, the `config.yml` configuration file is also necessary, which can be downloaded with the following command:

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../configuration/configuration-files.md#other-configyml-examples).

```bash
curl -fsS -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.1.0.yml
```

To use `pre-release` packages instead, use the following command:

```bash
curl -fsS -o config.yml https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/config-5.1.0-<STAGE>.yml
```

## Copy shipped in the Wazuh indexer package

The Wazuh indexer package also ships the tool as `/usr/share/wazuh-indexer/tools/wazuh-certs-tool.sh`, with a template `config.yml` next to it. With that copy, the default CA directory is `/usr/share/wazuh-indexer/tools/wazuh-ca`, not the CA of the package. To issue certificates from the CA the package created, set `WAZUH_CA_DIR=/etc/wazuh-indexer/ca`. See [Root CA](../../getting-started/usage.md#root-ca).
