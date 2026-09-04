# Certs Tool installation

The Certs Tool can be installed by downloading the `wazuh-certs-tool-5.1.0.sh` script from the Wazuh packages repository. You can do this by running the following command:

```bash
curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-certs-tool-5.1.0.sh
```

To use `pre-release` packages instead, use the following command:

```bash
curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-certs-tool-5.1.0-<STAGE>.sh
```

For the certs-tool, the `config.yml` configuration file is also necessary, which can be downloaded with the following command:

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../configuration/configuration-files.md#other-configyml-examples).

```bash
curl -s -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.1.0.yml
```

To use `pre-release` packages instead, use the following command:

```bash
curl -s -o config.yml https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/config-5.1.0-<STAGE>.yml
```
