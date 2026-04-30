# Certs Tool installation

The Certs Tool can be installed by downloading the `wazuh-certs-tool-5.9.9.sh` script from the Wazuh packages repository. You can do this by running the following command:

```bash
curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-certs-tool-5.9.9.sh
```

For the certs-tool, the `config.yml` configuration file is also necessary, which can be downloaded with the following command:

For DNS-based or mixed address configurations, see [Other `config.yml` examples](../../configuration/configuration-files.md#other-configyml-examples).

```bash
curl -s -o config.yml https://packages.wazuh.com/production/5.x/installation-assistant/config-5.9.9.yml
```
