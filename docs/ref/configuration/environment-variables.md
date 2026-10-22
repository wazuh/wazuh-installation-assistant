# Environment variables

The Wazuh installation assistant, the Wazuh certs tool and the Wazuh passwords tool support one environment variable:

| Variable | Purpose |
| -------- | ------- |
| `WAZUH_CA_DIR` | Directory of the root CA of the deployment, as an absolute path. By default it is the `wazuh-ca` directory next to the script. `wazuh-install-5.0.0.sh -g` and `wazuh-certs-tool-5.0.0.sh` read the root CA from it. `-g`, and the `-A` and `-ca` options of the certs tool, create one there when there is none. `-g` also keeps the passwords there, in `credentials.env`, and `wazuh-passwords-tool-5.0.0.sh` updates that file when it changes a password it holds. |

