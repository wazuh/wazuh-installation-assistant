# Generate artifacts manually

This section covers the process for generating artifacts for the Installation Assistant tools manually using the `builder.sh` script.

You can check the available builder options by running:

```bash
sudo bash ./builder.sh --help
```

## Wazuh Certs Tool

To generate the Wazuh Certs Tool artifact, follow these steps:

1. Navigate to the root directory of the Installation Assistant project.
2. Run the following command:

    ```bash
    sudo bash ./builder.sh --cert-tool
    # you can also use the short version
    sudo bash ./builder.sh -c
    ```
3. The file related to the Certs Tool will be generated in the same path where the `builder.sh` script is located. This file will be named `wazuh-certs-tool-5.0.0-1.sh`.

This file will contain all the files from the `cert_tool/` and `common_functions/` directories packaged into a single executable script.

## Wazuh Passwords Tool

To generate the Wazuh Passwords Tool artifact, follow these steps:
1. Navigate to the root directory of the Installation Assistant project.
2. Run the following command:
    ```bash
    sudo bash ./builder.sh --password-tool
    # you can also use the short version
    sudo bash ./builder.sh -p
    ```
3. The file related to the Passwords Tool will be generated in the same path where the `builder.sh` script is located. This file will be named `wazuh-passwords-tool-5.0.0-1.sh`.

This file will contain all the files from the `passwords_tool/` and `common_functions/` directories packaged into a single executable script.

## Wazuh Installation Assistant

To generate the Wazuh Installation Assistant artifact, follow these steps:
1. Navigate to the root directory of the Installation Assistant project.
2. Run the following command:
    ```bash
    sudo bash ./builder.sh --installer
    # you can also use the short version
    sudo bash ./builder.sh -i
3. The file related to the Installation Assistant will be generated in the same path where the `builder.sh` script is located. This file will be named `wazuh-install-5.0.0-1.sh`.

This file will contain all the files from the `install_functions/`, `cert_tool/`, and `common_functions/` directories packaged into a single executable script. It also includes a Linux distribution detection function obtained from the official Wazuh repository.
