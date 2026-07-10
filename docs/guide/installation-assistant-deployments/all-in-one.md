# All in one

## Download and run the Wazuh installation assistant

   ```bash
   curl -sO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.1.0.sh && sudo bash ./wazuh-install-5.1.0.sh -a
   ```

   > [!NOTE]
   > To install `pre-release` packages, download the `pre-release` Wazuh installation assistant and run it with the `-d pre-release` option:
   >
   > ```bash
   > curl -sO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-install-5.1.0-<STAGE>.sh && sudo bash ./wazuh-install-5.1.0-<STAGE>.sh -a -d pre-release
   > ```

   Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful.

   ```bash
   INFO: --- Summary ---
   INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
         User: admin
         Password: admin
   INFO: Installation finished.
   ```

   You now have installed and configured Wazuh.

## Access the Wazuh web interface

Access ``https://<WAZUH_DASHBOARD_IP_ADDRESS>`` and using your credentials:

- **Username**: ``admin``
- **Password**: ``admin``

> [!NOTE]
> When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. This is expected and the user has the option to accept the certificate as an exception or, alternatively, configure the system to use a certificate from a trusted authority.
