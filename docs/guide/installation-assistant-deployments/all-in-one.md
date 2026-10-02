# All in one

## Download and run the Wazuh installation assistant

   ```bash
   curl -fsSO https://packages.wazuh.com/production/5.x/installation-assistant/wazuh-install-5.0.0.sh && sudo bash ./wazuh-install-5.0.0.sh -a
   ```

   > [!NOTE]
   > To install `pre-release` packages, download the `pre-release` Wazuh installation assistant and run it with the `-d pre-release` option:
   >
   > ```bash
   > curl -fsSO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-install-5.0.0-<STAGE>.sh && sudo bash ./wazuh-install-5.0.0-<STAGE>.sh -a -d pre-release
   > ```

   > [!NOTE]
   > The assistant stops if a package it needs, such as `apt-transport-https`, is missing, and names it. Install it, or add `-id` to the command to install it automatically. To install packages that are not published yet, add `-d local` and list them in `artifact_urls.yaml`, as described in [Use development packages](../../ref/getting-started/usage.md#use-development-packages).

   Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful. There is one `You can access` line per address of the Wazuh dashboard certificate, and the line after `Password:` is the command that prints the `admin` password.

   ```bash
   INFO: Wazuh dashboard web application initialized.
   INFO: --- Summary ---
   INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>:443
   INFO:     User: admin
   INFO:     Password: to read it from the credentials file, run:
   INFO:         sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-
   INFO: Installation finished.
   ```

   You now have installed and configured Wazuh.

## Access the Wazuh web interface

Access ``https://<WAZUH_DASHBOARD_IP_ADDRESS>`` and using your credentials:

- **Username**: ``admin``
- **Password**: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `/etc/wazuh/credentials.env`

> [!NOTE]
> When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. This is expected and the user has the option to accept the certificate as an exception or, alternatively, configure the system to use a certificate from a trusted authority.

> [!NOTE]
> `/etc/wazuh/credentials.env` holds the passwords of the Wazuh users, generated during the installation. Once you have stored them in a safe place, remove the file from every node: the Wazuh components do not read it after the installation. To change a password later, see [Change all default passwords](../../ref/getting-started/usage.md#change-all-default-passwords).
