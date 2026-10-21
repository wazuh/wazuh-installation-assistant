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

   Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful. There is one `You can access` line per address of the Wazuh dashboard certificate. In an interactive terminal, the `Password:` line shows the `admin` password, followed by the command that prints it again. The password is not written to `/var/log/wazuh-install.log`, and when the output is redirected, as with cloud-init or CI, only the command is shown.

   ```bash
   INFO: Wazuh dashboard web application initialized.
   INFO: --- Summary ---
   INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>:443
   INFO:     User: admin (Wazuh dashboard login and Wazuh indexer administrator)
   INFO:     Password: <ADMIN_PASSWORD>
   INFO:     To read the password again, run:
   INFO:         sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2-
   INFO: The passwords of the other users are in /etc/wazuh-indexer/export/credentials.env and /etc/wazuh-manager/export/credentials.env.
   INFO: Installation finished.
   ```

   You now have installed and configured Wazuh.

## Access the Wazuh web interface

Access ``https://<WAZUH_DASHBOARD_IP_ADDRESS>`` and using your credentials:

- **Username**: ``admin``
- **Password**: the `WAZUH_INDEXER_ADMIN_PASSWORD` value in `/etc/wazuh-indexer/export/credentials.env`

> [!NOTE]
> When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. This is expected and the user has the option to accept the certificate as an exception or, alternatively, configure the system to use a certificate from a trusted authority.

> [!NOTE]
> The packages create the CAs, the certificates and the passwords of the Wazuh users during the installation. The Wazuh indexer users are in `/etc/wazuh-indexer/export/credentials.env`, and the Wazuh server API users are in `/etc/wazuh-manager/export/credentials.env`. Store them in a safe place, and keep these files: on a host with more than one component, the Wazuh manager and the Wazuh dashboard read their passwords from them. They are readable by `root` only. To change a password later, see [Change all default passwords](../../ref/getting-started/usage.md#change-all-default-passwords).
>
> Each package keeps its CA and the private key of that CA in its `ca/` directory: `/etc/wazuh-indexer/ca`, `/etc/wazuh-manager/ca` and `/etc/wazuh-dashboard/ca`. To trust the Wazuh dashboard certificate in your browser, import `/etc/wazuh-dashboard/ca/root-ca.pem`. Back up the three directories in a safe place: you need them to renew certificates later. See [Security](../security.md).
