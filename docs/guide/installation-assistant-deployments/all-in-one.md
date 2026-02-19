# All in one

## Download and run the Wazuh installation assistant.

      $ curl -sO https://packages.wazuh.com/5.x/wazuh-install-5.0.0-1.sh && sudo bash ./wazuh-install-5.0.0-1.sh -a


   Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful.



      INFO: --- Summary ---
      INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
          User: admin
          Password: admin
      INFO: Installation finished.

   You now have installed and configured Wazuh.

## Access the Wazuh web interface with ``https://<WAZUH_DASHBOARD_IP_ADDRESS>`` and your credentials:

   -  **Username**: ``admin``
   -  **Password**: ``admin``

> [!NOTE]
> When you access the Wazuh dashboard for the first time, the browser shows a warning message stating that the certificate was not issued by a trusted authority. This is expected and the user has the option to accept the certificate as an exception or, alternatively, configure the system to use a certificate from a trusted authority.