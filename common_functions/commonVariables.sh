# Common variables
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Configuration directory of each package: local.env, ca/, certs/ and export/.
indexer_config_path="/etc/wazuh-indexer"
manager_config_path="/etc/wazuh-manager"
dashboard_config_path="/etc/wazuh-dashboard"
adminpem="/etc/wazuh-indexer/certs/admin.pem"
adminkey="/etc/wazuh-indexer/certs/admin-key.pem"
manager_keystore="/var/wazuh-manager/bin/wazuh-manager-keystore"
manager_resolver="/var/wazuh-manager/bin/wazuh-manager-resolve-credentials"
