<!-- integration-check-installer-AmazonLinux_2023 -->
## 🧪 Integration Tests — `installer` on `AmazonLinux_2023`

❌ **Some tests failed**

### Results

```test_status=FAIL
total_tests=14
passed_tests=3
failed_tests=3
warning_tests=0
skipped_tests=8
test_type=installer
short_summary=Tests Summary  (installer): FAIL - Total: 14, Passed: 3, Failed: 3, Skipped: 8```

# Devops Integration Tests Results

## Summary  for INSTALLER

**Status**: FAIL :red_circle:

| Metric | Count |
|--------|-------|
| Total Tests | 14 |
| Passed | 3 |
| Failed | 3|
| Warnings | 0 |
| Skipped | 8 |

## Failed Tests :red_circle:

### Assistant

**Assistant: Certificates exist** :red_circle:

Errors found:

- /etc/wazuh-indexer/certs/root-ca.pem exists
- /etc/wazuh-indexer/certs/admin.pem exists
- /etc/wazuh-dashboard/certs/root-ca.pem exists
- /var/wazuh-manager/etc/certs/root-ca.pem exists
- /etc/wazuh-indexer/certs/indexer.pem does NOT exist
- /etc/wazuh-dashboard/certs/dashboard.pem does NOT exist
- /var/wazuh-manager/etc/certs/manager.pem does NOT exist
- /var/wazuh-manager/etc/certs/admin.pem does NOT exist

**Assistant: Ports listening** :red_circle:

Errors found:

- Port 55000 (wazuh-manager) is listening
- Port 9200 (wazuh-indexer) is listening
- Port 443 (wazuh-dashboard) is NOT listening

**Assistant: Health endpoints** :red_circle:

Errors found:

- https://localhost:9200/_cluster/health?pretty → 200 (for wazuh-indexer)
- https://localhost/status → 000 (expected [200], for wazuh-dashboard):


## Passed Tests

### Assistant

- Assistant: Services active :green_circle:

- Assistant: Services running :green_circle:

- Assistant: Required directories :green_circle:


## Skipped Tests :large_blue_circle:

### Assistant

**Assistant: Certificates validity** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/helpers.py', 308, 'Skipped: Some certificate validity checks were skipped. \nCertificate validity checks results:\n\nSuccessful checks:\n- /etc/wazuh-indexer/certs/root-ca.pem valid — 3649 days remaining\n- /etc/wazuh-indexer/certs/admin.pem valid — 3649 days remaining\n- /etc/wazuh-dashboard/certs/root-ca.pem valid — 3649 days remaining\n- /var/wazuh-manager/etc/certs/root-ca.pem valid — 3649 days remaining\n\nSkipped checks:\n- /etc/wazuh-indexer/certs/indexer.pem does not exist — skipping validity check\n- /etc/wazuh-dashboard/certs/dashboard.pem does not exist — skipping validity check\n- /var/wazuh-manager/etc/certs/manager.pem does not exist — skipping validity check\n- /var/wazuh-manager/etc/certs/admin.pem does not exist — skipping validity check')
```

**Assistant: Certificate subjects** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/helpers.py', 308, "Skipped: Some certificate subject checks were skipped. \nCertificate subject checks results:\n\nSuccessful checks:\n- /etc/wazuh-indexer/certs/root-ca.pem: 'subject=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n- /etc/wazuh-indexer/certs/admin.pem: 'subject=C=US, L=California, O=Wazuh, OU=Wazuh, CN=admin' contains 'CN=admin'\n- /etc/wazuh-dashboard/certs/root-ca.pem: 'subject=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n- /var/wazuh-manager/etc/certs/root-ca.pem: 'subject=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n\nSkipped checks:\n- /etc/wazuh-indexer/certs/indexer.pem does not exist\n- /etc/wazuh-dashboard/certs/dashboard.pem does not exist\n- /var/wazuh-manager/etc/certs/manager.pem does not exist\n- /var/wazuh-manager/etc/certs/admin.pem does not exist")
```

**Assistant: Certificate issuers** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/helpers.py', 308, "Skipped: Some certificate issuer checks were skipped. \nCertificate issuer checks results:\n\nSuccessful checks:\n- /etc/wazuh-indexer/certs/root-ca.pem: 'issuer=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n- /etc/wazuh-indexer/certs/admin.pem: 'issuer=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n- /etc/wazuh-dashboard/certs/root-ca.pem: 'issuer=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n- /var/wazuh-manager/etc/certs/root-ca.pem: 'issuer=OU=Wazuh, O=Wazuh, L=California' contains 'OU=Wazuh'\n\nSkipped checks:\n- /etc/wazuh-indexer/certs/indexer.pem does not exist\n- /etc/wazuh-dashboard/certs/dashboard.pem does not exist\n- /var/wazuh-manager/etc/certs/manager.pem does not exist\n- /var/wazuh-manager/etc/certs/admin.pem does not exist")
```

**Assistant: Certificate permissions** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/helpers.py', 308, 'Skipped: Some certificate permission checks were skipped. \nCertificate permission checks results:\n\nSuccessful checks:\n- /etc/wazuh-indexer/certs/root-ca.pem: 400 (expected 400)\n- /etc/wazuh-indexer/certs/admin.pem: 400 (expected 400)\n- /etc/wazuh-dashboard/certs/root-ca.pem: 400 (expected 400)\n- /var/wazuh-manager/etc/certs/root-ca.pem: 400 (expected 400)\n\nSkipped checks:\n- /etc/wazuh-indexer/certs/indexer.pem — file not found\n- /etc/wazuh-dashboard/certs/dashboard.pem — file not found\n- /var/wazuh-manager/etc/certs/manager.pem — file not found\n- /var/wazuh-manager/etc/certs/admin.pem — file not found')
```

**Assistant: New password accepted by indexer** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/test_assistant.py', 136, 'Skipped: Password acceptance check not applicable for test_type=installer')
```

**Assistant: New password accepted by dashboard** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/test_assistant.py', 158, 'Skipped: Password acceptance check not applicable for test_type=installer')
```

**Assistant: Old password rejected** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/test_assistant.py', 180, 'Skipped: Password rejection check not applicable for test_type=installer')
```

**Assistant: Wazuh manager api reachable** :large_blue_circle:

Reason:

```
('/home/runner/work/wazuh-installation-assistant/wazuh-installation-assistant/wazuh-automation/integration-test-module/src/test_runner/tests/test_assistant.py', 203, 'Skipped: Manager API check not applicable for test_type=installer')
```


EOF

```

- **Workflow:** [View Details](https://github.com/wazuh/wazuh-installation-assistant/actions/runs/23067599359)
