# Tests

This section covers the test suites available for the Wazuh Installation Assistant tools.

Two independent test pipelines exist, each targeting a different layer of the codebase:

- [**Unit tests**](unit-test/unit-tests.md) — Fast tests written in Python/pytest that exercise individual bash functions via subprocess with mock injection. Run automatically on every pull request.
- [**Integration tests**](integration-test/integration-tests.md): End-to-end tests that provision real AWS EC2 instances, build the tools from the pull request branch, run actual installations, and validate the results using the `integration-test-module` from `wazuh/wazuh-automation`. Triggered on demand via PR comments or manually via workflow dispatch.