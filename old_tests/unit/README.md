# Unit Test Instructions for Wazuh installation assistant

This document provides instructions on how to run unit tests for the Wazuh installation assistant using Docker.

## Overview 

- **Test Naming Convention**: All test files follow the naming pattern `tests-{script_name}.sh`, where `{script_name}.sh` corresponds to the script being tested.
- **Testing Environment**: The `unit-tests.sh` script is used to run these tests. It creates a clean Docker environment for each test run to ensure consistency.
- **Docker Requirement**: Docker must be installed, running, and accessible by the user. The Docker image used for testing is retained after the script execution to save time on subsequent runs. If the Dockerfile is modified, use the `-r` option to rebuild the image.

## Usage

```
unit-tests.sh - Unit test for the Wazuh installation assistant.
```

### Synopsis

```
bash unit-tests.sh [OPTIONS] -a | -d | -f <file-list>
```

### Options

| Option | Description |
|-------------------------------------|-------------------------------------------------------------------|
|     `-a`, `--test-all`              | Runs tests on all available scripts.                              |
|     `-d`, `--debug`                 | Displays the complete installation output for debugging purposes. |
|     `-f`, `--files <file-list>`     | Specifies a list of files to test. Example: `-f common checks`.   |
|     `-h`, `--help`                  | Displays the help message with usage details.                     |
|     `-r`, `--rebuild-image`         | Forces the Docker image to be rebuilt before running tests.       |

## Tips for Debugging

When multiple tests fail after a merge, it can be challenging to isolate and fix them. Here's a method to streamline this process:

> [!TIP]
> **1. Sequential Testing**: Since a bash script exits on an unknown character, you can insert a `Ç` character after the first test you want to run. Only the tests before the `Ç` character will be executed.
> 
> **2. Incremental Fixing**: As you fix each test, move the `Ç` character down to include the next test or group of tests. This approach prevents you from having to scroll through all tests to identify which ones are failing.

This technique allows for a more manageable and systematic approach to resolving issues, especially when dealing with a large number of tests.