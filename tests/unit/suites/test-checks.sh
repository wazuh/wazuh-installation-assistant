#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-checks_names() {
    @load_function "${base_dir}/checks.sh" checks_names
}

test-ASSERT-FAIL-01-checks_names-indexer-dashboard-equals() {
    load-checks_names
    indxname="node1"
    dashname="node1"
    winame="wazuh"
    checks_names
}

test-ASSERT-FAIL-02-checks_names-indexer-wazuh-equals() {
    load-checks_names
    indxname="node1"
    winame="node1"
    checks_names
}

test-ASSERT-FAIL-03-checks_names-dashboard-wazuh-equals() {
    load-checks_names
    dashname="node1"
    winame="node1"
    checks_names
}

test-ASSERT-FAIL-04-checks_names-wazuh-node-name-not-in-config() {
    load-checks_names
    winame="node1"
    server_node_names=(wazuh node10)
    @mock echo ${server_node_names[@]} === @out wazuh node10
    @mock grep -w $winame === @false
    checks_names
}

test-ASSERT-FAIL-05-checks_names-dashboard-node-name-not-in-config() {
    load-checks_names
    dashname="node1"
    dashboard_node_names=(dashboard node10)
    @mock echo ${dashboard_node_names[@]} === @out dashboard node10
    @mock grep -w $dashname === @false
    checks_names
}

test-ASSERT-FAIL-06-checks_names-indexer-node-name-not-in-config() {
    load-checks_names
    indxname="node1"
    indexer_node_names=(indexer node10)
    @mock echo ${indexer_node_names[@]} === @out indexer node10
    @mock grep -w $indxname === @false
    checks_names
}

test-07-checks_names-all-correct-installing-indexer() {
    load-checks_names
    indxname="indexer1"
    dashname="dashboard1"
    winame="wazuh1"
    indexer_node_names=(indexer1 node1)
    server_node_names=(wazuh1 node2)
    dashboard_node_names=(dashboard1 node3)
    indexer=1
    @mock echo ${indexer_node_names[@]} === @out indexer1 node1
    @mock echo ${server_node_names[@]} === @out wazuh1 node2
    @mock echo ${dashboard_node_names[@]} === @out dashboard1 node3
    @mock grep -w $indxname
    @mock grep -w $winame
    @mock grep -w $dashname
    checks_names
    @assert-success
}

test-08-checks_names-all-correct-installing-wazuh() {
    load-checks_names
    indxname="indexer1"
    dashname="dashboard1"
    winame="wazuh1"
    indexer_node_names=(indexer1 node1)
    server_node_names=(wazuh1 node2)
    dashboard_node_names=(dashboard1 node3)
    wazuh=1
    @mock echo ${indexer_node_names[@]} === @out indexer1 node1
    @mock echo ${server_node_names[@]} === @out wazuh1 node2
    @mock echo ${dashboard_node_names[@]} === @out dashboard1 node3
    @mock grep -w $indxname
    @mock grep -w $winame
    @mock grep -w $dashname
    checks_names
    @assert-success
}

test-09-checks_names-all-correct-installing-dashboard() {
    load-checks_names
    indxname="indexer1"
    dashname="dashboard1"
    winame="wazuh1"
    indexer_node_names=(indexer1 node1)
    server_node_names=(wazuh1 node2)
    dashboard_node_names=(dashboard1 node3)
    dashboard=1
    @mock echo ${indexer_node_names[@]} === @out indexer1 node1
    @mock echo ${server_node_names[@]} === @out wazuh1 node2
    @mock echo ${dashboard_node_names[@]} === @out dashboard1 node3
    @mock grep -w $indxname
    @mock grep -w $winame
    @mock grep -w $dashname
    checks_names
    @assert-success
}

function load-checks_arch() {
    @load_function "${base_dir}/checks.sh" checks_arch
}

test-10-checks_arch-x86_64() {
    @mock uname -m === @out x86_64
    load-checks_arch
    checks_arch
    @assert-success
}

test-ASSERT-FAIL-11-checks_arch-empty() {
    @mock uname -m === @out
    load-checks_arch
    checks_arch
}

test-ASSERT-FAIL-12-checks_arch-i386() {
    @mock uname -m === @out i386
    load-checks_arch
    checks_arch
}

function load-checks_arguments {
    @load_function "${base_dir}/checks.sh" checks_arguments
}

test-ASSERT-FAIL-13-checks_arguments-install-AIO-certs-file-present() {
    load-checks_arguments
    AIO=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checks_arguments
    @rm $tar_file

}

test-ASSERT-FAIL-14-checks_arguments-certificate-creation-certs-file-present() {
    load-checks_arguments
    certificates=1
    tar_file="tarfile.tar"
    @touch $tar_file
    checks_arguments
    @rm $tar_file
}

test-ASSERT-FAIL-15-checks_arguments-overwrite-with-no-component-installed() {
    load-checks_arguments
    overwrite=1
    AIO=
    indexer=
    wazuh=
    dashboard=
    checks_arguments
}

test-16-checks_arguments-uninstall-no-component-installed() {
    load-checks_arguments
    uninstall=1
    indexer_installed=""
    indexer_remaining_files=""
    wazuh_installed=""
    wazuh_remaining_files=""
    dashboard_installed=""
    dashboard_remaining_files=""
    filebeat_installed=""
    filebeat_remaining_files=""
    checks_arguments
    @assert-success
}

test-ASSERT-FAIL-17-checks_arguments-uninstall-and-AIO() {
    load-checks_arguments
    uninstall=1
    AIO=1
    checks_arguments
}

test-ASSERT-FAIL-18-checks_arguments-uninstall-and-wazuh() {
    load-checks_arguments
    uninstall=1
    wazuh=1
    checks_arguments
}

test-ASSERT-FAIL-19-checks_arguments-uninstall-and-dashboard() {
    load-checks_arguments
    uninstall=1
    dashboard=1
    checks_arguments
}

test-ASSERT-FAIL-20-checks_arguments-uninstall-and-indexer() {
    load-checks_arguments
    uninstall=1
    indexer=1
    checks_arguments
}

test-ASSERT-FAIL-21-checks_arguments-install-AIO-and-indexer () {
    load-checks_arguments
    AIO=1
    indexer=1
    checks_arguments
}

test-ASSERT-FAIL-22-checks_arguments-install-AIO-and-wazuh () {
    load-checks_arguments
    AIO=1
    wazuh=1
    checks_arguments
}

test-ASSERT-FAIL-23-checks_arguments-install-AIO-and-dashboard () {
    load-checks_arguments
    AIO=1
    dashboard=1
    checks_arguments
}

test-ASSERT-FAIL-24-checks_arguments-install-AIO-wazuh-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-25-checks_arguments-install-AIO-wazuh-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-26-checks_arguments-install-AIO-indexer-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    indexer_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-27-checks_arguments-install-AIO-indexer-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    indexer_remaining_files=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-28-checks_arguments-install-AIO-dashboard-installed-no-overwrite() {
    load-checks_arguments
    AIO=1
    dashboard_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-29-checks_arguments-install-AIO-dashboard-files-no-overwrite() {
    load-checks_arguments
    AIO=1
    dashboard_remaining_files=1
    overwrite=
    checks_arguments
}

test-30-checks_arguments-install-AIO-wazuh-installed-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_installed=1
    overwrite=1
    checks_arguments
}

test-30-checks_arguments-install-AIO-wazuh-installed-overwrite-assert() {
    installCommon_rollBack
}

test-31-checks_arguments-install-AIO-wazuh-files-overwrite() {
    load-checks_arguments
    AIO=1
    wazuh_remaining_files=1
    overwrite=1
    checks_arguments
}

test-31-checks_arguments-install-AIO-wazuh-files-overwrite-assert() {
    installCommon_rollBack
}

test-32-checks_arguments-install-AIO-indexer-installed-overwrite() {
    load-checks_arguments
    AIO=1
    indexer_installed=1
    overwrite=1
    checks_arguments
}

test-32-checks_arguments-install-AIO-indexer-installed-overwrite-assert() {
    installCommon_rollBack
}

test-33-checks_arguments-install-AIO-indexer-files-overwrite() {
    load-checks_arguments
    AIO=1
    indexer_remaining_files=1
    overwrite=1
    checks_arguments
}

test-33-checks_arguments-install-AIO-indexer-files-overwrite-assert() {
    installCommon_rollBack
}

test-34-checks_arguments-install-AIO-dashboard-installed-overwrite() {
    load-checks_arguments
    AIO=1
    dashboard_installed=1
    overwrite=1
    checks_arguments
}

test-34-checks_arguments-install-AIO-dashboard-installed-overwrite-assert() {
    installCommon_rollBack
}

test-35-checks_arguments-install-AIO-dashboard-files-overwrite() {
    load-checks_arguments
    AIO=1
    dashboard_remaining_files=1
    overwrite=1
    checks_arguments
}

test-35-checks_arguments-install-AIO-dashboard-files-overwrite-assert() {
    installCommon_rollBack
}

test-ASSERT-FAIL-36-checks_arguments-install-indexer-already-installed-no-overwrite() {
    load-checks_arguments
    indexer=1
    indexer_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-37-checks_arguments-install-indexer-remaining-files-no-overwrite() {
    load-checks_arguments
    indexer=1
    indexer_remaining_files=1
    overwrite=
    checks_arguments
}

test-38-checks_arguments-install-indexer-already-installed-overwrite() {
    load-checks_arguments
    indexer=1
    indexer_installed=1
    overwrite=1
    checks_arguments
}

test-38-checks_arguments-install-indexer-already-installed-overwrite-assert() {
    installCommon_rollBack
}

test-39-checks_arguments-install-indexer-remaining-files-overwrite() {
    load-checks_arguments
    indexer=1
    indexer_remaining_files=1
    overwrite=1
    checks_arguments
}

test-39-checks_arguments-install-indexer-remaining-files-overwrite-assert() {
    installCommon_rollBack
}

test-ASSERT-FAIL-40-checks_arguments-install-wazuh-already-installed-no-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-41-checks_arguments-install-wazuh-remaining-files-no-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=
    checks_arguments
}

test-42-checks_arguments-install-wazuh-already-installed-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_installed=1
    overwrite=1
    checks_arguments
}

test-42-checks_arguments-install-wazuh-already-installed-overwrite-assert() {
    installCommon_rollBack
}

test-43-checks_arguments-install-wazuh-remaining-files-overwrite() {
    load-checks_arguments
    wazuh=1
    wazuh_remaining_files=1
    overwrite=1
    checks_arguments
}

test-43-checks_arguments-install-wazuh-remaining-files-overwrite-assert() {
    installCommon_rollBack
}

test-ASSERT-FAIL-44-checks_arguments-install-wazuh-filebeat-already-installed-no-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-45-checks_arguments-install-wazuh-filebeat-remaining-files-no-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=
    checks_arguments
}

test-46-checks_arguments-install-wazuh-filebeat-already-installed-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_installed=1
    overwrite=1
    checks_arguments
}

test-46-checks_arguments-install-wazuh-filebeat-already-installed-overwrite-assert() {
    installCommon_rollBack
}

test-47-checks_arguments-install-wazuh-filebeat-remaining-files-overwrite() {
    load-checks_arguments
    wazuh=1
    filebeat_remaining_files=1
    overwrite=1
    checks_arguments
}

test-47-checks_arguments-install-wazuh-filebeat-remaining-files-overwrite-assert() {
    installCommon_rollBack
}

test-ASSERT-FAIL-48-checks_arguments-install-dashboard-already-installed-no-overwrite() {
    load-checks_arguments
    dashboard=1
    dashboard_installed=1
    overwrite=
    checks_arguments
}

test-ASSERT-FAIL-49-checks_arguments-install-dashboard-remaining-files-no-overwrite() {
    load-checks_arguments
    dashboard=1
    dashboard_remaining_files=1
    overwrite=
    checks_arguments
}

test-50-checks_arguments-install-dashboard-already-installed-overwrite() {
    load-checks_arguments
    dashboard=1
    dashboard_installed=1
    overwrite=1
    checks_arguments
}

test-50-checks_arguments-install-dashboard-already-installed-overwrite-assert() {
    installCommon_rollBack
}

test-51-checks_arguments-install-dashboard-remaining-files-overwrite() {
    load-checks_arguments
    dashboard=1
    dashboard_remaining_files=1
    overwrite=1
    checks_arguments
}

test-51-checks_arguments-install-dashboard-remaining-files-overwrite-assert() {
    installCommon_rollBack
}

function load-checks_health() {
    @load_function "${base_dir}/checks.sh" checks_health
    @mocktrue checks_specifications
}

test-52-checks_health-no-installation() {
    load-checks_health
    checks_health
    @assert-success
}

test-ASSERT-FAIL-53-checks_health-AIO-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    AIO=1
    checks_health
}

test-ASSERT-FAIL-54-checks_health-AIO-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    AIO=1
    checks_health
}

test-55-checks_health-AIO-2-cores-4gb() {
    load-checks_health
    cores=2
    ram_gb=3700
    AIO=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-56-checks_health-indexer-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    indexer=1
    checks_health
}

test-ASSERT-FAIL-57-checks_health-indexer-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    indexer=1
    checks_health
}

test-58-checks_health-indexer-2-cores-3700-ram() {
    load-checks_health
    cores=2
    ram_gb=3700
    indexer=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-59-checks_health-dashboard-1-core-3700-ram() {
    load-checks_health
    cores=1
    ram_gb=3700
    dashboard=1
    checks_health
}

test-ASSERT-FAIL-60-checks_health-dashboard-2-cores-3000-ram() {
    load-checks_health
    cores=2
    ram_gb=3000
    dashboard=1
    checks_health
}

test-61-checks_health-dashboard-2-cores-3700-ram() {
    load-checks_health
    cores=2
    ram_gb=3700
    dashboard=1
    checks_health
    @assert-success
}

test-ASSERT-FAIL-62-checks_health-wazuh-1-core-1700-ram() {
    load-checks_health
    cores=1
    ram_gb=1700
    wazuh=1
    checks_health
}

test-ASSERT-FAIL-63-checks_health-wazuh-2-cores-1000-ram() {
    load-checks_health
    cores=2
    ram_gb=1000
    wazuh=1
    checks_health
}

test-64-checks_health-wazuh-2-cores-1700-ram() {
    load-checks_health
    cores=2
    ram_gb=1700
    wazuh=1
    checks_health
    @assert-success
}

function load-checks_previousCertificate() {
    @load_function "${base_dir}/checks.sh" checks_previousCertificate
}

test-ASSERT-FAIL-65-checks_previousCertificate-no-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    if [ -f $tar_file ]; then
        @rm $tar_file
    fi
    checks_previousCertificate
}

test-ASSERT-FAIL-66-checks_previousCertificate-indxname-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    indxname="indexer1"
    @mockfalse grep -q indexer1.pem
    @mockfalse grep -q indexer1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-67-checks_previousCertificate-dashname-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    dashname="dashboard1"
    @mockfalse grep -q dashboard1.pem
    @mockfalse grep -q dashboard1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-ASSERT-FAIL-68-checks_previousCertificate-winame-not-in-tar_file() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    winame="wazuh1"
    @mockfalse grep -q wazuh1.pem
    @mockfalse grep -q wazuh1-key.pem
    checks_previousCertificate
    @rm /tmp/tarfile.tar
}

test-69-checks_previousCertificate-all-correct() {
    load-checks_previousCertificate
    tar_file=/tmp/tarfile.tar
    @touch /tmp/tarfile.tar
    @mock tar -tf tarfile.tar
    indxname="indexer1"
    @mocktrue grep -q indexer1.pem
    @mocktrue grep -q indexer1-key.pem
    winame="wazuh1"
    @mocktrue grep -q wazuh1.pem
    @mocktrue grep -q wazuh1-key.pem
    dashname="dashboard1"
    @mocktrue grep -q dashboard1.pem
    @mocktrue grep -q dashboard1-key.pem
    checks_previousCertificate
    @assert-success
    @rm /tmp/tarfile.tar
}

function load-check_dist() {
    @load_function "${base_dir}/checks.sh" check_dist
}

function mock-dist_detect() {
    eval "function dist_detect() { DIST_NAME='${1}'; DIST_VER='${2}'; DIST_SUBVER='${3:-}'; }"
}

# Usage: assert-check_dist <supported|1> <DIST_NAME> <DIST_VER> [DIST_SUBVER]
function assert-check_dist() {
    declare expected="${1}"
    shift
    mock-dist_detect "$@"
    notsupported=""
    check_dist
    @assert-equals "${expected}" "${notsupported:-supported}"
}

test-70-check_dist-rhel-accepted-versions() {
    load-check_dist
    for version in 7 8 9 10; do
        assert-check_dist supported rhel "${version}"
    done
}

test-71-check_dist-rhel-6-rejected() {
    load-check_dist
    assert-check_dist 1 rhel 6
}

test-72-check_dist-rhel-11-rejected() {
    load-check_dist
    assert-check_dist 1 rhel 11
}

test-73-check_dist-centos-accepted-versions() {
    load-check_dist
    for version in 7 8; do
        assert-check_dist supported centos "${version}"
    done
}

test-74-check_dist-centos-stream-9-rejected() {
    load-check_dist
    assert-check_dist 1 centos 9
}

test-75-check_dist-centos-stream-10-rejected() {
    load-check_dist
    assert-check_dist 1 centos 10
}

test-76-check_dist-ubuntu-accepted-versions() {
    load-check_dist
    for version in 16 18 20 22 24; do
        assert-check_dist supported ubuntu "${version}" 04
    done
}

test-77-check_dist-ubuntu-24.10-rejected() {
    load-check_dist
    assert-check_dist 1 ubuntu 24 10
}

test-78-check_dist-ubuntu-26.04-rejected() {
    load-check_dist
    assert-check_dist 1 ubuntu 26 04
}

test-79-check_dist-amzn-2-accepted() {
    load-check_dist
    assert-check_dist supported amzn 2
}

test-80-check_dist-amzn-2023-accepted-and-checks-special-deps() {
    load-check_dist
    function checks_specialDepsAL2023() { al2023_deps_checked=1; }
    al2023_deps_checked=""
    assert-check_dist supported amzn 2023
    @assert-equals "1" "${al2023_deps_checked:-not-called}"
}

test-81-check_dist-amzn-1-rejected() {
    load-check_dist
    assert-check_dist 1 amzn 1
}

test-82-check_dist-rocky-9.4-accepted() {
    load-check_dist
    assert-check_dist supported rocky 9 4
}

test-83-check_dist-rocky-9.5-rejected() {
    load-check_dist
    assert-check_dist 1 rocky 9 5
}

test-84-check_dist-unknown-distribution-rejected() {
    load-check_dist
    assert-check_dist 1 debian 12
}

test-85-check_dist-supported-system-no-recommended-systems-message() {
    load-check_dist
    function common_logger() { printf '%s\n' "$*"; }
    mock-dist_detect rhel 10
    notsupported=""
    check_dist
}

test-85-check_dist-supported-system-no-recommended-systems-message-assert() {
    @out "-d Checking system distribution."
    @out "-d Detected distribution name: rhel"
    @out "-d Detected distribution version: 10"
}

test-86-check_dist-unsupported-system-prints-recommended-systems() {
    load-check_dist
    function common_logger() { printf '%s\n' "$*"; }
    mock-dist_detect centos 10
    notsupported=""
    check_dist
}

test-86-check_dist-unsupported-system-prints-recommended-systems-assert() {
    @out "-d Checking system distribution."
    @out "The recommended systems are: Red Hat Enterprise Linux 7, 8, 9, 10; CentOS 7, 8; Amazon Linux 2; Amazon Linux 2023; Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04; Rocky Linux 9.4."
    @out "-w The current system does not match with the list of recommended systems. The installation may not work properly."
    @out "-d Detected distribution name: centos"
    @out "-d Detected distribution version: 10"
}
