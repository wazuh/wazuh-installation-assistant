# Wazuh installer - variables
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly wazuh_major="5.0"
readonly wazuh_version="5.0.0"
readonly wazuh_install_vesion="0.1"
source_branch="v${wazuh_version}"
last_stage=""

repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/5.x"
reporelease="stable"
bucket="packages.wazuh.com"
repository="5.x"

## Links and paths to resources
readonly resources="https://${bucket}/${wazuh_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
config_file="${base_path}/config.yml"
readonly tar_file_name="wazuh-install-files.tar"
tar_file="${base_path}/${tar_file_name}"
readonly artifact_urls_file_name="artifact_urls.yml"
readonly download_packages_directory="wazuh-install-packages"

readonly dashboard_cert_path="/etc/wazuh-dashboard/certs"
readonly server_cert_path="/var/ossec/etc/certs"
readonly indexer_cert_path="/etc/wazuh-indexer/certs"

readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"
readonly yum_lockfile="/var/run/yum.pid"
readonly apt_lockfile="/var/lib/dpkg/lock"

## Offline Installation vars
readonly base_dest_folder="wazuh-offline"
manager_deb_base_url="${base_url}/apt/pool/main/w/wazuh-manager"

indexer_deb_base_url="${base_url}/apt/pool/main/w/wazuh-indexer"
dashboard_deb_base_url="${base_url}/apt/pool/main/w/wazuh-dashboard"
manager_rpm_base_url="${base_url}/yum"

indexer_rpm_base_url="${base_url}/yum"
dashboard_rpm_base_url="${base_url}/yum"
readonly wazuh_gpg_key="https://${bucket}/key/GPG-KEY-WAZUH"

http_port=443
wazuh_aio_ports=( 9200 9300 1514 1515 1516 55000 "${http_port}")
readonly wazuh_indexer_ports=( 9200 9300 )
readonly wazuh_manager_ports=( 1514 1515 1516 55000 )
wazuh_dashboard_port="${http_port}"
# `lsof` and `openssl` are installed separately
wia_yum_dependencies=( systemd grep tar coreutils sed procps-ng gawk curl )
readonly wia_apt_dependencies=( systemd grep tar coreutils sed procps gawk curl )
readonly wazuh_yum_dependencies=()
readonly wazuh_apt_dependencies=( apt-transport-https gnupg )
readonly indexer_yum_dependencies=( coreutils )
readonly indexer_apt_dependencies=( debconf adduser procps )
readonly dashboard_yum_dependencies=( libcap yum-utils )
readonly dashboard_apt_dependencies=( debhelper tar curl libcap2-bin )
readonly wia_offline_dependencies=( curl tar gnupg openssl lsof )
wia_dependencies_installed=()
assistant_yum_dependencies=( "${wia_yum_dependencies[@]}" )
assistant_apt_dependencies=( "${wia_apt_dependencies[@]}" )
