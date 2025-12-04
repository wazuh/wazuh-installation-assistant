# Wazuh installer - variables
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly wazuh_major="4.14"
readonly wazuh_version="4.14.2"
readonly filebeat_version="7.10.2-*"
readonly wazuh_install_vesion="0.1"
source_branch="v${wazuh_version}"
last_stage=""

repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"
reporelease="stable"
filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.5.tar.gz"
bucket="packages.wazuh.com"
repository="4.x"

## Links and paths to resources
readonly resources="https://${bucket}/${wazuh_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
config_file="${base_path}/config.yml"
readonly tar_file_name="wazuh-install-files.tar"
tar_file="${base_path}/${tar_file_name}"

filebeat_wazuh_template="https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/extensions/elasticsearch/7.x/wazuh-template.json"

readonly dashboard_cert_path="/etc/wazuh-dashboard/certs"
readonly filebeat_cert_path="/etc/filebeat/certs"
readonly indexer_cert_path="/etc/wazuh-indexer/certs"

readonly logfile="/var/log/wazuh-install.log"
debug=">> ${logfile} 2>&1"
readonly yum_lockfile="/var/run/yum.pid"
readonly apt_lockfile="/var/lib/dpkg/lock"

## Offline Installation vars
readonly base_dest_folder="wazuh-offline"
manager_deb_base_url="${base_url}/apt/pool/main/w/wazuh-manager"
filebeat_deb_base_url="${base_url}/apt/pool/main/f/filebeat"

indexer_deb_base_url="${base_url}/apt/pool/main/w/wazuh-indexer"
dashboard_deb_base_url="${base_url}/apt/pool/main/w/wazuh-dashboard"
manager_rpm_base_url="${base_url}/yum"
filebeat_rpm_base_url="${base_url}/yum"

indexer_rpm_base_url="${base_url}/yum"
dashboard_rpm_base_url="${base_url}/yum"
readonly wazuh_gpg_key="https://${bucket}/key/GPG-KEY-WAZUH"
filebeat_config_file="${resources}/tpl/wazuh/filebeat/filebeat.yml"
readonly offline_filebeat_version="7.10.2"

adminUser="wazuh"
adminPassword="wazuh"

http_port=443
wazuh_aio_ports=( 9200 9300 1514 1515 1516 55000 "${http_port}")
readonly wazuh_indexer_ports=( 9200 9300 )
readonly wazuh_manager_ports=( 1514 1515 1516 55000 )
wazuh_dashboard_port="${http_port}"
# `lsof` and `openssl` are installed separately
wia_yum_dependencies=( systemd grep tar coreutils sed procps-ng gawk curl )
readonly wia_apt_dependencies=( systemd grep tar coreutils sed procps gawk curl )
readonly wazuh_yum_dependencies=( libcap )
readonly wazuh_apt_dependencies=( apt-transport-https libcap2-bin gnupg )
readonly indexer_yum_dependencies=( coreutils )
readonly indexer_apt_dependencies=( debconf adduser procps gnupg apt-transport-https )
readonly dashboard_yum_dependencies=( libcap )
readonly dashboard_apt_dependencies=( debhelper tar curl libcap2-bin gnupg apt-transport-https )
readonly wia_offline_dependencies=( curl tar gnupg openssl lsof )
wia_dependencies_installed=()
