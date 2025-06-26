#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function offline_download() {

  common_logger "Starting Wazuh packages download."
  common_logger "Downloading Wazuh ${package_type} packages for ${arch}."
  dest_path="${base_dest_folder}/wazuh-packages"

  if [ -d "${dest_path}" ]; then
    eval "rm -f ${dest_path}/* ${debug}" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path} ${debug}"
  else
    eval "mkdir -m700 -p ${dest_path} ${debug}" # Create folder if it does not exist
  fi

  packages_to_download=( "manager" "filebeat" "indexer" "dashboard" )

  manager_revision="1"
  indexer_revision="1"
  dashboard_revision="1"
  filebeat_revision="2"

  if [ -n "${development}" ]; then
    filebeat_config_file="https://${bucket}/${wazuh_major}/tpl/wazuh/filebeat/filebeat.yml"
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_base_url="${repobaseurl}/yum"
      indexer_rpm_base_url="${repobaseurl}/yum"
      dashboard_rpm_base_url="${repobaseurl}/yum"
      filebeat_rpm_base_url="${repobaseurl}/yum"
    elif [ "${package_type}" == "deb" ]; then
      manager_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-manager"
      indexer_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-indexer"
      dashboard_deb_base_url="${repobaseurl}/apt/pool/main/w/wazuh-dashboard"
      filebeat_deb_base_url="${repobaseurl}/apt/pool/main/f/filebeat"
    fi
  fi

  if [ "${package_type}" == "rpm" ]; then
    manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.${package_type}"
    indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.${package_type}"
    dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.${package_type}"
    filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.${package_type}"
    manager_base_url="${manager_rpm_base_url}"
    indexer_base_url="${indexer_rpm_base_url}"
    dashboard_base_url="${dashboard_rpm_base_url}"
    filebeat_base_url="${filebeat_rpm_base_url}"
    manager_package="${manager_rpm_package}"
    indexer_package="${indexer_rpm_package}"
    dashboard_package="${dashboard_rpm_package}"
    filebeat_package="${filebeat_rpm_package}"
  elif [ "${package_type}" == "deb" ]; then
    manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.${package_type}"
    indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.${package_type}"
    dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.${package_type}"
    filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.${package_type}"
    manager_base_url="${manager_deb_base_url}"
    indexer_base_url="${indexer_deb_base_url}"
    dashboard_base_url="${dashboard_deb_base_url}"
    filebeat_base_url="${filebeat_deb_base_url}"
    manager_package="${manager_deb_package}"
    indexer_package="${indexer_deb_package}"
    dashboard_package="${dashboard_deb_package}"
    filebeat_package="${filebeat_deb_package}"
  else
    common_logger "Unsupported package type: ${package_type}"
    exit 1
  fi

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${manager_base_url}/${manager_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    manager_revision=$((manager_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.rpm"
      manager_package="${manager_rpm_package}"
    else
      manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.deb"
      manager_package="${manager_deb_package}"
    fi
  done
  if [ "$manager_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${manager_base_url}/${manager_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    manager_revision=$((manager_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      manager_rpm_package="wazuh-manager-${wazuh_version}-${manager_revision}.${arch}.rpm"
    else
      manager_deb_package="wazuh-manager_${wazuh_version}-${manager_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh manager package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${filebeat_base_url}/${filebeat_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    filebeat_revision=$((filebeat_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.rpm"
      filebeat_package="${filebeat_rpm_package}"
    else
      filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.deb"
      filebeat_package="${filebeat_deb_package}"
    fi
  done
  if [ "$filebeat_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${filebeat_base_url}/${filebeat_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    filebeat_revision=$((filebeat_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      filebeat_rpm_package="filebeat-${offline_filebeat_version}-${filebeat_revision}.${arch}.rpm"
    else
      filebeat_deb_package="filebeat_${offline_filebeat_version}-${filebeat_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Filebeat package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${indexer_base_url}/${indexer_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    indexer_revision=$((indexer_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.rpm"
      indexer_package="${indexer_rpm_package}"
    else
      indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.deb"
      indexer_package="${indexer_deb_package}"
    fi
  done
  if [ "$indexer_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${indexer_base_url}/${indexer_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    indexer_revision=$((indexer_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      indexer_rpm_package="wazuh-indexer-${wazuh_version}-${indexer_revision}.${arch}.rpm"
    else
      indexer_deb_package="wazuh-indexer_${wazuh_version}-${indexer_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh indexer package revision fetched."

  while common_curl -s -I -o /dev/null -w "%{http_code}" "${dashboard_base_url}/${dashboard_package}" --max-time 300 --retry 5 --retry-delay 5 --fail | grep -q "200"; do
    dashboard_revision=$((dashboard_revision+1))
    if [ "${package_type}" == "rpm" ]; then
      dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.rpm"
      dashboard_package="${dashboard_rpm_package}"
    else
      dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.deb"
      dashboard_package="${dashboard_deb_package}"
    fi
  done
  if [ "$dashboard_revision" -gt 1 ] && [ "$(common_curl -s -I -o /dev/null -w "%{http_code}" "${dashboard_base_url}/${dashboard_package}" --max-time 300 --retry 5 --retry-delay 5 --fail)" -ne "200" ]; then
    dashboard_revision=$((dashboard_revision-1))
    if [ "${package_type}" == "rpm" ]; then
      dashboard_rpm_package="wazuh-dashboard-${wazuh_version}-${dashboard_revision}.${arch}.rpm"
    else
      dashboard_deb_package="wazuh-dashboard_${wazuh_version}-${dashboard_revision}_${arch}.deb"
    fi
  fi
  common_logger -d "Wazuh dashboard package revision fetched."

  for package in "${packages_to_download[@]}"
  do
    common_logger -d "Downloading Wazuh ${package} package..."
    package_name="${package}_${package_type}_package"
    eval "package_base_url=${package}_${package_type}_base_url"

    if output=$(common_curl -sSo "${dest_path}/${!package_name}" "${!package_base_url}/${!package_name}" --max-time 300 --retry 5 --retry-delay 5 --fail 2>&1); then
      common_logger "The ${package} package was downloaded."
    else
      common_logger -e "The ${package} package could not be downloaded. Exiting."
      eval "echo \${output} ${debug}"
      exit 1
    fi

  done

  common_logger "The packages are in ${dest_path}"

# --------------------------------------------------

  common_logger "Downloading configuration files and assets."
  dest_path="${base_dest_folder}/wazuh-files"

  if [ -d "${dest_path}" ]; then
    eval "rm -f ${dest_path}/* ${debug}" # Clean folder before downloading specific versions
    eval "chmod 700 ${dest_path} ${debug}"
  else
    eval "mkdir -m700 -p ${dest_path} ${debug}" # Create folder if it does not exist
  fi

  files_to_download=( "${wazuh_gpg_key}" "${filebeat_config_file}" "${filebeat_wazuh_template}" "${filebeat_wazuh_module}" )

  eval "cd ${dest_path}"
  for file in "${files_to_download[@]}"
  do
    common_logger -d "Downloading ${file}..."
    if output=$(common_curl -sSO ${file} --max-time 300 --retry 5 --retry-delay 5 --fail 2>&1); then
        common_logger "The resource ${file} was downloaded."
    else
        common_logger -e "The resource ${file} could not be downloaded. Exiting."
        eval "echo \${output} ${debug}"
        exit 1
    fi

  done
  eval "cd - > /dev/null"

  eval "chmod 500 ${base_dest_folder} ${debug}"

  common_logger "The configuration files and assets are in wazuh-offline.tar.gz"

  eval "tar -czf ${base_dest_folder}.tar.gz ${base_dest_folder} ${debug}"
  eval "chmod -R 700 ${base_dest_folder} && rm -rf ${base_dest_folder} ${debug}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/deployment-options/offline-installation.html"

}