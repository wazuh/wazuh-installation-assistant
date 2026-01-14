#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function offline_checkArtifactURLs_component_present() {
    common_logger -d "Checking required components are present in ${artifact_urls_file_name} file for download."
    common_logger -d "Architecture: ${arch}"
    common_logger -d "Package type: ${package_type}"
    artifact_file="${base_path}/${artifact_urls_file_name}"
    
    # Determine architecture suffix for artifact keys based on arch variable
    if [ "${arch}" == "x86_64" ] || [ "${arch}" == "amd64" ]; then
        arch_suffix="amd64"
    elif [ "${arch}" == "aarch64" ] || [ "${arch}" == "arm64" ]; then
        arch_suffix="arm64"
    else
        common_logger -e "Unsupported architecture: ${arch}"
        exit 1
    fi

    indexer_key="wazuh_indexer_${arch_suffix}_${package_type}"
    dashboard_key="wazuh_dashboard_${arch_suffix}_${package_type}"
    manager_key="wazuh_manager_${arch_suffix}_${package_type}"

    # Check that all required artifacts exist for offline download
    missing_keys=()
    
    if ! grep -q "^${indexer_key}:" "$artifact_file"; then
        missing_keys+=("${indexer_key}")
    fi
    
    if ! grep -q "^${dashboard_key}:" "$artifact_file"; then
        missing_keys+=("${dashboard_key}")
    fi
    
    if ! grep -q "^${manager_key}:" "$artifact_file"; then
        missing_keys+=("${manager_key}")
    fi
    
    if [ "${#missing_keys[@]}" -gt 0 ]; then
        common_logger -e "Missing required artifact keys in ${artifact_urls_file_name}:"
        for key in "${missing_keys[@]}"; do
            common_logger -e "  - ${key}"
        done
        exit 1
    fi
    
    common_logger -d "All required artifact keys found for offline download."
}

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

  # Determine architecture suffix for artifact keys based on arch variable
  if [ "${arch}" == "x86_64" ] || [ "${arch}" == "amd64" ]; then
    arch_suffix="amd64"
  elif [ "${arch}" == "aarch64" ] || [ "${arch}" == "arm64" ]; then
    arch_suffix="arm64"
  else
    common_logger -e "Unsupported architecture: ${arch}"
    exit 1
  fi

  artifact_file="${base_path}/${artifact_urls_file_name}"
  
  # Define components to download
  components=("wazuh_indexer" "wazuh_dashboard" "wazuh_manager")
  
  for component in "${components[@]}"; do
    # Build the artifact key
    artifact_key="${component}_${arch_suffix}_${package_type}"
    
    # Get the URL from the artifact file
    component_url=$(grep "^${artifact_key}:" "$artifact_file" | cut -d' ' -f2- | tr -d '"' | xargs)
    
    if [ -z "${component_url}" ]; then
      common_logger -e "Could not find URL for ${artifact_key} in ${artifact_urls_file_name}"
      exit 1
    fi
    
    # Extract filename from URL (remove query parameters after ?)
    component_filename=$(basename "${component_url%%\?*}")
    component_filepath="${dest_path}/${component_filename}"
    
    common_logger "Downloading ${component} package: ${component_filename}"
    
    # Download the component to the destination directory
    common_curl -sSLo '${component_filepath}' '${component_url}' --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}
    
    if [ ! -f "${component_filepath}" ]; then
      common_logger -e "Failed to download ${component} from ${component_url}."
      exit 1
    fi
    
    common_logger "The ${component} package was downloaded."
  done

  common_logger "The packages are in ${dest_path}"

  eval "chmod 500 ${base_dest_folder} ${debug}"

  common_logger "Creating wazuh-offline.tar.gz with all packages."

  eval "tar -czf ${base_dest_folder}.tar.gz ${base_dest_folder} ${debug}"
  eval "chmod -R 700 ${base_dest_folder} && rm -rf ${base_dest_folder} ${debug}"

  common_logger "You can follow the installation guide here https://documentation.wazuh.com/current/deployment-options/offline-installation.html"

}