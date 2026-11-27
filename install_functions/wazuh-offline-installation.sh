#!/bin/bash

# Wazuh installer: offline download
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Checks the necessary packages needed for a Wazuh component
function offline_checkPrerequisites(){

    if [ "$1" == "wia_offline_dependencies" ]; then
        dependencies=( "${@:2}" )
        common_logger "Checking dependencies for Wazuh installation assistant."
    else
        common_logger "Checking prerequisites for Offline installation."
        if [ "${sys_type}" == "yum" ]; then
            if [ "$1" == "AIO" ]; then
                dependencies=( $(echo "${wazuh_yum_dependencies[@]}" "${indexer_yum_dependencies[@]}" "${dashboard_yum_dependencies[@]}" | tr ' ' '\n' | sort -u) )
            elif [ "$1" == "indexer" ]; then
                dependencies=( "${indexer_yum_dependencies[@]}" )
            elif [ "$1" == "dashboard" ]; then
                dependencies=( "${dashboard_yum_dependencies[@]}" )
            elif [ "$1" == "wazuh" ]; then
                dependencies=( "${wazuh_yum_dependencies[@]}" )
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            if [ "$1" == "AIO" ]; then
                dependencies=( $(echo "${wazuh_apt_dependencies[@]}" "${indexer_apt_dependencies[@]}" "${dashboard_apt_dependencies[@]}" | tr ' ' '\n' | sort -u) )
            elif [ "$1" == "indexer" ]; then
                dependencies=( "${indexer_apt_dependencies[@]}" )
            elif [ "$1" == "dashboard" ]; then
                dependencies=( "${dashboard_apt_dependencies[@]}" )
            elif [ "$1" == "wazuh" ]; then
                dependencies=( "${wazuh_apt_dependencies[@]}" )
            fi
        fi
    fi

    for dep in "${dependencies[@]}"; do
        if [ "${sys_type}" == "yum" ]; then
            # By what the package provides, not its name: gnupg is gnupg2 on RHEL and
            # gnupg2-minimal on AL2023, curl may be curl-minimal. rpm does not go
            # through the yum repositories, which time out without Internet access
            rpm -q --whatprovides "${dep}" >/dev/null 2>&1
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/"
        fi

        if [ "${PIPESTATUS[0]}" != 0 ] && [[ " ${offline_missing_dependencies[*]} " != *" ${dep} "* ]]; then
            offline_missing_dependencies+=("${dep}")
        fi
    done
}

# Stops with every package the checks above found missing, so a single trip to a host
# with Internet access brings them all
function offline_reportMissingPrerequisites() {

    if [ "${#offline_missing_dependencies[@]}" -eq 0 ]; then
        common_logger -d "Prerequisites for Offline installation are installed."
        return 0
    fi
    if [ "${sys_type}" == "yum" ]; then
        download_command="yumdownloader --resolve ${offline_missing_dependencies[*]}"
    else
        download_command="apt-get download ${offline_missing_dependencies[*]}"
    fi
    common_logger -e "These packages are necessary for the offline installation and are not installed: ${offline_missing_dependencies[*]}."
    common_logger -e "Download them on a host with Internet access, for example with: ${download_command}. Then copy them to this host, install them and run the assistant again."
    exit 1
}

# Checks the necessary files for the installation
function offline_checkPreinstallation() {

    offline_tarfile="${base_dest_folder}.tar.gz"
    common_logger "Checking ${offline_tarfile} file."
    if [ ! -f "${base_path}/${offline_tarfile}" ]; then
        common_logger -e "The ${offline_tarfile} file was not found in ${base_path}."
        exit 1
    fi
    common_logger -d "${offline_tarfile} was found correctly."

}

# Extracts the files for the offline installation and check its content
function offline_extractFiles() {

    common_logger -d "Extracting files from ${offline_tarfile}"
    if [ ! -d "${base_path}/wazuh-offline/" ]; then
        eval "tar -xzf ${offline_tarfile} ${debug}"

        if [ ! -d "${base_path}/wazuh-offline/" ]; then
            common_logger -e "The ${offline_tarfile} file could not be decompressed."
            exit 1
        fi
    fi

    offline_packages_path="${base_path}/wazuh-offline/wazuh-packages"
    required_files=("${base_path}/wazuh-offline/GPG-KEY-WAZUH")

    if [ "${sys_type}" == "apt-get" ]; then
        required_files+=("${offline_packages_path}/wazuh-dashboard*.deb" "${offline_packages_path}/wazuh-indexer*.deb" "${offline_packages_path}/wazuh-manager*.deb")
    elif [ "${sys_type}" == "yum" ]; then
        required_files+=("${offline_packages_path}/wazuh-dashboard*.rpm" "${offline_packages_path}/wazuh-indexer*.rpm" "${offline_packages_path}/wazuh-manager*.rpm")
    fi

    for file in "${required_files[@]}"; do
        if ! compgen -G "${file}" > /dev/null; then
            common_logger -e "Missing necessary offline file: ${file}"
            exit 1
        fi
    done

    common_logger -d "Offline files extracted successfully."
}
