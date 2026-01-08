# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function installCommon_addCentOSRepository() {

    local repo_name="$1"
    local repo_description="$2"
    local repo_baseurl="$3"

    echo "[$repo_name]" >> "${centos_repo}"
    echo "name=${repo_description}" >> "${centos_repo}"
    echo "baseurl=${repo_baseurl}" >> "${centos_repo}"
    echo 'gpgcheck=1' >> "${centos_repo}"
    echo 'enabled=1' >> "${centos_repo}"
    echo "gpgkey=file://${centos_key}" >> "${centos_repo}"
    echo '' >> "${centos_repo}"

}

function installCommon_cleanExit() {

    rollback_conf=""

    if [ -n "$spin_pid" ]; then
        eval "kill -9 $spin_pid ${debug}"
    fi

    until [[ "${rollback_conf}" =~ ^[N|Y|n|y]$ ]]; do
        echo -ne "\nDo you want to remove the ongoing installation?[Y/N]"
        read -r rollback_conf
    done
    if [[ "${rollback_conf}" =~ [N|n] ]]; then
        exit 1
    else
        common_checkInstalled
        installCommon_rollBack
        exit 1
    fi

}

function installCommon_aptInstall() {

    package="${1}"
    version="${2}"
    attempt=0
    
    # Determine the installer package
    if [[ "${package}" == *.deb ]]; then
        installer="${package}"
    elif [ -n "${version}" ]; then
        installer="${package}${sep}${version}"
    else
        installer="${package}"
    fi

    # Override with offline package if needed
    if [ -n "${offline_install}" ] && [[ "${package}" != *.deb ]]; then
        package_name=$(ls ${offline_packages_path} | grep ${package})
        installer="${offline_packages_path}/${package_name}"
    fi

    # Build the installation command
    command="DEBIAN_FRONTEND=noninteractive apt-get install ${installer} -y -q"
    
    common_checkAptLock

    if [ "${attempt}" -ne "${max_attempts}" ]; then
        apt_output=$(eval "${command} 2>&1")
        install_result="${PIPESTATUS[0]}"
        eval "echo \${apt_output} ${debug}"
    fi

}

function installCommon_aptInstallList(){

    dependencies=("$@")
    not_installed=()

    for dep in "${dependencies[@]}"; do
        if ! apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/; then
            not_installed+=("${dep}")
            for wia_dep in "${wia_apt_dependencies[@]}"; do
                if [ "${wia_dep}" == "${dep}" ]; then
                    wia_dependencies_installed+=("${dep}")
                fi
            done
        fi
    done

    if [ "${#not_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ----"
        for dep in "${not_installed[@]}"; do
            common_logger "Installing $dep."
            installCommon_aptInstall "${dep}"
            if [ "${install_result}" != 0 ]; then
                common_logger -e "Cannot install dependency: ${dep}."
                installCommon_rollBack
                exit 1
            fi
        done
    fi

}

function installCommon_createCertificates() {

    common_logger -d "Creating Wazuh certificates."
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig certificate/config_aio.yml ${config_file} ${debug}"
    fi

    cert_readConfig

    if [ -d /tmp/wazuh-certificates/ ]; then
        eval "rm -rf /tmp/wazuh-certificates/ ${debug}"
    fi
    eval "mkdir /tmp/wazuh-certificates/ ${debug}"

    cert_tmp_path="/tmp/wazuh-certificates/"

    cert_generateRootCAcertificate
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateServercertificates
    cert_generateDashboardcertificates
    cert_cleanFiles
    eval "chmod 400 /tmp/wazuh-certificates/* ${debug}"
    eval "mv /tmp/wazuh-certificates/* /tmp/wazuh-install-files ${debug}"
    eval "rm -rf /tmp/wazuh-certificates/ ${debug}"

}

function installCommon_createClusterKey() {

    openssl rand -hex 16 >> "/tmp/wazuh-install-files/clusterkey"

}

function installCommon_createInstallFiles() {

    if [ -d /tmp/wazuh-install-files ]; then
        eval "rm -rf /tmp/wazuh-install-files ${debug}"
    fi

    if eval "mkdir /tmp/wazuh-install-files ${debug}"; then
        common_logger "Generating configuration files."

        dep="openssl"
        if [ "${sys_type}" == "yum" ]; then
            installCommon_yumInstallList "${dep}"
        elif [ "${sys_type}" == "apt-get" ]; then
            installCommon_aptInstallList "${dep}"
        fi

        if [ "${#not_installed[@]}" -gt 0 ]; then
            wia_dependencies_installed+=("${dep}")
        fi

        if [ -n "${configurations}" ]; then
            cert_checkOpenSSL
        fi
        installCommon_createCertificates
        if [ -n "${server_node_types[*]}" ]; then
            installCommon_createClusterKey
        fi
        eval "cp '${config_file}' '/tmp/wazuh-install-files/config.yml' ${debug}"
        eval "chown root:root /tmp/wazuh-install-files/* ${debug}"
        eval "tar -zcf '${tar_file}' -C '/tmp/' wazuh-install-files/ ${debug}"
        eval "rm -rf '/tmp/wazuh-install-files' ${debug}"
	    eval "rm -rf ${config_file} ${debug}"
        common_logger "Created ${tar_file_name}. It contains the Wazuh cluster key and the certificates necessary for installation."
    else
        common_logger -e "Unable to create /tmp/wazuh-install-files"
        exit 1
    fi
}

# Adds the CentOS repository to install lsof.
function installCommon_configureCentOSRepositories() {

    centos_repos_configured=1
    centos_key="/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"
    eval "common_curl -sLo ${centos_key} 'https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official' --max-time 300 --retry 5 --retry-delay 5 --fail"

    if [ ! -f "${centos_key}" ]; then
        common_logger -w "The CentOS key could not be added. Some dependencies may not be installed."
    else
        centos_repo="/etc/yum.repos.d/centos.repo"
        eval "touch ${centos_repo} ${debug}"
        common_logger -d "CentOS repository file created."

        if [ "${DIST_VER}" == "9" ]; then
            installCommon_addCentOSRepository "appstream" "CentOS Stream \$releasever - AppStream" "https://mirror.stream.centos.org/9-stream/AppStream/\$basearch/os/"
            installCommon_addCentOSRepository "baseos" "CentOS Stream \$releasever - BaseOS" "https://mirror.stream.centos.org/9-stream/BaseOS/\$basearch/os/"
        elif [ "${DIST_VER}" == "8" ]; then
            installCommon_addCentOSRepository "extras" "CentOS Linux \$releasever - Extras" "http://vault.centos.org/centos/\$releasever/extras/\$basearch/os/"
            installCommon_addCentOSRepository "baseos" "CentOS Linux \$releasever - BaseOS" "http://vault.centos.org/centos/\$releasever/BaseOS/\$basearch/os/"
            installCommon_addCentOSRepository "appstream" "CentOS Linux \$releasever - AppStream" "http://vault.centos.org/centos/\$releasever/AppStream/\$basearch/os/"
        fi

        common_logger -d "CentOS repositories added."
    fi

}

function installCommon_downloadArtifactURLs() {

    common_logger -d "Downloading artifact URLs file."
    artifact_url="https://${bucket}/${wazuh_major}/${artifact_urls_file_name}"
    eval "common_curl -sSo ${artifact_urls_file_name} ${artifact_url} --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}"
    
    curl_exit_code="${PIPESTATUS[0]}"
    if [ "${curl_exit_code}" -ne 0 ]; then
        common_logger -e "Failed to download artifact URLs from ${artifact_url}. Exit code: ${curl_exit_code}"
        exit 1
    fi
    
    if [ ! -f "${artifact_urls_file_name}" ]; then
        common_logger -e "Failed to download artifact URLs from ${artifact_url}."
        exit 1
    fi

}

function installCommon_downloadComponent() {
    # TODO: review the behavior of this function
    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_downloadComponent must be called with one argument (component name)."
        exit 1
    fi

    component="${1}"
    artifact_file="${base_path}/${artifact_urls_file_name}"
    download_dir="${base_path}/${download_packages_directory}"
    
    # Create download directory if it doesn't exist
    if [ ! -d "${download_dir}" ]; then
        eval "mkdir -p ${download_dir} ${debug}"
        if [ ! -d "${download_dir}" ]; then
            common_logger -e "Failed to create download directory: ${download_dir}"
            exit 1
        fi
    fi
    
    # Determine package type based on system
    if [ "${sys_type}" == "yum" ]; then
        pkg_type="rpm"
    elif [ "${sys_type}" == "apt-get" ]; then
        pkg_type="deb"
    fi
    
    # Determine architecture suffix for artifact keys
    if [ "${architecture}" == "x86_64" ]; then
        arch_suffix="amd64"
    elif [ "${architecture}" == "aarch64" ]; then
        arch_suffix="arm64"
    fi
    
    # Build the artifact key
    artifact_key="${component}_${arch_suffix}_${pkg_type}"
    
    # Get the URL from the artifact file
    component_url=$(grep "^${artifact_key}:" "$artifact_file" | cut -d' ' -f2- | tr -d '"' | xargs)

    # Extract filename from URL (remove query parameters after ?)
    component_filename=$(basename "${component_url%%\?*}")
    component_filepath="${download_dir}/${component_filename}"
    
    common_logger "Downloading ${component} package: ${component_filename}"
    
    # Download the component to the download directory
    common_curl -sSLo '${component_filepath}' '${component_url}' --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}
    
    if [ ! -f "${component_filepath}" ]; then
        common_logger -e "Failed to download ${component} from ${component_url}."
        exit 1
    fi
    
    common_logger "${component} package downloaded successfully: ${component_filepath}"

}

function installCommon_extractConfig() {

    common_logger -d "Extracting Wazuh configuration."
    if ! tar -tf "${tar_file}" | grep -q wazuh-install-files/config.yml; then
        common_logger -e "There is no config.yml file in ${tar_file}."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C /tmp wazuh-install-files/config.yml ${debug}"

}

function installCommon_getConfig() {

    if [ "$#" -ne 2 ]; then
        common_logger -e "installCommon_getConfig should be called with two arguments"
        exit 1
    fi

    config_name="config_file_$(eval "echo ${1} | sed 's|/|_|g;s|.yml||'")"
    if [ -z "$(eval "echo \${${config_name}}")" ]; then
        common_logger -e "Unable to find configuration file ${1}. Exiting."
        installCommon_rollBack
        exit 1
    fi
    eval "echo \"\${${config_name}}\"" > "${2}"
}

function installCommon_installCheckDependencies() {

    common_logger -d "Installing check dependencies."
    if [ "${sys_type}" == "yum" ]; then
        if [[ "${DIST_NAME}" == "rhel" ]] && [[ "${DIST_VER}" == "8" || "${DIST_VER}" == "9" ]]; then
            installCommon_configureCentOSRepositories
        fi
        installCommon_yumInstallList "${wia_yum_dependencies[@]}"

        # In RHEL cases, remove the CentOS repositories configuration
        if [ "${centos_repos_configured}" == 1 ]; then
            installCommon_removeCentOSrepositories
        fi

    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt-get update -q ${debug}"
        installCommon_aptInstallList "${wia_apt_dependencies[@]}"
    fi

}

function installCommon_installPrerequisites() {

    message="Installing prerequisites dependencies."
    if [ "${sys_type}" == "yum" ]; then
        if [ "${1}" == "AIO" ]; then
            deps=($(echo "${indexer_yum_dependencies[@]}" "${dashboard_yum_dependencies[@]}" | tr ' ' '\n' | sort -u))
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${deps[@]}"
            else
                offline_checkPrerequisites "${deps[@]}"
            fi
        fi
        if [ "${1}" == "indexer" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${indexer_yum_dependencies[@]}"
            else
                offline_checkPrerequisites "${indexer_yum_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "dashboard" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_yumInstallList "${dashboard_yum_dependencies[@]}"
            else
                offline_checkPrerequisites "${dashboard_yum_dependencies[@]}"
            fi
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        if [ -z "${offline_install}" ]; then
            eval "apt-get update -q ${debug}"
        fi
        if [ "${1}" == "AIO" ]; then
            deps=($(echo "${wazuh_apt_dependencies[@]}" "${indexer_apt_dependencies[@]}" "${dashboard_apt_dependencies[@]}" | tr ' ' '\n' | sort -u))
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${deps[@]}"
            else
                offline_checkPrerequisites "${deps[@]}"
            fi
        fi
        if [ "${1}" == "indexer" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${indexer_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${indexer_apt_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "dashboard" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${dashboard_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${dashboard_apt_dependencies[@]}"
            fi
        fi
        if [ "${1}" == "wazuh" ]; then
            if [ -z "${offline_install}" ]; then
                common_logger -d "${message}"
                installCommon_aptInstallList "${wazuh_apt_dependencies[@]}"
            else
                offline_checkPrerequisites "${wazuh_apt_dependencies[@]}"
            fi
        fi
    fi

}

function installCommon_removeCentOSrepositories() {

    eval "rm -f ${centos_repo} ${debug}"
    eval "rm -f ${centos_key} ${debug}"
    eval "yum clean all ${debug}"
    centos_repos_configured=0
    common_logger -d "CentOS repositories and key deleted."

}

function installCommon_rollBack() {

    if [ -z "${uninstall}" ]; then
        common_logger "--- Removing existing Wazuh installation ---"
    fi

    if [[ -n "${wazuh_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
        common_logger "Removing Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-manager -y ${debug}"
                eval "rpm -q wazuh-manager --quiet && wazuh_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-manager -y ${debug}"
            wazuh_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-manager)
        fi

        if [ -n "${wazuh_failed_uninstall}" ]; then
            common_logger -w "The Wazuh manager package could not be removed."
        else
            common_logger "Wazuh manager removed."
        fi

    fi

    if [[ ( -n "${wazuh_remaining_files}"  || -n "${wazuh_installed}" ) && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/ossec/ ${debug}"
    fi

    if [[ -n "${indexer_installed}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh indexer."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-indexer -y ${debug}"
                eval "rpm -q wazuh-indexer --quiet && indexer_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-indexer -y ${debug}"
            indexer_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-indexer)
        fi

        if [ -n "${indexer_failed_uninstall}" ]; then
            common_logger -w "The Wazuh indexer package could not be removed."
        else
            common_logger "Wazuh indexer removed."
        fi
    fi

    if [[ ( -n "${indexer_remaining_files}" || -n "${indexer_installed}" ) && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-indexer/ ${debug}"
        eval "rm -rf /usr/share/wazuh-indexer/ ${debug}"
        eval "rm -rf /etc/wazuh-indexer/ ${debug}"
    fi

    if [[ -n "${dashboard_installed}" && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh dashboard."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-dashboard -y ${debug}"
                eval "rpm -q wazuh-dashboard --quiet && dashboard_failed_uninstall=1"
            fi
        elif [ "${sys_type}" == "apt-get" ]; then
            common_checkAptLock
            eval "apt-get remove --purge wazuh-dashboard -y ${debug}"
            dashboard_failed_uninstall=$(apt list --installed 2>/dev/null | grep wazuh-dashboard)
        fi

        if [ -n "${dashboard_failed_uninstall}" ]; then
            common_logger -w "The Wazuh dashboard package could not be removed."
        else
            common_logger "Wazuh dashboard removed."
        fi
    fi

    if [[ ( -n "${dashboard_remaining_files}" || -n "${dashboard_installed}" ) && ( -n "${dashboard}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        eval "rm -rf /var/lib/wazuh-dashboard/ ${debug}"
        eval "rm -rf /usr/share/wazuh-dashboard/ ${debug}"
        eval "rm -rf /etc/wazuh-dashboard/ ${debug}"
        eval "rm -rf /run/wazuh-dashboard/ ${debug}"
    fi

    elements_to_remove=(    "/var/log/wazuh-indexer/"
                            "/etc/systemd/system/opensearch.service.wants/"
                            "/securityadmin_demo.sh"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-manager.service"
                            "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                            "/etc/systemd/system/multi-user.target.wants/wazuh-dashboard.service"
                            "/etc/systemd/system/wazuh-dashboard.service"
                            "/lib/firewalld/services/dashboard.xml"
                            "/lib/firewalld/services/opensearch.xml" )

    eval "rm -rf ${elements_to_remove[*]} ${debug}"

    installCommon_removeWIADependencies

    eval "systemctl daemon-reload ${debug}"

    if [ -z "${uninstall}" ]; then
        if [ -n "${rollback_conf}" ] || [ -n "${overwrite}" ]; then
            common_logger "Installation cleaned."
        else
            common_logger "Installation cleaned. Check the ${logfile} file to learn more about the issue."
        fi
    fi

}

function installCommon_startService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_startService must be called with 1 argument."
        exit 1
    fi

    common_logger "Starting service ${1}."

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable ${1}.service ${debug}"
        eval "systemctl start ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} start ${debug}"
        eval "/etc/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} start ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service started."
        fi
    else
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1
    fi

}

function installCommon_restartService() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "installCommon_restartService must be called with 1 argument."
        exit 1
    fi

    common_logger "Restarting service ${1}."

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl restart ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be restarted."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service restarted."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "chkconfig ${1} on ${debug}"
        eval "service ${1} restart ${debug}"
        eval "/etc/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be restarted."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service restarted."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be restarted."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            installCommon_rollBack
            exit 1
        else
            common_logger "${1} service restarted."
        fi
    else
        common_logger -e "${1} could not restart. No service manager found on the system."
        exit 1
    fi

}

function installCommon_yumInstallList(){

    dependencies=("$@")
    not_installed=()
    for dep in "${dependencies[@]}"; do
        if ! rpm -q "${dep}" --quiet;then
            not_installed+=("${dep}")
            for wia_dep in "${wia_yum_dependencies[@]}"; do
                if [ "${wia_dep}" == "${dep}" ]; then
                    wia_dependencies_installed+=("${dep}")
                fi
            done
        fi
    done

    if [ "${#not_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ---"
        for dep in "${not_installed[@]}"; do
            common_logger "Installing $dep."
            installCommon_yumInstall "${dep}"
            yum_code="${PIPESTATUS[0]}"

            eval "echo \${yum_output} ${debug}"
            if [  "${yum_code}" != 0  ]; then
                common_logger -e "Cannot install dependency: ${dep}."
                installCommon_rollBack
                exit 1
            fi
        done
    fi

}

function installCommon_removeWIADependencies() {

    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumRemoveWIADependencies
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptRemoveWIADependencies
    fi

}

function installCommon_yumRemoveWIADependencies(){

    if [ "${#wia_dependencies_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ---"
        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ]; then
                common_logger "Removing $dep."
                yum_output=$(yum remove ${dep} -y 2>&1)
                yum_code="${PIPESTATUS[0]}"

                eval "echo \${yum_output} ${debug}"
                if [  "${yum_code}" != 0  ]; then
                    common_logger -e "Cannot remove dependency: ${dep}."
                    exit 1
                fi
            fi
        done
    fi

}

function installCommon_aptRemoveWIADependencies(){

    if [ "${#wia_dependencies_installed[@]}" -gt 0 ]; then
        common_logger "--- Dependencies ----"
        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ]; then
                common_logger "Removing $dep."
                apt_output=$(apt-get remove --purge ${dep} -y 2>&1)
                apt_code="${PIPESTATUS[0]}"

                eval "echo \${apt_output} ${debug}"
                if [  "${apt_code}" != 0  ]; then
                    common_logger -e "Cannot remove dependency: ${dep}."
                    exit 1
                fi
            fi
        done
    fi

}

function installCommon_removeDownloadPackagesDirectory() {

    download_dir="${base_path}/${download_packages_directory}"
    if [ -d "${download_dir}" ]; then
        eval "rm -rf ${download_dir} ${debug}"
        common_logger -d "Removed download packages directory: ${download_dir}"
    else
        common_logger -w "Download packages directory does not exist: ${download_dir}"
    fi

}

function installCommon_yumInstall() {

    package="${1}"
    version="${2}"
    install_result=1
    
    # If package is a file path (contains .rpm), install directly
    if [[ "${package}" == *.rpm ]]; then
        installer="${package}"
        command="rpm -ivh ${installer}"
        common_logger -d "Installing local package: ${installer}"
    elif [ -n "${version}" ]; then
        installer="${package}-${version}"
        # Offline installation case: get package name and install it
        if [ -n "${offline_install}" ]; then
            package_name=$(ls ${offline_packages_path} | grep ${package})
            installer="${offline_packages_path}/${package_name}"
            command="rpm -ivh ${installer}"
            common_logger -d "Installing local package: ${installer}"
        else
            command="yum install ${installer} -y"
        fi
    else
        installer="${package}"
        # Offline installation case: get package name and install it
        if [ -n "${offline_install}" ]; then
            package_name=$(ls ${offline_packages_path} | grep ${package})
            installer="${offline_packages_path}/${package_name}"
            command="rpm -ivh ${installer}"
            common_logger -d "Installing local package: ${installer}"
        else
            command="yum install ${installer} -y"
        fi
    fi
    common_checkYumLock

    if [ "${attempt}" -ne "${max_attempts}" ]; then
        yum_output=$(eval "${command} 2>&1")
        install_result="${PIPESTATUS[0]}"
        eval "echo \${yum_output} ${debug}"
    fi

}


function installCommon_checkAptLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while fuser "${apt_lockfile}" >/dev/null 2>&1 && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using APT. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}
