# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

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

    if [[ "${installer}" == *.deb ]]; then
        installCommon_verifyPackageSignature "${installer}"
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

function installCommon_createCertificates() {

    common_logger -d "Creating Wazuh certificates."
    cert_readConfig

    cert_checkListenerReachability

    if [ -d /tmp/wazuh-certificates/ ]; then
        eval "rm -rf /tmp/wazuh-certificates/ ${debug}"
    fi
    eval "mkdir /tmp/wazuh-certificates/ ${debug}"

    cert_tmp_path="/tmp/wazuh-certificates/"

    cert_checkRootCA "create"
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateManagercertificates
    cert_generateDashboardcertificates
    cert_cleanFiles
    eval "chmod 400 /tmp/wazuh-certificates/* ${debug}"
    eval "mv /tmp/wazuh-certificates/* /tmp/wazuh-install-files ${debug}"
    eval "rm -rf /tmp/wazuh-certificates/ ${debug}"
    cert_verifyRemotedcertificates "/tmp/wazuh-install-files"

}

# Generates the passwords of every component in the credentials file of this host, where
# the indexer package reads them when it is installed here, and adds a copy to the tar.
# A password already in the file is kept, so running -g again gives the same ones.
function installCommon_createPasswords() {

    local key

    common_logger -d "Generating the Wazuh passwords."
    for key in "${credential_keys[@]}"; do
        if wazuh_env_get "${key}" > /dev/null 2>&1; then
            continue
        fi
        if ! wazuh_env_set "${key}" "$(wazuh_password_generate)"; then
            common_logger -e "Could not write ${key} to the credentials file."
            exit 1
        fi
    done

    if ! eval "cp '$(wazuh_env_get_file)' /tmp/wazuh-install-files/credentials.env ${debug}"; then
        common_logger -e "Could not copy the credentials file."
        exit 1
    fi
    eval "chmod 600 /tmp/wazuh-install-files/credentials.env ${debug}"

}

# Places the passwords given as arguments (the ones of the component being installed) and
# the root CA certificate from the tar before a component is installed, where its package
# reads them. The other passwords of the tar are never written, so a node only holds the
# passwords of its components. The CA private key is never placed: without it, a package
# that finds no certificate pair fails instead of issuing its own.
function installCommon_placeCredentials() {

    local base_dir ca_dir

    if [ "$#" -eq 0 ]; then
        common_logger -e "installCommon_placeCredentials needs the credential keys of the component."
        exit 1
    fi

    common_logger -d "Placing the credentials of the component and the root CA certificate."
    if ! base_dir=$(wazuh_base_get_dir); then
        common_logger -e "Could not resolve the Wazuh base directory."
        exit 1
    fi
    if ! ca_dir=$(wazuh_ca_get_dir); then
        common_logger -e "Could not resolve the root CA directory."
        exit 1
    fi

    # Nothing is written until both files are known to belong to this deployment.
    if [ -e "${ca_dir}/root-ca.pem" ] && ! tar -xOf "${tar_file}" wazuh-install-files/root-ca.pem 2>/dev/null | cmp -s - "${ca_dir}/root-ca.pem"; then
        common_logger -e "${ca_dir}/root-ca.pem already exists and is not the one in ${tar_file}. Remove it, or use the tar file of this deployment."
        exit 1
    fi
    if [ -e "${base_dir}/credentials.env" ]; then
        installCommon_mergeCredentials check
    fi

    eval "install -d -o root -g root -m 0700 '${base_dir}' ${debug}"
    installCommon_mergeCredentials merge "$@"

    eval "install -d -o root -g root -m 0700 '${ca_dir}' ${debug}"
    installCommon_placeFromTar "root-ca.pem" "${ca_dir}/root-ca.pem" root root 0644

}

# With "check", compares every password of the tar that is already in the credentials file
# of the host (the -g host, another component of this node, or one a failed install left
# behind after its package removed its own keys) and writes nothing: a password that
# differs belongs to another deployment. With "merge", followed by the keys of the
# component, adds to the file, creating it if needed, those keys it does not have yet, and
# never any other.
function installCommon_mergeCredentials() {

    local mode="${1:-merge}"
    local key value current credentials
    local -a keys

    [ "$#" -gt 0 ] && shift
    if [ "${mode}" = "check" ]; then
        keys=("${credential_keys[@]}")
    else
        keys=("$@")
    fi

    credentials=$(tar -xOf "${tar_file}" wazuh-install-files/credentials.env 2>/dev/null)
    for key in "${keys[@]}"; do
        value=$(sed -nE "s/^${key}=\"?([^\"]*)\"?$/\1/p" <<< "${credentials}" | tail -n 1)
        if [ -z "${value}" ]; then
            if [ "${mode}" = "check" ]; then
                continue
            fi
            common_logger -e "There is no ${key} in the credentials.env file of ${tar_file}."
            exit 1
        fi
        if current=$(wazuh_env_get "${key}" 2>/dev/null); then
            if [ "${current}" != "${value}" ]; then
                common_logger -e "${key} in $(wazuh_env_get_file) is not the one in ${tar_file}. Remove the file, or use the tar file of this deployment."
                exit 1
            fi
        elif [ "${mode}" != "check" ] && ! wazuh_env_set "${key}" "${value}"; then
            common_logger -e "Could not write ${key} to the credentials file."
            exit 1
        fi
    done

}

# Copies one file of the tar to its place with the given owner, group and mode. A file
# already there is kept when it is identical (the -g host already holds the credentials
# file and the CA), and is an error when it is not: it belongs to another deployment.
function installCommon_placeFromTar() {

    local member="${1}" destination="${2}" owner="${3}" group="${4}" mode="${5}"
    local staged

    staged=$(mktemp)
    if ! tar -xOf "${tar_file}" "wazuh-install-files/${member}" > "${staged}" 2>/dev/null; then
        rm -f "${staged}"
        common_logger -e "Could not extract ${member} from ${tar_file}."
        exit 1
    fi

    if [ -e "${destination}" ]; then
        if cmp -s "${staged}" "${destination}"; then
            rm -f "${staged}"
            common_logger -d "${destination} is already in place."
            return 0
        fi
        rm -f "${staged}"
        common_logger -e "${destination} already exists and is not the one in ${tar_file}. Remove it, or use the tar file of this deployment."
        exit 1
    fi

    if ! install -o "${owner}" -g "${group}" -m "${mode}" "${staged}" "${destination}"; then
        rm -f "${staged}"
        common_logger -e "Could not place ${destination}."
        exit 1
    fi
    rm -f "${staged}"

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

        if [ -n "${configurations}" ]; then
            cert_checkOpenSSL
        fi
        installCommon_createCertificates
        if [ -n "${manager_node_types[*]}" ]; then
            installCommon_createClusterKey
        fi
        installCommon_createPasswords
        # root-ca.key stays in the CA directory of this host and is not added to the tar:
        # with it, any node could issue a CN=admin certificate, which the indexer takes as
        # its superuser without a password and which cannot be revoked.
        eval "cp '${config_file}' '/tmp/wazuh-install-files/config.yml' ${debug}"
        eval "chown root:root /tmp/wazuh-install-files/* ${debug}"
        eval "tar -zcf '${tar_file}' -C '/tmp/' wazuh-install-files/ ${debug}"
        eval "rm -rf '/tmp/wazuh-install-files' ${debug}"
	    eval "rm -rf ${config_file} ${debug}"
        common_logger "Created ${tar_file_name}. It contains the Wazuh cluster key, the passwords and the certificates necessary for installation. Remove it from every node once the installation finishes."
        common_logger "The root CA and its private key are in $(wazuh_ca_get_dir). Back them up: they are needed to add nodes or renew certificates."
    else
        common_logger -e "Unable to create /tmp/wazuh-install-files"
        exit 1
    fi
}

function installCommon_determinePorts {

    used_ports=()

    if [ -n "${AIO}" ]; then
        used_ports+=( "${wazuh_aio_ports[@]}" )
    elif [ -n "${wazuh}" ]; then
        used_ports+=( "${wazuh_manager_ports[@]}" )
    elif [ -n "${indexer}" ]; then
        used_ports+=( "${wazuh_indexer_ports[@]}" )
    elif [ -n "${dashboard}" ]; then
        used_ports+=( "${wazuh_dashboard_port[@]}" )
    fi
}

function installCommon_downloadArtifactURLs() {

    common_logger -d "Downloading artifact URLs file."
    if [ -n "${devrepo}" ] && [ "${devrepo}" == "pre-release" ]; then
        artifact_urls_file_name="artifact_urls_${wazuh_version}-${staging_url_stage}.yaml"
        artifact_url="https://${bucket}/pre-release/${wazuh_major}.x/${artifact_urls_bucket_folder}/${artifact_urls_file_name}"
    else
        artifact_urls_file_name="artifact_urls_${wazuh_version}.yaml"
        artifact_url="https://${bucket}/production/${wazuh_major}.x/${artifact_urls_bucket_folder}/${artifact_urls_file_name}"
    fi
    eval "common_curl -sSo ${base_path}/${artifact_urls_file_name} ${artifact_url} --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}"

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
    if [ -n "${offline_install}" ]; then
        common_logger -d "Skipping download in offline installation mode. Package already available."
        return 0
    fi

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
        # Determine architecture suffix for artifact keys
        if [ "${architecture}" == "x86_64" ]; then
            arch_suffix="x86_64"
        elif [ "${architecture}" == "aarch64" ]; then
            arch_suffix="aarch64"
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        pkg_type="deb"
        # Determine architecture suffix for artifact keys
        if [ "${architecture}" == "x86_64" ]; then
            arch_suffix="amd64"
        elif [ "${architecture}" == "aarch64" ]; then
            arch_suffix="arm64"
        fi
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
    common_curl -sSLo '${component_filepath}' '${component_url}' --max-time 600 --retry 5 --retry-delay 5 --fail ${debug}
    curl_exit_code="${PIPESTATUS[0]}"

    # Check if download was successful
    if [ "${curl_exit_code}" -ne 0 ]; then
        common_logger -e "Failed to download ${component} from ${component_url}. Curl exit code: ${curl_exit_code}"
        # Remove incomplete file if it exists
        if [ -f "${component_filepath}" ]; then
            common_logger -d "Removing incomplete download: ${component_filepath}"
            eval "rm -f ${component_filepath} ${debug}"
        fi
        exit 1
    fi

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

    if [ "${1}" == "assistant" ]; then
        installing_assistant_deps=1
        wia_dependencies_installed=()
        installCommon_installList "${assistant_deps_to_install[@]}"
    else
        installing_assistant_deps=0
        installCommon_installList "${wazuh_deps_to_install[@]}"
    fi
}

function installCommon_installList(){

    dependencies=("$@")
    if [ "${#dependencies[@]}" -gt 0 ]; then

        if [ "${sys_type}" == "apt-get" ]; then
            eval "apt-get update -q ${debug}"
        fi

        common_logger "--- Dependencies ----"
        for dep in "${dependencies[@]}"; do
            common_logger "Installing $dep."
            if [ "${sys_type}" = "apt-get" ]; then
                installCommon_aptInstall "${dep}"
            else
                installCommon_yumInstall "${dep}"
            fi
            if [ "${install_result}" != 0 ]; then
                common_logger -e "Cannot install dependency: ${dep}."
                installCommon_rollBack
                exit 1
            fi
            if [ "${installing_assistant_deps}" == 1 ]; then
                wia_dependencies_installed+=("${dep}")
            fi
        done
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

    common_logger "--- Removing existing Wazuh installation ---"

    if [[ -n "${wazuh_installed}" && ( -n "${wazuh}" || -n "${AIO}" || -n "${uninstall}" ) ]];then
        common_logger "Removing Wazuh manager."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-manager -y ${debug}"
                rpm -q wazuh-manager --quiet && wazuh_failed_uninstall=1
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
        eval "rm -rf /var/wazuh-manager/ ${debug}"
    fi

    if [[ -n "${indexer_installed}" && ( -n "${indexer}" || -n "${AIO}" || -n "${uninstall}" ) ]]; then
        common_logger "Removing Wazuh indexer."
        if [ "${sys_type}" == "yum" ]; then
            common_checkYumLock
            if [ "${attempt}" -ne "${max_attempts}" ]; then
                eval "yum remove wazuh-indexer -y ${debug}"
                rpm -q wazuh-indexer --quiet && indexer_failed_uninstall=1
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
                rpm -q wazuh-dashboard --quiet && dashboard_failed_uninstall=1
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


function installCommon_scanDependencies() {

    wazuh_deps=()
    if [ -n "${AIO}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            wazuh_deps+=( "${indexer_yum_dependencies[@]}" "${wazuh_yum_dependencies[@]}" "${dashboard_yum_dependencies[@]}" )
        else
            wazuh_deps+=( "${indexer_apt_dependencies[@]}" "${wazuh_apt_dependencies[@]}" "${dashboard_apt_dependencies[@]}" )
        fi
    elif [ -n "${indexer}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            wazuh_deps+=( "${indexer_yum_dependencies[@]}" )
        else
            wazuh_deps+=( "${indexer_apt_dependencies[@]}" )
        fi
    elif [ -n "${wazuh}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            wazuh_deps+=( "${wazuh_yum_dependencies[@]}" )
        else
            wazuh_deps+=( "${wazuh_apt_dependencies[@]}" )
        fi
    elif [ -n "${dashboard}" ]; then
        if [ "${sys_type}" == "yum" ]; then
            wazuh_deps+=( "${dashboard_yum_dependencies[@]}" )
        else
            wazuh_deps+=( "${dashboard_apt_dependencies[@]}" )
        fi
    fi

    all_deps=( "${wazuh_deps[@]}" )
    if [ "${sys_type}" == "apt-get" ]; then
        assistant_deps+=( "${assistant_apt_dependencies[@]}" )
        command='! apt list --installed 2>/dev/null | grep -q -E ^"${dep}"\/'
    else
        assistant_deps+=( "${assistant_yum_dependencies[@]}" )
        command='! rpm -q ${dep} --quiet'
    fi

    # -g creates the CA and the passwords with the credentials library, which needs openssl,
    # cmp (diffutils) and flock (util-linux).
    if [ -n "${configurations}" ]; then
        assistant_deps+=( openssl diffutils util-linux )
    fi

    # Remove openssl dependency if not necessary
    if [ -z "${configurations}" ] && [ -z "${AIO}" ]; then
        assistant_deps=( "${assistant_deps[@]/openssl}" )
    fi

    # Remove lsof dependency if not necessary
    if [ -z "${AIO}" ] && [ -z "${wazuh}" ] && [ -z "${indexer}" ] && [ -z "${dashboard}" ]; then
        assistant_deps=( "${assistant_deps[@]/lsof}" )
    fi

    # Delete duplicates and sort
    all_deps+=( "${assistant_deps[@]}" )
    all_deps=( $(echo "${all_deps[@]}" | tr ' ' '\n' | sort -u) )
    deps_to_install=()

    # Get not installed dependencies of Assistant and Wazuh
    for dep in "${all_deps[@]}"; do
        if eval "${command}"; then
            deps_to_install+=("${dep}")
            if [[ "${assistant_deps[*]}" =~ "${dep}" ]]; then
                assistant_deps_to_install+=("${dep}")
            else
                wazuh_deps_to_install+=("${dep}")
            fi
        fi
    done

    # Format and print the message if the option is not specified
    if [ -z "${install_dependencies}" ] && [ "${#deps_to_install[@]}" -gt 0 ]; then
        printf -v joined_deps_not_installed '%s, ' "${deps_to_install[@]}"
        printf -v joined_assistant_not_installed '%s, ' "${assistant_deps_to_install[@]}"
        joined_deps_not_installed="${joined_deps_not_installed%, }"
        joined_assistant_not_installed="${joined_assistant_not_installed%, }"

        message="To perform the installation, the following package/s must be installed: ${joined_deps_not_installed}."
        if [ "${#assistant_deps_to_install[@]}" -gt 0 ]; then
            message+=" The following package/s will be removed after the installation: ${joined_assistant_not_installed}."
        fi
        message+=" Add the -id|--install-dependencies parameter to install them automatically or install them manually."
        common_logger -w "${message}"
        exit 1
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
        local wazuh_deps=()

        if [ -n "${AIO}" ]; then
            wazuh_deps=( $(echo "${wazuh_yum_dependencies[@]}" "${indexer_yum_dependencies[@]}" "${dashboard_yum_dependencies[@]}" | tr ' ' '\n' | sort -u) )
        else
            if [ -n "${wazuh}" ]; then
                wazuh_deps+=( "${wazuh_yum_dependencies[@]}" )
            fi
            if [ -n "${indexer}" ]; then
                wazuh_deps+=( "${indexer_yum_dependencies[@]}" )
            fi
            if [ -n "${dashboard}" ]; then
                wazuh_deps+=( "${dashboard_yum_dependencies[@]}" )
            fi

            if [ "${#wazuh_deps[@]}" -gt 0 ]; then
                mapfile -t wazuh_deps < <(printf '%s\n' "${wazuh_deps[@]}" | sort -u)
            fi
        fi

        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ] && [ "${dep}" != "util-linux" ]; then
                if [[ " ${wazuh_deps[*]} " == *" ${dep} "* ]]; then
                    common_logger -d "Skipping removal of ${dep}: it is also a Wazuh component dependency."
                    continue
                fi
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
        local wazuh_deps=()

        if [ -n "${AIO}" ]; then
            wazuh_deps=( $(echo "${wazuh_apt_dependencies[@]}" "${indexer_apt_dependencies[@]}" "${dashboard_apt_dependencies[@]}" | tr ' ' '\n' | sort -u) )
        else
            if [ -n "${wazuh}" ]; then
                wazuh_deps+=( "${wazuh_apt_dependencies[@]}" )
            fi
            if [ -n "${indexer}" ]; then
                wazuh_deps+=( "${indexer_apt_dependencies[@]}" )
            fi
            if [ -n "${dashboard}" ]; then
                wazuh_deps+=( "${dashboard_apt_dependencies[@]}" )
            fi

            if [ "${#wazuh_deps[@]}" -gt 0 ]; then
                mapfile -t wazuh_deps < <(printf '%s\n' "${wazuh_deps[@]}" | sort -u)
            fi
        fi

        for dep in "${wia_dependencies_installed[@]}"; do
            if [ "${dep}" != "systemd" ] && [ "${dep}" != "util-linux" ]; then
                if [[ " ${wazuh_deps[*]} " == *" ${dep} "* ]]; then
                    common_logger -d "Skipping removal of ${dep}: it is also a Wazuh component dependency."
                    continue
                fi
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

    if [ -n "${offline_install}" ]; then
        common_logger -d "Skipping removal of download packages directory in offline installation mode."
        return 0
    fi

    download_dir="${base_path}/${download_packages_directory}"
    if [ -d "${download_dir}" ]; then
        eval "rm -rf ${download_dir} ${debug}"
        common_logger -d "Removed download packages directory: ${download_dir}"
    else
        common_logger -w "Download packages directory does not exist: ${download_dir}"
    fi

}

# Checks that a downloaded Wazuh package is signed with the Wazuh key before installing it.
# Unsigned packages only pass with --skip-signature-check, which needs -d.
function installCommon_verifyPackageSignature() {

    package_file="${1}"
    if [ -n "${skip_signature_check}" ]; then
        common_logger -w "Skipping the signature check of ${package_file}. Use it only with development packages."
        return 0
    fi

    common_logger -d "Checking the signature of ${package_file}."
    if [[ "${package_file}" == *.rpm ]]; then
        installCommon_verifyRpmSignature "${package_file}"
    elif [[ "${package_file}" == *.deb ]]; then
        installCommon_verifyDebSignature "${package_file}"
    fi

}

# rpm -K passes on unsigned packages, so the signer key is checked first.
function installCommon_verifyRpmSignature() {

    package_file="${1}"
    if ! rpm -q "gpg-pubkey-${wazuh_gpg_key_id: -8}" --quiet; then
        key_file=$(mktemp)
        installCommon_writeWazuhGPGKey "${key_file}"
        eval "rpm --import ${key_file} ${debug}"
        rm -f "${key_file}"
    fi

    signature=$(rpm -qp --qf '%{RSAHEADER:pgpsig}' "${package_file}" 2>/dev/null)
    if [[ "${signature,,}" != *"key id ${wazuh_gpg_key_id}"* ]]; then
        installCommon_signatureCheckFailed "${package_file} is not signed with the Wazuh key."
    fi
    if ! rpm -K "${package_file}" >/dev/null 2>&1; then
        installCommon_signatureCheckFailed "The signature of ${package_file} is not valid."
    fi

}

# apt ignores the signature embedded in a .deb, so the _gpgbuilder member is checked with
# gpgv and the hashes it signs are compared with the other members. The .deb is an ar
# archive, read with coreutils because binutils is not always installed.
function installCommon_verifyDebSignature() {

    package_file="${1}"
    verify_dir=$(mktemp -d)
    installCommon_writeWazuhGPGKey "${verify_dir}/wazuh.asc"
    # gpgv only reads binary keyrings: decode the armored key body.
    sed '1,/^$/d; /^=/,$d' "${verify_dir}/wazuh.asc" | base64 -d > "${verify_dir}/wazuh.gpg"

    package_size=$(stat -c %s "${package_file}")
    offset=8
    touch "${verify_dir}/members"
    while [ "${offset}" -lt "${package_size}" ]; do
        member_header=$(dd if="${package_file}" bs=1 skip="${offset}" count=60 2>/dev/null)
        member_name=$(echo "${member_header:0:16}" | sed 's/[ /]*$//')
        member_size=$(echo "${member_header:48:10}" | tr -d ' ')
        member_start=$((offset + 61))
        if [ "${member_name}" == "_gpgbuilder" ]; then
            tail -c +"${member_start}" "${package_file}" | head -c "${member_size}" > "${verify_dir}/_gpgbuilder"
        elif [[ "${member_name}" != _gpg* ]]; then
            member_sha1=$(tail -c +"${member_start}" "${package_file}" | head -c "${member_size}" | sha1sum | awk '{print $1}')
            echo "${member_sha1} ${member_size} ${member_name}" >> "${verify_dir}/members"
        fi
        offset=$((offset + 60 + member_size + member_size % 2))
    done

    if [ ! -s "${verify_dir}/_gpgbuilder" ]; then
        rm -rf "${verify_dir}"
        installCommon_signatureCheckFailed "${package_file} is not signed."
    fi
    if ! gpgv --keyring "${verify_dir}/wazuh.gpg" --output "${verify_dir}/signed" "${verify_dir}/_gpgbuilder" >/dev/null 2>&1; then
        rm -rf "${verify_dir}"
        installCommon_signatureCheckFailed "${package_file} is not signed with the Wazuh key."
    fi
    # Signed lines: <md5> <sha1> <size> <member>
    signed_members=$(awk 'NF == 4 && length($1) == 32 && $1 ~ /^[0-9a-f]+$/ {print $2, $3, $4}' "${verify_dir}/signed" | sort)
    if [ -z "${signed_members}" ] || [ "${signed_members}" != "$(sort "${verify_dir}/members")" ]; then
        rm -rf "${verify_dir}"
        installCommon_signatureCheckFailed "The contents of ${package_file} do not match its signature."
    fi
    rm -rf "${verify_dir}"

}

function installCommon_signatureCheckFailed() {

    common_logger -e "${1}"
    common_logger -e "Wazuh packages are signed. Use --skip-signature-check along with -d only for unsigned development packages."
    installCommon_rollBack
    exit 1

}

# Wazuh package signing key (fingerprint 0DCF CA55 47B1 9D2A 6099 5060 96B3 EE5F 2911 1145).
# It expires on 2027-05-15.
function installCommon_writeWazuhGPGKey() {

    cat > "${1}" << 'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.22 (GNU/Linux)

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
bvP0H2BRCKoelsbRENu58BkU6YhiUry7pVul
=SJij
-----END PGP PUBLIC KEY BLOCK-----
EOF

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
    if [[ "${installer}" == *.rpm ]]; then
        installCommon_verifyPackageSignature "${installer}"
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
