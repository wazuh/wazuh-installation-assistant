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

    cert_tmp_path=""
    cert_createTmpDir

    cert_checkRootCA "create"
    cert_generateAdmincertificate
    cert_generateIndexercertificates
    cert_generateManagercertificates
    cert_generateDashboardcertificates
    cert_cleanFiles
    eval "chmod 400 ${cert_tmp_path}/* ${debug}"
    eval "mv ${cert_tmp_path}/* /tmp/wazuh-install-files ${debug}"
    eval "rm -rf ${cert_tmp_path} ${debug}"
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

    # mkdir fails if another user creates the directory first. The mode is the one the
    # directory has in the tar.
    eval "mkdir -m 755 /tmp/wazuh-install-files ${debug}; e_code=\${PIPESTATUS[0]}"
    if [ "${e_code}" == 0 ]; then
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
    eval "common_curl -sSo ${base_path}/${artifact_urls_file_name} ${artifact_url} --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}; curl_exit_code=\${PIPESTATUS[0]}"

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
        eval "mkdir -m 700 -p ${download_dir} ${debug}"
        if [ ! -d "${download_dir}" ]; then
            common_logger -e "Failed to create download directory: ${download_dir}"
            exit 1
        fi
    fi

    # Packages are checked before installing them, so no other user may be able to replace them in between
    if [ -L "${download_dir}" ] || [ ! -O "${download_dir}" ] || [ -n "$(find "${download_dir}" -maxdepth 0 \( -perm -020 -o -perm -002 \))" ]; then
        common_logger -e "The download directory ${download_dir} must belong to the current user and not be writable by others."
        exit 1
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
    # A new directory with a random name, so no other user can create it or change
    # config.yml before it is read.
    if ! install_tmp_path="$(mktemp -d /tmp/wazuh-install-files.XXXXXXXXXX)"; then
        common_logger -e "Could not create a temporary directory to extract config.yml."
        exit 1
    fi
    eval "tar -xf ${tar_file} -C ${install_tmp_path} wazuh-install-files/config.yml ${debug}"
    config_file="${install_tmp_path}/wazuh-install-files/config.yml"

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

function installCommon_logRunHeader() {

    local header
    header="$(date +'%d/%m/%Y %H:%M:%S') INFO: --- Wazuh installation assistant ${wazuh_install_vesion} (Wazuh ${wazuh_version}). Options: ${*:-none} ---"
    if [ -s "${logfile}" ]; then
        header=$'\n'"${header}"
    fi
    { printf "%s\n" "${header}" >> "${logfile}"; } 2>/dev/null || true

}

function installCommon_removeCentOSrepositories() {

    eval "rm -f ${centos_repo} ${debug}"
    eval "rm -f ${centos_key} ${debug}"
    eval "yum clean all ${debug}"
    centos_repos_configured=0
    common_logger -d "CentOS repositories and key deleted."

}

function installCommon_rollBack() {

    # The uninstall flow prints the header itself, before checking each component
    if [ -z "${uninstall}" ]; then
        common_logger "--- Removing existing Wazuh installation ---"
    fi

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
        eval "systemctl start ${1}.service ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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
        eval "/etc/init.d/${1} start ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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
        eval "/etc/rc.d/init.d/${1} start ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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
        eval "systemctl restart ${1}.service ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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
        eval "/etc/init.d/${1} restart ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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
        eval "/etc/rc.d/init.d/${1} restart ${debug}; e_code=\${PIPESTATUS[0]}"
        if [  "${e_code}" != 0  ]; then
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

# Downloads the packages of the components to install, or finds them in the offline bundle,
# and checks all their signatures before any of them is installed.
function installCommon_getPackages() {

    components=()
    if [ -n "${AIO}" ] || [ -n "${indexer}" ]; then
        components+=("wazuh_indexer")
    fi
    if [ -n "${AIO}" ] || [ -n "${wazuh}" ]; then
        components+=("wazuh_manager")
    fi
    if [ -n "${AIO}" ] || [ -n "${dashboard}" ]; then
        components+=("wazuh_dashboard")
    fi

    if [ -n "${offline_install}" ]; then
        packages_dir="${offline_packages_path}"
    else
        packages_dir="${base_path}/${download_packages_directory}"
    fi
    if [ "${sys_type}" == "yum" ]; then
        package_extension="rpm"
    else
        package_extension="deb"
    fi

    for component in "${components[@]}"; do
        installCommon_downloadComponent "${component}"
    done
    for component in "${components[@]}"; do
        package_file=$(ls "${packages_dir}/${component//_/-}"*."${package_extension}" 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "The ${component//_/ } package was not found in ${packages_dir}."
            installCommon_rollBack
            exit 1
        fi
        installCommon_verifyPackageSignature "${package_file}"
    done

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
    verify_dir=$(mktemp -d)
    installCommon_getWazuhGPGKey "${verify_dir}"
    if [[ "${package_file}" == *.rpm ]]; then
        installCommon_verifyRpmSignature "${package_file}"
    elif [[ "${package_file}" == *.deb ]]; then
        installCommon_verifyDebSignature "${package_file}"
    fi
    rm -rf "${verify_dir}"

}

# Leaves the Wazuh key in ${1}/wazuh.asc and as a binary keyring in ${1}/wazuh.gpg. The key
# comes from the offline bundle or from packages.wazuh.com, and is only trusted if it holds a
# single primary key whose fingerprint is in wazuh_gpg_key_fingerprints: a key whose expiry
# date was extended keeps its fingerprint and still passes.
function installCommon_getWazuhGPGKey() {

    key_dir="${1}"
    if [ -n "${offline_install}" ]; then
        eval "cp ${base_path}/wazuh-offline/GPG-KEY-WAZUH ${key_dir}/wazuh.asc ${debug}"
    else
        eval "common_curl -sSo ${key_dir}/wazuh.asc ${wazuh_gpg_key_url} --max-time 300 --retry 5 --retry-delay 5 --fail ${debug}"
    fi
    if [ ! -s "${key_dir}/wazuh.asc" ]; then
        installCommon_signatureCheckFailed "Could not get the Wazuh GPG key."
    fi
    # rpm --import would also take a second key appended to the file.
    if [ "$(grep -c -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "${key_dir}/wazuh.asc")" -ne 1 ]; then
        installCommon_signatureCheckFailed "The Wazuh GPG key file must hold a single key."
    fi

    # The armored body is the base64 of the binary keyring that gpgv reads.
    sed '1,/^$/d; /^=/,$d; /^-----/d' "${key_dir}/wazuh.asc" | base64 -d > "${key_dir}/wazuh.gpg" 2>/dev/null
    key_fingerprint=$(installCommon_getGPGKeyFingerprint "${key_dir}/wazuh.gpg")
    if [ -z "${key_fingerprint}" ] || [[ " ${wazuh_gpg_key_fingerprints[*]} " != *" ${key_fingerprint} "* ]]; then
        installCommon_signatureCheckFailed "The Wazuh GPG key does not have the expected fingerprint."
    fi

}

# Prints the fingerprint of the binary key in ${1}, or nothing if it does not hold exactly
# one primary key. Computed with coreutils, since gpg is not installed everywhere: the v4
# fingerprint is the SHA-1 of 0x99, the two-octet body length and the public key packet body.
function installCommon_getGPGKeyFingerprint() {

    key_bytes=( $(od -An -v -tu1 "${1}") )
    packet_start=0
    primary_keys=0
    primary_fingerprint=""
    while [ "${packet_start}" -lt "${#key_bytes[@]}" ]; do
        packet_tag_byte=${key_bytes[packet_start]}
        if (( (packet_tag_byte & 0x80) == 0 )); then
            return 0
        elif (( packet_tag_byte & 0x40 )); then
            packet_tag=$(( packet_tag_byte & 0x3f ))
            length_byte=${key_bytes[packet_start + 1]}
            if (( length_byte < 192 )); then
                packet_length=${length_byte}; header_length=2
            elif (( length_byte < 224 )); then
                packet_length=$(( ((length_byte - 192) << 8) + key_bytes[packet_start + 2] + 192 )); header_length=3
            elif (( length_byte == 255 )); then
                packet_length=$(( (key_bytes[packet_start + 2] << 24) + (key_bytes[packet_start + 3] << 16) + (key_bytes[packet_start + 4] << 8) + key_bytes[packet_start + 5] )); header_length=6
            else
                return 0
            fi
        else
            packet_tag=$(( (packet_tag_byte >> 2) & 0x0f ))
            case $(( packet_tag_byte & 3 )) in
                0) packet_length=${key_bytes[packet_start + 1]}; header_length=2 ;;
                1) packet_length=$(( (key_bytes[packet_start + 1] << 8) + key_bytes[packet_start + 2] )); header_length=3 ;;
                2) packet_length=$(( (key_bytes[packet_start + 1] << 24) + (key_bytes[packet_start + 2] << 16) + (key_bytes[packet_start + 3] << 8) + key_bytes[packet_start + 4] )); header_length=5 ;;
                *) return 0 ;;
            esac
        fi
        if [ "${packet_tag}" -eq 6 ]; then
            primary_keys=$(( primary_keys + 1 ))
            primary_fingerprint=$( { printf "\\x99\\x$(printf %02x $(( packet_length >> 8 )))\\x$(printf %02x $(( packet_length & 255 )))"; tail -c +$(( packet_start + header_length + 1 )) "${1}" | head -c "${packet_length}"; } | sha1sum | awk '{print toupper($1)}')
        fi
        packet_start=$(( packet_start + header_length + packet_length ))
    done
    if [ "${primary_keys}" -eq 1 ]; then
        echo "${primary_fingerprint}"
    fi

}

# rpm -K passes on unsigned packages, so the signer key is checked first. rpm keeps
# verifying with an expired copy of the key, as long as the package was signed before.
function installCommon_verifyRpmSignature() {

    package_file="${1}"
    key_fingerprint=$(installCommon_getGPGKeyFingerprint "${verify_dir}/wazuh.gpg")
    key_id="${key_fingerprint: -16}"
    if ! rpm -q "gpg-pubkey-${key_id: -8}" --quiet; then
        eval "rpm --import ${verify_dir}/wazuh.asc ${debug}"
    fi

    signature=$(rpm -qp --qf '%{RSAHEADER:pgpsig}' "${package_file}" 2>/dev/null)
    if [[ "${signature,,}" != *"key id ${key_id,,}"* ]]; then
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
        installCommon_signatureCheckFailed "${package_file} is not signed."
    fi
    if ! gpgv --keyring "${verify_dir}/wazuh.gpg" --output "${verify_dir}/signed" "${verify_dir}/_gpgbuilder" >/dev/null 2>&1; then
        installCommon_signatureCheckFailed "${package_file} is not signed with the Wazuh key."
    fi
    # Signed lines: <md5> <sha1> <size> <member>
    signed_members=$(awk 'NF == 4 && length($1) == 32 && $1 ~ /^[0-9a-f]+$/ {print $2, $3, $4}' "${verify_dir}/signed" | sort)
    if [ -z "${signed_members}" ] || [ "${signed_members}" != "$(sort "${verify_dir}/members")" ]; then
        installCommon_signatureCheckFailed "The contents of ${package_file} do not match its signature."
    fi

}

function installCommon_signatureCheckFailed() {

    common_logger -e "${1}"
    common_logger -e "Wazuh packages are signed. Use --skip-signature-check along with -d only for unsigned development packages."
    rm -rf "${verify_dir}"
    installCommon_rollBack
    exit 1

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
