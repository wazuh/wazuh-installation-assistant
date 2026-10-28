# Wazuh installer - manager.sh functions.
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function manager_startCluster() {

    common_logger -d "Starting Wazuh manager cluster."
    for i in "${!manager_node_names[@]}"; do
        if [[ "${manager_node_names[i]}" == "${winame}" ]]; then
            pos="${i}";
        fi
    done

    for i in "${!manager_node_types[@]}"; do
        if [[ "${manager_node_types[i],,}" == "master" ]]; then
            master_address=${manager_node_ips[i]}
        fi
    done

    key=$(tar -axf "${tar_file}" wazuh-install-files/clusterkey -O)
    bind_address="0.0.0.0"
    port="1516"
    hidden="no"
    disabled="no"
    lstart=$(grep -n "<cluster>" "${manager_conf_file}" | cut -d : -f 1)
    lend=$(grep -n "</cluster>" "${manager_conf_file}" | cut -d : -f 1)

    sed -i -e "${lstart},${lend}s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/" \
        -e "${lstart},${lend}s/<node_name>.*<\/node_name>/<node_name>${winame}<\/node_name>/" \
        -e "${lstart},${lend}s/<node_type>.*<\/node_type>/<node_type>${manager_node_types[pos],,}<\/node_type>/" \
        -e "${lstart},${lend}s/<key>.*<\/key>/<key>${key}<\/key>/" \
        -e "${lstart},${lend}s/<port>.*<\/port>/<port>${port}<\/port>/" \
        -e "${lstart},${lend}s/<bind_addr>.*<\/bind_addr>/<bind_addr>${bind_address}<\/bind_addr>/" \
        -e "${lstart},${lend}s/<node>.*<\/node>/<node>${master_address}<\/node>/" \
        -e "${lstart},${lend}s/<hidden>.*<\/hidden>/<hidden>${hidden}<\/hidden>/" \
        -e "${lstart},${lend}s/<disabled>.*<\/disabled>/<disabled>${disabled}<\/disabled>/" \
        "${manager_conf_file}"

}

function manager_configure(){

    common_logger -d "Configuring Wazuh manager."

    # The pairs were placed before the package created the wazuh-manager group. On RPM
    # the package resolver runs before the package fixes their owner, so it is run again
    # once the owner is right. --upgrade never creates a CA or issues a pair.
    eval "chown root:wazuh-manager ${manager_cert_path} ${manager_cert_path}/*.pem ${debug}"
    eval "chmod 750 ${manager_cert_path} ${debug}"
    eval "chmod 640 ${manager_cert_path}/*.pem ${debug}"
    common_logger -d "Running the Wazuh manager credentials resolver again now that ${manager_cert_path} belongs to wazuh-manager."
    eval "${manager_resolver} --upgrade -H /var/wazuh-manager ${debug}"

    for i in "${!indexer_node_ips[@]}"; do
        if [ $i -eq 0 ]; then
            eval "sed -i 's/<host>.*<\/host>/<host>https:\/\/${indexer_node_ips[0]}:9200<\/host>/g' ${manager_conf_file} ${debug}"
        else
            sed -i "/<hosts>/a\      <host>https://${indexer_node_ips[$i]}:9200</host>" "${manager_conf_file}"
        fi
    done

}

# The manager package issues remoted.pem on an all-in-one install, with the addresses it finds
# on the host. Addresses given with -as|--agent-san go to WAZUH_MANAGER_REMOTED_CERT_SANS in
# the manager local.env. It replaces the discovered list, so the host addresses go in too.
function manager_setRemotedSans() {

    local san value
    local -a sans=()

    if [ "${#agent_san[@]}" -eq 0 ]; then
        return 0
    fi

    while IFS= read -r san; do
        [ -n "${san}" ] || continue
        if cert_isIP "${san}"; then
            sans+=("IP:${san}")
        else
            sans+=("DNS:${san}")
        fi
    done < <(printf '%s\n' "${agent_san[@]}"; cert_hostAddresses)

    value=$(printf '%s\n' "${sans[@]}" | awk '!seen[$0]++' | paste -sd, -)
    manager_setLocalEnv WAZUH_MANAGER_REMOTED_CERT_SANS "${value}"
    common_logger -d "Agent listener addresses: ${value}"

}

# Same for the Server API certificate, apid.pem: addresses given with -ap|--api-san go to
# WAZUH_MANAGER_APID_CERT_SANS. The package always adds loopback.
function manager_setApidSans() {

    local san value
    local -a sans=()

    if [ "${#api_san[@]}" -eq 0 ]; then
        return 0
    fi

    while IFS= read -r san; do
        [ -n "${san}" ] || continue
        if cert_isIP "${san}"; then
            sans+=("IP:${san}")
        else
            sans+=("DNS:${san}")
        fi
    done < <(printf '%s\n' "${api_san[@]}"; cert_hostAddresses)

    value=$(printf '%s\n' "${sans[@]}" | awk '!seen[$0]++' | paste -sd, -)
    manager_setLocalEnv WAZUH_MANAGER_APID_CERT_SANS "${value}"
    common_logger -d "Server API addresses: ${value}"

}

# On an all-in-one install the only client of the Server API is the Wazuh dashboard of this
# host, so the API listens on loopback only, like the Wazuh indexer. The package ships api.yaml
# with every option commented out and does not start the service, so this applies on the first start.
# Addresses given with -ap|--api-san mean other hosts call the API, so it keeps the package default.
function manager_setApiLoopback() {

    if [ "${#api_san[@]}" -ne 0 ]; then
        common_logger -d "Server API addresses given with -ap|--api-san: the Wazuh server API keeps listening on all network interfaces."
        return 0
    fi

    common_logger -d "Setting the Wazuh server API to listen on 127.0.0.1 and ::1 only."
    eval "sed -i -E \"s|^(# )?host:.*|host: ['127.0.0.1', '::1']|\" ${manager_api_conf_file} ${debug}"
    if ! grep -qx "host: \['127.0.0.1', '::1'\]" "${manager_api_conf_file}" 2>/dev/null; then
        common_logger -w "Could not set the host option in ${manager_api_conf_file}. The Wazuh server API listens on all network interfaces."
    fi

}

# Writes one key to the manager local.env before the package is installed.
function manager_setLocalEnv() {

    eval "install -d -o root -g root -m 0750 ${manager_config_path} ${debug}"
    if ! common_envSet "${manager_config_path}/local.env" "${1}" "${2}"; then
        common_logger -e "Could not write ${1} to ${manager_config_path}/local.env."
        exit 1
    fi

}

function manager_install() {

    common_logger "Starting the Wazuh manager installation."

    if [ -n "${offline_install}" ]; then
        download_dir="${offline_packages_path}"
    else
        download_dir="${base_path}/${download_packages_directory}"
    fi

    # Find the downloaded package file
    if [ "${sys_type}" == "yum" ]; then
        package_file=$(ls "${download_dir}"/wazuh-manager*.rpm 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh manager package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_yumInstall "${package_file}"
    elif [ "${sys_type}" == "apt-get" ]; then
        package_file=$(ls "${download_dir}"/wazuh-manager*.deb 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh manager package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_aptInstall "${package_file}"
    fi

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${wazuh_installed}" ]; then
        common_logger -e "Wazuh installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh manager installation finished."
    fi
}

# Places the CA certificate and the pairs of this node from the tar before the package
# is installed, with the names the package expects. The CA has no key, so the package
# uses these pairs and issues none. The deployment CA also signs the indexer pairs, so
# it is the indexer CA too. manager_configure sets the owner once the group exists.
function manager_copyCertificates() {

    common_logger -d "Placing the Wazuh manager certificates."
    eval "install -d -o root -g root -m 0750 ${manager_config_path} ${manager_cert_path} ${debug}"
    eval "install -d -o root -g root -m 0700 ${manager_config_path}/ca ${debug}"
    installCommon_placeFromTar "root-ca.pem" "${manager_config_path}/ca/root-ca.pem" root root 0644
    installCommon_placeFromTar "root-ca.pem" "${manager_cert_path}/root-ca.pem" root root 0640
    installCommon_placeFromTar "root-ca.pem" "${manager_cert_path}/indexer-ca.pem" root root 0640
    installCommon_placeFromTar "${winame}.pem" "${manager_cert_path}/indexer-connector.pem" root root 0640
    installCommon_placeFromTar "${winame}-key.pem" "${manager_cert_path}/indexer-connector-key.pem" root root 0640
    installCommon_placeFromTar "${winame}-remoted.pem" "${manager_cert_path}/remoted.pem" root root 0640
    installCommon_placeFromTar "${winame}-remoted-key.pem" "${manager_cert_path}/remoted-key.pem" root root 0640
    installCommon_placeFromTar "${winame}-apid.pem" "${manager_cert_path}/apid.pem" root root 0640
    installCommon_placeFromTar "${winame}-apid-key.pem" "${manager_cert_path}/apid-key.pem" root root 0640

}
