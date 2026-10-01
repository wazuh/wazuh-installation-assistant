# Wazuh installer - manager.sh functions.
# Copyright (C) 2015, Wazuh Inc.
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
    lstart=$(grep -n "<cluster>" /var/wazuh-manager/etc/wazuh-manager.conf | cut -d : -f 1)
    lend=$(grep -n "</cluster>" /var/wazuh-manager/etc/wazuh-manager.conf | cut -d : -f 1)

    sed -i -e "${lstart},${lend}s/<name>.*<\/name>/<name>wazuh_cluster<\/name>/" \
        -e "${lstart},${lend}s/<node_name>.*<\/node_name>/<node_name>${winame}<\/node_name>/" \
        -e "${lstart},${lend}s/<node_type>.*<\/node_type>/<node_type>${manager_node_types[pos],,}<\/node_type>/" \
        -e "${lstart},${lend}s/<key>.*<\/key>/<key>${key}<\/key>/" \
        -e "${lstart},${lend}s/<port>.*<\/port>/<port>${port}<\/port>/" \
        -e "${lstart},${lend}s/<bind_addr>.*<\/bind_addr>/<bind_addr>${bind_address}<\/bind_addr>/" \
        -e "${lstart},${lend}s/<node>.*<\/node>/<node>${master_address}<\/node>/" \
        -e "${lstart},${lend}s/<hidden>.*<\/hidden>/<hidden>${hidden}<\/hidden>/" \
        -e "${lstart},${lend}s/<disabled>.*<\/disabled>/<disabled>${disabled}<\/disabled>/" \
        /var/wazuh-manager/etc/wazuh-manager.conf

}

function manager_configure(){

    common_logger -d "Configuring Wazuh manager."

    for i in "${!indexer_node_ips[@]}"; do
        if [ $i -eq 0 ]; then
            eval "sed -i 's/<host>.*<\/host>/<host>https:\/\/${indexer_node_ips[0]}:9200<\/host>/g' /var/wazuh-manager/etc/wazuh-manager.conf ${debug}"
        else
            sed -i "/<hosts>/a\      <host>https://${indexer_node_ips[$i]}:9200</host>" /var/wazuh-manager/etc/wazuh-manager.conf
        fi
    done

}

# The manager package issues remoted.pem on an all-in-one install, with the addresses it finds
# on the host. Addresses given with -as|--agent-san (NAT, a published name, a load balancer)
# reach it through WAZUH_MANAGER_REMOTED_CERT_SANS, which replaces the discovered list, so the
# host addresses go in too.
function manager_setRemotedSans() {

    local san
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

    WAZUH_MANAGER_REMOTED_CERT_SANS=$(printf '%s\n' "${sans[@]}" | awk '!seen[$0]++' | paste -sd, -)
    export WAZUH_MANAGER_REMOTED_CERT_SANS
    common_logger -d "Agent listener addresses: ${WAZUH_MANAGER_REMOTED_CERT_SANS}"

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

# Places the indexer connector and agent listener pairs of this node from the tar before
# the package is installed, with the names the package expects. The package uses them
# instead of issuing its own and sets their owner and mode.
function manager_copyCertificates() {

    common_logger -d "Placing the Wazuh manager certificates."
    # The installer umask would leave the directory without the search bit; the package
    # sets its owner.
    eval "(umask 022 && mkdir -p ${manager_cert_path}) ${debug}"
    installCommon_placeFromTar "${winame}.pem" "${manager_cert_path}/indexer-connector.pem" root root 0640
    installCommon_placeFromTar "${winame}-key.pem" "${manager_cert_path}/indexer-connector-key.pem" root root 0640
    installCommon_placeFromTar "${winame}-remoted.pem" "${manager_cert_path}/remoted.pem" root root 0640
    installCommon_placeFromTar "${winame}-remoted-key.pem" "${manager_cert_path}/remoted-key.pem" root root 0640

}
