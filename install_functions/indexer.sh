# Wazuh installer - indexer.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function indexer_configure() {

    common_logger -d "Configuring Wazuh indexer."

    # Configure JVM options for Wazuh indexer
    ram_mb=$(free -m | awk 'FNR == 2 {print $2}')

    if [ "${AIO}" ]; then
        ram="$(( ram_mb / 4 ))"
    else
        ram="$(( ram_mb / 2 ))"
    fi

    if [ "${ram}" -eq "0" ]; then
        ram=1024;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"

    # On an all-in-one install the package already configured a single node with its own
    # certificates and nodes_dn. Only keep the indexer off the network, as before.
    if [ "${AIO}" ]; then
        eval "sed -i 's|network.host:.*|network.host: \"127.0.0.1\"|' /etc/wazuh-indexer/opensearch.yml ${debug}"
        common_logger "Wazuh indexer post-install configuration finished."
        return 0
    fi

    for i in "${!indexer_node_names[@]}"; do
        if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
            indexer_ip=${indexer_node_ips[i]};
            break
        fi
    done
    indexer_configuration_ips=("${indexer_node_ips[@]}") # I'll take all the ips
    indexer_configuration_names=("${indexer_node_names[@]}") # I'll take all the names

    eval "sed -i 's|node.name:.*|node.name: ${indxname}|' /etc/wazuh-indexer/opensearch.yml ${debug}"
    eval "sed -i 's|network.host:.*|network.host: ${indexer_ip}|' /etc/wazuh-indexer/opensearch.yml ${debug}"
    eval "sed -i '/.*- \"node-.*/d' /etc/wazuh-indexer/opensearch.yml ${debug}"

    # cluster.initial_cluster_manager_nodes configuration
    indexer_master_nodes="cluster.initial_cluster_manager_nodes:\n"
    for node_name in "${indexer_configuration_names[@]}"; do
        indexer_master_nodes+="- \"${node_name}\"\n"
    done
    eval "sed -i 's|cluster.initial_cluster_manager_nodes:.*|${indexer_master_nodes}|' /etc/wazuh-indexer/opensearch.yml ${debug}"

    # seed_hosts configuration
    indexer_seed_hosts="discovery.seed_hosts:\n"
    for ip in "${indexer_configuration_ips[@]}"; do
        indexer_seed_hosts+="  - \"${ip}\"\n"
    done
    eval "sed -i 's|#discovery.seed_hosts:.*|${indexer_seed_hosts}|' /etc/wazuh-indexer/opensearch.yml ${debug}"

    # nodes_dn configuration. The package only lists the DN of this node; the cluster needs
    # every node, in the subject format of the certificates (RFC 2253, as the package writes it).
    eval "sed -i '/^plugins.security.nodes_dn:/,/^[^-]/{/^- /d;}' /etc/wazuh-indexer/opensearch.yml ${debug}"
    indexer_cn_nodes="plugins.security.nodes_dn:\n"
    for node_name in "${indexer_configuration_names[@]}"; do
        indexer_cn_nodes+="- \"C=US,L=California,O=Wazuh,OU=Wazuh,CN=${node_name}\"\n"
    done
    eval "sed -i 's|plugins.security.nodes_dn:.*|${indexer_cn_nodes}|' /etc/wazuh-indexer/opensearch.yml ${debug}"

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        {
        echo "wazuh-indexer hard nproc 4096"
        echo "wazuh-indexer soft nproc 4096"
        echo "wazuh-indexer hard nproc 4096"
        echo "wazuh-indexer soft nproc 4096"
        } >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/wazuh-indexer/opensearch.yml
    fi

    common_logger "Wazuh indexer post-install configuration finished."
}

# Places the pair of this node and the admin pair from the tar before the package is
# installed, with the names the package expects. The package uses them instead of issuing
# its own, gives them to wazuh-indexer and writes their DNs in opensearch.yml.
function indexer_copyCertificates() {

    common_logger -d "Placing the Wazuh indexer certificates."
    # The modes the package ships. The installer umask would leave the directories without
    # the search bit, and the DEB package keeps the mode of a directory that already exists.
    eval "install -d -m 0750 ${indexer_cert_path%/*} ${debug}"
    eval "install -d -m 0500 ${indexer_cert_path} ${debug}"
    installCommon_placeFromTar "${indxname}.pem" "${indexer_cert_path}/indexer.pem" root root 0400
    installCommon_placeFromTar "${indxname}-key.pem" "${indexer_cert_path}/indexer-key.pem" root root 0400
    installCommon_placeFromTar "admin.pem" "${indexer_cert_path}/admin.pem" root root 0400
    installCommon_placeFromTar "admin-key.pem" "${indexer_cert_path}/admin-key.pem" root root 0400

}

function indexer_install() {

    common_logger "Starting Wazuh indexer installation."

    if [ -n "${offline_install}" ]; then
        download_dir="${offline_packages_path}"
    else
        download_dir="${base_path}/${download_packages_directory}"
    fi

    # Find the downloaded package file
    if [ "${sys_type}" == "yum" ]; then
        package_file=$(ls "${download_dir}"/wazuh-indexer*.rpm 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh indexer package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_yumInstall "${package_file}"
    elif [ "${sys_type}" == "apt-get" ]; then
        package_file=$(ls "${download_dir}"/wazuh-indexer*.deb 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh indexer package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_aptInstall "${package_file}"
    fi

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}

function indexer_startCluster() {

    common_logger -d "Starting Wazuh indexer cluster."

    # The package leaves loading the security configuration to the operator, once, from one
    # indexer node. Its wrapper finds the host, port and admin certificate by itself.
    eval "bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer cluster security configuration initialized."
    fi

}
