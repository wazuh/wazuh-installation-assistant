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
    ram_gb=$(free -m | awk 'FNR == 2 {print $2}')
    ram="$(( ram_mb / 2 ))"

    if [ "${ram}" -eq "0" ]; then
        ram=1024;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/wazuh-indexer/jvm.options ${debug}"

    if [ "${AIO}" ]; then
        indexer_ip="${indexer_node_ips[0]}"
        indxname="${indexer_node_ips[0]}"
        # This variables are used to not overwrite the indexer_node* arrays
        indexer_configuration_ips=("${indexer_node_ips[0]}") # I'll take only the first ip
        indexer_configuration_names=("${indexer_node_names[0]}") # I'll take only the first name
    else 
        for i in "${!indexer_node_names[@]}"; do
            if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
                indexer_ip=${indexer_node_ips[i]};
                break
            fi
        done
        indexer_configuration_ips=("${indexer_node_ips[@]}") # I'll take all the ips
        indexer_configuration_names=("${indexer_node_names[@]}") # I'll take all the names
    fi

    sed -i "s|node.name:.*|node.name: ${indxname}|" /etc/wazuh-indexer/opensearch.yml ${debug}
    sed -i "s|network.host:.*|network.host: ${indexer_ip}|" /etc/wazuh-indexer/opensearch.yml ${debug}
    sed -i "/.*- \"node-.*/d" /etc/wazuh-indexer/opensearch.yml ${debug}

    # cluster.initial_cluster_manager_nodes configuration
    indexer_master_nodes="cluster.initial_cluster_manager_nodes:\n"
    for node_name in "${indexer_configuration_names[@]}"; do
        indexer_master_nodes+="- \"${node_name}\"\n"
    done
    sed -i "s|cluster.initial_cluster_manager_nodes:.*|${indexer_master_nodes}|" /etc/wazuh-indexer/opensearch.yml ${debug}

    # seed_hosts configuration
    indexer_seed_hosts="discovery.seed_hosts:\n"
    for ip in "${indexer_configuration_ips[@]}"; do
        indexer_seed_hosts+="  - \"${ip}\"\n"
    done
    sed -i "s|#discovery.seed_hosts:.*|${indexer_seed_hosts}|" /etc/wazuh-indexer/opensearch.yml ${debug}
    
    # CN configuration
    sed -i "/.*- \"CN=node-.*/d" /etc/wazuh-indexer/opensearch.yml ${debug}
    indexer_cn_nodes="plugins.security.nodes_dn:\n"
    for node_name in "${indexer_configuration_names[@]}"; do
        indexer_cn_nodes+="- \"CN=${node_name},OU=Wazuh,O=Wazuh,L=California,C=US\"\n"
    done
    sed -i "s|plugins.security.nodes_dn:.*|${indexer_cn_nodes}|" /etc/wazuh-indexer/opensearch.yml ${debug}

    indexer_copyCertificates

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

function indexer_copyCertificates() {

    common_logger -d "Copying Wazuh indexer certificates."
    eval "rm -f ${indexer_cert_path}/* ${debug}"

    if [ "${AIO}" ]; then
        indxname="${indexer_node_ips[0]}"
    fi

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${indxname}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${indxname}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${indexer_cert_path} ${debug}"
        eval "sed -i s/indexer.pem/${indxname}.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "sed -i s/indexer-key.pem/${indxname}-key.pem/ /etc/wazuh-indexer/opensearch.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${indxname}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${indxname}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin-key.pem --strip-components 1 ${debug}"
        eval "rm -rf ${indexer_cert_path}/wazuh-install-files/ ${debug}"
        eval "chown -R wazuh-indexer:wazuh-indexer ${indexer_cert_path} ${debug}"
        eval "chmod 500 ${indexer_cert_path} ${debug}"
        eval "chmod 400 ${indexer_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Wazuh indexer"
        installCommon_rollBack
        exit 1;
    fi

}

function indexer_install() {

    common_logger "Starting Wazuh indexer installation."

    download_dir="${base_path}/${download_packages_directory}"
    
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

    eval "wazuh_indexer_ip=( $(cat /etc/wazuh-indexer/opensearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/wazuh-indexer/opensearch-security -icl -p 9200 -nhnv -cacert ${indexer_cert_path}/root-ca.pem -cert ${indexer_cert_path}/admin.pem -key ${indexer_cert_path}/admin-key.pem -h ${wazuh_indexer_ip} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer cluster security configuration initialized."
    fi

}
