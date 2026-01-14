# Wazuh installer - dashboard.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function dashboard_obtainNodeIp() {

    if [ -z "${dashboard_ip}" ]; then
        if [ "${AIO}" ]; then
            dashboard_ip="${dashboard_node_ips[0]}"
        else 
            for i in "${!dashboard_node_names[@]}"; do
                if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                    dashboard_ip=${dashboard_node_ips[i]};
                    break
                fi
            done
        fi
    fi
}

function dashboard_configure() {

    common_logger -d "Configuring Wazuh dashboard."

    # dashboard configuration itself
    dashboard_obtainNodeIp
    dashboard_copyCertificates "${debug}"

    # dashboard configuration to connect to the indexer cluster
    if [ "${#indexer_node_names[@]}" -eq 1 ]; then
        eval "sed -i 's|opensearch.hosts:.*|opensearch.hosts: https://${indexer_node_ips[0]}:9200|' /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
    else
        ips_list="["
        for i in "${indexer_node_ips[@]}"; do
            ips_list+="\"https://${i}:9200\", "
        done
        ips_list=${ips_list%, }"]" # if there are more than one indexer, there will be a list of urls ["url1", "url2", ...]
        eval "sed -i 's|opensearch.hosts:.*|opensearch.hosts: ${ips_list}|' /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
    fi

    # dashboard configuration to connect to the wazuh api
    if [ -n "${AIO}" ]; then
        wazuh_api_address=${server_node_ips[0]}
    else
        for i in "${!server_node_types[@]}"; do
            if [[ "${server_node_types[i]}" == "master" ]]; then
                wazuh_api_address=${server_node_ips[i]}
            fi
        done
    fi
    eval "sed -i 's|url:.*|url: https://${wazuh_api_address}|' /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"

    common_logger "Wazuh dashboard post-install configuration finished."

}

function dashboard_copyCertificates() {

    common_logger -d "Copying Wazuh dashboard certificates."
    eval "rm -f ${dashboard_cert_path}/* ${debug}"
    if [ "${AIO}" ]; then
        dashname="${dashboard_node_names[0]}"
    fi
    # else we assume that dashname is already set

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${dashname}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${dashname}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${dashboard_cert_path} ${debug}"
        eval "sed -i s/dashboard.pem/${dashname}.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "sed -i s/dashboard-key.pem/${dashname}-key.pem/ /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${dashname}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/${dashname}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/ ${debug}"
        eval "chmod 500 ${dashboard_cert_path} ${debug}"
        eval "chmod 400 ${dashboard_cert_path}/* ${debug}"
        eval "chown wazuh-dashboard:wazuh-dashboard ${dashboard_cert_path}/* ${debug}"
        common_logger -d "Wazuh dashboard certificate setup finished."
    else
        common_logger -e "No certificates found. Wazuh dashboard  could not be initialized."
        installCommon_rollBack
        exit 1
    fi

}

function dashboard_displaySummary() {

    dashboard_obtainNodeIp

    common_logger -d "Wazuh dashboard connection was successful."

    common_logger "Wazuh dashboard web application initialized."
    common_logger -nl "--- Summary ---"
    common_logger -nl "You can access the web interface https://<wazuh_dashboard_ip>:${http_port}\n    User: admin\n    Password: admin"

}

function dashboard_install() {

    common_logger "Starting Wazuh dashboard installation."

    if [ -n "${offline_install}" ]; then
        download_dir="${offline_packages_path}"
    else
        download_dir="${base_path}/${download_packages_directory}"
    fi

    # Find the downloaded package file
    if [ "${sys_type}" == "yum" ]; then
        package_file=$(ls "${download_dir}"/wazuh-dashboard*.rpm 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh dashboard package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_yumInstall "${package_file}"
    elif [ "${sys_type}" == "apt-get" ]; then
        package_file=$(ls "${download_dir}"/wazuh-dashboard*.deb 2>/dev/null | head -n 1)
        if [ -z "${package_file}" ]; then
            common_logger -e "Wazuh dashboard package file not found in ${download_dir}."
            exit 1
        fi
        installCommon_aptInstall "${package_file}"
    fi
    
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Wazuh dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh dashboard installation finished."
    fi

}
