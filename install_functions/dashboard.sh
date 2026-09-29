# Wazuh installer - dashboard.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function dashboard_configure() {

    common_logger -d "Configuring Wazuh dashboard."

    # The package keeps a pair placed before it was installed as it is, and the service runs
    # as wazuh-dashboard, which did not exist yet when the pair and its directory were placed.
    eval "chown -R wazuh-dashboard:wazuh-dashboard ${dashboard_cert_path} ${debug}"
    eval "chmod 500 ${dashboard_cert_path} ${debug}"

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
        wazuh_api_address=${manager_node_ips[0]}
    else
        if [ -n "${manager_node_types[*]}" ]; then
            for i in "${!manager_node_types[@]}"; do
                if [[ "${manager_node_types[i]}" == "master" ]]; then
                    wazuh_api_address=${manager_node_ips[i]}
                fi
            done
        else
            wazuh_api_address=${manager_node_ips[0]}
        fi
    fi
    eval "sed -i 's|url:.*|url: https://${wazuh_api_address}|' /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"

    common_logger "Wazuh dashboard post-install configuration finished."

}

# Places the pair of this node from the tar before the package is installed, with the
# names the package expects. The package uses it instead of issuing its own.
function dashboard_copyCertificates() {

    common_logger -d "Placing the Wazuh dashboard certificates."
    eval "mkdir -p ${dashboard_cert_path} ${debug}"
    installCommon_placeFromTar "${dashname}.pem" "${dashboard_cert_path}/dashboard.pem" root root 0400
    installCommon_placeFromTar "${dashname}-key.pem" "${dashboard_cert_path}/dashboard-key.pem" root root 0400

}

function dashboard_displaySummary() {

    common_logger -nl "--- Summary ---"
    common_logger -nl "You can access the web interface https://<wazuh_dashboard_ip>:${http_port}\n    User: admin\n    Password: the WAZUH_INDEXER_ADMIN_PASSWORD value in /etc/wazuh/credentials.env"

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
