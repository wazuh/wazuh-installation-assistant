# Wazuh installer - dashboard.sh functions.
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function dashboard_configure() {

    common_logger -d "Configuring Wazuh dashboard."

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

# Places the pair of this node and the CAs of the indexer and the manager (both the
# deployment CA) from the tar before the package is installed. The package uses them
# instead of issuing or importing its own and sets their owner and mode.
function dashboard_copyCertificates() {

    common_logger -d "Placing the Wazuh dashboard certificates."
    eval "install -d -o root -g root -m 0750 ${dashboard_config_path} ${dashboard_cert_path} ${debug}"
    installCommon_placeFromTar "${dashname}.pem" "${dashboard_cert_path}/dashboard.pem" root root 0640
    installCommon_placeFromTar "${dashname}-key.pem" "${dashboard_cert_path}/dashboard-key.pem" root root 0640
    installCommon_placeFromTar "root-ca.pem" "${dashboard_cert_path}/indexer-ca.pem" root root 0640
    installCommon_placeFromTar "root-ca.pem" "${dashboard_cert_path}/manager-ca.pem" root root 0640

}

# Prints the global addresses in the SANs of the dashboard certificate, one per line.
# The dashboard package takes them from the default-route interfaces; loopback and
# link-local are dropped.
function dashboard_globalAddresses() {

    openssl x509 -in "${dashboard_cert_path}/dashboard.pem" -noout -ext subjectAltName 2>/dev/null \
        | grep -o 'IP Address:[^,[:space:]]*' | cut -d: -f2- \
        | grep -Ev '^(127\.|169\.254\.|0:0:0:0:0:0:0:1$|::1$|[Ff][Ee]80:)'

}

# Waits until the dashboard answers and prints the summary. Without credentials: a
# distributed dashboard node does not have the admin password.
function dashboard_initialize() {

    common_logger "Initializing Wazuh dashboard web application."

    # The all-in-one config.yml is not read, and its node address would be 127.0.0.1 anyway.
    local dashboard_ip="127.0.0.1"
    local max_retries=20
    local delay=15
    if [ -z "${AIO}" ]; then
        max_retries=12
        delay=10
        dashboard_ip="${dashboard_node_ips[0]}"
        for i in "${!dashboard_node_names[@]}"; do
            if [ "${dashboard_node_names[i]}" == "${dashname}" ]; then
                dashboard_ip="${dashboard_node_ips[i]}"
            fi
        done
    fi

    # Without a global address in the certificate, the node address, unless it is loopback.
    local print_ips
    mapfile -t print_ips < <(dashboard_globalAddresses)
    if [ "${#print_ips[@]}" -eq 0 ]; then
        print_ips=("${dashboard_ip}")
        if [ "${dashboard_ip}" == "localhost" ] || [[ "${dashboard_ip}" == 127.* ]]; then
            print_ips=("<wazuh-dashboard-ip>")
        fi
    fi

    # The dashboard answers 503 until it is ready, and 000 is no connection.
    local code j=0
    code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${dashboard_ip}:${http_port}/status")
    until [ "${code}" != "000" ] && [ "${code}" != "503" ] || [ "${j}" -ge "${max_retries}" ]; do
        common_logger -d "Retrying Wazuh dashboard connection..."
        sleep "${delay}"
        j=$((j+1))
        code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${dashboard_ip}:${http_port}/status")
    done

    if [ "${code}" == "000" ] || [ "${code}" == "503" ]; then
        common_logger -e "Cannot connect to Wazuh dashboard."
        # Without credentials, an indexer answers 503 until its security is initialized.
        for i in "${indexer_node_ips[@]:-127.0.0.1}"; do
            code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${i}:9200/")
            if [ "${code}" == "000" ]; then
                common_logger -e "Failed to connect with the Wazuh indexer at ${i}:9200."
            elif [ "${code}" == "503" ]; then
                common_logger -e "Wazuh indexer security settings not initialized in ${i}. Please run the installation assistant using -s|--start-cluster in one of the Wazuh indexer nodes."
            fi
        done
        installCommon_rollBack
        exit 1
    fi

    # A distributed dashboard node only receives its own passwords, not the admin one.
    local indexer_export="${indexer_config_path}/export/credentials.env"
    local password_source="${indexer_export}"
    local credentials_file="${indexer_export} and ${manager_config_path}/export/credentials.env"
    local password_command="sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' ${indexer_export} | cut -d= -f2-"
    if [ -z "${AIO}" ]; then
        password_source="${tar_file_name}"
        credentials_file="wazuh-install-files/credentials.env of ${tar_file_name}"
        password_command="sudo tar -xOf ${tar_file_name} wazuh-install-files/credentials.env | grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' | cut -d= -f2-"
    fi

    # The password goes to an interactive terminal only, never to the log or redirected output.
    # The command that reads it is logged too.
    common_logger "Wazuh dashboard web application initialized."
    common_logger "--- Summary ---"
    local ip
    for ip in "${print_ips[@]}"; do
        [[ "${ip}" == *:* ]] && ip="[${ip}]"
        common_logger "You can access the web interface https://${ip}:${http_port}"
    done
    common_logger "    User: admin (Wazuh dashboard login and Wazuh indexer administrator)"
    local admin_password
    if [ -n "${AIO}" ] && dashboard_stdoutIsTerminal && admin_password=$(common_envGet "${indexer_export}" WAZUH_INDEXER_ADMIN_PASSWORD 2>/dev/null) && [ -n "${admin_password}" ]; then
        common_logger -nl "    Password: ${admin_password}"
        common_logger "    To read the password again, run:"
    else
        common_logger "    Password: to read it from ${password_source}, run:"
    fi
    common_logger "        ${password_command}"
    common_logger "The passwords of the other users are in ${credentials_file}."

    # Agents enroll only with a token, created on the manager master node.
    local token_node="this server"
    [ -z "${AIO}" ] && token_node="the Wazuh manager (the master node in a cluster)"
    common_logger "--- Next steps ---"
    common_logger "To enroll agents, use Deploy new agent in the Wazuh dashboard, or create an enrollment token on ${token_node}:"
    common_logger "    sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <WAZUH_MANAGER_ADDRESS>"
    common_logger "For more information, see https://documentation.wazuh.com/${wazuh_version%.*}/installation-guide/wazuh-agent/index.html"

}

function dashboard_stdoutIsTerminal() {
    [ -t 1 ]
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
