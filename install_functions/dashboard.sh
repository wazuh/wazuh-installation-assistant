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
    # The installer umask would leave the directory without the search bit; the package
    # sets its owner.
    eval "(umask 022 && mkdir -p ${dashboard_cert_path}) ${debug}"
    installCommon_placeFromTar "${dashname}.pem" "${dashboard_cert_path}/dashboard.pem" root root 0400
    installCommon_placeFromTar "${dashname}-key.pem" "${dashboard_cert_path}/dashboard-key.pem" root root 0400

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

    local print_ips=("${dashboard_ip}")
    if [ "${dashboard_ip}" == "localhost" ] || [[ "${dashboard_ip}" == 127.* ]]; then
        mapfile -t print_ips < <(dashboard_globalAddresses)
        [ "${#print_ips[@]}" -eq 0 ] && print_ips=("<wazuh-dashboard-ip>")
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
    local password_command="sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env"
    if [ -z "${AIO}" ]; then
        password_command="sudo tar -xOf ${tar_file_name} wazuh-install-files/credentials.env | grep '^WAZUH_INDEXER_ADMIN_PASSWORD='"
    fi

    # Logged too: it holds the command that reads the password, not the password.
    common_logger "Wazuh dashboard web application initialized."
    common_logger "--- Summary ---"
    local ip
    for ip in "${print_ips[@]}"; do
        [[ "${ip}" == *:* ]] && ip="[${ip}]"
        common_logger "You can access the web interface https://${ip}:${http_port}"
    done
    common_logger "    User: admin"
    common_logger "    Password: run ${password_command}"

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
