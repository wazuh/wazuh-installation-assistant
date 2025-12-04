#!/bin/bash
function check_package() {

    if [ "${sys_type}" == "deb" ]; then
        if ! apt list --installed 2>/dev/null | grep -q "${1}"; then
            echo "INFO: The package "${1}" is not installed."
            return 1
        fi
    elif [ "${sys_type}" == "rpm" ]; then
        if ! yum list installed 2>/dev/null | grep -q "${1}"; then
            echo "INFO: The package "${1}" is not installed."
            return 1
        fi
    fi
    return 0

}

function dashboard_installation() {

    install_package "wazuh-dashboard"
    check_package "wazuh-dashboard"

    echo "INFO: Generating certificates of the Wazuh dashboard..."
    NODE_NAME=dashboard
    mkdir /etc/wazuh-dashboard/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
    chmod 500 /etc/wazuh-dashboard/certs
    chmod 400 /etc/wazuh-dashboard/certs/*
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

    if [ "${sys_type}" == "deb" ]; then
        enable_start_service "wazuh-dashboard"
    elif [ "${sys_type}" == "rpm" ]; then
        /usr/share/wazuh-dashboard/bin/opensearch-dashboards "-c /etc/wazuh-dashboard/opensearch_dashboards.yml" --allow-root > /dev/null 2>&1 &
    fi

    retries=0
    # In this context, 302 HTTP code refers to SSL certificates warning: success.
    until [ "$(curl -k -s -I -w "%{http_code}" https://127.0.0.1 -o /dev/null --fail)" -ne "302" ] || [ "${retries}" -eq 5 ]; do
        echo "INFO: Sleeping 10 seconds."
        sleep 10
        retries=$((retries+1))
    done
    if [ ${retries} -eq 5 ]; then
        echo "ERROR: The Wazuh dashboard installation has failed."
        exit 1
    else
        echo "INFO: The Wazuh dashboard is ready."
    fi

}

function enable_start_service() {

    systemctl daemon-reload
    systemctl enable "${1}"
    systemctl start "${1}"

    retries=0
    until [ "$(systemctl status "${1}" | grep "active")" ] || [ "${retries}" -eq 3 ]; do
        sleep 2
        retries=$((retries+1))
        systemctl start "${1}"
    done

    if [ ${retries} -eq 3 ]; then
        echo "ERROR: The "${1}" service could not be started."
        exit 1
    fi

}

function filebeat_installation() {

    install_package "filebeat"
    check_package "filebeat"

    cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
    cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
    chmod go+r /etc/filebeat/wazuh-template.json

    sed -i 's|\("index.number_of_shards": \)".*"|\1 "1"|' /etc/filebeat/wazuh-template.json
    filebeat keystore create
    echo admin | filebeat keystore add username --stdin --force
    echo admin | filebeat keystore add password --stdin --force
    tar -xzf ./wazuh-offline/wazuh-files/wazuh-filebeat-0.5.tar.gz -C /usr/share/filebeat/module

    echo "INFO: Generating certificates of Filebeat..."
    NODE_NAME=wazuh-1
    mkdir /etc/filebeat/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
    cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
    chmod 500 /etc/filebeat/certs
    chmod 400 /etc/filebeat/certs/*
    chown -R root:root /etc/filebeat/certs

    if [ "${sys_type}" == "deb" ]; then
        enable_start_service "filebeat"
    elif [ "${sys_type}" == "rpm" ]; then
        /usr/share/filebeat/bin/filebeat --environment systemd -c /etc/filebeat/filebeat.yml --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat --path.logs /var/log/filebeat &
    fi

    sleep 30
    eval "filebeat test output"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        echo "ERROR: The Filebeat installation has failed."
        exit 1
    fi

}

function indexer_initialize() {
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh

    retries=0
    while ! grep -E "\[node-[0-9]+\] Node 'node-[0-9]+' initialized" /var/log/wazuh-indexer/wazuh-cluster.log && [ "${retries}" -lt 5 ]; do
        sleep 5
        retries=$((retries+1))
    done

    if [ ${retries} -eq 5 ]; then
        echo "ERROR: The indexer node is not started."
        exit 1
    fi

}

function indexer_installation() {

    if [ "${sys_type}" == "rpm" ]; then
        rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
    fi

    install_package "wazuh-indexer"
    check_package "wazuh-indexer"

    echo "INFO: Generating certificates of the Wazuh indexer..."
    NODE_NAME=node-1
    mkdir /etc/wazuh-indexer/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    mv wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
    mv wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
    chmod 500 /etc/wazuh-indexer/certs
    chmod 400 /etc/wazuh-indexer/certs/*
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

    sed -i 's|\(network.host: \)"0.0.0.0"|\1"127.0.0.1"|' /etc/wazuh-indexer/opensearch.yml

    if [ "${sys_type}" == "rpm" ]; then
        runuser "wazuh-indexer" --shell="/bin/bash" --command="OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch" > /dev/null 2>&1 &
        sleep 20
    elif [ "${sys_type}" == "deb" ]; then
        enable_start_service "wazuh-indexer"
    fi

    indexer_initialize
    sleep 10
    eval "curl -s -XGET https://127.0.0.1:9200 -u admin:admin -k --fail"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        echo "ERROR: The Wazuh indexer installation has failed."
        exit 1
    fi

}

function install_package() {

    if [ "${sys_type}" == "deb" ]; then
        dpkg -i ./wazuh-offline/wazuh-packages/"${1}"*.deb
    elif [ "${sys_type}" == "rpm" ]; then
        rpm -ivh ./wazuh-offline/wazuh-packages/"${1}"*.rpm
    fi

}

function manager_installation() {

    install_package "wazuh-manager"
    check_package "wazuh-manager"

    if [ "${sys_type}" == "deb" ]; then
        enable_start_service "wazuh-manager"
    elif [ "${sys_type}" == "rpm" ]; then
        /var/ossec/bin/wazuh-control start
    fi

}

export sys_type="$1"

indexer_installation
echo "INFO: Wazuh indexer installation completed."

manager_installation
echo "INFO: Wazuh manager installation completed."

filebeat_installation
echo "INFO: Filebeat installation completed."

dashboard_installation
echo "INFO: Wazuh dashboard installation completed."
