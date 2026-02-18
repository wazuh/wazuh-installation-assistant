# Passwords tool - library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function passwords_changePassword() {

    if [ -z "${api}" ] && [ -n "${indexer_installed}" ]; then
        eval "mkdir /etc/wazuh-indexer/backup/ ${debug}"
        eval "cp /etc/wazuh-indexer/opensearch-security/* /etc/wazuh-indexer/backup/ ${debug}"
        passwords_createBackUp
    fi
    
    if [ -n "${indexer_installed}" ] && [ -f "/etc/wazuh-indexer/backup/internal_users.yml" ]; then
        awk -v new='"'"${hash}"'"' 'prev=="'${nuser}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml
    fi

    if [ "${nuser}" == "admin" ]; then
        adminpass=${password}
    elif [ "${nuser}" == "kibanaserver" ]; then
        dashpass=${password}
    fi

    if [ "${nuser}" == "admin" ]; then
        if [ -n "${wazuh_installed}" ]; then
            eval "/var/wazuh-manager/bin/wazuh-keystore -f indexer -k password -v ${adminpass}"
            passwords_restartService "wazuh-manager"
        fi
    fi

    if [ "${nuser}" == "kibanaserver" ]; then
        if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
            if /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root list | grep -q opensearch.password; then
                eval "echo ${dashpass} | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password ${debug_pass} > /dev/null 2>&1"
            else
                wazuhdashold=$(grep "password:" /etc/wazuh-dashboard/opensearch_dashboards.yml )
                rk="opensearch.password: "
                wazuhdashold="${wazuhdashold//$rk}"
                conf="$(awk '{sub("opensearch.password: .*", "opensearch.password: '"${dashpass}"'")}1' /etc/wazuh-dashboard/opensearch_dashboards.yml)"
                echo "${conf}" > /etc/wazuh-dashboard/opensearch_dashboards.yml
            fi
            passwords_restartService "wazuh-dashboard"
        fi
    fi

}

function passwords_changePasswordApi() {
    # Change API password tool
    if [ -n "${wazuh_installed}" ]; then
        passwords_getApiUserId "${nuser}"
        WAZUH_PASS_API='{\"password\":\"'"${password}"'\"}'
        eval 'common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "$WAZUH_PASS_API" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail'
        common_logger -nl $"The password for Wazuh API user ${nuser} is ${password}"
    fi
    if [ "${nuser}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
        passwords_changeDashboardApiPassword "${password}"
    fi
}

function passwords_changeDashboardApiPassword() {

    eval "sed -i 's|password: .*|password: \"${1}\"|g' /etc/wazuh-dashboard/opensearch_dashboards.yml ${debug}"
}

function passwords_checkUser() {

    if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
        for i in "${!api_users[@]}"; do
            if [ "${api_users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    else
        for i in "${!users[@]}"; do
            if [ "${users[i]}" == "${nuser}" ]; then
                exists=1
            fi
        done
    fi

    if [ -z "${exists}" ]; then
        common_logger -e "The given user does not exist"
        exit 1;
    fi

}

function passwords_checkPassword() {

    if ! echo "$1" | grep -q "[A-Z]" || ! echo "$1" | grep -q "[a-z]" || ! echo "$1" | grep -q "[0-9]" || ! echo "$1" | grep -q "[.*+?-]" || [ "${#1}" -lt 8 ] || [ "${#1}" -gt 64 ]; then
        common_logger -e "The password must have a length between 8 and 64 characters and contain at least one upper and lower case letter, a number and a symbol(.*+?-)."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
    fi

}

function passwords_createBackUp() {

    if [ -z "${indexer_installed}" ] && [ -z "${dashboard_installed}" ]; then
        common_logger -e "Cannot find Wazuh indexer or Wazuh dashboard on the system."
        exit 1;
    else
        if [ -n "${indexer_installed}" ]; then
            capem=$(grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml )
            rcapem="plugins.security.ssl.transport.pemtrustedcas_filepath: "
            capem="${capem//$rcapem}"
        fi
    fi

    common_logger -d "Creating password backup."
    if [ ! -d "/etc/wazuh-indexer/backup" ]; then
        eval "mkdir /etc/wazuh-indexer/backup ${debug}"
    fi
    eval "JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -backup /etc/wazuh-indexer/backup -icl -p 9200 -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -h ${IP} ${debug}"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        common_logger -e "The backup could not be created"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1;
    fi
    common_logger -d "Password backup created in /etc/wazuh-indexer/backup."

}

function passwords_generateHash() {

    common_logger "Generating password hash"
    hash=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${password}" 2>&1)
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "Hash generation failed."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1;
    fi
    common_logger -d "Password hash generated."

}

function passwords_generatePassword() {

    common_logger -d "Generating random password."
    pass=$(< /dev/urandom tr -dc "A-Za-z0-9.*+?" | head -c "${1:-28}";echo;)
    special_char=$(< /dev/urandom tr -dc ".*+?" | head -c "${1:-1}";echo;)
    minus_char=$(< /dev/urandom tr -dc "a-z" | head -c "${1:-1}";echo;)
    mayus_char=$(< /dev/urandom tr -dc "A-Z" | head -c "${1:-1}";echo;)
    number_char=$(< /dev/urandom tr -dc "0-9" | head -c "${1:-1}";echo;)
    password="$(echo "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The password could not been generated."
        exit 1;
    fi

}

function passwords_getApiToken() {
    retries=0
    max_internal_error_retries=20

    TOKEN_API=$(curl -s -u "${adminUser}":"${adminPassword}" -k -X POST "https://localhost:55000/security/user/authenticate?raw=true" --max-time 300 --retry 5 --retry-delay 5)
    while [[ "${TOKEN_API}" =~ "Wazuh Internal Error" ]] && [ "${retries}" -lt "${max_internal_error_retries}" ]
    do
        common_logger "There was an error accessing the API. Retrying..."
        TOKEN_API=$(curl -s -u "${adminUser}":"${adminPassword}" -k -X POST "https://localhost:55000/security/user/authenticate?raw=true" --max-time 300 --retry 5 --retry-delay 5)
        retries=$((retries+1))
        sleep 10
    done
    if [[ ${TOKEN_API} =~ "Wazuh Internal Error" ]]; then
        common_logger -e "There was an error while trying to get the API token."
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    elif [[ ${TOKEN_API} =~ "Invalid credentials" ]]; then
        common_logger -e "Invalid admin user credentials"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        exit 1
    fi

}

function passwords_getApiUsers() {

    mapfile -t api_users < <(common_curl -s -k -X GET -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\"  \"https://localhost:55000/security/users?pretty=true\" --max-time 300 --retry 5 --retry-delay 5 | grep username | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")

}

function passwords_getApiUserId() {
    user_id=$(common_curl -s -k -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" \"https://localhost:55000/security/users?pretty=true\" | grep -B2 -A2 "\"username\": \"${1}\"" | grep '"id"' | grep -o '[0-9]\+')

    if [ -z "${user_id}" ]; then
        common_logger -e "User ${1} is not registered in Wazuh API"
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
        fi
        exit 1
    fi

}


function passwords_getNetworkHost() {

    IP=$(grep -hr "^network.host:" /etc/wazuh-indexer/opensearch.yml)
    NH="network.host: "
    IP="${IP//$NH}"

    # Remove surrounding double quotes if present
    IP="${IP//\"}"

    #allow to find ip with an interface
    if [[ ${IP} =~ _.*_ ]]; then
        interface="${IP//_}"
        IP=$(ip -o -4 addr list "${interface}" | awk '{print $4}' | cut -d/ -f1)
    fi

    if [ "${IP}" == "0.0.0.0" ]; then
        IP="localhost"
    fi
}

function passwords_readUsers() {

    passwords_updateInternalUsers
    susers=$(grep '^[a-z-]*:$' /etc/wazuh-indexer/opensearch-security/internal_users.yml | sed 's/:$//')
    mapfile -t users <<< "${susers[@]}"

}

function passwords_restartService() {

    common_logger -d "Restarting ${1} service..."
    if [ "$#" -ne 1 ]; then
        common_logger -e "passwords_restartService must be called with 1 argument."
        exit 1
    fi

    if [[ -d /run/systemd/system ]]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl restart ${1}.service ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        eval "/etc/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    elif [ -x "/etc/rc.d/init.d/${1}" ] ; then
        eval "/etc/rc.d/init.d/${1} restart ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "${1} could not be started."
            if [ -n "$(command -v journalctl)" ]; then
                eval "journalctl -u ${1} >> ${logfile}"
            fi
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        else
            common_logger -d "${1} started."
        fi
    else
        if [[ $(type -t installCommon_rollBack) == "function" ]]; then
            installCommon_rollBack
        fi
        common_logger -e "${1} could not start. No service manager found on the system."
        exit 1;
    fi

}

function passwords_runSecurityAdmin() {

    common_logger -d "Running security admin tool."
    if [ -z "${indexer_installed}" ] && [ -z "${dashboard_installed}" ]; then
        common_logger -e "Cannot find Wazuh indexer or Wazuh dashboard on the system."
        exit 1;
    else
        if [ -n "${indexer_installed}" ]; then
            capem=$(grep "plugins.security.ssl.transport.pemtrustedcas_filepath: " /etc/wazuh-indexer/opensearch.yml )
            rcapem="plugins.security.ssl.transport.pemtrustedcas_filepath: "
            capem="${capem//$rcapem}"
        fi
    fi

    common_logger -d "Loading new passwords changes."
    eval "OPENSEARCH_CONF_DIR=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/backup/internal_users.yml -t internalusers -p 9200 -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${IP} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "Could not load the changes."
        exit 1;
    fi
    eval "cp /etc/wazuh-indexer/backup/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml"
    eval "rm -rf /etc/wazuh-indexer/backup/ ${debug}"

    if [[ -n "${nuser}" ]] && [[ -n ${autopass} ]]; then
        common_logger -nl "The password for user ${nuser} is ${password}"
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

    if [[ -n "${nuser}" ]] && [[ -z ${autopass} ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

}

function passwords_updateInternalUsers() {

    common_logger "Updating the internal users."
    backup_datetime=$(date +"%Y%m%d_%H%M%S")
    internal_users_backup_path="/etc/wazuh-indexer/internalusers-backup"
    passwords_getNetworkHost
    passwords_createBackUp

    eval "mkdir -p ${internal_users_backup_path} ${debug}"
    eval "cp /etc/wazuh-indexer/backup/internal_users.yml ${internal_users_backup_path}/internal_users_${backup_datetime}.yml.bkp ${debug}"
    eval "chmod 750 ${internal_users_backup_path} ${debug}"
    eval "chmod 640 ${internal_users_backup_path}/internal_users_${backup_datetime}.yml.bkp"
    eval "chown -R wazuh-indexer:wazuh-indexer ${internal_users_backup_path} ${debug}"
    common_logger "A backup of the internal users has been saved in the /etc/wazuh-indexer/internalusers-backup folder."

    eval "cp /etc/wazuh-indexer/backup/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml ${debug}"
    eval "rm -rf /etc/wazuh-indexer/backup/ ${debug}"
    common_logger -d "The internal users have been updated before changing the passwords."

}
