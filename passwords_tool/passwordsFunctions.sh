# Passwords tool - library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function passwords_changePassword() {

    if [ -n "${changeall}" ]; then
        if [ -n "${indexer_installed}" ]; then
            eval "mkdir /etc/wazuh-indexer/backup/ ${debug}"
            eval "cp /etc/wazuh-indexer/opensearch-security/* /etc/wazuh-indexer/backup/ ${debug}"
            passwords_createBackUp
        fi

        for i in "${!passwords[@]}"; do
            if [ -n "${indexer_installed}" ] && [ -f "/etc/wazuh-indexer/backup/internal_users.yml" ]; then
                awk -v new='"'"${hashes[i]}"'"' 'prev=="'${users[i]}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml
            fi

            if [ "${users[i]}" == "wazuh-manager" ]; then
                managerpass=${passwords[i]}
            elif [ "${users[i]}" == "kibanaserver" ]; then
                dashpass=${passwords[i]}
            fi
        done
    else
        if [ -z "${api}" ] && [ -n "${indexer_installed}" ]; then
            eval "mkdir /etc/wazuh-indexer/backup/ ${debug}"
            eval "cp /etc/wazuh-indexer/opensearch-security/* /etc/wazuh-indexer/backup/ ${debug}"
            passwords_createBackUp
        fi

        if [ -n "${indexer_installed}" ] && [ -f "/etc/wazuh-indexer/backup/internal_users.yml" ]; then
            awk -v new='"'"${hash}"'"' 'prev=="'${nuser}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml
        fi

        if [ "${nuser}" == "wazuh-manager" ]; then
            managerpass=${password}
        elif [ "${nuser}" == "kibanaserver" ]; then
            dashpass=${password}
        fi
    fi

    if [ "${nuser}" == "wazuh-manager" ] || [ -n "${changeall}" ]; then
        if [ -n "${wazuh_installed}" ]; then
            if [ -n "${managerpass}" ]; then
                if ! passwords_updateManagerKeystore "${managerpass}"; then
                    common_logger -e "The new password was not applied to the Wazuh indexer, so the credentials currently in the keystore are still valid."
                    exit 1;
                fi
                manager_keystore_updated=1
                restart_manager=1
                common_logger -w "If this is a multi-node deployment, update the keystore of every other Wazuh manager node and restart them."
            else
                common_logger -w "Skipping Wazuh manager keystore update: no password available for the wazuh-manager user."
            fi
        fi
    fi

    if [ "${nuser}" == "kibanaserver" ] || [ -n "${changeall}" ]; then
        if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
            if /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root list | grep -q opensearch.password; then
                echo "${dashpass}" | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password ${debug_pass} > /dev/null 2>&1
                dashboard_keystore_updated=1
            else
                wazuhdashold=$(grep "password:" /etc/wazuh-dashboard/opensearch_dashboards.yml )
                rk="opensearch.password: "
                wazuhdashold="${wazuhdashold//$rk}"
                # Double-quoted: an unquoted value starting with "@", "%" or "," or ending with ":" is not
                # valid YAML. The value reaches awk through the environment, not the program text.
                conf="$(DASHPASS="${dashpass}" awk '{sub("opensearch.password: .*", "opensearch.password: \"" ENVIRON["DASHPASS"] "\"")}1' /etc/wazuh-dashboard/opensearch_dashboards.yml)"
                echo "${conf}" > /etc/wazuh-dashboard/opensearch_dashboards.yml
                dashboard_config_updated=1
            fi
            restart_dashboard=1
        fi
    fi

}

function passwords_changePasswordApi() {
    # Change API password tool
    if [ -n "${changeall}" ]; then
        if [ -n "${wazuh_installed}" ]; then
            if ! passwords_isServiceActive "wazuh-manager"; then
                common_logger -e "wazuh-manager service is not running. Skipping Wazuh API password change."
                exit 1;
            fi
        fi
        for i in "${!api_passwords[@]}"; do
            if [ -n "${wazuh_installed}" ]; then
                passwords_getApiUserId "${api_users[i]}"
                # Single-quoted for the eval in common_curl, which would otherwise brace-expand a "," in the
                # password; "'" is outside the password character set.
                WAZUH_PASS_API="{\"password\":\"${api_passwords[i]}\"}"
                common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "'${WAZUH_PASS_API}'" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail
                if [ "${api_users[i]}" == "${adminUser}" ]; then
                    sleep 1
                    adminPassword="${api_passwords[i]}"
                    passwords_getApiToken
                fi
                common_logger -nl $"The password for Wazuh API user ${api_users[i]} is ${api_passwords[i]}"
            fi
            if [ "${api_users[i]}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
                passwords_changeDashboardApiPassword "${api_passwords[i]}"
            fi
        done
    else
        if [ -n "${wazuh_installed}" ]; then
            if ! passwords_isServiceActive "wazuh-manager"; then
                common_logger -e "wazuh-manager service is not running. Skipping API password change for user ${nuser}."
                exit 1;
            fi
            passwords_getApiUserId "${nuser}"
            WAZUH_PASS_API="{\"password\":\"${password}\"}"
            common_curl -s -k -X PUT -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" -d "'${WAZUH_PASS_API}'" "https://localhost:55000/security/users/${user_id}" -o /dev/null --max-time 300 --retry 5 --retry-delay 5 --fail
            common_logger -nl $"The password for Wazuh API user ${nuser} is ${password}"
        fi
        if [ "${nuser}" == "wazuh-wui" ] && [ -n "${dashboard_installed}" ]; then
            passwords_changeDashboardApiPassword "${password}"
        fi
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

    # The same policy as wazuh_password_validate in credentials_lib/wazuh-credentials.sh, written out
    # again so that this tool keeps working as a standalone script. The character sets are spelled out
    # rather than given as ranges, so the match does not depend on the locale, and the set is checked
    # first so that every accepted value is ASCII and its length is counted in characters.
    local valid="yes"

    case "$1" in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-]*) valid="no" ;;
    esac
    if [ "${#1}" -lt 12 ] || [ "${#1}" -gt 64 ]; then
        valid="no"
    fi
    case "$1" in *[abcdefghijklmnopqrstuvwxyz]*) ;; *) valid="no" ;; esac
    case "$1" in *[ABCDEFGHIJKLMNOPQRSTUVWXYZ]*) ;; *) valid="no" ;; esac
    case "$1" in *[0123456789]*) ;; *) valid="no" ;; esac
    case "$1" in *[.,_+:@%^=~-]*) ;; *) valid="no" ;; esac

    if [ "${valid}" != "yes" ]; then
        common_logger -e "The password must have a length between 12 and 64 characters, use only A-Z a-z 0-9 . , _ + : @ % ^ = ~ - and contain at least one upper and lower case letter, a number and a symbol (. , _ + : @ % ^ = ~ -)."
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

    common_logger -d "Creating passwords backup."
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
    common_logger -d "Passwords backup created in /etc/wazuh-indexer/backup."

}

function passwords_generateHash() {

    if [ -n "${changeall}" ]; then
        common_logger -d "Generating password hashes."
        hashes=()
        for i in "${!passwords[@]}"; do
            # -env, not -p: the hasher reads a value starting with "-p", "-a"... as an option, and the
            # environment also keeps the password out of the process list.
            nhash=$(WAZUH_PASSWORD_TO_HASH="${passwords[i]}" bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env WAZUH_PASSWORD_TO_HASH 2>/dev/null)
            if [  "${PIPESTATUS[0]}" != 0  ]; then
                common_logger -e "Hash generation failed."
                if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                    installCommon_rollBack
                fi
                exit 1;
            fi
            hashes+=("${nhash}")
        done
        common_logger -d "Password hashes generated."
    else
        common_logger "Generating password hash"
        hash=$(WAZUH_PASSWORD_TO_HASH="${password}" bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env WAZUH_PASSWORD_TO_HASH 2>/dev/null)
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "Hash generation failed."
            if [[ $(type -t installCommon_rollBack) == "function" ]]; then
                installCommon_rollBack
            fi
            exit 1;
        fi
        common_logger -d "Password hash generated."
    fi

}

function passwords_generatePassword() {

    # 32 characters from the same set wazuh_password_generate uses (credentials_lib/wazuh-credentials.sh),
    # with at least one symbol, lowercase letter, uppercase letter and digit. `-` goes last in the tr
    # sets so it is literal, and LC_ALL=C keeps the ranges to ASCII.
    common_logger -d "Generating random password."
    pass=$(< /dev/urandom LC_ALL=C tr -dc 'A-Za-z0-9.,_+:@%^=~-' | head -c "${1:-28}";echo;)
    special_char=$(< /dev/urandom LC_ALL=C tr -dc '.,_+:@%^=~-' | head -c 1;echo;)
    minus_char=$(< /dev/urandom LC_ALL=C tr -dc 'a-z' | head -c 1;echo;)
    mayus_char=$(< /dev/urandom LC_ALL=C tr -dc 'A-Z' | head -c 1;echo;)
    number_char=$(< /dev/urandom LC_ALL=C tr -dc '0-9' | head -c 1;echo;)
    password="$(printf '%s' "${pass}${special_char}${minus_char}${mayus_char}${number_char}" | fold -w1 | shuf | tr -d '\n')"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The password could not been generated."
        exit 1;
    fi

}

function passwords_generatePasswords() {

    common_logger -d "Generating random passwords."
    passwords=()
    api_passwords=()

    for i in "${!users[@]}"; do
        passwords_generatePassword
        passwords+=("${password}")
    done

    for i in "${!api_users[@]}"; do
        passwords_generatePassword
        api_passwords+=("${password}")
    done

    password=""

}

function passwords_getApiToken() {
    retries=0
    max_internal_error_retries=20

    if ! passwords_isServiceActive "wazuh-manager"; then
        if [ -n "${changeall}" ]; then
            common_logger -e "wazuh-manager service is not running. Skipping Wazuh API password change."
        else
            common_logger -e "wazuh-manager service is not running. Skipping API password change for user ${nuser}."
        fi
        exit 1;
    fi

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

    if passwords_isServiceActive "wazuh-manager"; then
        mapfile -t api_users < <(common_curl -s -k -X GET -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\"  \"https://localhost:55000/security/users?pretty=true\" --max-time 300 --retry 5 --retry-delay 5 | grep username | awk -F': ' '{print $2}' | sed -e "s/[\'\",]//g")
    else
        if [ -n "${changeall}" ]; then
            common_logger -e "wazuh-manager service is not running. Skipping Wazuh API password change."
        else
            common_logger -e "wazuh-manager service is not running. Skipping API password change for user ${nuser}."
        fi
        exit 1;
    fi

}

function passwords_getApiUserId() {

    # The manager can respond on the API port right after restarting while
    # it is still registering its internal users. A single lookup here can
    # race that registration and report a false "not registered" error
    # (see external-devel-requests#6840). Poll for a short, bounded window
    # instead of failing on the first empty response.
    api_user_lookup_retries=12
    api_user_lookup_delay=5
    api_user_lookup_attempt=0
    user_id=""

    while [ "${api_user_lookup_attempt}" -lt "${api_user_lookup_retries}" ]; do
        user_id=$(common_curl -s -k -H \"Authorization: Bearer $TOKEN_API\" -H \"Content-Type: application/json\" \"https://localhost:55000/security/users?pretty=true\" | grep -B2 -A2 "\"username\": \"${1}\"" | grep '"id"' | grep -o '[0-9]\+')

        if [ -n "${user_id}" ]; then
            break
        fi

        api_user_lookup_attempt=$((api_user_lookup_attempt+1))
        if [ "${api_user_lookup_attempt}" -lt "${api_user_lookup_retries}" ]; then
            common_logger -d "User ${1} not found yet in the Wazuh API (attempt ${api_user_lookup_attempt}/${api_user_lookup_retries}). The API may still be registering internal users, retrying in ${api_user_lookup_delay}s."
            sleep "${api_user_lookup_delay}"
        fi
    done

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

function passwords_isServiceActive() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "passwords_isServiceActive must be called with 1 argument."
        return 1
    fi

    local service_name="${1}"

    # wazuh-manager is Type=forking with RemainAfterExit=yes and no PIDFile,
    # so systemd (and the equivalent SysV init status action) only require
    # *some* forked process from the unit's cgroup to still be alive to keep
    # reporting it as active/running -- e.g. wazuh-manager-apid on its own,
    # even if the core daemons (analysisd, remoted, etc.) already crashed.
    # Checking wazuh-manager-control status reflects each daemon's real
    # state instead.
    if [ "${service_name}" == "wazuh-manager" ] && [ -x /var/wazuh-manager/bin/wazuh-manager-control ]; then
        # Daemons enabled by default on every install, per the DAEMONS list
        # in wazuh/wazuh's src/init/wazuh-server.sh on 5.0.0. wazuh-manager-
        # clusterd and wazuh-manager-authd are optional/configurable, so they
        # are intentionally left out of this check. wazuh-manager-execd,
        # wazuh-manager-syscheckd, wazuh-manager-logcollector and
        # wazuh-manager-monitord no longer exist as separate daemons in
        # 5.0.0 (#992) -- they are not in that DAEMONS list either.
        manager_core_daemons=(wazuh-manager-db wazuh-manager-analysisd wazuh-manager-remoted wazuh-manager-modulesd wazuh-manager-apid)
        manager_status=$(/var/wazuh-manager/bin/wazuh-manager-control status 2>/dev/null)
        for manager_daemon in "${manager_core_daemons[@]}"; do
            if ! echo "${manager_status}" | grep -q "^${manager_daemon} is running"; then
                return 1
            fi
        done
        return 0
    fi

    if [[ -d /run/systemd/system ]]; then
        # Check if service is active using systemctl
        if systemctl is-active --quiet "${service_name}.service" 2>/dev/null; then
            return 0
        else
            return 1
        fi
    elif ps -p 1 -o comm= | grep "init"; then
        # Check service status for init systems
        if /etc/init.d/"${service_name}" status >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    elif [ -x "/etc/rc.d/init.d/${service_name}" ]; then
        # Check service status for rc.d systems
        if /etc/rc.d/init.d/"${service_name}" status >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    else
        common_logger -w "Cannot determine service status. No service manager found on the system."
        return 1
    fi

}

function passwords_restartPendingServices() {

    if [ -n "${restart_manager}" ]; then
        if passwords_isServiceActive "wazuh-manager"; then
            passwords_restartService "wazuh-manager"
        elif [ -n "${manager_keystore_updated}" ]; then
            common_logger -w "The Wazuh manager keystore was updated, but the wazuh-manager service is not running. The restart is pending: the new Wazuh indexer credentials will be applied when the service starts."
        else
            common_logger -w "wazuh-manager service is not running. Skipping restart."
        fi
    fi

    if [ -n "${restart_dashboard}" ]; then
        if passwords_isServiceActive "wazuh-dashboard"; then
            passwords_restartService "wazuh-dashboard"
        elif [ -n "${dashboard_keystore_updated}" ]; then
            common_logger -w "The Wazuh dashboard keystore was updated, but the wazuh-dashboard service is not running. The restart is pending: the new Wazuh indexer credentials will be applied when the service starts."
        elif [ -n "${dashboard_config_updated}" ]; then
            common_logger -w "The Wazuh dashboard configuration file was updated, but the wazuh-dashboard service is not running. The restart is pending: the new Wazuh indexer credentials will be applied when the service starts."
        else
            common_logger -w "wazuh-dashboard service is not running. Skipping restart."
        fi
    fi

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
            # systemctl restart can return success immediately even if the
            # service later fails to initialize (e.g. under resource
            # pressure). Poll is-active for a short window to catch that
            # before moving on, instead of only checking the restart call
            # itself.
            restart_check_retries=12
            restart_check_delay=5
            restart_check_attempt=0
            service_is_active=""

            while [ "${restart_check_attempt}" -lt "${restart_check_retries}" ]; do
                if passwords_isServiceActive "${1}"; then
                    service_is_active="true"
                    break
                fi
                restart_check_attempt=$((restart_check_attempt+1))
                sleep "${restart_check_delay}"
            done

            if [ -z "${service_is_active}" ]; then
                common_logger -e "${1} restarted but did not stay active (checked for $((restart_check_retries * restart_check_delay))s). It may have failed to initialize, for example due to insufficient resources."
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
            # Same rationale as the systemd branch above: the restart command
            # can return success immediately even if the service later fails
            # to initialize. Poll the init script's own status action for a
            # short window before considering the restart actually successful.
            restart_check_retries=12
            restart_check_delay=5
            restart_check_attempt=0
            service_is_active=""

            while [ "${restart_check_attempt}" -lt "${restart_check_retries}" ]; do
                if passwords_isServiceActive "${1}"; then
                    service_is_active="true"
                    break
                fi
                restart_check_attempt=$((restart_check_attempt+1))
                sleep "${restart_check_delay}"
            done

            if [ -z "${service_is_active}" ]; then
                common_logger -e "${1} restarted but did not stay active (checked for $((restart_check_retries * restart_check_delay))s). It may have failed to initialize, for example due to insufficient resources."
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
            # Same rationale as the systemd branch above: poll the init
            # script's own status action for a short window before
            # considering the restart actually successful.
            restart_check_retries=12
            restart_check_delay=5
            restart_check_attempt=0
            service_is_active=""

            while [ "${restart_check_attempt}" -lt "${restart_check_retries}" ]; do
                if passwords_isServiceActive "${1}"; then
                    service_is_active="true"
                    break
                fi
                restart_check_attempt=$((restart_check_attempt+1))
                sleep "${restart_check_delay}"
            done

            if [ -z "${service_is_active}" ]; then
                common_logger -e "${1} restarted but did not stay active (checked for $((restart_check_retries * restart_check_delay))s). It may have failed to initialize, for example due to insufficient resources."
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
    cp /etc/wazuh-indexer/backup/internal_users.yml /etc/wazuh-indexer/opensearch-security/internal_users.yml
    eval "rm -rf /etc/wazuh-indexer/backup/ ${debug}"

    if [[ -n "${nuser}" ]] && [[ -n ${autopass} ]]; then
        common_logger -nl "The password for user ${nuser} is ${password}"
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

    if [[ -n "${nuser}" ]] && [[ -z ${autopass} ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

    if [ -n "${changeall}" ]; then
        for i in "${!users[@]}"; do
            common_logger -nl "The password for user ${users[i]} is ${passwords[i]}"
        done
        common_logger -w "Wazuh indexer passwords changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
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

function passwords_updateManagerKeystore() {

    if [ "$#" -ne 1 ]; then
        common_logger -e "passwords_updateManagerKeystore must be called with 1 argument."
        return 1
    fi

    printf '%s\n' "wazuh-manager" | "${manager_keystore}" -f indexer -k username
    if [  "${PIPESTATUS[1]}" != 0  ]; then
        common_logger -e "Could not write the Wazuh indexer username to the Wazuh manager keystore."
        return 1
    fi

    printf '%s\n' "${1}" | "${manager_keystore}" -f indexer -k password
    if [  "${PIPESTATUS[1]}" != 0  ]; then
        common_logger -e "Could not write the Wazuh indexer password to the Wazuh manager keystore."
        return 1
    fi

}
