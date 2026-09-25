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
                passwords_replaceHash "${users[i]}" "${hashes[i]}"
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
            passwords_replaceHash "${nuser}" "${hash}"
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
            if ! passwords_updateDashboardKeystore "opensearch.password" "${dashpass}"; then
                common_logger -e "The new password was not applied to the Wazuh indexer, so the credentials currently in the Wazuh dashboard keystore are still valid."
                exit 1;
            fi
            dashboard_keystore_updated=1
            restart_dashboard=1
        fi
    fi

}

function passwords_changePasswordApi() {

    if [ -n "${changeall}" ]; then
        for i in "${!api_users[@]}"; do
            if ! passwords_changeApiUserPassword "${api_users[i]}" "${api_passwords[i]}" 1; then
                return 1
            fi
        done
    else
        if ! passwords_changeApiUserPassword "${nuser}" "${password}" "${autopass}"; then
            return 1
        fi
    fi

}

function passwords_changeApiUserPassword() {

    local user="${1}"
    local new_password="${2}"
    local generated="${3}"
    local rbac_output
    local rbac_status

    if [ ! -x "${rbac_control}" ]; then
        common_logger -e "Cannot find ${rbac_control}. The password of the Wazuh API user ${user} was not changed."
        return 1
    fi

    # rbac_control reads the new password from the standard input and never prints it.
    rbac_output=$(printf '%s\n' "${new_password}" | "${rbac_control}" change-password -u "${user}" -p - 2>&1)
    rbac_status=$?
    if [ "${rbac_status}" -ne 0 ] || ! grep -Eq "^[[:space:]]*${user}: UPDATED$" <<< "${rbac_output}"; then
        common_logger -e "The password of the Wazuh API user ${user} could not be changed: $(echo "${rbac_output}" | tr -s '\n\t' '  ')"
        return 1
    fi
    common_logger "The password of the Wazuh API user ${user} was changed."

    passwords_saveCredential "${user}" "${new_password}" "${generated}"

    if [ "${user}" == "wazuh-wui" ]; then
        if [ -n "${dashboard_installed}" ]; then
            if ! passwords_updateDashboardKeystore "wazuh_core.hosts.default.password" "${new_password}"; then
                return 1
            fi
            dashboard_keystore_updated=1
            restart_dashboard=1
        else
            common_logger -w "The Wazuh dashboard is not installed on this host. Update wazuh_core.hosts.default.password in the keystore of every Wazuh dashboard node and restart them."
        fi
    fi

}

function passwords_checkUser() {

    if passwords_isInList "${nuser}" "${api_accounts[@]}"; then
        if [ -z "${wazuh_installed}" ]; then
            common_logger -e "The Wazuh manager is not installed on this host, so the password of the Wazuh API user ${nuser} cannot be changed here."
            exit 1;
        fi
        api=1
        return 0
    fi

    if passwords_isInList "${nuser}" "${indexer_accounts[@]}"; then
        if [ -z "${indexer_installed}" ]; then
            common_logger -e "The Wazuh indexer is not installed on this host, so the password of the Wazuh indexer user ${nuser} cannot be changed here."
            exit 1;
        fi
        if ! passwords_isInList "${nuser}" "${users[@]}"; then
            common_logger -e "The given user does not exist"
            exit 1;
        fi
        return 0
    fi

    common_logger -e "The user ${nuser} is not supported. Supported users: ${indexer_accounts[*]} ${api_accounts[*]}."
    exit 1;

}

function passwords_checkCredentialsFile() {

    local env_status=0

    # A broken or insecure credentials file is reported before any password is changed.
    wazuh_env_get WAZUH_INDEXER_ADMIN_PASSWORD > /dev/null || env_status=$?
    if [ "${env_status}" -eq 2 ]; then
        common_logger -e "The credentials file $(wazuh_env_get_file 2>/dev/null) cannot be used, so no password was changed. Fix the problem shown above and run the tool again."
        exit 1;
    fi

}

function passwords_checkPassword() {

    local invalid_chars
    local validation_error

    # Same rule as the Wazuh packages: only these characters, so every component accepts the password.
    invalid_chars=$(printf '%s' "${1}" | LC_ALL=C tr -d 'A-Za-z0-9.,_+:@%^=~-')
    if [ -n "${invalid_chars}" ]; then
        common_logger -e "The password can only contain these characters: A-Z a-z 0-9 . , _ + : @ % ^ = ~ -"
        exit 1
    fi

    # The Wazuh dashboard keystore would store a value that looks like a number as a number.
    if printf '%s' "${1}" | LC_ALL=C grep -Eqx -- '-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?'; then
        common_logger -e "The password cannot be a number."
        exit 1
    fi

    if ! validation_error=$(wazuh_password_validate "${1}" 2>&1); then
        common_logger -e "Invalid password: ${validation_error#wazuh-credentials: }."
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
            nhash=$(passwords_hashPassword "${passwords[i]}")
            if [ -z "${nhash}" ]; then
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
        hash=$(passwords_hashPassword "${password}")
        if [ -z "${hash}" ]; then
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

    common_logger -d "Generating random password."
    if ! password=$(wazuh_password_generate); then
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

# Prints the credentials.env key of a user, the same key the Wazuh packages use.
function passwords_getEnvKey() {

    case "${1}" in
        "admin") echo "WAZUH_INDEXER_ADMIN_PASSWORD" ;;
        "kibanaserver") echo "WAZUH_INDEXER_KIBANASERVER_PASSWORD" ;;
        "wazuh-manager") echo "WAZUH_INDEXER_MANAGER_PASSWORD" ;;
        "wazuh") echo "WAZUH_MANAGER_API_PASSWORD" ;;
        "wazuh-wui") echo "WAZUH_MANAGER_WUI_PASSWORD" ;;
        *) return 1 ;;
    esac

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

# Prints the bcrypt hash of a password. The password reaches hash.sh through its
# environment, never through the command line.
function passwords_hashPassword() {

    WAZUH_PASSWORDS_TOOL_SECRET="${1}" OPENSEARCH_JAVA_HOME="/usr/share/wazuh-indexer/jdk" bash "${hash_tool}" -env WAZUH_PASSWORDS_TOOL_SECRET 2>/dev/null | grep -Eo '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' | tail -n 1

}

function passwords_isInList() {

    local item="${1}"
    local element
    shift

    for element in "$@"; do
        if [ "${element}" == "${item}" ]; then
            return 0
        fi
    done
    return 1

}

function passwords_readUsers() {

    passwords_updateInternalUsers
    users=()
    for account in "${indexer_accounts[@]}"; do
        if grep -q "^${account}:$" /etc/wazuh-indexer/opensearch-security/internal_users.yml; then
            users+=("${account}")
        fi
    done

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

# Reads the new password from the standard input, so it never shows up in the process list.
function passwords_readPassword() {

    local password_confirmation

    if [ -t 0 ]; then
        IFS= read -r -s -p "New password for user ${nuser}: " password
        echo >&2
        IFS= read -r -s -p "Repeat the new password: " password_confirmation
        echo >&2
        if [ "${password}" != "${password_confirmation}" ]; then
            common_logger -e "The passwords do not match."
            exit 1;
        fi
    else
        IFS= read -r password
    fi

    if [ -z "${password}" ]; then
        common_logger -e "No password was given on the standard input."
        exit 1;
    fi

}

# Writes the hash of a user in the internal_users.yml backup. The hash reaches awk
# through its environment.
function passwords_replaceHash() {

    WAZUH_PASSWORDS_TOOL_HASH="${2}" awk -v user="${1}:" 'prev==user{sub(/\042.*/,""); $0=$0 "\"" ENVIRON["WAZUH_PASSWORDS_TOOL_HASH"] "\""} {prev=$1} 1' /etc/wazuh-indexer/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /etc/wazuh-indexer/backup/internal_users.yml

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
            common_logger -w "The Wazuh dashboard keystore was updated, but the wazuh-dashboard service is not running. The restart is pending: the new credentials will be applied when the service starts."
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

    if [[ -n "${nuser}" ]]; then
        common_logger -w "Password changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

    if [ -n "${changeall}" ]; then
        common_logger -w "Wazuh indexer passwords changed. Remember to update the password in the Wazuh dashboard and the Wazuh manager nodes if necessary, and restart the services."
    fi

}

# Records a new password in credentials.env, as the Wazuh packages do. A generated
# password is always recorded, because it is not shown anywhere else. A password
# given by the operator only updates a credentials file that already exists.
function passwords_saveCredential() {

    local user="${1}"
    local new_password="${2}"
    local generated="${3}"
    local key
    local env_file

    if ! key=$(passwords_getEnvKey "${user}"); then
        return 0
    fi
    if ! env_file=$(wazuh_env_get_file); then
        save_failed=1
        return 1
    fi

    if [ -z "${generated}" ] && [ ! -e "${env_file}" ]; then
        return 0
    fi

    if ! wazuh_env_set "${key}" "${new_password}"; then
        common_logger -e "The new password of user ${user} was applied, but it could not be saved in ${env_file}. Run the tool again for this user with -p to set a password you know."
        save_failed=1
        return 1
    fi

    if [ -n "${generated}" ]; then
        common_logger "The new password of user ${user} was saved in ${env_file} as ${key}."
    else
        common_logger "${key} was updated in ${env_file}."
    fi

}

function passwords_saveIndexerCredentials() {

    if [ -n "${changeall}" ]; then
        for i in "${!users[@]}"; do
            passwords_saveCredential "${users[i]}" "${passwords[i]}" 1
        done
    else
        passwords_saveCredential "${nuser}" "${password}" "${autopass}"
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

# Writes a value in the Wazuh dashboard keystore. The keystore belongs to the dashboard
# service user, so it is written as that user, and the value goes through the standard input.
function passwords_updateDashboardKeystore() {

    if [ "$#" -ne 2 ]; then
        common_logger -e "passwords_updateDashboardKeystore must be called with 2 arguments."
        return 1
    fi

    if [ ! -x "${dashboard_keystore}" ]; then
        common_logger -e "Cannot find ${dashboard_keystore}. ${1} was not written to the Wazuh dashboard keystore."
        return 1
    fi

    if ! printf '%s' "${2}" | (cd / && runuser -u "${dashboard_user}" -- "${dashboard_keystore}" add -f --stdin "${1}") > /dev/null 2>&1; then
        common_logger -e "Could not write ${1} to the Wazuh dashboard keystore."
        return 1
    fi

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
