# Passwords tool - main functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "${0}") - Manage passwords for Wazuh indexer and Wazuh API users."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --change-all"
    echo -e "                Changes the passwords of all the Wazuh indexer and Wazuh API users installed on this host."
    echo -e "                The new passwords are generated and saved in the credentials file."
    echo -e ""
    echo -e "        -u,  --user <user>"
    echo -e "                Indicates the name of the user whose password will be changed."
    echo -e "                Wazuh indexer users: ${indexer_accounts[*]}."
    echo -e "                Wazuh API users: ${api_accounts[*]}."
    echo -e "                If -p|--password is not used, a random password is generated and saved in the credentials file."
    echo -e ""
    echo -e "        -p,  --password"
    echo -e "                Reads the new password from the standard input, must be used with option -u."
    echo -e "                The password must have between 12 and 64 characters, at least one letter and one digit,"
    echo -e "                and only these characters: A-Z a-z 0-9 . , _ + : @ % ^ = ~ -"
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete script execution output."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "FILES"
    echo -e "        $(wazuh_env_get_file 2>/dev/null)"
    echo -e "                Credentials file. Generated passwords are always saved here. A password given with"
    echo -e "                -p|--password only updates it when the file already exists. The directory can be"
    echo -e "                changed with WAZUH_BASE_DIR."
    echo -e ""
    exit 1

}

function main() {

    umask 177

    common_checkRoot

    if [ -n "${1}" ]; then
        while [ -n "${1}" ]
        do
            case "${1}" in
            "-v"|"--verbose")
                verboseenabled=1
                shift 1
                ;;
            "-a"|"--change-all")
                changeall=1
                shift 1
                ;;
            "-u"|"--user")
                if [ -z "${2}" ]; then
                    echo "Argument --user needs a second argument"
                    getHelp
                    exit 1
                fi
                nuser=${2}
                shift 2
                ;;
            "-p"|"--password")
                readpassword=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                getHelp
            esac
        done

        export JAVA_HOME=/usr/share/wazuh-indexer/jdk/

        if [ -n "${verboseenabled}" ]; then
            debug="2>&1 | tee -a ${logfile}"
        fi

        common_checkSystem
        common_checkInstalled

        if [ -z "${nuser}" ] && [ -z "${changeall}" ]; then
            common_logger -e "Either -u|--user or -a|--change-all is required."
            getHelp
        fi

        if [ -n "${nuser}" ] && [ -n "${changeall}" ]; then
            getHelp
        fi

        if [ -n "${readpassword}" ] && [ -z "${nuser}" ]; then
            getHelp
        fi

        if [ -n "${readpassword}" ]; then
            passwords_readPassword
            passwords_checkPassword "${password}"
        fi

        passwords_checkCredentialsFile

        if [ -n "${nuser}" ]; then
            if passwords_isInList "${nuser}" "${indexer_accounts[@]}" && [ -n "${indexer_installed}" ]; then
                passwords_readUsers
            fi
            passwords_checkUser
        fi

        if [ -n "${changeall}" ]; then
            if [ -n "${indexer_installed}" ]; then
                passwords_readUsers
            fi
            if [ -n "${wazuh_installed}" ]; then
                api_users=("${api_accounts[@]}")
            fi
            if [ "${#users[@]}" -eq 0 ] && [ "${#api_users[@]}" -eq 0 ]; then
                common_logger -e "No Wazuh indexer or Wazuh API user to change on this host."
                exit 1
            fi
            passwords_generatePasswords
        fi

        if [ -n "${nuser}" ] && [ -z "${readpassword}" ]; then
            autopass=1
            passwords_generatePassword
        fi

        if [ -z "${api}" ] && [ -n "${indexer_installed}" ]; then
            passwords_getNetworkHost
            passwords_generateHash
            passwords_changePassword
            passwords_runSecurityAdmin
            passwords_saveIndexerCredentials
        fi

        if [ -n "${api}" ] || [ "${#api_users[@]}" -gt 0 ]; then
            if ! passwords_changePasswordApi; then
                passwords_restartPendingServices
                exit 1
            fi
        fi

        passwords_restartPendingServices

        if [ -n "${save_failed}" ]; then
            exit 1
        fi

    else
        getHelp
    fi

}
