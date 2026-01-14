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
    echo -e "        $(basename "${0}") - Manage passwords for Wazuh indexer users."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -A,  --api"
    echo -e "                Change the Wazuh API password."
    echo -e "                Requires -u|--user, and -p|--password, -au|--admin-user and -ap|--admin-password."
    echo -e ""
    echo -e "        -au,  --admin-user <adminUser>"
    echo -e "                Admin user for Wazuh API, Required to change Wazuh API passwords."
    echo -e "                Requires -A|--api."
    echo -e ""
    echo -e "        -ap,  --admin-password <adminPassword>"
    echo -e "                Password for Wazuh API admin user, Required to change Wazuh API passwords."
    echo -e "                Requires -A|--api."
    echo -e ""
    echo -e "        -u,  --user <user>"
    echo -e "                Required parameter."
    echo -e "                Indicates the name of the user whose password will be changed."
    echo -e "                If no password specified it will generate a random one."
    echo -e ""
    echo -e "        -p,  --password <password>"
    echo -e "                Indicates the new password, must be used with option -u."
    echo -e ""
    echo -e "        -c,  --cert <route-admin-certificate>"
    echo -e "                Indicates route to the admin certificate."
    echo -e ""
    echo -e "        -k,  --certkey <route-admin-certificate-key>"
    echo -e "                Indicates route to the admin certificate key."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete script execution output."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
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
            "-A"|"--api")
                api=1
                shift 1
                ;;
            "-au"|"--admin-user")
                if [ -z "${2}" ]; then
                    echo "Argument au|--admin-user needs a second argument"
                    getHelp
                    exit 1
                fi
                adminUser=${2}
                shift 2
                ;;
            "-ap"|"--admin-password")
                if [ -z "${2}" ]; then
                    echo "Argument -ap|--admin-password needs a second argument"
                    getHelp
                    exit 1
                fi
                adminPassword=${2}
                shift 2
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
                if [ -z "${2}" ]; then
                    echo "Argument --password needs a second argument"
                    getHelp
                    exit 1
                fi
                password=${2}
                shift 2
                ;;
            "-c"|"--cert")
                if [ -z "${2}" ]; then
                    echo "Argument --cert needs a second argument"
                    getHelp
                    exit 1
                fi
                adminpem=${2}
                shift 2
                ;;
            "-k"|"--certkey")
                if [ -z "${2}" ]; then
                    echo "Argument --certkey needs a second argument"
                    getHelp
                    exit 1
                fi
                adminkey=${2}
                shift 2
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

        if [ -z "${nuser}" ]; then
            echo "Error: -u|--user is required"
            getHelp
        fi

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ] && [ -z "${api}" ]; then
            getHelp
        fi

        if [ -n "${nuser}" ]; then
            if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
                passwords_getApiToken
                passwords_getApiUsers
                passwords_getApiIds
            elif [ -n "${indexer_installed}" ]; then
                passwords_readUsers
            fi
            passwords_checkUser
        fi

        if [ -n "${nuser}" ] && [ -z "${password}" ]; then
            autopass=1
            passwords_generatePassword
        fi

        if [ -n "${nuser}" ] && [ -n "${password}" ]; then
            passwords_checkPassword "${password}"
        fi

        if [ -z "${api}" ] && [ -n "${indexer_installed}" ]; then
            passwords_getNetworkHost
            passwords_generateHash
            passwords_changePassword
            passwords_runSecurityAdmin
        fi

        if [ -n "${api}" ]; then
            if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
                passwords_changePasswordApi
                if [ -n "${wazuh_installed}" ]; then
                    passwords_restartService "wazuh-manager"
                fi
                if [ -n "${dashboard_installed}" ]; then
                    passwords_restartService "wazuh-dashboard"
                fi
            fi
        fi

    else
        getHelp
    fi

}