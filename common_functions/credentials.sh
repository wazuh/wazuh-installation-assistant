# Credential helpers: env files, passwords and the deployment root CA
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Prints the value of a key in an env file (KEY=value, optionally quoted).
# Returns 1 when the file or the key does not exist, and 2 when the file is not a
# regular file owned by root.
function common_envGet() {

    local file="${1}" key="${2}" value

    if [ ! -e "${file}" ] && [ ! -L "${file}" ]; then
        return 1
    fi
    if [ -L "${file}" ] || [ ! -f "${file}" ] || [ "$(stat -c %u "${file}")" != "0" ]; then
        echo "${file} must be a regular file owned by root." >&2
        return 2
    fi

    value=$(sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "${file}" | tail -n 1)
    if ! grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${file}"; then
        return 1
    fi
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "${value}" =~ ^\"(.*)\"$ ]] || [[ "${value}" =~ ^\'(.*)\'$ ]]; then
        value="${BASH_REMATCH[1]}"
    fi
    printf '%s\n' "${value}"

}

# Replaces a key in an env file, in the same line, or adds it at the end. The file is
# written as root:root 0600 through a temporary file in the same directory, so it is
# never left half written.
function common_envSet() {

    local file="${1}" key="${2}" value="${3}" tmp

    if [ -L "${file}" ] || { [ -e "${file}" ] && [ ! -f "${file}" ]; }; then
        echo "${file} must be a regular file." >&2
        return 1
    fi
    if ! tmp=$(mktemp "${file}.XXXXXX"); then
        return 1
    fi
    if [ -f "${file}" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${file}"; then
        KEY="${key}" VALUE="${value}" awk '
            $0 ~ "^[[:space:]]*" ENVIRON["KEY"] "[[:space:]]*=" { if (!done) print ENVIRON["KEY"] "=" ENVIRON["VALUE"]; done = 1; next }
            { print }
        ' "${file}" > "${tmp}"
    else
        [ -f "${file}" ] && cat "${file}" > "${tmp}"
        printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
    fi
    if ! chown root:root "${tmp}" || ! chmod 600 "${tmp}" || ! mv -f "${tmp}" "${file}"; then
        rm -f "${tmp}"
        return 1
    fi

}

# Prints a 32-character password with at least one uppercase letter, one lowercase
# letter, one digit and one symbol, from the character set the packages accept.
function common_passwordGenerate() {

    local password=""

    until common_passwordValidate "${password}" 2>/dev/null; do
        password=$(LC_ALL=C tr -dc 'A-Za-z0-9.,_+:@%^=~-' < /dev/urandom 2>/dev/null | head -c 32)
    done
    printf '%s\n' "${password}"

}

# Checks the password rule of the Wazuh packages: 12 to 64 characters from
# A-Z a-z 0-9 . , _ + : @ % ^ = ~ - with at least one of each class. The reason
# goes to stderr and never includes the password.
function common_passwordValidate() {

    local password="${1}"

    if [[ "${password}" =~ [^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-] ]]; then
        echo "password must only contain characters from A-Z a-z 0-9 . , _ + : @ % ^ = ~ -" >&2
        return 1
    fi
    if [ "${#password}" -lt 12 ] || [ "${#password}" -gt 64 ]; then
        echo "password must contain between 12 and 64 characters" >&2
        return 1
    fi
    if [[ ! "${password}" =~ [abcdefghijklmnopqrstuvwxyz] ]]; then
        echo "password must contain at least one lowercase letter" >&2
        return 1
    fi
    if [[ ! "${password}" =~ [ABCDEFGHIJKLMNOPQRSTUVWXYZ] ]]; then
        echo "password must contain at least one uppercase letter" >&2
        return 1
    fi
    if [[ ! "${password}" =~ [0123456789] ]]; then
        echo "password must contain at least one digit" >&2
        return 1
    fi
    if [[ ! "${password}" =~ [.,_+:@%^=~-] ]]; then
        echo "password must contain at least one symbol from . , _ + : @ % ^ = ~ -" >&2
        return 1
    fi

}

# Prints the directory of the deployment root CA: WAZUH_CA_DIR, or wazuh-ca next
# to the tool.
function common_caGetDir() {

    local dir="${WAZUH_CA_DIR:-${base_path}/wazuh-ca}"

    if [[ "${dir}" != /* ]]; then
        echo "WAZUH_CA_DIR must be an absolute path." >&2
        return 1
    fi
    printf '%s\n' "${dir}"

}

# Checks the root CA in a directory: a valid, current, self-signed CA certificate
# and, if present, its matching private key.
function common_caValidate() {

    local dir="${1}"
    local cert="${dir}/root-ca.pem" key="${dir}/root-ca.key"

    if [ -L "${dir}" ] || [ ! -d "${dir}" ]; then
        echo "${dir} is not a directory." >&2
        return 1
    fi
    if [ ! -f "${cert}" ]; then
        echo "There is no root-ca.pem in ${dir}." >&2
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -checkend 0 > /dev/null 2>&1; then
        echo "${cert} is not a valid or current certificate." >&2
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -text 2>/dev/null | grep -q 'CA:TRUE'; then
        echo "${cert} is not a CA certificate." >&2
        return 1
    fi
    if ! openssl verify -CAfile "${cert}" "${cert}" > /dev/null 2>&1; then
        echo "${cert} is not a self-signed CA." >&2
        return 1
    fi
    if [ ! -e "${key}" ]; then
        return 0
    fi
    if [ "$(openssl x509 -in "${cert}" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "${key}" -pubout 2>/dev/null)" ]; then
        echo "root-ca.key does not match root-ca.pem in ${dir}." >&2
        return 1
    fi

}

# Creates the root CA in a directory (root only, 0700) when it has none. An
# existing CA is validated and never replaced.
function common_caEnsure() {

    local dir="${1}" tmp

    if [ -e "${dir}/root-ca.pem" ] || [ -e "${dir}/root-ca.key" ]; then
        if [ ! -e "${dir}/root-ca.pem" ]; then
            echo "root-ca.key exists without root-ca.pem in ${dir}." >&2
            return 1
        fi
        common_caValidate "${dir}"
        return $?
    fi

    if ! (umask 077 && mkdir -p "${dir}") || [ -L "${dir}" ]; then
        echo "Could not create ${dir}." >&2
        return 1
    fi
    chown root:root "${dir}" && chmod 700 "${dir}" || return 1

    tmp=$(mktemp -d "${dir}/.root-ca.XXXXXX") || return 1
    printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = v3_ca' 'prompt = no' \
        '[dn]' 'OU = Wazuh' 'O = Wazuh' 'L = California' \
        '[v3_ca]' 'basicConstraints = critical, CA:TRUE' 'keyUsage = critical, keyCertSign, cRLSign' \
        'subjectKeyIdentifier = hash' 'authorityKeyIdentifier = keyid:always' > "${tmp}/openssl.cnf"
    if ! (umask 077 && openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 3650 -batch \
        -config "${tmp}/openssl.cnf" -keyout "${tmp}/root-ca.key" -out "${tmp}/root-ca.pem" > /dev/null 2>&1); then
        rm -rf "${tmp}"
        echo "OpenSSL could not create the root CA." >&2
        return 1
    fi
    chmod 400 "${tmp}/root-ca.key" && chmod 644 "${tmp}/root-ca.pem" \
        && mv "${tmp}/root-ca.key" "${dir}/root-ca.key" && mv "${tmp}/root-ca.pem" "${dir}/root-ca.pem"
    local e_code=$?
    rm -rf "${tmp}"
    return "${e_code}"

}
