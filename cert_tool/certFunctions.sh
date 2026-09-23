# Certificate tool - Library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Security validation functions

function cert_validatePath() {
    local path="$1"
    local path_type="${2:-file}"

    # Check if path is empty
    if [[ -z "${path}" ]]; then
        common_logger -e "Path cannot be empty."
        return 1
    fi

    # Prevent path traversal attacks - reject paths with suspicious patterns
    if [[ "${path}" =~ \.\./|\.\.\\ ]]; then
        common_logger -e "Path traversal detected in: ${path}"
        return 1
    fi

    # Reject paths with newlines, carriage returns, or tabs (specific problematic characters)
    if [[ "${path}" =~ $'\n'|$'\r'|$'\t' ]]; then
        common_logger -e "Invalid characters detected in path: ${path}"
        return 1
    fi

    # For absolute paths validation
    if [[ "${path}" == /* ]]; then
        # Resolve to canonical path to prevent symlink attacks
        if command -v realpath >/dev/null 2>&1; then
            local canonical_path
            canonical_path=$(realpath -m "${path}" 2>/dev/null) || return 1

            # Ensure the canonical path doesn't escape expected boundaries
            if [[ ! "${canonical_path}" =~ ^/[a-zA-Z0-9/_.\-]+$ ]]; then
                common_logger -e "Invalid canonical path: ${canonical_path}"
                return 1
            fi
        fi
    fi

    return 0
}

function cert_sanitizeFilename() {
    local filename="$1"

    # Remove any path components
    filename="${filename##*/}"

    # Only allow alphanumeric, dash, underscore, and dot
    filename=$(echo "${filename}" | sed 's/[^a-zA-Z0-9._-]/_/g')

    # Prevent hidden files
    filename="${filename#.}"

    # Limit length to 255 characters
    if [[ ${#filename} -gt 255 ]]; then
        filename="${filename:0:255}"
    fi

    echo "${filename}"
}

function cert_sanitizeNodeName() {
    local component_name="$1"
    local node_names_var="$2"

    # Use nameref for safe dynamic array access
    declare -n component_node_names="${node_names_var}"

    for i in "${!component_node_names[@]}"; do

        # Only allow alphanumeric, dash, underscore, and dot (typical for hostnames)
        if [[ ! "${component_node_names[$i]}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
            common_logger -e "Invalid ${component_name} node name: ${component_node_names[$i]}. Only alphanumeric characters, dots, dashes, and underscores are allowed."
            exit 1
        fi

        # Prevent names starting with dash or dot
        if [[ "${component_node_names[$i]}" =~ ^[-\.] ]]; then
            common_logger -e "${component_name} node name cannot start with dash or dot: ${component_node_names[$i]}"
            exit 1
        fi

        # Limit length
        if [[ ${#component_node_names[$i]} -gt 253 ]]; then
            common_logger -e "${component_name} node name too long: ${component_node_names[$i]}"
            exit 1
        fi
    done

    return 0
}


function cert_cleanFiles() {

    # Validate cert_tmp_path before use
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        exit 1
    fi

    # Remove files
    rm -f "${cert_tmp_path}"/*.csr
    rm -f "${cert_tmp_path}"/*.srl
    rm -f "${cert_tmp_path}"/*.conf
    rm -f "${cert_tmp_path}"/admin-key-temp.pem
    # Single-use CA workspaces of the server leaves, in case one was left behind.
    for workspace in "${cert_tmp_path}"/*-ca; do
        if [ -d "${workspace}" ]; then
            rm -rf "${workspace}"
        fi
    done

}

function cert_checkOpenSSL() {

    common_logger -d "Checking if OpenSSL is installed."

    if [ -z "$(command -v openssl)" ]; then
        common_logger -e "OpenSSL not installed."
        exit 1
    fi

}

function cert_checkRootCA() {

    common_logger -d "Checking if the root CA exists."

    if  [[ -n ${rootca} || -n ${rootcakey} ]]; then
        # Verify variables match keys
        if [[ ${rootca} == *".key" ]]; then
            ca_temp=${rootca}
            rootca=${rootcakey}
            rootcakey=${ca_temp}
        fi

        # Validate paths
        if ! cert_validatePath "${rootca}" "file"; then
            common_logger -e "Invalid root CA certificate path: ${rootca}"
            cert_cleanFiles
            exit 1
        fi

        if ! cert_validatePath "${rootcakey}" "file"; then
            common_logger -e "Invalid root CA key path: ${rootcakey}"
            cert_cleanFiles
            exit 1
        fi

        if ! cert_validatePath "${cert_tmp_path}" "directory"; then
            common_logger -e "Invalid certificate temporary path."
            cert_cleanFiles
            exit 1
        fi

        # Validate that files exist
        if [[ -e ${rootca} ]]; then
            cp "${rootca}" "${cert_tmp_path}/root-ca.pem"
        else
            common_logger -e "The file ${rootca} does not exists"
            cert_cleanFiles
            exit 1
        fi
        if [[ -e ${rootcakey} ]]; then
            cp "${rootcakey}" "${cert_tmp_path}/root-ca.key"
        else
            common_logger -e "The file ${rootcakey} does not exists"
            cert_cleanFiles
            exit 1
        fi
    else
        cert_generateRootCAcertificate
    fi

}

# Executes and analyze the output of the command. It prints the output
# in case of an error
# Note: This function now executes commands directly
function cert_executeAndValidate() {

    command_output=$("$@" 2>&1)
    e_code="${PIPESTATUS[0]}"

    if [ "${e_code}" -ne 0 ]; then
        common_logger -e "Error generating the certificates."
        common_logger -d "Error executing command: $@"
        common_logger -d "Error output: ${command_output}"
        cert_cleanFiles
        exit 1
    fi

}

function cert_generateAdmincertificate() {

    common_logger "Generating Admin certificates."

    # Validate cert_tmp_path
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        exit 1
    fi

    common_logger -d "Generating Admin private key."
    cert_executeAndValidate openssl genrsa -out "${cert_tmp_path}/admin-key-temp.pem" 2048
    common_logger -d "Converting Admin private key to PKCS8 format."
    cert_executeAndValidate openssl pkcs8 -inform PEM -outform PEM -in "${cert_tmp_path}/admin-key-temp.pem" -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "${cert_tmp_path}/admin-key.pem"
    common_logger -d "Generating Admin CSR."
    cert_executeAndValidate openssl req -new -key "${cert_tmp_path}/admin-key.pem" -out "${cert_tmp_path}/admin.csr" -batch -subj '/C=US/L=California/O=Wazuh/OU=Wazuh/CN=admin'

    # The admin certificate carries no SAN: it is never dialled, it authenticates
    # against the indexer security API. Hence an extension file of its own rather
    # than cert_generateCertificateconfiguration, which builds a SAN.
    cat > "${cert_tmp_path}/admin.conf" <<- EOF
        [ v3_admin ]
        authorityKeyIdentifier=keyid,issuer
        basicConstraints = critical, CA:FALSE
        keyUsage = critical, digitalSignature, keyEncipherment
        extendedKeyUsage = clientAuth
	EOF

    common_logger -d "Creating Admin certificate."
    cert_executeAndValidate openssl x509 -days 3650 -req -in "${cert_tmp_path}/admin.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -sha256 -out "${cert_tmp_path}/admin.pem" -extfile "${cert_tmp_path}/admin.conf" -extensions v3_admin

}

# OpenSSL configuration for a component certificate. Takes the node name, the
# extendedKeyUsage the component needs, and the SAN entries.
#
# The extendedKeyUsage is not the same for every component, and getting it wrong
# breaks the link it is meant to secure:
#
#   indexer    serverAuth, clientAuth  it answers on the HTTP layer and is both ends
#                                      of the transport layer inside an indexer cluster
#   dashboard  serverAuth              it answers browsers
#   manager    clientAuth              deployed as indexer-connector.pem, it only dials
#                                      the indexer; the agent listener is a separate leaf
#   admin      clientAuth              it authenticates against the indexer security API
function cert_generateCertificateconfiguration() {

    common_logger -d "Generating certificate configuration."

    local node_name="$1"
    local extended_key_usage="$2"

    # Validate cert_tmp_path
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        exit 1
    fi

    if [ -z "${extended_key_usage}" ]; then
        common_logger -e "No extendedKeyUsage specified for ${node_name}."
        exit 1
    fi

    cat > "${cert_tmp_path}/${node_name}.conf" <<- EOF
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = req_distinguished_name
        x509_extensions = v3_req

        [req_distinguished_name]
        C = US
        L = California
        O = Wazuh
        OU = Wazuh
        CN = cname

        [ v3_req ]
        authorityKeyIdentifier=keyid,issuer
        basicConstraints = critical, CA:FALSE
        keyUsage = critical, digitalSignature, keyEncipherment
        extendedKeyUsage = ekusage
        subjectAltName = @alt_names

        [alt_names]
        IP.1 = cip
	EOF


    conf="$(awk '{sub("CN = cname", "CN = '"${node_name}"'"); sub("extendedKeyUsage = ekusage", "extendedKeyUsage = '"${extended_key_usage}"'")}1' "${cert_tmp_path}/${node_name}.conf")"
    echo "${conf}" > "${cert_tmp_path}/${node_name}.conf"

    if [ "${#@}" -gt 2 ]; then
        sed -i '/IP.1/d' "${cert_tmp_path}/${node_name}.conf"
        local ip_counter=0
        local dns_counter=0
        for (( i=3; i<=${#@}; i++ )); do
            if cert_isIP "${!i}"; then
                ip_counter=$((ip_counter+1))
                printf '%s\n' "        IP.${ip_counter} = ${!i}" >> "${cert_tmp_path}/${node_name}.conf"
            elif cert_isDNS "${!i}"; then
                dns_counter=$((dns_counter+1))
                printf '%s\n' "        DNS.${dns_counter} = ${!i}" >> "${cert_tmp_path}/${node_name}.conf"
            else
                common_logger -e "Invalid IP or DNS ${!i}"
                exit 1
            fi
        done
    else
        common_logger -e "No IP or DNS specified"
        exit 1
    fi

}

function cert_generateIndexercertificates() {

    if [ ${#indexer_node_names[@]} -gt 0 ]; then
        common_logger "Generating Wazuh indexer certificates."

        for i in "${!indexer_node_names[@]}"; do
            indexer_node_name=${indexer_node_names[$i]}

            common_logger -d "Creating the certificates for ${indexer_node_name} indexer node."
            j=$((i+1))
            # Use nameref for safe dynamic array access
            declare -n idx_ip="indexer_node_ip_${j}"
            declare -n idx_dns="indexer_node_dns_${j}"
            declare -a idx_san=()
            if [ "${#idx_ip[@]}" -gt 0 ]; then
                idx_san+=("${idx_ip[@]}")
            fi
            if [ "${#idx_dns[@]}" -gt 0 ]; then
                idx_san+=("${idx_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${indexer_node_name}" "serverAuth, clientAuth" "${idx_san[@]}"
            common_logger -d "Creating the Wazuh indexer tmp key pair."
            cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${indexer_node_name}-key.pem" -out "${cert_tmp_path}/${indexer_node_name}.csr" -config "${cert_tmp_path}/${indexer_node_name}.conf"
            common_logger -d "Creating the Wazuh indexer certificates."
            cert_executeAndValidate openssl x509 -req -in "${cert_tmp_path}/${indexer_node_name}.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -out "${cert_tmp_path}/${indexer_node_name}.pem" -extfile "${cert_tmp_path}/${indexer_node_name}.conf" -extensions v3_req -days 3650
        done
    else
        return 1
    fi

}

function cert_generateManagercertificates() {

    if [ ${#manager_node_names[@]} -gt 0 ]; then
        common_logger "Generating Wazuh manager certificates."

        for i in "${!manager_node_names[@]}"; do
            manager_name="${manager_node_names[i]}"

            common_logger -d "Generating the certificates for ${manager_name} manager node."
            j=$((i+1))
            # Use nameref for safe dynamic array access
            declare -n manager_ip="manager_node_ip_${j}"
            declare -n mgr_dns="manager_node_dns_${j}"
            declare -a manager_san=()
            if [ "${#manager_ip[@]}" -gt 0 ]; then
                manager_san+=("${manager_ip[@]}")
            fi
            if [ "${#mgr_dns[@]}" -gt 0 ]; then
                manager_san+=("${mgr_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${manager_name}" "clientAuth" "${manager_san[@]}"
            common_logger -d "Creating the Wazuh manager tmp key pair."
            cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${manager_name}-key.pem" -out "${cert_tmp_path}/${manager_name}.csr" -config "${cert_tmp_path}/${manager_name}.conf"
            common_logger -d "Creating the Wazuh manager certificates."
            cert_executeAndValidate openssl x509 -req -in "${cert_tmp_path}/${manager_name}.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -out "${cert_tmp_path}/${manager_name}.pem" -extfile "${cert_tmp_path}/${manager_name}.conf" -extensions v3_req -days 3650
            # Agent-facing listener leaf for this manager node: the node SAN plus the
            # addresses given with --agent-san, which every node shares. Only this leaf
            # gets them; the manager certificate above keeps the node SAN alone.
            cert_generateRemotedcertificate "${manager_name}" "${manager_san[@]}" "${agent_san[@]}"
        done
    else
        return 1
    fi

}

# OpenSSL configuration for a TLS server leaf, shared by the agent listener of a
# manager node and by the certificate of a TLS-terminating load balancer:
# basicConstraints critical CA:FALSE, keyUsage critical digitalSignature +
# keyEncipherment, extendedKeyUsage serverAuth, and a SAN with the ip/dns entries
# given plus the name itself when it is a DNS label (agents are usually pointed at
# that name). CN = <name>. Takes the configuration file to write and the name.
#
# The SAN is de-duplicated: an address reaches this function from the node fields and
# from --agent-san alike, and openssl would otherwise emit the same name twice.
function cert_generateServerLeafconfiguration() {

    common_logger -d "Generating server leaf certificate configuration."

    local conf_file="$1"
    local node_name="$2"
    local ip_counter=0
    local dns_counter=0
    local san
    local -A listed=()

    # Validate cert_tmp_path
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        exit 1
    fi

    if [ "${#@}" -le 2 ]; then
        common_logger -e "No IP or DNS specified"
        exit 1
    fi

    {
        printf '%s\n' "[ req ]"
        printf '%s\n' "prompt = no"
        printf '%s\n' "default_bits = 2048"
        printf '%s\n' "default_md = sha256"
        printf '%s\n' "distinguished_name = req_distinguished_name"
        printf '%s\n' "x509_extensions = v3_remoted"
        printf '\n'
        printf '%s\n' "[req_distinguished_name]"
        printf '%s\n' "C = US"
        printf '%s\n' "L = California"
        printf '%s\n' "O = Wazuh"
        printf '%s\n' "OU = Wazuh"
        printf '%s\n' "CN = ${node_name}"
        printf '\n'
        printf '%s\n' "[ v3_remoted ]"
        printf '%s\n' "authorityKeyIdentifier = keyid,issuer"
        printf '%s\n' "subjectKeyIdentifier = hash"
        printf '%s\n' "basicConstraints = critical,CA:FALSE"
        printf '%s\n' "keyUsage = critical,digitalSignature,keyEncipherment"
        printf '%s\n' "extendedKeyUsage = serverAuth"
        printf '%s\n' "subjectAltName = @alt_names"
        printf '\n'
        printf '%s\n' "[alt_names]"
    } > "${conf_file}"

    for (( i=3; i<=${#@}; i++ )); do
        san="${!i}"
        if cert_isIP "${san}"; then
            if [ -n "${listed[${san}]+listed}" ]; then
                continue
            fi
            listed["${san}"]=1
            ip_counter=$((ip_counter+1))
            printf '%s\n' "IP.${ip_counter} = ${san}" >> "${conf_file}"
        elif cert_isDNS "${san}"; then
            if [ -n "${listed[${san,,}]+listed}" ]; then
                continue
            fi
            listed["${san,,}"]=1
            dns_counter=$((dns_counter+1))
            printf '%s\n' "DNS.${dns_counter} = ${san}" >> "${conf_file}"
        else
            common_logger -e "Invalid IP or DNS ${san}"
            exit 1
        fi
    done

    if cert_isDNS "${node_name}" && [ -z "${listed[${node_name,,}]+listed}" ]; then
        dns_counter=$((dns_counter+1))
        printf '%s\n' "DNS.${dns_counter} = ${node_name}" >> "${conf_file}"
    fi

}

# Configuration of the agent listener leaf of a manager node. Takes the node name
# followed by the SAN entries.
function cert_generateRemotedcertificateconfiguration() {

    local node_name="$1"
    shift

    cert_generateServerLeafconfiguration "${cert_tmp_path}/${node_name}-remoted.conf" "${node_name}" "$@"

}

# Minimal single-use CA workspace for "openssl ca", created under the temporary
# directory and removed by the caller. Needed because "openssl x509 -req" cannot
# backdate notBefore before OpenSSL 3.5, newer than the oldest platform supported.
# The order of the policy section is what lays out the subject, so commonName goes
# last: that is where the other leaves carry it, and openssl ca would otherwise emit
# CN first.
function cert_generateRemotedCAworkspace() {

    local ca_dir="$1"

    rm -rf "${ca_dir}"
    if ! mkdir -p "${ca_dir}/newcerts"; then
        common_logger -e "Could not create the temporary CA directory ${ca_dir}."
        cert_cleanFiles
        exit 1
    fi
    chmod 700 "${ca_dir}"
    : > "${ca_dir}/index.txt"
    printf '%s\n' "unique_subject = no" > "${ca_dir}/index.txt.attr"
    # A random 16-byte serial: each node gets its own workspace, so an incrementing
    # counter would hand every manager node the same serial from the same CA.
    openssl rand -hex 16 > "${ca_dir}/serial"

    {
        printf '%s\n' "[ ca ]"
        printf '%s\n' "default_ca = CA_remoted"
        printf '\n'
        printf '%s\n' "[ CA_remoted ]"
        printf '%s\n' "dir = ${ca_dir}"
        printf '%s\n' "database = ${ca_dir}/index.txt"
        printf '%s\n' "serial = ${ca_dir}/serial"
        printf '%s\n' "new_certs_dir = ${ca_dir}/newcerts"
        printf '%s\n' "certificate = ${cert_tmp_path}/root-ca.pem"
        printf '%s\n' "private_key = ${cert_tmp_path}/root-ca.key"
        printf '%s\n' "default_md = sha256"
        printf '%s\n' "preserve = yes"
        printf '%s\n' "email_in_dn = no"
        printf '%s\n' "policy = policy_remoted"
        printf '\n'
        printf '%s\n' "[ policy_remoted ]"
        printf '%s\n' "countryName = optional"
        printf '%s\n' "stateOrProvinceName = optional"
        printf '%s\n' "localityName = optional"
        printf '%s\n' "organizationName = optional"
        printf '%s\n' "organizationalUnitName = optional"
        printf '%s\n' "commonName = supplied"
    } > "${ca_dir}/ca.conf"

}

# Issues <prefix>.pem / <prefix>-key.pem (RSA 2048, SHA-256, valid for 3650 days,
# signed by root-ca) and appends root-ca.pem to the leaf, so the file holds the chain
# (leaf followed by the CA) that the server hands its peers in the TLS handshake.
# Takes the file prefix, the certificate name and the SAN entries.
#
# notBefore is backdated one day so an agent whose clock lags does not reject a
# freshly issued certificate. That is why this leaf goes through "openssl ca" instead
# of "openssl x509 -req" like the others: -startdate has been available since OpenSSL
# 1.0.2, whereas "x509 -req -not_before" only exists from OpenSSL 3.5 on.
function cert_generateServerLeaf() {

    local prefix="$1"
    local node_name="$2"
    local ca_dir="${cert_tmp_path}/${prefix}-ca"
    local start_date
    local end_date

    shift 2

    common_logger -d "Creating the server leaf certificate ${prefix}."

    cert_generateServerLeafconfiguration "${cert_tmp_path}/${prefix}.conf" "${node_name}" "$@"
    common_logger -d "Creating the ${prefix} tmp key pair."
    cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${prefix}-key.pem" -out "${cert_tmp_path}/${prefix}.csr" -config "${cert_tmp_path}/${prefix}.conf"

    # Two-digit years: OpenSSL reads them as 20YY below 50, and the notAfter of a
    # 3650-day certificate is well before 2049.
    start_date="$(date -u -d '-1 day' '+%y%m%d%H%M%SZ' 2>/dev/null)"
    end_date="$(date -u -d '+3650 days' '+%y%m%d%H%M%SZ' 2>/dev/null)"
    if [[ -z "${start_date}" || -z "${end_date}" ]]; then
        common_logger -e "Could not compute the validity dates of the ${prefix} certificate."
        cert_cleanFiles
        exit 1
    fi

    common_logger -d "Creating the ${prefix} certificate, valid from ${start_date} to ${end_date}."
    cert_generateRemotedCAworkspace "${ca_dir}"
    cert_executeAndValidate openssl ca -batch -notext -md sha256 -config "${ca_dir}/ca.conf" -in "${cert_tmp_path}/${prefix}.csr" -out "${cert_tmp_path}/${prefix}.pem" -extfile "${cert_tmp_path}/${prefix}.conf" -extensions v3_remoted -startdate "${start_date}" -enddate "${end_date}"
    rm -rf "${ca_dir}"

    if ! cat "${cert_tmp_path}/root-ca.pem" >> "${cert_tmp_path}/${prefix}.pem"; then
        common_logger -e "Could not append root-ca.pem to ${prefix}.pem."
        cert_cleanFiles
        exit 1
    fi

}

# Issues the agent listener pair of a manager node: <name>-remoted.pem and
# <name>-remoted-key.pem. Takes the node name followed by the SAN entries.
function cert_generateRemotedcertificate() {

    local node_name="$1"
    shift

    common_logger -d "Creating the remoted (agent listener) certificate for ${node_name}."

    cert_generateServerLeaf "${node_name}-remoted" "${node_name}" "$@"

}

# Every listener leaf must chain to the CA written next to it; a failure here means
# remoted would serve a bundle agents cannot validate. Takes the directory holding
# the issued certificates as first argument.
function cert_verifyRemotedcertificates() {

    local certs_dir="${1}"
    local manager_name

    if [ ${#manager_node_names[@]} -eq 0 ]; then
        return 0
    fi

    if ! cert_validatePath "${certs_dir}" "directory"; then
        common_logger -e "Invalid certificates directory."
        exit 1
    fi

    for manager_name in "${manager_node_names[@]}"; do
        if ! openssl verify -CAfile "${certs_dir}/root-ca.pem" "${certs_dir}/${manager_name}-remoted.pem" > /dev/null 2>&1; then
            common_logger -e "The certificate ${certs_dir}/${manager_name}-remoted.pem does not verify against ${certs_dir}/root-ca.pem."
            exit 1
        fi
        common_logger -d "Verified ${manager_name}-remoted.pem against root-ca.pem."
    done

}

function cert_generateDashboardcertificates() {
    if [ ${#dashboard_node_names[@]} -gt 0 ]; then
        common_logger "Generating Wazuh dashboard certificates."

        for i in "${!dashboard_node_names[@]}"; do
            dashboard_node_name="${dashboard_node_names[i]}"

            j=$((i+1))
            # Use nameref for safe dynamic array access
            declare -n dash_ip="dashboard_node_ip_${j}"
            declare -n dash_dns="dashboard_node_dns_${j}"
            declare -a dash_san=()
            if [ "${#dash_ip[@]}" -gt 0 ]; then
                dash_san+=("${dash_ip[@]}")
            fi
            if [ "${#dash_dns[@]}" -gt 0 ]; then
                dash_san+=("${dash_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${dashboard_node_name}" "serverAuth" "${dash_san[@]}"
            common_logger -d "Creating the Wazuh dashboard tmp key pair."
            cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${dashboard_node_name}-key.pem" -out "${cert_tmp_path}/${dashboard_node_name}.csr" -config "${cert_tmp_path}/${dashboard_node_name}.conf"
            common_logger -d "Creating the Wazuh dashboard certificates."
            cert_executeAndValidate openssl x509 -req -in "${cert_tmp_path}/${dashboard_node_name}.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -out "${cert_tmp_path}/${dashboard_node_name}.pem" -extfile "${cert_tmp_path}/${dashboard_node_name}.conf" -extensions v3_req -days 3650
        done
    else
        return 1
    fi

}

# Issues the certificate a TLS-terminating proxy serves to agents, from the same
# root-ca.pem the agents pin, so an operator does not have to place a second anchor
# on every endpoint.
#
# This is only for a proxy that terminates TLS. With a layer-4 passthrough load
# balancer the agent's session ends at the manager, the manager's own listener leaf
# is what agents validate, and the answer is --agent-san with the balancer address
# instead of a certificate of its own.
function cert_generateLoadbalancercertificates() {

    if [ ${#lb_node_names[@]} -gt 0 ]; then
        common_logger "Generating load balancer certificates."

        for i in "${!lb_node_names[@]}"; do
            lb_node_name="${lb_node_names[i]}"

            common_logger -d "Creating the certificate for ${lb_node_name} load balancer."
            j=$((i+1))
            # Use nameref for safe dynamic array access
            declare -n lb_ip="lb_node_ip_${j}"
            declare -n lb_dns="lb_node_dns_${j}"
            declare -a lb_san=()
            if [ "${#lb_ip[@]}" -gt 0 ]; then
                lb_san+=("${lb_ip[@]}")
            fi
            if [ "${#lb_dns[@]}" -gt 0 ]; then
                lb_san+=("${lb_dns[@]}")
            fi
            cert_generateServerLeaf "${lb_node_name}" "${lb_node_name}" "${lb_san[@]}"
        done
    else
        return 1
    fi

}

# Same check as the listener leaves: a load balancer certificate that does not chain
# to the CA agents pin cannot terminate their connections. Takes the directory
# holding the issued certificates as first argument.
function cert_verifyLoadbalancercertificates() {

    local certs_dir="${1}"
    local lb_name

    if [ ${#lb_node_names[@]} -eq 0 ]; then
        return 0
    fi

    if ! cert_validatePath "${certs_dir}" "directory"; then
        common_logger -e "Invalid certificates directory."
        exit 1
    fi

    for lb_name in "${lb_node_names[@]}"; do
        if ! openssl verify -CAfile "${certs_dir}/root-ca.pem" "${certs_dir}/${lb_name}.pem" > /dev/null 2>&1; then
            common_logger -e "The certificate ${certs_dir}/${lb_name}.pem does not verify against ${certs_dir}/root-ca.pem."
            exit 1
        fi
        common_logger -d "Verified ${lb_name}.pem against root-ca.pem."
    done

}

function cert_generateRootCAcertificate() {

    common_logger "Generating the root certificate."

    # Validate cert_tmp_path
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        exit 1
    fi

    cert_executeAndValidate openssl req -x509 -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/root-ca.key" -out "${cert_tmp_path}/root-ca.pem" -batch -subj '/OU=Wazuh/O=Wazuh/L=California/' -days 3650

}

function cert_normalizeYamlFormat() {

    # Normalize the certs-tool YAML schema regardless of incoming indentation.
    # It supports optional node fields (ip, dns, node_type). Both ip and dns may be
    # given as a scalar value or as a list; node_type is always a scalar.
    #
    # list_key holds the field whose list is currently being read, so that the items
    # under it are folded into that field instead of being taken for new nodes.
    awk '
    function ltrim(str) {
        sub(/^[ \t]+/, "", str)
        return str
    }
    function rtrim(str) {
        sub(/[ \t]+$/, "", str)
        return str
    }
    function trim(str) {
        return rtrim(ltrim(str))
    }
    BEGIN {
        in_nodes = 0
        nodes_indent = 0
        current_section = ""
        in_node = 0
        list_key = ""
    }
    {
        line = $0
        match(line, /^[ \t]*/)
        indent = RLENGTH

        if (match(line, /^[ \t]*$/)) {
            print ""
            list_key = ""
            next
        }

        if (match(line, /^[ \t]*#/)) {
            print line
            next
        }

        stripped = trim(line)

        if (stripped == "nodes:") {
            print "nodes:"
            in_nodes = 1
            nodes_indent = indent
            current_section = ""
            in_node = 0
            list_key = ""
            next
        }

        if (in_nodes == 1 && current_section != "" && match(stripped, /^-[ \t]/)) {
            list_payload = trim(substr(stripped, 2))

            if (match(list_payload, /^name:[ \t]*/)) {
                name_value = trim(substr(list_payload, 6))
                print "    - name: " name_value
                in_node = 1
                list_key = ""
                next
            }

            if (in_node == 1 && list_key != "") {
                print "        - " list_payload
                next
            }

            print "    - " list_payload
            in_node = 1
            list_key = ""
            next
        }

        if (in_nodes == 1 && in_node == 1 && list_key != "" && match(stripped, /^-[ \t]/)) {
            item_value = trim(substr(stripped, 2))
            print "        - " item_value
            next
        }

        if (in_nodes == 1 && match(stripped, /^[a-zA-Z0-9_ ]+:[ \t]*/)) {
            key_name = trim(substr(stripped, 1, index(stripped, ":") - 1))
            key_value = trim(substr(stripped, index(stripped, ":") + 1))

            if (key_name == "node type") {
                key_name = "node_type"
            }

            if (in_node == 1 && key_name == "name") {
                print "    - name: " key_value
                list_key = ""
                next
            }

            if (in_node == 1 && key_name == "node_type") {
                print "      node_type: " key_value
                list_key = ""
                next
            }

            if (in_node == 1 && (key_name == "ip" || key_name == "dns")) {
                if (key_value == "") {
                    print "      " key_name ":"
                    list_key = key_name
                } else {
                    print "      " key_name ": " key_value
                    list_key = ""
                }
                next
            }

            if (key_value == "" && (in_node == 0 || indent <= nodes_indent + 2)) {
                print "  " key_name ":"
                current_section = key_name
                in_node = 0
                list_key = ""
                next
            }

            if (in_node == 1) {
                if (key_value == "") {
                    print "      " key_name ":"
                } else {
                    print "      " key_name ": " key_value
                }
                list_key = ""
                next
            }
        }

        if (!match(stripped, /^-[ \t]/)) {
            list_key = ""
        }

        print line
    }
    '
}

function cert_parseYaml() {

    local config_file_path="$1"
    local prefix="$2"
    local separator="${3:-_}"
    local indexfix

    # Detect awk flavor
    if awk --version 2>&1 | grep -q "GNU Awk" ; then
    # GNU Awk detected
    indexfix=-1
    elif awk -Wv 2>&1 | grep -q "mawk" ; then
    # mawk detected
    indexfix=0
    fi

    local s='[[:space:]]*' sm='[ \t]*' w='[a-zA-Z0-9_]*' fs=${fs:-$(echo @|tr @ '\034')} i=${i:-  }

    # Normalize YAML format first to handle both valid YAML indentation styles
    cat $config_file_path 2>/dev/null | cert_normalizeYamlFormat | \
    awk -F$fs "{multi=0;
        if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
        if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
        while(multi>0){
            str=\$0; gsub(/^$sm/,\"\", str);
            indent=index(\$0,str);
            indentstr=substr(\$0, 0, indent+$indexfix) \"$i\";
            obuf=\$0;
            getline;
            while(index(\$0,indentstr)){
                obuf=obuf substr(\$0, length(indentstr)+1);
                if (multi==1){obuf=obuf \"\\\\n\";}
                if (multi==2){
                    if(match(\$0,/^$sm$/))
                        obuf=obuf \"\\\\n\";
                        else obuf=obuf \" \";
                }
                getline;
            }
            sub(/$sm$/,\"\",obuf);
            print obuf;
            multi=0;
            if(match(\$0,/$sm\|$sm$/)){multi=1; sub(/$sm\|$sm$/,\"\");}
            if(match(\$0,/$sm>$sm$/)){multi=2; sub(/$sm>$sm$/,\"\");}
        }
    print}" | \
    sed  -e "s|^\($s\)?|\1-|" \
        -ne "s|^$s#.*||;s|$s#[^\"']*$||;s|^\([^\"'#]*\)#.*|\1|;t1;t;:1;s|^$s\$||;t2;p;:2;d" | \
    sed -ne "s|,$s\]$s\$|]|" \
        -e ":1;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1\2: \3[\4]\n\1$i- \5|;t1" \
        -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s\[$s\(.*\)$s\]|\1\2: \3\n\1$i- \4|;" \
        -e ":2;s|^\($s\)-$s\[$s\(.*\)$s,$s\(.*\)$s\]|\1- [\2]\n\1$i- \3|;t2" \
        -e "s|^\($s\)-$s\[$s\(.*\)$s\]|\1-\n\1$i- \2|;p" | \
    sed -ne "s|,$s}$s\$|}|" \
        -e ":1;s|^\($s\)-$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1- {\2}\n\1$i\3: \4|;t1" \
        -e "s|^\($s\)-$s{$s\(.*\)$s}|\1-\n\1$i\2|;" \
        -e ":2;s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s,$s\($w\)$s:$s\(.*\)$s}|\1\2: \3 {\4}\n\1$i\5: \6|;t2" \
        -e "s|^\($s\)\($w\)$s:$s\(&$w\)\?$s{$s\(.*\)$s}|\1\2: \3\n\1$i\4|;p" | \
    sed  -e "s|^\($s\)\($w\)$s:$s\(&$w\)\(.*\)|\1\2:\4\n\3|" \
        -e "s|^\($s\)-$s\(&$w\)\(.*\)|\1- \3\n\2|" | \
    sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\(---\)\($s\)||" \
        -e "s|^\($s\)\(\.\.\.\)\($s\)||" \
        -e "s|^\($s\)-$s[\"']\(.*\)[\"']$s\$|\1$fs$fs\2|p;t" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p;t" \
        -e "s|^\($s\)-$s\(.*\)$s\$|\1$fs$fs\2|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\?\(.*\)$s\$|\1$fs\2$fs\3|" \
        -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)[\"']$s\$|\1$fs$fs$fs\2|" \
        -e "s|^\($s\)[\"']\?\([^&][^$fs]\+\)$s\$|\1$fs$fs$fs\2|" \
        -e "s|$s\$||p" | \
    awk -F$fs "{
        gsub(/\t/,\"        \",\$1);
        gsub(\"name: \", \"\");
        if(NF>3){if(value!=\"\"){value = value \" \";}value = value  \$4;}
        else {
        if(match(\$1,/^&/)){anchor[substr(\$1,2)]=full_vn;getline};
        indent = length(\$1)/length(\"$i\");
        vname[indent] = \$2;
        value= \$3;
        for (i in vname) {if (i > indent) {delete vname[i]; idx[i]=0}}
        if(length(\$2)== 0){  vname[indent]= ++idx[indent] };
        vn=\"\"; for (i=0; i<indent; i++) { vn=(vn)(vname[i])(\"$separator\")}
        vn=\"$prefix\" vn;
        full_vn=vn vname[indent];
        if(vn==\"$prefix\")vn=\"$prefix$separator\";
        if(vn==\"_\")vn=\"__\";
        }
        assignment[full_vn]=value;
        if(!match(assignment[vn], full_vn))assignment[vn]=assignment[vn] \" \" full_vn;
        if(match(value,/^\*/)){
            ref=anchor[substr(value,2)];
            if(length(ref)==0){
            printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
            } else {
            for(val in assignment){
                if((length(ref)>0)&&index(val, ref)==1){
                    tmpval=assignment[val];
                    sub(ref,full_vn,val);
                if(match(val,\"$separator\$\")){
                    gsub(ref,full_vn,tmpval);
                } else if (length(tmpval) > 0) {
                    printf(\"%s=\\\"%s\\\"\n\", val, tmpval);
                }
                assignment[val]=tmpval;
                }
            }
        }
    } else if (length(value) > 0) {
        printf(\"%s=\\\"%s\\\"\n\", full_vn, value);
    }
    }END{
        for(val in assignment){
            if(match(val,\"$separator\$\"))
                printf(\"%s=\\\"%s\\\"\n\", val, assignment[val]);
        }
    }"

}

function cert_checkPrivateIp() {

    local ip="$1"
    common_logger -d "Checking if ${ip} is private."

    # Check private IPv4 ranges
    if [[ $ip =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^(127\.) ]]; then
        return 0
    fi

    # Check private IPv6 ranges (fc00::/7 prefix), link-local (fe80::/10), and loopback (::1)
    if [[ $ip =~ ^(fc|fd) ]] || [[ $ip =~ ^fe[89abAB] ]] || [[ $ip == "::1" ]]; then
        return 0
    fi

    return 1

}

function cert_isIPv4() {

    local ip="$1"
    local octet

    [[ ${ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    for octet in ${ip//./ }; do
        # A leading zero is read as octal by some resolvers and as decimal by others,
        # so 010.0.0.1 is not one address but two. OpenSSL rejects both forms below.
        if [[ ${#octet} -gt 1 && ${octet:0:1} == "0" ]]; then
            return 1
        fi
        if [ "${octet}" -gt 255 ]; then
            return 1
        fi
    done

    return 0

}

function cert_isIPv6() {

    local ip="$1"
    [[ ${ip} =~ ^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|:([0-9A-Fa-f]{1,4}:){1,7}|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|::)$ ]]

}

function cert_isIP() {

    local ip="$1"
    cert_isIPv4 "${ip}" || cert_isIPv6 "${ip}"

}

function cert_isDNS() {

    local dns="$1"
    if ! cert_isIP "${dns}" && [[ ${dns} =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1

}

# Prints, one per line, the addresses this host answers at: its global IP addresses
# and its host name, loopback left out. On an all-in-one install config.yml names every
# component 127.0.0.1, which is right for the indexer and dashboard links the manager
# opens locally, and useless in the certificate agents check. These are the addresses
# that make that certificate usable.
function cert_hostAddresses() {

    local address
    local name
    local -a addresses=()

    if command -v hostname > /dev/null 2>&1; then
        mapfile -t addresses < <(hostname -I 2>/dev/null | tr ' ' '\n')
    fi

    if [ "${#addresses[@]}" -eq 0 ] && command -v ip > /dev/null 2>&1; then
        mapfile -t addresses < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d / -f 1)
    fi

    for address in "${addresses[@]}"; do
        if [ -z "${address}" ] || ! cert_isIP "${address}"; then
            continue
        fi
        # Link-local addresses are no more dialable from another host than loopback is.
        if [[ "${address}" =~ ^127\. ]] || [ "${address}" == "::1" ] || [[ "${address}" =~ ^169\.254\. ]] || [[ "${address}" =~ ^fe[89abAB] ]]; then
            continue
        fi
        printf '%s\n' "${address}"
    done

    for name in "$(hostname -f 2>/dev/null)" "$(hostname 2>/dev/null)"; do
        # localhost.localdomain is what a host with no name of its own reports, and it
        # names this host to every other one.
        if [ -n "${name}" ] && [[ ! "${name,,}" =~ ^localhost(\..*)?$ ]] && cert_isDNS "${name}"; then
            printf '%s\n' "${name}"
        fi
    done

}

# True when the addresses given name nothing an agent on another host could dial:
# loopback only, and no name of its own. The node name is appended to every listener
# SAN, but it is a label from config.yml rather than an address, so it is not counted
# here: on an all-in-one install it resolves nowhere.
function cert_listenerSanIsUnreachable() {

    local san

    for san in "$@"; do
        if cert_isIP "${san}"; then
            if [[ ! "${san}" =~ ^127\. ]] && [ "${san}" != "::1" ]; then
                return 1
            fi
        elif cert_isDNS "${san}"; then
            if [ "${san,,}" != "localhost" ]; then
                return 1
            fi
        fi
    done

    return 0

}

# A listener certificate naming only loopback cannot enroll a single agent, and the
# failure surfaces much later, on every endpoint at once. Takes the severity: an
# install is refused, because it is about to produce a manager no agent can reach,
# while wazuh-certs-tool is warned, since an operator may be issuing certificates for
# a host whose addresses this one cannot see.
function cert_checkListenerReachability() {

    local severity="${1:-error}"
    local i
    local j
    local -a listener_san=()

    for i in "${!manager_node_names[@]}"; do
        j=$((i+1))
        declare -n manager_ip="manager_node_ip_${j}"
        declare -n mgr_dns="manager_node_dns_${j}"
        listener_san=()
        if [ "${#manager_ip[@]}" -gt 0 ]; then
            listener_san+=("${manager_ip[@]}")
        fi
        if [ "${#mgr_dns[@]}" -gt 0 ]; then
            listener_san+=("${mgr_dns[@]}")
        fi
        if [ "${#agent_san[@]}" -gt 0 ]; then
            listener_san+=("${agent_san[@]}")
        fi

        if cert_listenerSanIsUnreachable "${listener_san[@]}"; then
            if [ "${severity}" == "warning" ]; then
                common_logger -w "The agent listener certificate of the Wazuh manager node ${manager_node_names[$i]} only names loopback addresses, so no agent on another host can verify it. Set the address agents dial in the ip or dns field of the node in ${config_file}, or pass it with -as|--agent-san."
            else
                common_logger -e "The agent listener certificate of the Wazuh manager node ${manager_node_names[$i]} would only name loopback addresses, and no agent could verify it. Set the address agents dial in the ip or dns field of the node in ${config_file}, or pass it with -as|--agent-san."
                exit 1
            fi
        fi
    done

}

# Validates the addresses given with -as|--agent-san. They are checked here instead of
# by cert_validateComponentSanValues because they are not node fields: they name an
# address agents dial that no single node owns, which may legitimately be a public one.
function cert_validateAgentSan() {

    local san

    if [ "${#agent_san[@]}" -eq 0 ]; then
        return 0
    fi

    if [[ -z "${all}" && -z "${cmanager}" && -z "${AIO}" && -z "${configurations}" ]]; then
        common_logger -e "The option -as|--agent-san must be used along with one of these options: -A, -wm in wazuh-certs-tool.sh, or -a, -g in wazuh-install.sh"
        exit 1
    fi

    for san in "${agent_san[@]}"; do
        if ! cert_isIP "${san}" && ! cert_isDNS "${san}"; then
            common_logger -e "Invalid IP or DNS in -as|--agent-san: ${san}."
            exit 1
        fi
    done

}

function cert_validateComponentSanValues() {

    local component_name="$1"
    local node_names_var="$2"
    local node_ip_prefix="$3"
    local node_dns_prefix="$4"
    local i
    local j

    # Use nameref for safe dynamic array access
    declare -n component_node_names="${node_names_var}"

    for i in "${!component_node_names[@]}"; do
        j=$((i+1))
        # Use namerefs for dynamic array names
        declare -n component_ip="${node_ip_prefix}_${j}"
        declare -n component_dns="${node_dns_prefix}_${j}"

        if [ "${#component_ip[@]}" -eq 0 ] && [ "${#component_dns[@]}" -eq 0 ]; then
            common_logger -e "${component_name} node ${component_node_names[$i]} requires at least one field: ip or dns."
            exit 1
        fi

        for ip in "${component_ip[@]}"; do
            if ! cert_isIP "${ip}"; then
                common_logger -e "Invalid IP in field ip for ${component_name,,} node ${component_node_names[$i]}: ${ip}."
                exit 1
            fi
            # A public address is legitimate: a manager agents reach over the internet,
            # a node behind a cloud load balancer. It is worth naming, not refusing.
            if ! cert_checkPrivateIp "$ip"; then
                common_logger -w "The IP ${ip} of ${component_name,,} node ${component_node_names[$i]} is public. Make sure it is meant to be reachable from outside your network."
            fi
        done

        for dns in "${component_dns[@]}"; do
            if ! cert_isDNS "${dns}"; then
                common_logger -e "Invalid DNS in field dns for ${component_name,,} node ${component_node_names[$i]}: ${dns}."
                exit 1
            fi
        done
    done

}

function cert_validateComponentDuplicatedValues() {

    local component_name="$1"
    local node_names_var="$2"
    local node_ips_var="$3"
    local node_dns_prefix="$4"
    local i
    local j

    # Use namerefs for safe dynamic array access
    declare -n component_node_names="${node_names_var}"
    declare -n component_node_ips="${node_ips_var}"
    declare -a component_node_dns=()

    for i in "${!component_node_names[@]}"; do
        j=$((i+1))
        # Use nameref for dynamic DNS array
        declare -n node_dns="${node_dns_prefix}_${j}"
        if [ "${#node_dns[@]}" -gt 0 ]; then
            component_node_dns+=("${node_dns[@]}")
        fi
    done

    unique_names=($(echo "${component_node_names[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    if [ "${#unique_names[@]}" -ne "${#component_node_names[@]}" ]; then
        common_logger -e "Duplicated ${component_name,,} node names."
        exit 1
    fi

    unique_ips=($(echo "${component_node_ips[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    if [ "${#unique_ips[@]}" -ne "${#component_node_ips[@]}" ]; then
        common_logger -e "Duplicated ${component_name,,} node ips."
        exit 1
    fi

    unique_dns=($(echo "${component_node_dns[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    if [ "${#unique_dns[@]}" -ne "${#component_node_dns[@]}" ]; then
        common_logger -e "Duplicated ${component_name,,} node dns."
        exit 1
    fi

}

function cert_validateManagerNodeTypes() {

    for i in "${manager_node_types[@]}"; do
        if ! echo "$i" | grep -ioq master && ! echo "$i" | grep -ioq worker; then
            common_logger -e "Incorrect node_type $i must be master or worker"
            exit 1
        fi
    done

    if [ "${#manager_node_names[@]}" -le 1 ]; then
        if [ "${#manager_node_types[@]}" -ne 0 ]; then
            common_logger -e "The tag node_type can only be used with more than one Wazuh manager."
            exit 1
        fi
    elif [ "${#manager_node_names[@]}" -gt "${#manager_node_types[@]}" ]; then
        common_logger -e "The tag node_type needs to be specified for all Wazuh manager nodes."
        exit 1
    elif [ "${#manager_node_names[@]}" -lt "${#manager_node_types[@]}" ]; then
        common_logger -e "Found extra node_type tags."
        exit 1
    elif [ "$(grep -io master <<< "${manager_node_types[*]}" | wc -l)" -ne 1 ]; then
        common_logger -e "Wazuh cluster needs a single master node."
        exit 1
    elif [ "$(grep -io worker <<< "${manager_node_types[*]}" | wc -l)" -ne $(( ${#manager_node_types[@]} - 1 )) ]; then
        common_logger -e "Incorrect number of workers."
        exit 1
    fi

}

# Fills a flat array with the first ip of each node, in node order. install_functions
# reads these arrays by node index — the master's address, the Wazuh API address the
# dashboard is pointed at, the indexer's network.host — so an entry has to stay at the
# position of the node it belongs to even when that node lists several addresses.
# Takes the array to fill, the array of node names and the prefix of the per-node
# address arrays.
function cert_firstAddressPerNode() {

    local target_var="$1"
    local node_names_var="$2"
    local node_ip_prefix="$3"
    local i
    local j

    declare -n target_array="${target_var}"
    declare -n component_node_names="${node_names_var}"

    target_array=()

    for i in "${!component_node_names[@]}"; do
        j=$((i+1))
        declare -n component_ip="${node_ip_prefix}_${j}"
        if [ "${#component_ip[@]}" -gt 0 ]; then
            target_array+=("${component_ip[0]}")
        fi
    done

}

function cert_readConfig() {

    common_logger -d "Reading configuration file."

    if [ -f "${config_file}" ]; then
        if [ ! -s "${config_file}" ]; then
            common_logger -e "File ${config_file} is empty"
            exit 1
        fi
        # Convert CRLF to LF without eval
        cert_convertCRLFtoLF "${config_file}"

        # Use mapfile for safe array assignment (prevents command injection)
        mapfile -t indexer_node_names < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t manager_node_names < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+[0-9]+=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t dashboard_node_names < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t lb_node_names < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+load_balancer[_]+[0-9]+=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t indexer_node_all_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t manager_node_all_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+[0-9]+[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t dashboard_node_all_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t manager_node_types < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+[0-9]+[_]+node_type=" | cut -d = -f 2 | sed 's/^"//;s/"$//')

        # Parse DNS entries for each indexer node
        for i in "${!indexer_node_names[@]}"; do
            j=$((i+1))
            # Create dynamic arrays using declare and mapfile
            mapfile -t "indexer_node_ip_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
            mapfile -t "indexer_node_dns_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        # Parse DNS entries for each dashboard node
        for i in "${!dashboard_node_names[@]}"; do
            j=$((i+1))
            mapfile -t "dashboard_node_ip_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
            mapfile -t "dashboard_node_dns_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        for i in $(seq 1 "${#manager_node_names[@]}"); do
            mapfile -t "manager_node_ip_$i" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//' | sed -r 's/\s+//g')
            mapfile -t "manager_node_dns_$i" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        # Parse the addresses of each load balancer entry
        for i in "${!lb_node_names[@]}"; do
            j=$((i+1))
            mapfile -t "lb_node_ip_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+load_balancer[_]+${j}[_]+ip([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
            mapfile -t "lb_node_dns_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+load_balancer[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        # The installer addresses a node by its position in these arrays, so they hold
        # one entry per node. A node reachable at several addresses puts them all in
        # its certificate through the per-node arrays above; the first one is the
        # address the components are configured with.
        cert_firstAddressPerNode "indexer_node_ips" "indexer_node_names" "indexer_node_ip"
        cert_firstAddressPerNode "manager_node_ips" "manager_node_names" "manager_node_ip"
        cert_firstAddressPerNode "dashboard_node_ips" "dashboard_node_names" "dashboard_node_ip"

        cert_validateComponentSanValues "Indexer" "indexer_node_names" "indexer_node_ip" "indexer_node_dns"
        cert_validateComponentSanValues "Manager" "manager_node_names" "manager_node_ip" "manager_node_dns"
        cert_validateComponentSanValues "Dashboard" "dashboard_node_names" "dashboard_node_ip" "dashboard_node_dns"
        cert_validateComponentSanValues "Load balancer" "lb_node_names" "lb_node_ip" "lb_node_dns"

        cert_sanitizeNodeName "Indexer" "indexer_node_names"
        cert_sanitizeNodeName "Manager" "manager_node_names"
        cert_sanitizeNodeName "Dashboard" "dashboard_node_names"
        cert_sanitizeNodeName "Load balancer" "lb_node_names"

        cert_validateComponentDuplicatedValues "Indexer" "indexer_node_names" "indexer_node_all_ips" "indexer_node_dns"
        cert_validateComponentDuplicatedValues "Wazuh manager" "manager_node_names" "manager_node_all_ips" "manager_node_dns"
        cert_validateComponentDuplicatedValues "Dashboard" "dashboard_node_names" "dashboard_node_all_ips" "dashboard_node_dns"

        cert_validateManagerNodeTypes

    else
        common_logger -e "No configuration file found."
        exit 1
    fi

}

function cert_setpermisions() {
    # Validate cert_tmp_path before setting permissions
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
        return 1
    fi

    # Private keys (root CA and every node/admin/remoted key) must stay
    # owner-only: the umask this tool sets at startup already creates them
    # at 0600, this only re-asserts it. Public certificates can be 0644 -
    # they carry no secret. The directory itself must stay 700 so the mode
    # on the files inside cannot be reached even if a later 'chmod 755' on
    # a copy of this directory relaxes traversal.
    if [ -n "${debugEnabled}" ]; then
        chmod 700 "${cert_tmp_path}"
        find "${cert_tmp_path}" -maxdepth 1 -type f \( -name '*-key.pem' -o -name 'root-ca.key' \) -exec chmod 600 {} +
        find "${cert_tmp_path}" -maxdepth 1 -type f -name '*.pem' ! -name '*-key.pem' -exec chmod 644 {} +
    else
        chmod 700 "${cert_tmp_path}" > /dev/null 2>&1
        find "${cert_tmp_path}" -maxdepth 1 -type f \( -name '*-key.pem' -o -name 'root-ca.key' \) -exec chmod 600 {} + > /dev/null 2>&1
        find "${cert_tmp_path}" -maxdepth 1 -type f -name '*.pem' ! -name '*-key.pem' -exec chmod 644 {} + > /dev/null 2>&1
    fi
}

function cert_convertCRLFtoLF() {
    local config_file_path="$1"
    local temp_dir="/tmp/wazuh-install-files"

    # Validate input file path
    if ! cert_validatePath "${config_file_path}" "file"; then
        common_logger -e "Invalid config file path."
        return 1
    fi

    # Create temp directory if it doesn't exist
    if [[ ! -d "${temp_dir}" ]]; then
        if [ -n "${debugEnabled}" ]; then
            mkdir "${temp_dir}"
        else
            mkdir "${temp_dir}" > /dev/null 2>&1
        fi
    fi

    # Set permissions on temp directory
    if [ -n "${debugEnabled}" ]; then
        chmod -R 755 "${temp_dir}"
    else
        chmod -R 755 "${temp_dir}" > /dev/null 2>&1
    fi

    # Convert CRLF to LF
    tr -d '\015' < "${config_file_path}" > "${temp_dir}/new_config.yml"

    # Move converted file back
    if [ -n "${debugEnabled}" ]; then
        mv "${temp_dir}/new_config.yml" "${config_file_path}"
    else
        mv "${temp_dir}/new_config.yml" "${config_file_path}" > /dev/null 2>&1
    fi
}
