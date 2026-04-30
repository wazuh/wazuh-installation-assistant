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
    common_logger -d "Creating Admin certificate."
    cert_executeAndValidate openssl x509 -days 3650 -req -in "${cert_tmp_path}/admin.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -sha256 -out "${cert_tmp_path}/admin.pem"

}

function cert_generateCertificateconfiguration() {

    common_logger -d "Generating certificate configuration."

    local node_name="$1"

    # Validate cert_tmp_path
    if ! cert_validatePath "${cert_tmp_path}" "directory"; then
        common_logger -e "Invalid certificate temporary path."
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
        basicConstraints = CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        IP.1 = cip
	EOF


    conf="$(awk '{sub("CN = cname", "CN = '"${node_name}"'")}1' "${cert_tmp_path}/${node_name}.conf")"
    echo "${conf}" > "${cert_tmp_path}/${node_name}.conf"

    if [ "${#@}" -gt 1 ]; then
        sed -i '/IP.1/d' "${cert_tmp_path}/${node_name}.conf"
        local ip_counter=0
        local dns_counter=0
        for (( i=2; i<=${#@}; i++ )); do
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
            cert_generateCertificateconfiguration "${indexer_node_name}" "${idx_san[@]}"
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
            cert_generateCertificateconfiguration "${manager_name}" "${manager_san[@]}"
            common_logger -d "Creating the Wazuh manager tmp key pair."
            cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${manager_name}-key.pem" -out "${cert_tmp_path}/${manager_name}.csr" -config "${cert_tmp_path}/${manager_name}.conf"
            common_logger -d "Creating the Wazuh manager certificates."
            cert_executeAndValidate openssl x509 -req -in "${cert_tmp_path}/${manager_name}.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -out "${cert_tmp_path}/${manager_name}.pem" -extfile "${cert_tmp_path}/${manager_name}.conf" -extensions v3_req -days 3650
        done
    else
        return 1
    fi

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
            cert_generateCertificateconfiguration "${dashboard_node_name}" "${dash_san[@]}"
            common_logger -d "Creating the Wazuh dashboard tmp key pair."
            cert_executeAndValidate openssl req -new -nodes -newkey rsa:2048 -keyout "${cert_tmp_path}/${dashboard_node_name}-key.pem" -out "${cert_tmp_path}/${dashboard_node_name}.csr" -config "${cert_tmp_path}/${dashboard_node_name}.conf"
            common_logger -d "Creating the Wazuh dashboard certificates."
            cert_executeAndValidate openssl x509 -req -in "${cert_tmp_path}/${dashboard_node_name}.csr" -CA "${cert_tmp_path}/root-ca.pem" -CAkey "${cert_tmp_path}/root-ca.key" -CAcreateserial -out "${cert_tmp_path}/${dashboard_node_name}.pem" -extfile "${cert_tmp_path}/${dashboard_node_name}.conf" -extensions v3_req -days 3650
        done
    else
        return 1
    fi

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
    # It supports optional node fields (ip, dns, node_type), with dns defined as
    # either a scalar value or as a list.
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
        in_dns_list = 0
    }
    {
        line = $0
        match(line, /^[ \t]*/)
        indent = RLENGTH

        if (match(line, /^[ \t]*$/)) {
            print ""
            in_dns_list = 0
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
            in_dns_list = 0
            next
        }

        if (in_nodes == 1 && current_section != "" && match(stripped, /^-[ \t]/)) {
            list_payload = trim(substr(stripped, 2))

            if (match(list_payload, /^name:[ \t]*/)) {
                name_value = trim(substr(list_payload, 6))
                print "    - name: " name_value
                in_node = 1
                in_dns_list = 0
                next
            }

            if (in_node == 1 && in_dns_list == 1) {
                print "        - " list_payload
                next
            }

            print "    - " list_payload
            in_node = 1
            in_dns_list = 0
            next
        }

        if (in_nodes == 1 && in_node == 1 && in_dns_list == 1 && match(stripped, /^-[ \t]/)) {
            dns_value = trim(substr(stripped, 2))
            print "        - " dns_value
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
                in_dns_list = 0
                next
            }

            if (in_node == 1 && (key_name == "ip" || key_name == "node_type")) {
                print "      " key_name ": " key_value
                in_dns_list = 0
                next
            }

            if (in_node == 1 && key_name == "dns") {
                if (key_value == "") {
                    print "      dns:"
                    in_dns_list = 1
                } else {
                    print "      dns: " key_value
                    in_dns_list = 0
                }
                next
            }

            if (key_value == "" && (in_node == 0 || indent <= nodes_indent + 2)) {
                print "  " key_name ":"
                current_section = key_name
                in_node = 0
                in_dns_list = 0
                next
            }

            if (in_node == 1) {
                if (key_value == "") {
                    print "      " key_name ":"
                } else {
                    print "      " key_name ": " key_value
                }
                in_dns_list = 0
                next
            }
        }

        if (!match(stripped, /^-[ \t]/)) {
            in_dns_list = 0
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
    [[ ${ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]

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
            if ! cert_checkPrivateIp "$ip"; then
                common_logger -e "The IP ${ip} is public."
                exit 1
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
        mapfile -t indexer_node_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t manager_node_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+[0-9]+[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t dashboard_node_ips < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        mapfile -t manager_node_types < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+[0-9]+[_]+node_type=" | cut -d = -f 2 | sed 's/^"//;s/"$//')

        # Parse DNS entries for each indexer node
        for i in "${!indexer_node_names[@]}"; do
            j=$((i+1))
            # Create dynamic arrays using declare and mapfile
            mapfile -t "indexer_node_ip_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
            mapfile -t "indexer_node_dns_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        # Parse DNS entries for each dashboard node
        for i in "${!dashboard_node_names[@]}"; do
            j=$((i+1))
            mapfile -t "dashboard_node_ip_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
            mapfile -t "dashboard_node_dns_${j}" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        for i in $(seq 1 "${#manager_node_names[@]}"); do
            mapfile -t "manager_node_ip_$i" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+ip=" | cut -d = -f 2 | sed 's/^"//;s/"$//' | sed -r 's/\s+//g')
            mapfile -t "manager_node_dns_$i" < <(cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2 | sed 's/^"//;s/"$//')
        done

        cert_validateComponentSanValues "Indexer" "indexer_node_names" "indexer_node_ip" "indexer_node_dns"
        cert_validateComponentSanValues "Manager" "manager_node_names" "manager_node_ip" "manager_node_dns"
        cert_validateComponentSanValues "Dashboard" "dashboard_node_names" "dashboard_node_ip" "dashboard_node_dns"

        cert_sanitizeNodeName "Indexer" "indexer_node_names"
        cert_sanitizeNodeName "Manager" "manager_node_names"
        cert_sanitizeNodeName "Dashboard" "dashboard_node_names"

        cert_validateComponentDuplicatedValues "Indexer" "indexer_node_names" "indexer_node_ips" "indexer_node_dns"
        cert_validateComponentDuplicatedValues "Wazuh manager" "manager_node_names" "manager_node_ips" "manager_node_dns"
        cert_validateComponentDuplicatedValues "Dashboard" "dashboard_node_names" "dashboard_node_ips" "dashboard_node_dns"

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

    if [ -n "${debugEnabled}" ]; then
        chmod -R 744 "${cert_tmp_path}"
    else
        chmod -R 744 "${cert_tmp_path}" > /dev/null 2>&1
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
