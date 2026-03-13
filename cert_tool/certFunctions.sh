# Certificate tool - Library functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


function cert_cleanFiles() {
    
    common_logger -d "Cleaning certificate files."
    eval "rm -f ${cert_tmp_path}/*.csr ${debug}"
    eval "rm -f ${cert_tmp_path}/*.srl ${debug}"
    eval "rm -f ${cert_tmp_path}/*.conf ${debug}"
    eval "rm -f ${cert_tmp_path}/admin-key-temp.pem ${debug}"

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
        # Validate that files exist
        if [[ -e ${rootca} ]]; then
            eval "cp ${rootca} ${cert_tmp_path}/root-ca.pem ${debug}"
        else
            common_logger -e "The file ${rootca} does not exists"
            cert_cleanFiles
            exit 1
        fi
        if [[ -e ${rootcakey} ]]; then
            eval "cp ${rootcakey} ${cert_tmp_path}/root-ca.key ${debug}"
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
function cert_executeAndValidate() {

    command_output=$(eval "$@" 2>&1)
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
    common_logger -d "Generating Admin private key."
    cert_executeAndValidate "openssl genrsa -out ${cert_tmp_path}/admin-key-temp.pem 2048"
    common_logger -d "Converting Admin private key to PKCS8 format."
    cert_executeAndValidate "openssl pkcs8 -inform PEM -outform PEM -in ${cert_tmp_path}/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${cert_tmp_path}/admin-key.pem"
    common_logger -d "Generating Admin CSR."
    cert_executeAndValidate "openssl req -new -key ${cert_tmp_path}/admin-key.pem -out ${cert_tmp_path}/admin.csr -batch -subj '/C=US/L=California/O=Wazuh/OU=Wazuh/CN=admin'"
    common_logger -d "Creating Admin certificate."
    cert_executeAndValidate "openssl x509 -days 3650 -req -in ${cert_tmp_path}/admin.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -sha256 -out ${cert_tmp_path}/admin.pem"

}

function cert_generateCertificateconfiguration() {

    common_logger -d "Generating certificate configuration."
    cat > "${cert_tmp_path}/${1}.conf" <<- EOF
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


    conf="$(awk '{sub("CN = cname", "CN = '"${1}"'")}1' "${cert_tmp_path}/${1}.conf")"
    echo "${conf}" > "${cert_tmp_path}/${1}.conf"

    if [ "${#@}" -gt 1 ]; then
        sed -i '/IP.1/d' "${cert_tmp_path}/${1}.conf"
        local ip_counter=0
        local dns_counter=0
        for (( i=2; i<=${#@}; i++ )); do
            if cert_isIP "${!i}"; then
                ip_counter=$((ip_counter+1))
                printf '%s\n' "        IP.${ip_counter} = ${!i}" >> "${cert_tmp_path}/${1}.conf"
            elif cert_isDNS "${!i}"; then
                dns_counter=$((dns_counter+1))
                printf '%s\n' "        DNS.${dns_counter} = ${!i}" >> "${cert_tmp_path}/${1}.conf"
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
            eval "idx_ip=( \${indexer_node_ip_${j}[@]} )"
            eval "idx_dns=( \${indexer_node_dns_${j}[@]} )"
            declare -a idx_san=()
            if [ -n "${idx_ip}" ]; then
                idx_san+=("${idx_ip}")
            fi
            if [ "${#idx_dns[@]}" -gt 0 ]; then
                idx_san+=("${idx_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${indexer_node_name}" "${idx_san[@]}"
            common_logger -d "Creating the Wazuh indexer tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${indexer_node_name}-key.pem -out ${cert_tmp_path}/${indexer_node_name}.csr -config ${cert_tmp_path}/${indexer_node_name}.conf"
            common_logger -d "Creating the Wazuh indexer certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${indexer_node_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${indexer_node_name}.pem -extfile ${cert_tmp_path}/${indexer_node_name}.conf -extensions v3_req -days 3650"
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
            eval "manager_ip=( \${manager_node_ip_${j}[@]} )"
            eval "mgr_dns=( \${manager_node_dns_${j}[@]} )"
            declare -a manager_san=()
            if [ -n "${manager_ip}" ]; then
                manager_san+=("${manager_ip}")
            fi
            if [ "${#mgr_dns[@]}" -gt 0 ]; then
                manager_san+=("${mgr_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${manager_name}" "${manager_san[@]}"
            common_logger -d "Creating the Wazuh manager tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${manager_name}-key.pem -out ${cert_tmp_path}/${manager_name}.csr  -config ${cert_tmp_path}/${manager_name}.conf"
            common_logger -d "Creating the Wazuh manager certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${manager_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${manager_name}.pem -extfile ${cert_tmp_path}/${manager_name}.conf -extensions v3_req -days 3650"
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
            eval "dash_ip=( \${dashboard_node_ip_${j}[@]} )"
            eval "dash_dns=( \${dashboard_node_dns_${j}[@]} )"
            declare -a dash_san=()
            if [ -n "${dash_ip}" ]; then
                dash_san+=("${dash_ip}")
            fi
            if [ "${#dash_dns[@]}" -gt 0 ]; then
                dash_san+=("${dash_dns[@]}")
            fi
            cert_generateCertificateconfiguration "${dashboard_node_name}" "${dash_san[@]}"
            common_logger -d "Creating the Wazuh dashboard tmp key pair."
            cert_executeAndValidate "openssl req -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/${dashboard_node_name}-key.pem -out ${cert_tmp_path}/${dashboard_node_name}.csr -config ${cert_tmp_path}/${dashboard_node_name}.conf"
            common_logger -d "Creating the Wazuh dashboard certificates."
            cert_executeAndValidate "openssl x509 -req -in ${cert_tmp_path}/${dashboard_node_name}.csr -CA ${cert_tmp_path}/root-ca.pem -CAkey ${cert_tmp_path}/root-ca.key -CAcreateserial -out ${cert_tmp_path}/${dashboard_node_name}.pem -extfile ${cert_tmp_path}/${dashboard_node_name}.conf -extensions v3_req -days 3650"
        done
    else
        return 1
    fi

}

function cert_generateRootCAcertificate() {

    common_logger "Generating the root certificate."
    cert_executeAndValidate "openssl req -x509 -new -nodes -newkey rsa:2048 -keyout ${cert_tmp_path}/root-ca.key -out ${cert_tmp_path}/root-ca.pem -batch -subj '/OU=Wazuh/O=Wazuh/L=California/' -days 3650"

}

function cert_normalizeYamlFormat() {
    
    # Normalize YAML format to ensure list items are properly indented
    # Handles various YAML indentation styles and normalizes them to standard format:
    # - List items at same level as parent key -> indent by 2 spaces
    # - List items with excessive indentation -> normalize to standard indent
    # - Properties within list items -> ensure proper relative indentation
    
    awk '
    BEGIN {
        last_was_key = 0
        last_key_indent = 0
        in_list = 0
        list_base_indent = 0
        expected_list_indent = 0
    }
    {
        # Store current line
        line = $0
        
        # Skip empty lines and comments
        if (match(line, /^[ \t]*$/) || match(line, /^[ \t]*#/)) {
            print line
            next
        }
        
        # Get indentation level (number of leading spaces)
        match(line, /^[ \t]*/)
        indent = RLENGTH
        
        # Check if line ends with colon (is a key)
        if (match(line, /:[ \t]*$/)) {
            # Store this key and its indentation
            last_key_line = line
            last_key_indent = indent
            last_was_key = 1
            in_list = 0
            print line
            next
        }
        
        # Check if this is a list item (starts with -)
        if (match(line, /^[ \t]*-[ \t]/)) {
            list_indent = indent
            
            # If previous line was a key
            if (last_was_key == 1) {
                # Calculate expected indentation (parent indent + 2)
                expected_list_indent = last_key_indent + 2
                
                # Normalize indentation regardless of current indent
                # (handles both under-indented and over-indented cases)
                if (list_indent != expected_list_indent) {
                    sub(/^[ \t]*/, sprintf("%*s", expected_list_indent, ""), line)
                    indent = expected_list_indent
                }
                list_base_indent = indent
                in_list = 1
            } else if (in_list == 1) {
                # If we are already in a list, normalize subsequent items to same level
                if (list_indent != expected_list_indent) {
                    sub(/^[ \t]*/, sprintf("%*s", expected_list_indent, ""), line)
                    indent = expected_list_indent
                }
                list_base_indent = indent
            } else {
                list_base_indent = indent
                expected_list_indent = indent
                in_list = 1
            }
            
            last_was_key = 0
            print line
            next
        }
        
        # If we are in a list and this line is not a new list item
        # Make sure it is properly indented relative to the list item
        if (in_list == 1) {
            if (indent > 0) {
                if (!match(line, /^[ \t]*-[ \t]/)) {
                    # This line should have exactly 2 more spaces than the list marker
                    expected_indent = list_base_indent + 2
                    if (indent != expected_indent) {
                        sub(/^[ \t]*/, sprintf("%*s", expected_indent, ""), line)
                    }
                }
            }
        }
        
        # If line indent is less than or equal to key indent, we are out of the list
        if (indent > 0) {
            if (indent <= last_key_indent) {
                in_list = 0
            }
        }
        
        last_was_key = 0
        print line
    }
    '
}

function cert_parseYaml() {

    local config_file_path=$1
    local prefix=$2
    local separator=${3:-_}
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
    
    local ip=$1
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

    local ip=$1
    [[ ${ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]

}

function cert_isIPv6() {

    local ip=$1
    [[ ${ip} =~ ^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|:([0-9A-Fa-f]{1,4}:){1,7}|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|::)$ ]]

}

function cert_isIP() {

    local ip=$1
    cert_isIPv4 "${ip}" || cert_isIPv6 "${ip}"

}

function cert_isDNS() {

    local dns=$1
    if ! cert_isIP "${dns}" && [[ ${dns} =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1

}

function cert_validateComponentSanValues() {

    local component_name=$1
    local node_names_var=$2
    local node_ip_prefix=$3
    local node_dns_prefix=$4
    local i
    local j

    eval "component_node_names=( \${${node_names_var}[@]} )"

    for i in "${!component_node_names[@]}"; do
        j=$((i+1))
        eval "component_ip=( \${${node_ip_prefix}_${j}[@]} )"
        eval "component_dns=( \${${node_dns_prefix}_${j}[@]} )"

        if [ -z "${component_ip}" ] && [ "${#component_dns[@]}" -eq 0 ]; then
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

    local component_name=$1
    local node_names_var=$2
    local node_ips_var=$3
    local node_dns_prefix=$4
    local i
    local j

    eval "component_node_names=( \${${node_names_var}[@]} )"
    eval "component_node_ips=( \${${node_ips_var}[@]} )"
    declare -a component_node_dns=()

    for i in "${!component_node_names[@]}"; do
        j=$((i+1))
        eval "node_dns=( \${${node_dns_prefix}_${j}[@]} )"
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
        eval "$(cert_convertCRLFtoLF "${config_file}")"

        eval "indexer_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+=" | cut -d = -f 2 ) )"
        eval "manager_node_names=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+manager[_]+[0-9]+=" | cut -d = -f 2 ) )"
        eval "dashboard_node_names=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+[0-9]+=" | cut -d = -f 2) )"
        eval "indexer_node_ips=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
        eval "manager_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+manager[_]+[0-9]+[_]+ip=" | cut -d = -f 2) )"
        eval "dashboard_node_ips=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+dashboard[_]+[0-9]+[_]+ip=" | cut -d = -f 2 ) )"
        eval "manager_node_types=( $(cert_parseYaml "${config_file}"  | grep -E "nodes[_]+manager[_]+[0-9]+[_]+node_type=" | cut -d = -f 2 ) )"

        # Parse DNS entries for each indexer node
        for i in "${!indexer_node_names[@]}"; do
            j=$((i+1))
            eval "indexer_node_ip_${j}=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+ip=" | cut -d = -f 2) )"
            eval "indexer_node_dns_${j}=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+indexer[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2) )"
        done

        # Parse DNS entries for each dashboard node
        for i in "${!dashboard_node_names[@]}"; do
            j=$((i+1))
            eval "dashboard_node_ip_${j}=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+ip=" | cut -d = -f 2) )"
            eval "dashboard_node_dns_${j}=( $(cert_parseYaml "${config_file}" | grep -E "nodes[_]+dashboard[_]+${j}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2) )"
        done

        for i in $(seq 1 "${#manager_node_names[@]}"); do
            eval "manager_node_ip_$i=( $( cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+ip=" | cut -d = -f 2 | sed -r 's/\s+//g') )"
            eval "manager_node_dns_$i=( $( cert_parseYaml "${config_file}" | grep -E "nodes[_]+manager[_]+${i}[_]+dns([_]+[0-9]+)?=" | cut -d = -f 2) )"
        done

        cert_validateComponentSanValues "Indexer" "indexer_node_names" "indexer_node_ip" "indexer_node_dns"
        cert_validateComponentSanValues "Manager" "manager_node_names" "manager_node_ip" "manager_node_dns"
        cert_validateComponentSanValues "Dashboard" "dashboard_node_names" "dashboard_node_ip" "dashboard_node_dns"

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
    eval "chmod -R 744 ${cert_tmp_path} ${debug}"
}

function cert_convertCRLFtoLF() {
    if [[ ! -d "/tmp/wazuh-install-files" ]]; then
        eval "mkdir /tmp/wazuh-install-files ${debug}"
    fi
    eval "chmod -R 755 /tmp/wazuh-install-files ${debug}"
    eval "tr -d '\015' < $1 > /tmp/wazuh-install-files/new_config.yml"
    eval "mv /tmp/wazuh-install-files/new_config.yml $1 ${debug}"
}
