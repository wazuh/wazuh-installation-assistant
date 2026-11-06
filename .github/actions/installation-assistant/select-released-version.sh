#!/bin/bash
# Select the Wazuh version that the installation assistant tests of a pull request install.
#
# The version of the branch under development is only published when its release candidate is
# built, and the installer built from the code has no stage, so it cannot use the Filebeat
# template of an rc tag. A version is installable by these tests when it meets both conditions:
#   1. The tag v<version> (no suffix) exists in wazuh/wazuh.
#   2. wazuh-indexer, wazuh-manager and wazuh-dashboard are in the apt index of the repository.
# If the version of the branch meets them nothing changes. If not, the highest version of the same
# line that meets them is written to WAZUH_VERSION_OVERRIDE (GITHUB_ENV).
#
# Usage: select-released-version.sh <pre-release|staging> <path to installVariables.sh>

set -eo pipefail

repository="${1}"
variables_file="${2}"
env_file="${GITHUB_ENV:-/dev/null}"
packages=(wazuh-indexer wazuh-manager wazuh-dashboard)

if [ -z "${repository}" ] || [ ! -f "${variables_file}" ]; then
    echo "::error::Usage: $(basename "$0") <pre-release|staging> <path to installVariables.sh>"
    exit 1
fi

major=$(grep -oP '(?<=readonly wazuh_major=").*(?=")' "${variables_file}" || true)
branch_version=$(grep -oP '(?<=readonly wazuh_version=").*(?=")' "${variables_file}" || true)
if [ -z "${major}" ] || [ -z "${branch_version}" ]; then
    echo "::error::Could not read wazuh_major and wazuh_version from ${variables_file}."
    exit 1
fi

# Versions of the line with a tag without suffix (v4.14.9 yes, v4.14.10-rc2 no)
tag_versions=$(git ls-remote --tags --refs https://github.com/wazuh/wazuh "refs/tags/v${major}.*" \
    | sed 's|.*refs/tags/v||' | grep -E "^${major//./\\.}\.[0-9]+$" | sort -u || true)

# Versions of the line (without the package revision) with the three packages in the apt index
index_url="https://packages-dev.wazuh.com/${repository}/apt/dists/unstable/main/binary-amd64/Packages.gz"
index=$(curl -fsS --retry 5 --retry-delay 5 --max-time 300 "${index_url}" | gunzip)
package_versions=""
first=1
for package in "${packages[@]}"; do
    versions=$(echo "${index}" | awk -v p="${package}" '$1=="Package:"{cur=$2} $1=="Version:" && cur==p {print $2}' \
        | sed 's/-[^-]*$//' | grep -E "^${major//./\\.}\.[0-9]+$" | sort -u || true)
    if [ -n "${first}" ]; then
        package_versions="${versions}"
        first=""
    else
        package_versions=$(comm -12 <(echo "${package_versions}") <(echo "${versions}"))
    fi
done

installable=$(comm -12 <(echo "${tag_versions}" | sort) <(echo "${package_versions}" | sort) | sort -V)

if echo "${installable}" | grep -qx "${branch_version}"; then
    echo "::notice::Version ${branch_version} has its tag and packages in ${repository}. Nothing to change."
    exit 0
fi

selected=$(echo "${installable}" | tail -n 1)
if [ -z "${selected}" ]; then
    echo "::error::No ${major}.x version has a tag in wazuh/wazuh and ${packages[*]} in ${repository}."
    exit 1
fi

echo "::notice::Version ${branch_version} is not installable from ${repository} (tag v${branch_version} in wazuh/wazuh or its packages are missing). The tests will install ${selected}."
echo "WAZUH_VERSION_OVERRIDE=${selected}" >> "${env_file}"
echo "WAZUH_VERSION_OVERRIDE=${selected}"
