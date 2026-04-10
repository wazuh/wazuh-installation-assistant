#!/bin/bash
# generate_offline_files.sh
#
# Replicates the offline preparation steps from check_integration_tools.yaml.
# Clones the repo, builds the installer, and produces all files needed for
# an offline installation test.
#
# Output (in WORKDIR):
#   wazuh-install.sh
#   config.yml
#   wazuh-install-files.tar   (via -g)
#   wazuh-offline.tar.gz      (via -dw)
#   artifact_urls.yaml        (via generate_presigned_dev_urls.py)
#
# Usage:
#   Edit the variables below, then run:
#     bash generate_offline_files.sh
#   Or override any variable via environment:
#     PR_HEAD_REF=my-branch AWS_S3_BUCKET_DEV=my-bucket bash generate_offline_files.sh

set -euo pipefail

# ===========================================================================
# CONFIGURATION — mirror of CI workflow globals
# Edit these before running, or export them as environment variables.
# ===========================================================================

# Branch of wazuh-installation-assistant to clone and build
PR_HEAD_REF="${PR_HEAD_REF:-enhancement/590-wazuh-installation-assistant-integration-tests}"

# Branch of wazuh-automation to clone
AUTOMATION_REFERENCE="${AUTOMATION_REFERENCE:-enhancement/590-wazuh-installation-assistant-integration-tests}"

# Wazuh installation assistant repo URL
WIA_REPO="${WIA_REPO:-https://github.com/wazuh/wazuh-installation-assistant}"

# wazuh-automation repo URL
AUTOMATION_REPO="${AUTOMATION_REPO:-https://github.com/wazuh/wazuh-automation}"

# GitHub token — needed only for private repos
GH_TOKEN="${GH_TOKEN:-}"

# AWS S3 bucket for presigned URLs (vars.AWS_S3_BUCKET_DEV in CI)
AWS_S3_BUCKET_DEV="${AWS_S3_BUCKET_DEV:-xdrsiem-packages-dev-internal}"

# AWS region (env.REGION in CI)
REGION="${REGION:-us-east-1}"

# Path to the presigned URL generator script relative to wazuh-automation root
# (env.GENERATE_PRESIGNED_URLS_SCRIPT_PATH in CI)
GENERATE_PRESIGNED_URLS_SCRIPT_PATH="tools/sign_urls/generate_presigned_dev_urls.py"

# Package type: deb | rpm  (auto-detected if empty)
PKG_TYPE="${PKG_TYPE:-}"

# Architecture: amd64 | arm64 | x86_64 | aarch64  (auto-detected if empty)
ARCH="${ARCH:-}"

# Output directory
WORKDIR="${WORKDIR:-/tmp/wazuh-offline-build}"

# ===========================================================================
# END OF CONFIGURATION
# ===========================================================================

# ---------------------------------------------------------------------------
# Validate required vars
# ---------------------------------------------------------------------------
if [ -z "$PR_HEAD_REF" ]; then
  echo "ERROR: PR_HEAD_REF is required. Set it in the script or export it." >&2
  exit 1
fi
if [ -z "$AWS_S3_BUCKET_DEV" ]; then
  echo "ERROR: AWS_S3_BUCKET_DEV is required. Set it in the script or export it." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Auto-detect pkg type and arch
# ---------------------------------------------------------------------------
if [ -z "$PKG_TYPE" ]; then
  command -v apt-get &>/dev/null && PKG_TYPE="deb" || PKG_TYPE="rpm"
fi

if [ -z "$ARCH" ]; then
  RAW_ARCH="$(uname -m)"
  if [ "$PKG_TYPE" = "deb" ]; then
    case "$RAW_ARCH" in
      aarch64|arm64) ARCH="arm64"   ;;
      *)             ARCH="amd64"   ;;
    esac
  else
    case "$RAW_ARCH" in
      aarch64|arm64) ARCH="aarch64" ;;
      *)             ARCH="x86_64"  ;;
    esac
  fi
fi

CLONE_DIR="${WORKDIR}/wazuh-installation-assistant"
AUTOMATION_DIR="${WORKDIR}/wazuh-automation"

mkdir -p "${WORKDIR}"

echo "=== Offline file generation ==="
echo "  WIA branch        : ${PR_HEAD_REF}"
echo "  Automation branch : ${AUTOMATION_REFERENCE}"
echo "  Package type      : ${PKG_TYPE}"
echo "  Architecture      : ${ARCH}"
echo "  Workdir           : ${WORKDIR}"
echo "  S3 bucket         : ${AWS_S3_BUCKET_DEV}"
echo ""

# Helper: inject token into HTTPS URL if GH_TOKEN is set
clone_url() {
  local url="$1"
  if [ -n "$GH_TOKEN" ]; then
    echo "${url/https:\/\//https://${GH_TOKEN}@}"
  else
    echo "$url"
  fi
}

# ---------------------------------------------------------------------------
# Step 1: Clone wazuh-installation-assistant
# ---------------------------------------------------------------------------
echo "[1/6] Cloning wazuh-installation-assistant @ ${PR_HEAD_REF}..."
rm -rf "${CLONE_DIR}"
git clone --depth 1 --branch "${PR_HEAD_REF}" "$(clone_url "${WIA_REPO}")" "${CLONE_DIR}"
echo "  -> ${CLONE_DIR}"

# ---------------------------------------------------------------------------
# Step 2: Build wazuh-install.sh
# ---------------------------------------------------------------------------
echo "[2/6] Building wazuh-install.sh..."
pushd "${CLONE_DIR}" > /dev/null
bash builder.sh -i
popd > /dev/null
cp "${CLONE_DIR}/wazuh-install.sh" "${WORKDIR}/wazuh-install.sh"
echo "  -> ${WORKDIR}/wazuh-install.sh"

# ---------------------------------------------------------------------------
# Step 3: Clone wazuh-automation + generate presigned artifact URLs
# Mirrors exactly what the CI does:
#   pip install pyyaml
#   python3 $GENERATE_PRESIGNED_URLS_SCRIPT_PATH \
#     --process test_assistant \
#     --wazuh-version <VERSION> \
#     --aws-s3-bucket-dev <BUCKET>
#   output -> /tmp/artifact_urls.yaml
# ---------------------------------------------------------------------------
echo "[3/6] Cloning wazuh-automation @ ${AUTOMATION_REFERENCE}..."
rm -rf "${AUTOMATION_DIR}"
git clone --depth 1 --branch "${AUTOMATION_REFERENCE}" "$(clone_url "${AUTOMATION_REPO}")" "${AUTOMATION_DIR}"
echo "  -> ${AUTOMATION_DIR}"

echo "  Generating presigned artifact URLs..."
WAZUH_VERSION="$(jq -r '.version' "${CLONE_DIR}/VERSION.json")"

# The presigned URL script requires Python >= 3.11 (uses StrEnum).
# The CI uses Python 3.12. Prefer python3.12 > python3.11 > python3, fail if too old.
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3 python; do
  if command -v "$candidate" &>/dev/null; then
    PY_VER="$("$candidate" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)"
    PY_MAJ="$("$candidate" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 0)"
    if [ "$PY_MAJ" -ge 3 ] && [ "$PY_VER" -ge 11 ]; then
      PYTHON_BIN="$candidate"
      break
    fi
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  echo "ERROR: Python >= 3.11 is required. Install it with:" >&2
  echo "  sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt-get install -y python3.12" >&2
  exit 1
fi
echo "  Using ${PYTHON_BIN} ($(${PYTHON_BIN} --version))"

# Bootstrap a clean venv to avoid system pip/distutils issues (python3.12 on Ubuntu).
VENV_DIR="${WORKDIR}/.venv"
if ! "${PYTHON_BIN}" -m venv "${VENV_DIR}" 2>/dev/null; then
  echo "  venv module missing — installing python3.12-venv..."
  sudo apt-get install -y "python${PY_MAJ}.${PY_VER}-venv" --quiet
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi
PIP_BIN="${VENV_DIR}/bin/pip"
PYTHON_VENV="${VENV_DIR}/bin/python"
"${PIP_BIN}" install pyyaml --quiet
"${PYTHON_VENV}" "${AUTOMATION_DIR}/${GENERATE_PRESIGNED_URLS_SCRIPT_PATH}" \
  --process test_assistant \
  --wazuh-version "${WAZUH_VERSION}" \
  --aws-s3-bucket-dev "${AWS_S3_BUCKET_DEV}"
echo "Generated presigned URLs:"
cat /tmp/artifact_urls.yaml
cp /tmp/artifact_urls.yaml "${WORKDIR}/artifact_urls.yaml"
echo "  -> ${WORKDIR}/artifact_urls.yaml"

# ---------------------------------------------------------------------------
# Step 4: Create config.yml
# ---------------------------------------------------------------------------
echo "[4/6] Creating config.yml..."
cat > "${WORKDIR}/config.yml" <<'EOF'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: 127.0.0.1
  manager:
    - name: wazuh-manager
      ip: 127.0.0.1
  dashboard:
    - name: wazuh-dashboard
      ip: 127.0.0.1
EOF
echo "  -> ${WORKDIR}/config.yml"

# ---------------------------------------------------------------------------
# Step 5: Generate install files (certificates + tar) via -g
# The installer reads config.yml and artifact_urls.yaml from its own directory.
# ---------------------------------------------------------------------------
echo "[5/6] Generating wazuh-install-files.tar (-g -id)..."
pushd "${WORKDIR}" > /dev/null
sudo bash wazuh-install.sh -g -id
popd > /dev/null
echo "  -> ${WORKDIR}/wazuh-install-files.tar"

# ---------------------------------------------------------------------------
# Step 6: Download offline packages via -dw
# ---------------------------------------------------------------------------
echo "[6/6] Downloading offline packages (-dw ${PKG_TYPE} -da ${ARCH} -d local)..."
pushd "${WORKDIR}" > /dev/null
sudo bash wazuh-install.sh -dw "${PKG_TYPE}" -da "${ARCH} -d local"
sudo chmod 644 wazuh-offline.tar.gz
popd > /dev/null
echo "  -> ${WORKDIR}/wazuh-offline.tar.gz"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Generated files ==="
ls -lh \
  "${WORKDIR}/wazuh-install.sh" \
  "${WORKDIR}/config.yml" \
  "${WORKDIR}/wazuh-install-files.tar" \
  "${WORKDIR}/wazuh-offline.tar.gz" \
  "${WORKDIR}/artifact_urls.yaml"

echo ""
echo "=== wazuh-install-files.tar contents ==="
sudo tar -tvf "${WORKDIR}/wazuh-install-files.tar"

echo ""
echo "=== wazuh-offline.tar.gz packages ==="
sudo tar -tzvf "${WORKDIR}/wazuh-offline.tar.gz"
