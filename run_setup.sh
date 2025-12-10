#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color


# Function to log to master log file (will be initialized after WORKDIR is set)
log_to_master() {
    if [ -n "${MASTER_LOG}" ] && [ -f "${MASTER_LOG}" ]; then
        echo "$1" >> "${MASTER_LOG}" 2>&1
    fi
}

# Function to print status
print_status() {
    local msg="${GREEN}[INFO]${NC} $1"
    echo -e "$msg"
    log_to_master "[INFO] $1"
}

print_error() {
    local msg="${RED}[ERROR]${NC} $1"
    echo -e "$msg" >&2
    log_to_master "[ERROR] $1"
}

print_step() {
    local msg="${YELLOW}[STEP]${NC} $1"
    echo -e "$msg"
    log_to_master "[STEP] $1"
}

# Step 1: Check for required environment variables
print_step "Checking required environment variables..."

if [ -z "$L1_CHAIN_ID" ]; then
    print_error "L1_CHAIN_ID is not set"
    exit 1
fi

if [ -z "$L2_CHAIN_ID" ]; then
    print_error "L2_CHAIN_ID is not set"
    exit 1
fi

if [ -z "$RPC_URL" ]; then
    print_error "RPC_URL is not set"
    exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
    print_error "PRIVATE_KEY is not set"
    exit 1
fi

if [ -z "$EOA_ADDRESS" ]; then
    print_error "EOA_ADDRESS is not set"
    exit 1
fi

print_status "L1_CHAIN_ID: $L1_CHAIN_ID"
print_status "L2_CHAIN_ID: $L2_CHAIN_ID"
print_status "RPC_URL: $RPC_URL"
print_status "EOA_ADDRESS: $EOA_ADDRESS"

# Validate RPC_URL format
if [[ ! "$RPC_URL" =~ ^https?:// ]]; then
    print_error "RPC_URL must start with http:// or https://"
    print_error "Current value: $RPC_URL"
    exit 1
fi

# Step 1.5: Check for required tools
print_step "Checking required tools..."

# Check for foundry (forge command)
if ! command -v forge >/dev/null 2>&1; then
    print_error "foundry (forge) is not installed or not in PATH"
    print_error "Please install foundry: https://book.getfoundry.sh/getting-started/installation"
    exit 1
fi
print_status "✓ foundry (forge) found: $(forge --version 2>/dev/null | head -n1 || echo 'version unknown')"

# Check for go
if ! command -v go >/dev/null 2>&1; then
    print_error "go is not installed or not in PATH"
    print_error "Please install Go: https://go.dev/doc/install"
    exit 1
fi
print_status "✓ go found: $(go version)"

# Check for just
if ! command -v just >/dev/null 2>&1; then
    print_error "just is not installed or not in PATH"
    print_error "Please install just: https://github.com/casey/just#installation"
    exit 1
fi
print_status "✓ just found: $(just --version 2>/dev/null || echo 'version unknown')"

echo ""

# Get workspace folder (script directory)
WORKSPACE_FOLDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate folder name: L1_CHAIN_ID_DATE_TODAY_L2_CHAIN_ID
DATE_TODAY=$(date +%d_%m_%Y)
FOLDER_NAME="${L1_CHAIN_ID}_${DATE_TODAY}_${L2_CHAIN_ID}"
WORKDIR="${WORKSPACE_FOLDER}/${FOLDER_NAME}"

print_step "Creating folder structure..."
mkdir -p "${WORKDIR}/.deployer"
mkdir -p "${WORKDIR}/logs"
print_status "Created folder: ${WORKDIR}"

# Initialize master log file
MASTER_LOG="${WORKDIR}/logs/setup.log"
echo "=== Setup started at $(date) ===" > "${MASTER_LOG}"
echo "L1_CHAIN_ID: ${L1_CHAIN_ID}" >> "${MASTER_LOG}"
echo "L2_CHAIN_ID: ${L2_CHAIN_ID}" >> "${MASTER_LOG}"
echo "RPC_URL: ${RPC_URL}" >> "${MASTER_LOG}"
echo "EOA_ADDRESS: ${EOA_ADDRESS}" >> "${MASTER_LOG}"
echo "" >> "${MASTER_LOG}"

# Progress tracking
TOTAL_STEPS=11  # Increased to include build steps
CURRENT_STEP=0
SCRIPT_START_TIME=$(date +%s)

print_status "Starting setup process with $TOTAL_STEPS steps..."
print_status "Master log file: ${MASTER_LOG}"
echo ""

# Function to print progress
print_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    local filled=$((CURRENT_STEP * 50 / TOTAL_STEPS))
    local empty=$((50 - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    local progress_msg="[$CURRENT_STEP/$TOTAL_STEPS] ${bar} ${percentage}%"
    echo -e "\n${YELLOW}${progress_msg}${NC}"
    log_to_master "${progress_msg}"
}

# Function to show spinner animation
show_spinner() {
    local pid=$1
    local message=$2
    local spinstr='|/-\'
    local delay=0.1
    
    # Run spinner in background
    (
        while kill -0 $pid 2>/dev/null; do
            local temp=${spinstr#?}
            printf "\r${YELLOW}[SPINNER]${NC} %s %c" "$message" "$spinstr" >&2
            spinstr=$temp${spinstr%"$temp"}
            sleep $delay
        done
        printf "\r%*s\r" $(tput cols) "" >&2  # Clear the line
    ) &
    echo $!  # Return spinner PID
}

# Function to run a command and save output to log
run_command() {
    local step_name="$1"
    local log_file="$2"
    shift 2
    local cmd=("$@")
    
    print_progress
    print_step "Running: $step_name"
    local start_time=$(date +%s)
    
    # Show the full command with proper formatting
    local cmd_str=""
    for arg in "${cmd[@]}"; do
        if [[ "$arg" =~ [[:space:]] ]]; then
            cmd_str+=" \"$arg\""
        else
            cmd_str+=" $arg"
        fi
    done
    print_status "Command:${cmd_str}"
    print_status "Log file: ${log_file}"
    log_to_master "=== Command: ${cmd_str} ==="
    log_to_master "=== Step: ${step_name} ==="
    echo ""
    
    # Run command in background, writing to both individual log and master log in real-time
    # Use a temporary file to capture exit code
    local exit_code_file="${log_file}.exit"
    rm -f "${exit_code_file}"
    
    # Run command with tee to write to both logs simultaneously in real-time
    # We need to capture the exit code of the actual command, not tee
    (
        set +e
        set -o pipefail  # This makes the pipeline return the exit code of the first failing command
        # Use tee to write to both files simultaneously
        "${cmd[@]}" 2>&1 | tee -a "${log_file}" >> "${MASTER_LOG}"
        local cmd_exit=$?
        echo $cmd_exit > "${exit_code_file}"
        exit $cmd_exit
    ) &
    local cmd_pid=$!
    
    # Show spinner while command is running
    local spinner_pid=$(show_spinner $cmd_pid "$step_name")
    
    # Wait for command to finish
    # Disable set -e to handle wait and cleanup properly
    set +e
    wait $cmd_pid
    set +e
    
    # Read exit code from file (this is the actual command exit code)
    local exit_code=1  # Default to failure
    if [ -f "${exit_code_file}" ]; then
        exit_code=$(cat "${exit_code_file}")
        rm -f "${exit_code_file}"
    fi
    
    # Stop spinner (ignore errors)
    kill $spinner_pid 2>/dev/null || true
    wait $spinner_pid 2>/dev/null || true
    
    # Calculate elapsed time before re-enabling set -e
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    # Ensure exit_code is set (default to 1 if somehow unset, to be safe)
    exit_code=${exit_code:-1}
    
    # Re-enable set -e
    set -e
    
    # Handle success/failure
    if [ "$exit_code" -eq 0 ]; then
        print_status "✓ $step_name completed successfully (${elapsed}s)"
        return 0
    else
        print_error "✗ $step_name failed with exit code $exit_code (${elapsed}s)"
        print_error "Check log file: ${log_file}"
        # Show last few lines of log for quick debugging
        if [ -f "${log_file}" ]; then
            print_error "Last 10 lines of log:"
            tail -10 "${log_file}" | sed 's/^/  /' >&2
        fi
        exit $exit_code
    fi
}

# Function to build op-deployer
build_op_deployer() {
    local deployer_bin="${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer"
    
    print_step "Building op-deployer (including contracts)..."
    local start_time=$(date +%s)
    
    # Check if 'just' is available, use full build which includes contracts
    if command -v just >/dev/null 2>&1; then
        # Use 'just build' which includes: build-contracts, copy-contract-artifacts, build-go
        (cd "${WORKSPACE_FOLDER}/optimism/op-deployer" && just build)
    else
        # Fallback: try to build contracts and artifacts manually, then build Go binary
        print_error "just command not found. Please install 'just' to build op-deployer with contracts."
        print_error "Alternatively, run 'just build' manually in ${WORKSPACE_FOLDER}/optimism/op-deployer"
        exit 1
    fi
    
    if [ -f "${deployer_bin}" ]; then
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        print_status "✓ op-deployer built successfully (${elapsed}s)"
        
        # Verify artifacts exist
        local artifacts_file="${WORKSPACE_FOLDER}/optimism/op-deployer/pkg/deployer/artifacts/forge-artifacts/artifacts.tzst"
        if [ -f "${artifacts_file}" ]; then
            print_status "✓ Contract artifacts verified"
        else
            print_error "✗ Contract artifacts not found at ${artifacts_file}"
            exit 1
        fi
    else
        print_error "✗ op-deployer build failed - binary not found"
        exit 1
    fi
}

# Function to build op-geth
build_op_geth() {
    local geth_bin="${WORKSPACE_FOLDER}/op-geth/build/bin/geth"
    
    print_step "Building op-geth..."
    local start_time=$(date +%s)
    
    # Use make geth which runs: go run build/ci.go install ./cmd/geth
    (cd "${WORKSPACE_FOLDER}/op-geth" && make geth)
    
    if [ -f "${geth_bin}" ]; then
        local end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        print_status "✓ op-geth built successfully (${elapsed}s)"
    else
        print_error "✗ op-geth build failed - binary not found"
        exit 1
    fi
}

# Function to update intent.toml and state.json after init
update_config_files() {
    local intent_file="${WORKDIR}/intent.toml"
    local state_file="${WORKDIR}/state.json"
    
    print_step "Updating intent.toml and state.json configuration..."
    
    # Convert L2_CHAIN_ID to hex and pad to 64 hex digits (32 bytes)
    # Format: 0x + 64 hex digits, with chain ID right-aligned
    # Use Python for reliable hex conversion and padding
    local padded_hex=$(python3 -c "print('0x' + format(${L2_CHAIN_ID}, '064x'))")
    
    # Update intent.toml - add eip1559 values and replace zero addresses
    if [ -f "${intent_file}" ]; then
        # Use Python for reliable TOML manipulation (more reliable than sed)
        python3 <<PYTHON_SCRIPT
import re

with open('${intent_file}', 'r') as f:
    content = f.read()

# Replace zero addresses (0x0000000000000000000000000000000000000000) with EOA_ADDRESS
# But NOT in the chain ID field (id = "...")
zero_address = '0x0000000000000000000000000000000000000000'
eoa_address = '${EOA_ADDRESS}'

# Only replace zero addresses that are NOT in the chain ID field
# Match zero addresses that appear after = signs (address fields)
# but not when preceded by "id ="
lines = content.split('\n')
result_lines = []
for line in lines:
    # Skip replacement if this is the chain ID line
    if re.match(r'^\s*id\s*=', line):
        result_lines.append(line)
    else:
        # Replace zero addresses in all other lines
        result_lines.append(line.replace(zero_address, eoa_address))
content = '\n'.join(result_lines)

# Check if eip1559 values exist
has_eip1559 = 'eip1559DenominatorCanyon' in content

if not has_eip1559:
    # Add the values after sequencerFeeVaultRecipient line
    content = re.sub(
        r'(sequencerFeeVaultRecipient[^\n]+\n)',
        r'\1  eip1559DenominatorCanyon = 250\n  eip1559Denominator = 50\n  eip1559Elasticity = 6\n',
        content
    )
else:
    # Update existing values
    content = re.sub(r'^(\s*eip1559DenominatorCanyon\s*=\s*).*$', r'\1 250', content, flags=re.MULTILINE)
    content = re.sub(r'^(\s*eip1559Denominator\s*=\s*).*$', r'\1 50', content, flags=re.MULTILINE)
    content = re.sub(r'^(\s*eip1559Elasticity\s*=\s*).*$', r'\1 6', content, flags=re.MULTILINE)

with open('${intent_file}', 'w') as f:
    f.write(content)
PYTHON_SCRIPT
        
        print_status "Updated intent.toml with eip1559 values and replaced zero addresses with ${EOA_ADDRESS}"
    else
        print_error "intent.toml not found at ${intent_file}"
        return 1
    fi
    
    # Update state.json - set create2Salt to hex value of L2_CHAIN_ID
    if [ -f "${state_file}" ]; then
        # Use Python or jq if available, otherwise use sed
        if command -v jq >/dev/null 2>&1; then
            jq --arg salt "${padded_hex}" '.create2Salt = $salt' "${state_file}" > "${state_file}.tmp" && mv "${state_file}.tmp" "${state_file}"
        elif command -v python3 >/dev/null 2>&1; then
            python3 <<EOF
import json
with open('${state_file}', 'r') as f:
    data = json.load(f)
data['create2Salt'] = '${padded_hex}'
with open('${state_file}', 'w') as f:
    json.dump(data, f, indent=2)
EOF
        else
            # Fallback to sed (less reliable but works)
            sed -i.bak "s/\"create2Salt\":[[:space:]]*\"[^\"]*\"/\"create2Salt\": \"${padded_hex}\"/" "${state_file}"
            rm -f "${state_file}.bak"
        fi
        
        print_status "Updated state.json create2Salt to ${padded_hex}"
    else
        print_error "state.json not found at ${state_file}"
        return 1
    fi
    
    print_status "Configuration files updated successfully"
}

# Use EOA_ADDRESS for all owner/role addresses
PROXY_OWNER="${PROXY_OWNER:-${EOA_ADDRESS}}"
SUPERCHAIN_PROXY_ADMIN_OWNER="${SUPERCHAIN_PROXY_ADMIN_OWNER:-${EOA_ADDRESS}}"
PROTOCOL_VERSIONS_OWNER="${PROTOCOL_VERSIONS_OWNER:-${EOA_ADDRESS}}"
GUARDIAN="${GUARDIAN:-${EOA_ADDRESS}}"

# Bootstrap Implementations addresses (should be extracted from previous steps, but defaults provided)
UPGRADE_CONTROLLER="${UPGRADE_CONTROLLER:-${EOA_ADDRESS}}"
CHALLENGER="${CHALLENGER:-${EOA_ADDRESS}}"

# Step 1.5: Build op-deployer
build_op_deployer

# Step 2: Launch OP-Deployer Initialise Testnet
run_command \
    "OP-Deployer Initialise Testnet" \
    "${WORKDIR}/logs/01_init.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    init \
    --l1-chain-id "${L1_CHAIN_ID}" \
    --l2-chain-ids "${L2_CHAIN_ID}" \
    --workdir "${WORKDIR}" \
    --intent-type custom

# Step 2.5: Update intent.toml and state.json configuration
update_config_files

# Step 3: Launch OP-Deployer Bootstrap Proxy
run_command \
    "OP-Deployer Bootstrap Proxy" \
    "${WORKDIR}/logs/02_bootstrap_proxy.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    bootstrap \
    proxy \
    --l1-rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    --outfile="${WORKDIR}/.deployer/proxy_testnet-sync_broadcast.json" \
    --artifacts-locator=embedded \
    --proxy-owner="${PROXY_OWNER}"

# Step 4: Launch OP-Deployer Bootstrap Superchain
export DEPLOYER_LOG_LEVEL=trace
run_command \
    "OP-Deployer Bootstrap Superchain" \
    "${WORKDIR}/logs/03_bootstrap_superchain.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    bootstrap \
    superchain \
    --l1-rpc-url="${RPC_URL}" \
    --outfile="${WORKDIR}/.deployer/superchain_testnet-sync_broadcast.json" \
    --private-key="${PRIVATE_KEY}" \
    --artifacts-locator=embedded \
    --superchain-proxy-admin-owner="${SUPERCHAIN_PROXY_ADMIN_OWNER}" \
    --protocol-versions-owner="${PROTOCOL_VERSIONS_OWNER}" \
    --guardian="${GUARDIAN}" \
    --paused=false
unset DEPLOYER_LOG_LEVEL

# Extract addresses from superchain bootstrap output
print_step "Reading addresses from superchain bootstrap output..."
SUPERCHAIN_OUTPUT_FILE="${WORKDIR}/.deployer/superchain_testnet-sync_broadcast.json"

if [ ! -f "${SUPERCHAIN_OUTPUT_FILE}" ]; then
    print_error "Superchain output file not found: ${SUPERCHAIN_OUTPUT_FILE}"
    exit 1
fi

# Extract addresses using jq if available, otherwise use python3
if command -v jq >/dev/null 2>&1; then
    PROTOCOL_VERSIONS_PROXY=$(jq -r '.protocolVersionsProxyAddress' "${SUPERCHAIN_OUTPUT_FILE}")
    SUPERCHAIN_CONFIG_PROXY=$(jq -r '.superchainConfigProxyAddress' "${SUPERCHAIN_OUTPUT_FILE}")
    SUPERCHAIN_PROXY_ADMIN=$(jq -r '.proxyAdminAddress' "${SUPERCHAIN_OUTPUT_FILE}")
elif command -v python3 >/dev/null 2>&1; then
    PROTOCOL_VERSIONS_PROXY=$(python3 -c "import json; print(json.load(open('${SUPERCHAIN_OUTPUT_FILE}'))['protocolVersionsProxyAddress'])")
    SUPERCHAIN_CONFIG_PROXY=$(python3 -c "import json; print(json.load(open('${SUPERCHAIN_OUTPUT_FILE}'))['superchainConfigProxyAddress'])")
    SUPERCHAIN_PROXY_ADMIN=$(python3 -c "import json; print(json.load(open('${SUPERCHAIN_OUTPUT_FILE}'))['proxyAdminAddress'])")
else
    print_error "Neither jq nor python3 is available. Cannot parse superchain output file."
    exit 1
fi

# Validate addresses are not empty
if [ -z "${PROTOCOL_VERSIONS_PROXY}" ] || [ "${PROTOCOL_VERSIONS_PROXY}" = "null" ]; then
    print_error "Failed to extract PROTOCOL_VERSIONS_PROXY from superchain output"
    exit 1
fi

if [ -z "${SUPERCHAIN_CONFIG_PROXY}" ] || [ "${SUPERCHAIN_CONFIG_PROXY}" = "null" ]; then
    print_error "Failed to extract SUPERCHAIN_CONFIG_PROXY from superchain output"
    exit 1
fi

if [ -z "${SUPERCHAIN_PROXY_ADMIN}" ] || [ "${SUPERCHAIN_PROXY_ADMIN}" = "null" ]; then
    print_error "Failed to extract SUPERCHAIN_PROXY_ADMIN from superchain output"
    exit 1
fi

print_status "Extracted addresses:"
print_status "  PROTOCOL_VERSIONS_PROXY: ${PROTOCOL_VERSIONS_PROXY}"
print_status "  SUPERCHAIN_CONFIG_PROXY: ${SUPERCHAIN_CONFIG_PROXY}"
print_status "  SUPERCHAIN_PROXY_ADMIN: ${SUPERCHAIN_PROXY_ADMIN}"

# Step 5: Launch OP-Deployer Bootstrap Implementations
run_command \
    "OP-Deployer Bootstrap Implementations" \
    "${WORKDIR}/logs/04_bootstrap_implementations.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    bootstrap \
    implementations \
    --l1-rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}" \
    --artifacts-locator=embedded \
    --outfile="${WORKDIR}/.deployer/implementations_testnet-sync_broadcast.json" \
    --protocol-versions-proxy="${PROTOCOL_VERSIONS_PROXY}" \
    --superchain-config-proxy="${SUPERCHAIN_CONFIG_PROXY}" \
    --upgrade-controller="${UPGRADE_CONTROLLER}" \
    --superchain-proxy-admin="${SUPERCHAIN_PROXY_ADMIN}" \
    --challenger="${CHALLENGER}"

# Step 6: Launch OP-Deployer Apply Testnet
run_command \
    "OP-Deployer Apply Testnet" \
    "${WORKDIR}/logs/05_apply.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    apply \
    --workdir="${WORKDIR}" \
    --l1-rpc-url="${RPC_URL}" \
    --private-key="${PRIVATE_KEY}"

# Step 7: Launch OP-Deployer Inspect Genesis Testnet
run_command \
    "OP-Deployer Inspect Genesis Testnet" \
    "${WORKDIR}/logs/06_inspect_genesis.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    inspect \
    genesis \
    --workdir "${WORKDIR}" \
    --outfile "${WORKDIR}/genesis.json" \
    "${L2_CHAIN_ID}"

# Step 8: Launch OP-Deployer Inspect Rollup Testnet
run_command \
    "OP-Deployer Inspect Rollup Testnet" \
    "${WORKDIR}/logs/07_inspect_rollup.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    inspect \
    rollup \
    --workdir "${WORKDIR}" \
    --outfile "${WORKDIR}/rollup.json" \
    "${L2_CHAIN_ID}"

# Step 9: Launch OP-Deployer Inspect L1 Testnet
run_command \
    "OP-Deployer Inspect L1 Testnet" \
    "${WORKDIR}/logs/08_inspect_l1.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    inspect \
    l1 \
    --workdir "${WORKDIR}" \
    --outfile "${WORKDIR}/l1.json" \
    "${L2_CHAIN_ID}"

# Step 10: Launch OP-Deployer Inspect Deploy Config Testnet
run_command \
    "OP-Deployer Inspect Deploy Config Testnet" \
    "${WORKDIR}/logs/09_inspect_deploy_config.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    inspect \
    deploy-config \
    --workdir "${WORKDIR}" \
    --outfile "${WORKDIR}/deploy-config.json" \
    "${L2_CHAIN_ID}"

# Step 11: Launch OP-Deployer Inspect L2 Semvers Testnet
run_command \
    "OP-Deployer Inspect L2 Semvers Testnet" \
    "${WORKDIR}/logs/10_inspect_l2_semvers.log" \
    "${WORKSPACE_FOLDER}/optimism/op-deployer/bin/op-deployer" \
    inspect \
    l2-semvers \
    --workdir "${WORKDIR}" \
    --outfile "${WORKDIR}/l2-semvers.json" \
    "${L2_CHAIN_ID}"

# # Step 11.5: Build op-geth
# build_op_geth

# # Step 12: Initialise OP-Geth with genesis file
# run_command \
#     "Initialise OP-Geth with genesis file" \
#     "${WORKDIR}/logs/11_init_op_geth.log" \
#     "${WORKSPACE_FOLDER}/op-geth/build/bin/geth" \
#     init \
#     --datadir="${WORKDIR}/op-geth-data" \
#     --state.scheme=hash \
#     "${WORKDIR}/genesis.json"

# Calculate total time
SCRIPT_END_TIME=$(date +%s)
TOTAL_ELAPSED=$((SCRIPT_END_TIME - SCRIPT_START_TIME))
MINUTES=$((TOTAL_ELAPSED / 60))
SECONDS=$((TOTAL_ELAPSED % 60))

echo ""
print_status "═══════════════════════════════════════════════════════════"
print_status "All $TOTAL_STEPS steps completed successfully!"
print_status "Total time: ${MINUTES}m ${SECONDS}s"
print_status "Work directory: ${WORKDIR}"
print_status "Log files are in: ${WORKDIR}/logs/"
print_status "Master log: ${MASTER_LOG}"
print_status "═══════════════════════════════════════════════════════════"

# Write completion to master log
log_to_master ""
log_to_master "=== Setup completed successfully at $(date) ==="
log_to_master "Total time: ${MINUTES}m ${SECONDS}s"

