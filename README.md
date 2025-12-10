# Rollup Node

A unified rollup node that combines [op-geth](https://github.com/ethereum-optimism/op-geth) (execution layer) and [op-node](https://github.com/ethereum-optimism/optimism/tree/develop/op-node) (consensus layer) into a single binary, simplifying deployment and operation of Optimism-style rollups.

## Overview

This repository provides:

- **`rollup-node`**: A unified binary that runs both execution and consensus layers together
- **`run_setup.sh`**: Automated setup script for deploying rollup networks using [op-deployer](https://github.com/ethereum-optimism/optimism/tree/develop/op-deployer)

## Prerequisites

- **Go** 1.23+ ([install](https://go.dev/doc/install))
- **Foundry** ([install](https://book.getfoundry.sh/getting-started/installation)) - for building contracts
- **just** ([install](https://github.com/casey/just#installation)) - command runner for build automation
- Access to an L1 RPC endpoint (e.g., RSK, Ethereum)

## Installation

### Clone the Repository

```bash
git clone <repository-url>
cd rollup
```

### Initialize Submodules

This repository uses Git submodules for `op-geth` and `optimism`. Initialize them with:

```bash
git submodule update --init --depth 1
```

## Quick Start

### 1. Build the Rollup Node

```bash
go build -o bin/rollup-node ./cmd/rollup-node
```

### 2. Deploy a Rollup Network

Use the setup script to deploy a new rollup network:

```bash
export L1_CHAIN_ID=31          # L1 chain ID (e.g., RSK Testnet)
export L2_CHAIN_ID=100005      # L2 chain ID
export RPC_URL=http://localhost:4444  # L1 RPC endpoint
export PRIVATE_KEY=0x...       # Private key for deployment
export EOA_ADDRESS=0x...       # EOA address matching private key

./run_setup.sh
```

The script will:

1. Build op-deployer and op-geth
2. Initialize the rollup configuration
3. Deploy contracts to L1
4. Generate genesis and rollup configuration files
5. Initialize op-geth data directory

Output is saved to a timestamped directory: `{L1_CHAIN_ID}_{DATE}_{L2_CHAIN_ID}/`

### 3. Run the Rollup Node

After setup, run the rollup node using the generated configuration files:

```bash
./bin/rollup-node \
  --l1-rpc $RPC_URL \
  --rollup-config <path_to_rollup_config_file> \
  --genesis <path_to_genesis_config_file> \
  --datadir <path_to_geth_data_dir> \
  --jwt-secret <path_to_token_file>
```

For example:

```bash
./bin/rollup-node \
  --l1-rpc http://localhost:4444 \
  --rollup-config 31_08_12_2025_100005/rollup.json \
  --genesis 31_08_12_2025_100005/genesis.json \
  --datadir 31_08_12_2025_100005/op-geth-data \
  --jwt-secret jwt.txt
```

**Optional flags:**

- `--sequencer`: Enable sequencer mode (default: false)
- `--l1-chain-config`: Path to L1 chain config JSON (required for unknown chains)
- `--l2-http-port`: L2 HTTP RPC port (default: 8545)
- `--l2-ws-port`: L2 WebSocket RPC port (default: 8546)
- `--op-node-rpc-port`: op-node RPC port (default: 9545)

## Monitoring Logs

### Setup Logs

When running `run_setup.sh`, logs are saved to a `logs/` directory within each deployment directory:

```text
{L1_CHAIN_ID}_{DATE}_{L2_CHAIN_ID}/logs/
├── setup.log                    # Master log with all setup output
├── 01_init.log                  # OP-Deployer initialization
├── 02_bootstrap_proxy.log       # Proxy bootstrap
├── 03_bootstrap_superchain.log  # Superchain bootstrap
├── 04_bootstrap_implementations.log  # Implementations bootstrap
├── 05_apply.log                 # Contract deployment
├── 06_inspect_genesis.log       # Genesis inspection
├── 07_inspect_rollup.log        # Rollup config inspection
├── 08_inspect_l1.log            # L1 chain inspection
├── 09_inspect_deploy_config.log # Deploy config inspection
├── 10_inspect_l2_semvers.log    # L2 semvers inspection
└── 11_init_op_geth.log          # op-geth initialization
```

**Viewing setup logs:**

```bash
# View master log (all steps)
tail -f {WORKDIR}/logs/setup.log

# View specific step log
cat {WORKDIR}/logs/05_apply.log

# Monitor setup progress in real-time
tail -f {WORKDIR}/logs/setup.log
```

### Runtime Logs

The `rollup-node` binary logs to stdout/stderr with prefixes to distinguish between execution and consensus layers:

- **`[EXECUTION]`**: Logs from op-geth (execution layer)
- **`[CONSENSUS]`**: Logs from op-node (consensus layer)

**Monitoring runtime logs:**

```bash
# Run with output visible in terminal
./bin/rollup-node \
  --l1-rpc http://localhost:4444 \
  --rollup-config 31_08_12_2025_100005/rollup.json \
  --genesis 31_08_12_2025_100005/genesis.json \
  --datadir 31_08_12_2025_100005/op-geth-data \
  --jwt-secret jwt.txt

# Save logs to file
./bin/rollup-node \
  --l1-rpc http://localhost:4444 \
  --rollup-config 31_08_12_2025_100005/rollup.json \
  --genesis 31_08_12_2025_100005/genesis.json \
  --datadir 31_08_12_2025_100005/op-geth-data \
  --jwt-secret jwt.txt \
  2>&1 | tee rollup-node.log

# Filter logs by component
./bin/rollup-node ... 2>&1 | grep "\[EXECUTION\]"  # Only execution logs
./bin/rollup-node ... 2>&1 | grep "\[CONSENSUS\]"  # Only consensus logs

# Monitor logs in real-time (if saved to file)
tail -f rollup-node.log | grep "\[EXECUTION\]"
```

**Common log patterns:**

- **Startup**: Look for `STEP 1/3`, `STEP 2/3`, `STEP 3/3` messages
- **Errors**: Check for `ERROR` or `failed` messages
- **Sync status**: Monitor `[CONSENSUS]` logs for L1 sync progress
- **Block production**: Check `[EXECUTION]` logs for new blocks

## Configuration Files

After running `run_setup.sh`, the following files are generated in the work directory:

- `genesis.json`: L2 genesis configuration
- `rollup.json`: Rollup configuration (chain parameters, contract addresses)
- `deploy-config.json`: Deployment configuration
- `l1.json`: L1 chain information
- `intent.toml`: Deployment intent configuration
- `state.json`: Deployment state
- `op-geth-data/`: Initialized op-geth data directory

## Architecture

The rollup node integrates:

1. **op-geth** (Execution Layer): Processes transactions and maintains state
   - HTTP RPC: `http://127.0.0.1:8545`
   - WebSocket RPC: `ws://127.0.0.1:8546`
   - Engine API: `http://127.0.0.1:8551` (authenticated)

2. **op-node** (Consensus Layer): Syncs with L1 and drives block production
   - RPC: `http://127.0.0.1:9545`

Both layers communicate via the Engine API using JWT authentication.

## Project Structure

```text
.
├── cmd/rollup-node/     # Main rollup-node binary source
├── bin/                 # Built binaries
├── op-geth/            # op-geth fork (execution layer)
├── optimism/           # Optimism monorepo (op-node, op-deployer)
├── run_setup.sh        # Automated deployment script
└── {L1}_{DATE}_{L2}/   # Generated deployment directories
```

## Environment Variables

All `rollup-node` flags can be set via environment variables:

- `L1_RPC`: L1 RPC endpoint URL
- `ROLLUP_CONFIG`: Path to rollup config JSON
- `GENESIS`: Path to genesis JSON
- `DATADIR`: Data directory for op-geth
- `JWT_SECRET`: Path to JWT secret file
- `SEQUENCER`: Enable sequencer mode (true/false)

## Troubleshooting

- **Build errors**: Ensure all prerequisites are installed and submodules are initialized (see the [Initialize Submodules](#initialize-submodules) section)
- **Missing submodules**: If `op-geth` or `optimism` directories are empty, run see the [Initialize Submodules](#initialize-submodules) section.
- **Deployment failures**: Check L1 RPC connectivity and ensure the private key has sufficient funds
- **Sync issues**: Verify L1 RPC endpoint is accessible and rollup config matches deployed contracts

## License

This project uses dependencies from the Optimism and Ethereum ecosystems. Refer to individual component licenses.
