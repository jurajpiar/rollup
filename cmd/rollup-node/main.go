package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"math/big"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/urfave/cli/v2"

	"github.com/ethereum-optimism/optimism/op-node/config"
	"github.com/ethereum-optimism/optimism/op-node/metrics"
	opnode "github.com/ethereum-optimism/optimism/op-node/node"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/driver"
	"github.com/ethereum-optimism/optimism/op-node/rollup/sync"
	opeth "github.com/ethereum-optimism/optimism/op-service/eth"
	oplog "github.com/ethereum-optimism/optimism/op-service/log"
	oprpc "github.com/ethereum-optimism/optimism/op-service/rpc"
	"github.com/ethereum-optimism/optimism/op-service/sources"
)

func main() {
	app := &cli.App{
		Name:  "rollup-node",
		Usage: "Run op-geth execution layer and op-node consensus layer as a single rollup node",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "l1-rpc",
				Usage:    "L1 RPC endpoint URL",
				Required: true,
				EnvVars:  []string{"L1_RPC"},
			},
			&cli.StringFlag{
				Name:     "l1-beacon",
				Usage:    "L1 Beacon API endpoint URL",
				Required: false,
				EnvVars:  []string{"L1_BEACON"},
			},
			&cli.StringFlag{
				Name:     "rollup-config",
				Usage:    "Path to rollup config JSON file",
				Required: true,
				EnvVars:  []string{"ROLLUP_CONFIG"},
			},
			&cli.StringFlag{
				Name:     "genesis",
				Usage:    "Path to genesis JSON file",
				Required: true,
				EnvVars:  []string{"GENESIS"},
			},
			&cli.StringFlag{
				Name:     "datadir",
				Usage:    "Data directory for op-geth",
				Required: true,
				EnvVars:  []string{"DATADIR"},
			},
			&cli.StringFlag{
				Name:     "jwt-secret",
				Usage:    "Path to JWT secret file (will be created if doesn't exist)",
				Required: false,
				Value:    "jwt.txt",
				EnvVars:  []string{"JWT_SECRET"},
			},
			&cli.StringFlag{
				Name:    "l2-http-addr",
				Usage:   "L2 HTTP RPC address",
				Value:   "127.0.0.1",
				EnvVars: []string{"L2_HTTP_ADDR"},
			},
			&cli.IntFlag{
				Name:    "l2-http-port",
				Usage:   "L2 HTTP RPC port",
				Value:   8545,
				EnvVars: []string{"L2_HTTP_PORT"},
			},
			&cli.StringFlag{
				Name:    "l2-ws-addr",
				Usage:   "L2 WebSocket RPC address",
				Value:   "127.0.0.1",
				EnvVars: []string{"L2_WS_ADDR"},
			},
			&cli.IntFlag{
				Name:    "l2-ws-port",
				Usage:   "L2 WebSocket RPC port",
				Value:   8546,
				EnvVars: []string{"L2_WS_PORT"},
			},
			&cli.StringFlag{
				Name:    "l2-auth-addr",
				Usage:   "L2 Engine API (auth) address",
				Value:   "127.0.0.1",
				EnvVars: []string{"L2_AUTH_ADDR"},
			},
			&cli.IntFlag{
				Name:    "l2-auth-port",
				Usage:   "L2 Engine API (auth) port",
				Value:   8551,
				EnvVars: []string{"L2_AUTH_PORT"},
			},
			&cli.StringFlag{
				Name:    "op-node-rpc-addr",
				Usage:   "op-node RPC address",
				Value:   "127.0.0.1",
				EnvVars: []string{"OP_NODE_RPC_ADDR"},
			},
			&cli.IntFlag{
				Name:    "op-node-rpc-port",
				Usage:   "op-node RPC port",
				Value:   9545,
				EnvVars: []string{"OP_NODE_RPC_PORT"},
			},
			&cli.BoolFlag{
				Name:    "sequencer",
				Usage:   "Enable sequencer mode",
				Value:   false,
				EnvVars: []string{"SEQUENCER"},
			},
			&cli.StringFlag{
				Name:     "l1-chain-config",
				Usage:    "Path to L1 chain config JSON file (optional, will try known chains if not provided)",
				Required: false,
				EnvVars:  []string{"L1_CHAIN_CONFIG"},
			},
		},
		Action: runRollupNode,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runRollupNode(ctx *cli.Context) error {
	// Setup logging
	log.SetDefault(log.NewLogger(log.NewTerminalHandler(os.Stdout, true)))

	// Create context with cancellation
	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info("Received signal, shutting down...", "signal", sig)
		cancel()
	}()

	// Ensure JWT secret exists
	jwtPath := ctx.String("jwt-secret")
	if err := ensureJWTSecret(jwtPath); err != nil {
		return fmt.Errorf("failed to ensure JWT secret: %w", err)
	}

	// Load genesis
	genesisPath := ctx.String("genesis")
	genesis, err := loadGenesis(genesisPath)
	if err != nil {
		return fmt.Errorf("failed to load genesis: %w", err)
	}

	// Start op-geth
	log.Info("Starting op-geth execution layer...")
	gethNode, err := startOpGeth(mainCtx, ctx, genesis)
	if err != nil {
		return fmt.Errorf("failed to start op-geth: %w", err)
	}
	defer func() {
		log.Info("Stopping op-geth...")
		if err := gethNode.Close(); err != nil {
			log.Error("Error closing op-geth", "err", err)
		}
	}()

	// Wait for op-geth to be ready
	log.Info("Waiting for op-geth to be ready...")
	if err := waitForGethReady(mainCtx, ctx); err != nil {
		return fmt.Errorf("op-geth failed to become ready: %w", err)
	}

	// Get the engine API endpoint
	engineEndpoint := fmt.Sprintf("http://%s:%d", ctx.String("l2-auth-addr"), ctx.Int("l2-auth-port"))

	// Start op-node
	log.Info("Starting op-node consensus layer...")
	opNode, err := startOpNode(mainCtx, ctx, engineEndpoint, jwtPath)
	if err != nil {
		return fmt.Errorf("failed to start op-node: %w", err)
	}
	defer func() {
		log.Info("Stopping op-node...")
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if err := opNode.Stop(stopCtx); err != nil {
			log.Error("Error stopping op-node", "err", err)
		}
	}()

	log.Info("Rollup node started successfully!")
	log.Info("op-geth HTTP RPC", "endpoint", fmt.Sprintf("http://%s:%d", ctx.String("l2-http-addr"), ctx.Int("l2-http-port")))
	log.Info("op-geth WebSocket RPC", "endpoint", fmt.Sprintf("ws://%s:%d", ctx.String("l2-ws-addr"), ctx.Int("l2-ws-port")))
	log.Info("op-node RPC", "endpoint", fmt.Sprintf("http://%s:%d", ctx.String("op-node-rpc-addr"), ctx.Int("op-node-rpc-port")))

	// Wait for context cancellation
	<-mainCtx.Done()
	log.Info("Shutting down rollup node...")

	return nil
}

func ensureJWTSecret(jwtPath string) error {
	// Check if file exists
	if _, err := os.Stat(jwtPath); err == nil {
		log.Info("Using existing JWT secret", "path", jwtPath)
		return nil
	}

	// Generate new JWT secret
	log.Info("Generating new JWT secret", "path", jwtPath)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("failed to generate random secret: %w", err)
	}

	// Write hex-encoded secret to file
	hexSecret := hex.EncodeToString(secret)
	if err := os.WriteFile(jwtPath, []byte(hexSecret), 0600); err != nil {
		return fmt.Errorf("failed to write JWT secret: %w", err)
	}

	log.Info("Generated JWT secret", "path", jwtPath)
	return nil
}

func loadGenesis(genesisPath string) (*core.Genesis, error) {
	data, err := os.ReadFile(genesisPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis file: %w", err)
	}

	var genesis core.Genesis
	if err := genesis.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("failed to parse genesis JSON: %w", err)
	}

	return &genesis, nil
}

func startOpGeth(ctx context.Context, cliCtx *cli.Context, genesis *core.Genesis) (*node.Node, error) {
	// Create node config
	nodeCfg := &node.Config{
		Name:        "rollup-geth",
		DataDir:     cliCtx.String("datadir"),
		HTTPHost:    cliCtx.String("l2-http-addr"),
		HTTPPort:    cliCtx.Int("l2-http-port"),
		WSHost:      cliCtx.String("l2-ws-addr"),
		WSPort:      cliCtx.Int("l2-ws-port"),
		AuthAddr:    cliCtx.String("l2-auth-addr"),
		AuthPort:    cliCtx.Int("l2-auth-port"),
		JWTSecret:   cliCtx.String("jwt-secret"),
		HTTPModules: []string{"debug", "admin", "eth", "txpool", "net", "rpc", "web3", "personal", "engine"},
		WSModules:   []string{"debug", "admin", "eth", "txpool", "net", "rpc", "web3", "personal", "engine"},
	}

	// Create eth config
	ethCfg := &ethconfig.Config{
		Genesis:     genesis,
		NetworkId:   genesis.Config.ChainID.Uint64(),
		StateScheme: "hash",
	}

	// Create and start node
	stack, err := node.New(nodeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create geth node: %w", err)
	}

	// Register Ethereum backend
	backend, err := eth.New(stack, ethCfg)
	if err != nil {
		stack.Close()
		return nil, fmt.Errorf("failed to create eth backend: %w", err)
	}

	// Register catalyst (Engine API)
	if err := catalyst.Register(stack, backend); err != nil {
		stack.Close()
		return nil, fmt.Errorf("failed to register catalyst: %w", err)
	}

	// Start the node
	if err := stack.Start(); err != nil {
		stack.Close()
		return nil, fmt.Errorf("failed to start geth node: %w", err)
	}

	return stack, nil
}

func waitForGethReady(ctx context.Context, cliCtx *cli.Context) error {
	// Try to connect to the RPC endpoint
	endpoint := fmt.Sprintf("http://%s:%d", cliCtx.String("l2-http-addr"), cliCtx.Int("l2-http-port"))

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			client, err := rpc.DialContext(ctx, endpoint)
			if err == nil {
				client.Close()
				log.Info("op-geth is ready")
				return nil
			}
			log.Debug("Waiting for op-geth to be ready...", "endpoint", endpoint)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func startOpNode(ctx context.Context, cliCtx *cli.Context, engineEndpoint, jwtPath string) (*opnode.OpNode, error) {
	// Load rollup config
	rollupConfigPath := cliCtx.String("rollup-config")
	rollupCfg, err := loadRollupConfig(rollupConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load rollup config: %w", err)
	}

	// Read JWT secret
	jwtSecret := readJWTSecret(jwtPath)

	// Get L1 chain config
	l1ChainConfig, err := getL1ChainConfig(rollupCfg.L1ChainID, cliCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get L1 chain config: %w", err)
	}

	// Create op-node config
	nodeCfg := &config.Config{
		L1: &config.L1EndpointConfig{
			L1NodeAddr:       cliCtx.String("l1-rpc"),
			L1TrustRPC:       true, // Hardcoded: trust L1 RPC for PoW chains like RSK
			L1RPCKind:        sources.RPCKindStandard,
			RateLimit:        0,
			BatchSize:        20,
			HttpPollInterval: time.Millisecond * 100,
			MaxConcurrency:   10,
			CacheSize:        0,
		},
		L2: &config.L2EndpointConfig{
			L2EngineAddr:      engineEndpoint,
			L2EngineJWTSecret: jwtSecret,
		},
		Driver: driver.Config{
			SequencerEnabled:   cliCtx.Bool("sequencer"),
			SequencerConfDepth: 2,
		},
		Rollup:        *rollupCfg,
		L1ChainConfig: l1ChainConfig,
		RPC: oprpc.CLIConfig{
			ListenAddr:  cliCtx.String("op-node-rpc-addr"),
			ListenPort:  cliCtx.Int("op-node-rpc-port"),
			EnableAdmin: true,
		},
		Sync: sync.Config{
			SyncMode: sync.CLSync,
		},
		Cancel: func(err error) {
			log.Warn("op-node requested shutdown", "err", err)
		},
	}

	// Only set Beacon config if l1-beacon is provided (needed for PoS chains, not PoW like RSK)
	if l1BeaconAddr := cliCtx.String("l1-beacon"); l1BeaconAddr != "" {
		nodeCfg.Beacon = &config.L1BeaconEndpointConfig{
			BeaconAddr:        l1BeaconAddr,
			BeaconCheckIgnore: true, // Hardcoded: ignore beacon health checks
		}
	} else {
		log.Info("L1 Beacon API disabled (PoW chain)")
	}

	// Create logger
	logger := oplog.NewLogger(os.Stdout, oplog.DefaultCLIConfig())

	// Create metrics
	metrics := metrics.NewMetrics("rollup-node")

	// Create and start op-node
	opNode, err := opnode.New(ctx, nodeCfg, logger, "", metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create op-node: %w", err)
	}

	if err := opNode.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start op-node: %w", err)
	}

	return opNode, nil
}

func loadRollupConfig(path string) (*rollup.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rollup config: %w", err)
	}
	defer file.Close()

	var rollupCfg rollup.Config
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rollupCfg); err != nil {
		return nil, fmt.Errorf("failed to decode rollup config: %w", err)
	}

	return &rollupCfg, nil
}

func readJWTSecret(jwtPath string) [32]byte {
	data, err := os.ReadFile(jwtPath)
	if err != nil {
		panic(fmt.Sprintf("failed to read JWT secret: %v", err))
	}

	// Remove newlines and decode hex
	hexStr := strings.TrimSpace(string(data))
	secret, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("failed to decode JWT secret: %v", err))
	}

	var secret32 [32]byte
	copy(secret32[:], secret)
	return secret32
}

func getL1ChainConfig(chainID *big.Int, cliCtx *cli.Context) (*params.ChainConfig, error) {
	// First try known chains
	if cfg := opeth.L1ChainConfigByChainID(opeth.ChainIDFromBig(chainID)); cfg != nil {
		log.Info("Using known L1 chain config", "chainID", chainID)
		return cfg, nil
	}

	// If L1 chain config file is provided, load from it
	if l1ChainConfigPath := cliCtx.String("l1-chain-config"); l1ChainConfigPath != "" {
		return loadL1ChainConfigFromFile(l1ChainConfigPath, chainID)
	}

	// If no file provided and not a known chain, we need to query L1 RPC
	// For now, return an error asking for the config file
	return nil, fmt.Errorf("L1 chain ID %d is not a known chain. Please provide --l1-chain-config with path to L1 chain config JSON file", chainID)
}

func loadL1ChainConfigFromFile(path string, expectedChainID *big.Int) (*params.ChainConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read L1 chain config: %w", err)
	}
	defer file.Close()

	// Try to decode directly as ChainConfig
	var chainConfig params.ChainConfig
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&chainConfig); err == nil {
		if chainConfig.ChainID.Cmp(expectedChainID) != 0 {
			return nil, fmt.Errorf("L1 chain config chain ID mismatch: %v != %v", chainConfig.ChainID, expectedChainID)
		}
		return &chainConfig, nil
	}

	// If that fails, try to load from genesis file format (.config property)
	file.Seek(0, 0)
	var genesis struct {
		Config *params.ChainConfig `json:"config"`
	}
	dec = json.NewDecoder(file)
	if err := dec.Decode(&genesis); err != nil {
		return nil, fmt.Errorf("failed to decode L1 chain config: %w", err)
	}
	if genesis.Config == nil {
		return nil, fmt.Errorf("L1 chain config file does not contain config")
	}
	if genesis.Config.ChainID.Cmp(expectedChainID) != 0 {
		return nil, fmt.Errorf("L1 chain config chain ID mismatch: %v != %v", genesis.Config.ChainID, expectedChainID)
	}
	return genesis.Config, nil
}
