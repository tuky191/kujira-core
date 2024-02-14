package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	rosettaCmd "cosmossdk.io/tools/rosetta/cmd"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	"github.com/Team-Kujira/core/app"
	"github.com/Team-Kujira/core/app/params"
	dbm "github.com/cometbft/cometbft-db"
	tmcfg "github.com/cometbft/cometbft/config"
	tmcli "github.com/cometbft/cometbft/libs/cli"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/pruning"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/server"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/version"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
)

// NewRootCmd creates a new root command for wasmd. It is called once in the
// main function.
func NewRootCmd() (*cobra.Command, params.EncodingConfig) {
	encodingConfig := app.MakeEncodingConfig()

	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Codec).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithBroadcastMode(flags.BroadcastSync).
		WithHomeDir(app.DefaultNodeHome).
		WithViper("")

	rootCmd := &cobra.Command{
		Use:   version.AppName,
		Short: "Kujira Daemon (server)",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SetOut(cmd.OutOrStdout())
			cmd.SetErr(cmd.ErrOrStderr())

			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}

			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}

			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}

			customAppTemplate, customAppConfig := initAppConfig()
			customTMConfig := initTendermintConfig()

			return server.InterceptConfigsPreRunHandler(cmd, customAppTemplate, customAppConfig, customTMConfig)
		},
	}

	initRootCmd(rootCmd, encodingConfig)

	return rootCmd, encodingConfig
}

// initTendermintConfig helps to override default Tendermint Config values.
// return tmcfg.DefaultConfig if no custom configuration is required for the application.
func initTendermintConfig() *tmcfg.Config {
	cfg := tmcfg.DefaultConfig()

	cfg.P2P.Seeds = ""

	// these values put a higher strain on node memory
	cfg.P2P.MaxNumInboundPeers = 320
	cfg.P2P.MaxNumOutboundPeers = 40

	return cfg
}

// initAppConfig helps to override default appConfig template and configs.
// return "", nil if no custom configuration is required for the application.
func initAppConfig() (string, interface{}) {
	// The following code snippet is just for reference.

	// WASMConfig defines configuration for the wasm module.
	type WASMConfig struct {
		// This is the maximum sdk gas (wasm and storage) that we allow for any x/wasm "smart" queries
		QueryGasLimit uint64 `mapstructure:"query_gas_limit"`

		// Address defines the gRPC-web server to listen on
		LruSize uint64 `mapstructure:"lru_size"`
	}

	type CustomAppConfig struct {
		serverconfig.Config

		WASM WASMConfig `mapstructure:"wasm"`
	}

	// Optionally allow the chain developer to overwrite the SDK's default
	// server config.
	srvCfg := serverconfig.DefaultConfig()
	// The SDK's default minimum gas price is set to "" (empty value) inside
	// app.toml. If left empty by validators, the node will halt on startup.
	// However, the chain developer can set a default app.toml value for their
	// validators here.
	//
	// In summary:
	// - if you leave srvCfg.MinGasPrices = "", all validators MUST tweak their
	//   own app.toml config,
	// - if you set srvCfg.MinGasPrices non-empty, validators CAN tweak their
	//   own app.toml to override, or use this default value.
	//
	// In simapp, we set the min gas prices to 0.
	srvCfg.MinGasPrices = "0ukuji"
	// srvCfg.BaseConfig.IAVLDisableFastNode = true // disable fastnode by default

	customAppConfig := CustomAppConfig{
		Config: *srvCfg,
		WASM: WASMConfig{
			LruSize:       1,
			QueryGasLimit: 30000000,
		},
	}

	customAppTemplate := serverconfig.DefaultConfigTemplate + `
 [wasm]
 # This is the maximum sdk gas (wasm and storage) that we allow for any x/wasm "smart" queries
 query_gas_limit = 30000000
 # This is the number of wasm vm instances we keep cached in memory for speed-up
 # Warning: this is currently unstable and may lead to crashes, best to keep for 0 unless testing locally
 lru_size = 0`

	return customAppTemplate, customAppConfig
}

func initRootCmd(rootCmd *cobra.Command, encodingConfig params.EncodingConfig) {
	a := appCreator{encodingConfig}
	rootCmd.AddCommand(
		genutilcli.InitCmd(app.ModuleBasics, app.DefaultNodeHome),
		genutilcli.GenesisCoreCommand(encodingConfig.TxConfig, app.ModuleBasics, app.DefaultNodeHome),
		tmcli.NewCompletionCmd(rootCmd, true),
		debug.Cmd(),
		config.Cmd(),
		pruning.PruningCmd(a.newApp),
	)

	server.AddCommands(rootCmd, app.DefaultNodeHome, a.newApp, a.appExport, addModuleInitFlags)

	// add keybase, auxiliary RPC, query, and tx child commands
	rootCmd.AddCommand(
		rpc.StatusCommand(),
		queryCommand(),
		txCommand(),
		keys.Commands(app.DefaultNodeHome),
	)

	// add rosetta
	rootCmd.AddCommand(rosettaCmd.RosettaCommand(encodingConfig.InterfaceRegistry, encodingConfig.Codec))
}

func addModuleInitFlags(startCmd *cobra.Command) {
	crisis.AddModuleInitFlags(startCmd)
}

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetAccountCmd(),
		rpc.ValidatorCommand(),
		rpc.BlockCommand(),
		authcmd.QueryTxsByEventsCmd(),
		//		authcmd.QueryTxCmd(),
		QueryTxCmd(),
		QueryTxCmdServer(),
	)

	app.ModuleBasics.AddQueryCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

func QueryTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx hash",
		Short: "Query for a transaction by hash",
		Long:  "",
		Args:  cobra.ExactArgs(1),
		RunE:  queryTx,
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func QueryTxCmdServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start-api",
		Short: "Start API server for transaction query",
		Long:  "",
		Args:  cobra.NoArgs,
		RunE:  queryTx,
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

type apiError struct {
	Message string     `json:"message"`
	Code    codes.Code `json:"code"`
	Details []string   `json:"details"`
}

func queryTx(cmd *cobra.Command, args []string) error {

	if len(args) > 0 {
		clientCtx, err := client.GetClientQueryContext(cmd)
		if err != nil {
			return err
		}
		clientCtx.Output = os.Stdout

		if args[0] == "" {
			return fmt.Errorf("argument should be a tx hash")
		}
		txResult, err := getTx(clientCtx, args[0])
		if err != nil {
			return err
		}
		return clientCtx.PrintProto(txResult)
	}
	r := mux.NewRouter()
	r.HandleFunc("/cosmos/tx/v1beta1/txs/{hash}", func(w http.ResponseWriter, r *http.Request) {
		clientCtx, err := client.GetClientQueryContext(cmd)
		if err != nil {
			http.Error(w, "Failed to get client query context", http.StatusInternalServerError)
			return
		}
		buffer := new(bytes.Buffer)
		clientCtx.Output = buffer

		vars := mux.Vars(r)
		txHash := vars["hash"]
		txResult, err := getTx(clientCtx, txHash)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				notFound := apiError{
					Message: fmt.Sprintf("tx not found: %s", txHash),
					Code:    codes.NotFound,
					Details: []string{err.Error()},
				}
				notFoundJSON, _ := json.Marshal(notFound)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(notFoundJSON)
				return
			}
			rpcResponseError := apiError{
				Message: fmt.Sprintf("unable to process %s", txHash),
				Code:    codes.NotFound,
				Details: []string{err.Error()},
			}
			rpcResponseErrorJSON, _ := json.Marshal(rpcResponseError)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(rpcResponseErrorJSON)
			return

		}
		if err := clientCtx.PrintProto(txResult); err != nil {
			http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(buffer.Bytes())
		if err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	fmt.Println("Starting API server on port 1317...")
	if err := http.ListenAndServe(":1317", r); err != nil {
		return fmt.Errorf("Error starting server: %s", err)
	}
	return nil
}

func getTx(clientCtx client.Context, txhash string) (*txtypes.GetTxResponse, error) {
	result, err := authtx.QueryTx(clientCtx, txhash)
	if err != nil {
		return nil, err
	}
	if result.Empty() {
		return nil, fmt.Errorf("tx not found %s", txhash)
	}
	protoTx, ok := result.Tx.GetCachedValue().(*txtypes.Tx)
	if !ok {
		return nil, fmt.Errorf("expected %T, got %T", txtypes.Tx{}, result.Tx.GetCachedValue())
	}
	return &txtypes.GetTxResponse{
		Tx:         protoTx,
		TxResponse: result,
	}, nil
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetMultiSignBatchCmd(),
		authcmd.GetValidateSignaturesCommand(),
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		authcmd.GetAuxToFeeCommand(),
	)

	app.ModuleBasics.AddTxCommands(cmd)
	cmd.PersistentFlags().String(flags.FlagChainID, "", "The network chain ID")

	return cmd
}

type appCreator struct {
	encCfg params.EncodingConfig
}

// newApp is an appCreator
func (a appCreator) newApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) servertypes.Application {
	var wasmOpts []wasmkeeper.Option
	if cast.ToBool(appOpts.Get("telemetry.enabled")) {
		wasmOpts = append(wasmOpts, wasmkeeper.WithVMCacheMetrics(prometheus.DefaultRegisterer))
	}

	skipUpgradeHeights := make(map[int64]bool)
	for _, h := range cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades)) {
		skipUpgradeHeights[int64(h)] = true
	}
	baseappOptions := server.DefaultBaseappOptions(appOpts)
	return app.New(
		logger,
		db,
		traceStore,
		true,
		a.encCfg,
		appOpts,
		wasmOpts,
		baseappOptions...,
	)
}

// appExport creates a new kujiraApp (optionally at a given height)
// and exports state.
func (a appCreator) appExport(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	var kujiraApp *app.App
	homePath, ok := appOpts.Get(flags.FlagHome).(string)
	if !ok || homePath == "" {
		return servertypes.ExportedApp{}, errors.New("application home is not set")
	}

	loadLatest := height == -1
	var emptyWasmOpts []wasmkeeper.Option
	kujiraApp = app.New(
		logger,
		db,
		traceStore,
		loadLatest,
		a.encCfg,
		appOpts,
		emptyWasmOpts,
	)

	if height != -1 {
		if err := kujiraApp.LoadHeight(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	}

	return kujiraApp.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}
