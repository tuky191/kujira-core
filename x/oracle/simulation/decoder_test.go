package simulation_test

import (
	"fmt"
	"testing"

	"cosmossdk.io/math"
	gogotypes "github.com/cosmos/gogoproto/types"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/kv"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	sim "github.com/Team-Kujira/core/x/oracle/simulation"
	"github.com/Team-Kujira/core/x/oracle/types"
)

var (
	delPk      = ed25519.GenPrivKey().PubKey()
	feederAddr = sdk.AccAddress(delPk.Address())
	valAddr    = sdk.ValAddress(delPk.Address())
	denomA     = "testdenoma"
	denomB     = "testdenomb"
)

func TestDecodeDistributionStore(t *testing.T) {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	authtypes.RegisterInterfaces(interfaceRegistry)

	cdc := codec.NewProtoCodec(interfaceRegistry)
	dec := sim.NewDecodeStore(cdc)

	exchangeRate := math.LegacyNewDecWithPrec(1234, 1)
	missCounter := uint64(23)

	aggregatePrevote := types.NewAggregateExchangeRatePrevote(types.AggregateVoteHash([]byte("12345")), valAddr, 123)
	aggregateVote := types.NewAggregateExchangeRateVote(types.ExchangeRateTuples{
		{Denom: denomA, ExchangeRate: math.LegacyNewDecWithPrec(1234, 1)},
		{Denom: denomB, ExchangeRate: math.LegacyNewDecWithPrec(4321, 1)},
	}, valAddr)

	kvPairs := kv.Pairs{
		Pairs: []kv.Pair{
			{Key: types.ExchangeRateKey, Value: cdc.MustMarshal(&sdk.DecProto{Dec: exchangeRate})},
			{Key: types.FeederDelegationKey, Value: feederAddr.Bytes()},
			{Key: types.MissCounterKey, Value: cdc.MustMarshal(&gogotypes.UInt64Value{Value: missCounter})},
			{Key: types.AggregateExchangeRatePrevoteKey, Value: cdc.MustMarshal(&aggregatePrevote)},
			{Key: types.AggregateExchangeRateVoteKey, Value: cdc.MustMarshal(&aggregateVote)},
			{Key: []byte{0x99}, Value: []byte{0x99}},
		},
	}

	tests := []struct {
		name        string
		expectedLog string
	}{
		{"ExchangeRate", fmt.Sprintf("%v\n%v", exchangeRate, exchangeRate)},
		{"FeederDelegation", fmt.Sprintf("%v\n%v", feederAddr, feederAddr)},
		{"MissCounter", fmt.Sprintf("%v\n%v", missCounter, missCounter)},
		{"AggregatePrevote", fmt.Sprintf("%v\n%v", aggregatePrevote, aggregatePrevote)},
		{"AggregateVote", fmt.Sprintf("%v\n%v", aggregateVote, aggregateVote)},
		{"other", ""},
	}

	for i, tt := range tests {
		i, tt := i, tt
		t.Run(tt.name, func(t *testing.T) {
			switch i {
			case len(tests) - 1:
				require.Panics(t, func() { dec(kvPairs.Pairs[i], kvPairs.Pairs[i]) }, tt.name)
			default:
				require.Equal(t, tt.expectedLog, dec(kvPairs.Pairs[i], kvPairs.Pairs[i]), tt.name)
			}
		})
	}
}
