// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// The go-obsidian library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-obsidian library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-obsidian library. If not, see <http://www.gnu.org/licenses/>.

package tendermint

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is the RPC API for the Tendermint consensus engine
type API struct {
	chain      consensus.ChainHeaderReader
	tendermint *Tendermint
}

// GetSnapshot retrieves the state snapshot at a given block
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.tendermint.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block hash
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.tendermint.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetValidators retrieves the list of validators at the specified block
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}

	snap, err := api.tendermint.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.validators(), nil
}

// GetValidatorsAtHash retrieves the list of validators at a given block hash
func (api *API) GetValidatorsAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.tendermint.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.validators(), nil
}

// Propose injects a new validator proposal
func (api *API) Propose(address common.Address, auth bool) {
	api.tendermint.lock.Lock()
	defer api.tendermint.lock.Unlock()

	api.tendermint.proposals[address] = auth
}

// Discard drops a currently running proposal
func (api *API) Discard(address common.Address) {
	api.tendermint.lock.Lock()
	defer api.tendermint.lock.Unlock()

	delete(api.tendermint.proposals, address)
}

// Status returns the current validator status
func (api *API) Status() (*ValidatorStatus, error) {
	header := api.chain.CurrentHeader()
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.tendermint.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}

	api.tendermint.lock.RLock()
	signer := api.tendermint.signer
	api.tendermint.lock.RUnlock()

	_, authorized := snap.Validators[signer]
	inturn := snap.inturn(header.Number.Uint64()+1, signer)

	return &ValidatorStatus{
		Validator:     signer,
		Authorized:    authorized,
		Inturn:        inturn,
		BlockPeriod:   api.tendermint.config.Period,
		NumValidators: len(snap.Validators),
	}, nil
}

// ValidatorStatus represents the current status of a validator
type ValidatorStatus struct {
	Validator     common.Address `json:"validator"`
	Authorized    bool           `json:"authorized"`
	Inturn        bool           `json:"inturn"`
	BlockPeriod   uint64         `json:"blockPeriod"`
	NumValidators int            `json:"numValidators"`
}
