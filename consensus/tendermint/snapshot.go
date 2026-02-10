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
	"bytes"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// Vote represents a single vote that an authorized validator made to modify the
// list of authorizations.
type Vote struct {
	Validator common.Address `json:"validator"` // Authorized validator that cast this vote
	Block     uint64         `json:"block"`     // Block number the vote was cast in
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account
}

// Tally is a simple vote tally to keep the current score of votes.
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or deauthorizing
	Votes     int  `json:"votes"`     // Number of votes until now
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.TendermintConfig // Consensus engine parameters to fine tune behavior
	sigcache *sigLRU

	Number     uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Validators map[common.Address]struct{} `json:"validators"` // Set of authorized validators at this moment
	Stakes     map[common.Address]*big.Int `json:"stakes"`     // Stake amounts for each validator
	Recents    map[uint64]common.Address   `json:"recents"`    // Set of recent validators for spam protections
	Votes      []*Vote                     `json:"votes"`      // List of votes cast in chronological order
	Tally      map[common.Address]Tally    `json:"tally"`      // Current vote tally to avoid recalculating
}

// validatorsAscending implements the sort interface to allow sorting a list of addresses
type validatorsAscending []common.Address

func (s validatorsAscending) Len() int           { return len(s) }
func (s validatorsAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s validatorsAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newSnapshot creates a new snapshot with the specified startup parameters.
func newSnapshot(config *params.TendermintConfig, sigcache *sigLRU, number uint64, hash common.Hash, validators []common.Address) *Snapshot {
	snap := &Snapshot{
		config:     config,
		sigcache:   sigcache,
		Number:     number,
		Hash:       hash,
		Validators: make(map[common.Address]struct{}),
		Stakes:     make(map[common.Address]*big.Int),
		Recents:    make(map[uint64]common.Address),
		Tally:      make(map[common.Address]Tally),
	}
	for _, validator := range validators {
		snap.Validators[validator] = struct{}{}
		// Initialize with minimum stake
		if config.MinStake != nil {
			snap.Stakes[validator] = new(big.Int).Set(config.MinStake)
		} else {
			snap.Stakes[validator] = big.NewInt(1000000000000000000) // 1 ETH default
		}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.TendermintConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("tendermint-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("tendermint-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:     s.config,
		sigcache:   s.sigcache,
		Number:     s.Number,
		Hash:       s.Hash,
		Validators: make(map[common.Address]struct{}),
		Stakes:     make(map[common.Address]*big.Int),
		Recents:    make(map[uint64]common.Address),
		Votes:      make([]*Vote, len(s.Votes)),
		Tally:      make(map[common.Address]Tally),
	}
	for validator := range s.Validators {
		cpy.Validators[validator] = struct{}{}
	}
	for validator, stake := range s.Stakes {
		cpy.Stakes[validator] = new(big.Int).Set(stake)
	}
	for block, validator := range s.Recents {
		cpy.Recents[block] = validator
	}
	for i, vote := range s.Votes {
		cpy.Votes[i] = new(Vote)
		*cpy.Votes[i] = *vote
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context.
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, validator := s.Validators[address]
	return (authorize && !validator) || (!authorize && validator)
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		number := header.Number.Uint64()

		// Delete the oldest validator from the recent list to allow it signing again
		// Slashing Relaxation: Increase the recent signing limit to allow more frequent rotations
		// Original: limit := uint64(len(snap.Validators)/2 + 1)
		// Relaxed: limit := uint64(len(snap.Validators)/3 + 1)
		if limit := uint64(len(snap.Validators)/3 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}

		// Resolve the authorization key and check against validators
		validator, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Validators[validator]; !ok {
			return nil, errUnauthorizedValidator
		}
		for _, recent := range snap.Recents {
			if recent == validator {
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = validator

		// Header authorized, discard any previous votes from the validator
		for i, vote := range snap.Votes {
			if vote.Validator == validator && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // only one vote allowed
			}
		}
		// Tally up the new vote from the validator
		var authorize bool
		switch {
		case bytes.Equal(header.Nonce[:], nonceAuthVote):
			authorize = true
		case bytes.Equal(header.Nonce[:], nonceDropVote):
			authorize = false
		default:
			return nil, errInvalidVote
		}
		if snap.cast(header.Coinbase, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Validator: validator,
				Block:     number,
				Address:   header.Coinbase,
				Authorize: authorize,
			})
		}
		// If the vote passed, update the list of validators
		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Validators)/2 {
			if tally.Authorize {
				snap.Validators[header.Coinbase] = struct{}{}
				if snap.config.MinStake != nil {
					snap.Stakes[header.Coinbase] = new(big.Int).Set(snap.config.MinStake)
				} else {
					snap.Stakes[header.Coinbase] = big.NewInt(1000000000000000000)
				}
			} else {
				delete(snap.Validators, header.Coinbase)
				delete(snap.Stakes, header.Coinbase)

				// Discard any previous votes the deauthorized validator cast
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Validator == header.Coinbase {
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase)
		}

		// If we're at a checkpoint block, reset the votes
		if number%snap.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// validators retrieves the list of authorized validators in ascending order.
func (s *Snapshot) validators() []common.Address {
	validators := make([]common.Address, 0, len(s.Validators))
	for validator := range s.Validators {
		validators = append(validators, validator)
	}
	sort.Sort(validatorsAscending(validators))
	return validators
}

// inturn returns if a validator at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, validator common.Address) bool {
	validators := s.validators()
	for i, v := range validators {
		if v == validator {
			return number%uint64(len(validators)) == uint64(i)
		}
	}
	return false
}