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

// Package tendermint implements the Tendermint PoS consensus engine.
package tendermint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

const (
	// checkpointInterval is the number of blocks after which to save the validator snapshot
	checkpointInterval = 1024

	// inmemorySnapshots is the number of recent snapshots to keep in memory
	inmemorySnapshots = 128

	// inmemorySignatures is the number of recent block signatures to keep in memory
	inmemorySignatures = 4096

	// DefaultBlockPeriod is the default block time (2 seconds for Tendermint PoS)
	DefaultBlockPeriod = 2
)

// Tendermint PoS protocol constants
var (
	// epochLength is the default number of blocks after which to checkpoint
	epochLength = uint64(30000)

	// extraVanity is the fixed number of extra-data prefix bytes reserved for validator vanity
	extraVanity = 32

	// extraSeal is the fixed number of extra-data suffix bytes reserved for validator seal
	extraSeal = crypto.SignatureLength

	// uncleHash is always Keccak256(RLP([])) as uncles are meaningless in PoS
	uncleHash = types.CalcUncleHash(nil)

	// diffInTurn is the block difficulty for in-turn validators
	diffInTurn = big.NewInt(2)

	// diffNoTurn is the block difficulty for out-of-turn validators
	diffNoTurn = big.NewInt(1)

	// Magic nonce for validator votes
	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff")
	nonceDropVote = hexutil.MustDecode("0x0000000000000000")
)

// Various error messages
var (
	errUnknownBlock                    = errors.New("unknown block")
	errInvalidCheckpointBeneficiary    = errors.New("beneficiary in checkpoint block non-zero")
	errInvalidVote                     = errors.New("vote nonce not 0x00..0 or 0xff..f")
	errInvalidCheckpointVote           = errors.New("vote nonce in checkpoint block non-zero")
	errMissingVanity                   = errors.New("extra-data 32 byte vanity prefix missing")
	errMissingSignature                = errors.New("extra-data 65 byte signature suffix missing")
	errExtraValidators                 = errors.New("non-checkpoint block contains extra validator list")
	errInvalidCheckpointValidators     = errors.New("invalid validator list on checkpoint block")
	errInvalidMixDigest                = errors.New("non-zero mix digest")
	errInvalidUncleHash                = errors.New("non empty uncle hash")
	errInvalidDifficulty               = errors.New("invalid difficulty")
	errInvalidTimestamp                = errors.New("invalid timestamp")
	errInvalidVotingChain              = errors.New("invalid voting chain")
	errUnauthorizedValidator           = errors.New("unauthorized validator")
	errRecentlySigned                  = errors.New("recently signed")
)

// sigLRU is a type alias for the signature LRU cache
type sigLRU = lru.Cache[common.Hash, common.Address]

// SignerFn is a callback for signing
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// Tendermint is the Tendermint PoS consensus engine
type Tendermint struct {
	config *params.TendermintConfig // Consensus engine configuration
	db     ethdb.Database           // Database for snapshot checkpoints

	recents    *lru.Cache[common.Hash, *Snapshot] // Recent snapshots for reorg speed
	signatures *sigLRU                            // Recent block signatures

	proposals map[common.Address]bool // Current validator proposals

	signer common.Address // Obsidian address of this validator
	signFn SignerFn       // Signing function
	lock   sync.RWMutex   // Protects signer and proposals
}

// New creates a new Tendermint PoS consensus engine
func New(config *params.TendermintConfig, db ethdb.Database) *Tendermint {
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	if conf.Period == 0 {
		conf.Period = DefaultBlockPeriod
	}

	recents := lru.NewCache[common.Hash, *Snapshot](inmemorySnapshots)
	signatures := lru.NewCache[common.Hash, common.Address](inmemorySignatures)

	return &Tendermint{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
	}
}

// Author returns the Obsidian address of the block validator
func (t *Tendermint) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, t.signatures)
}

// VerifyHeader checks whether a header conforms to consensus rules
func (t *Tendermint) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	return t.verifyHeader(chain, header, nil)
}

// VerifyHeaders verifies a batch of headers concurrently
func (t *Tendermint) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	// Optimization: Verify headers in parallel
	var wg sync.WaitGroup
	for i, header := range headers {
		wg.Add(1)
		go func(i int, header *types.Header) {
			defer wg.Done()
			err := t.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}(i, header)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return abort, results
}

// verifyHeader checks whether a header conforms to consensus rules
func (t *Tendermint) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't verify future blocks
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Check checkpoint rules
	checkpoint := (number % t.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}

	// Check nonce
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}

	// Check extra-data
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	validatorsBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && validatorsBytes != 0 {
		return errExtraValidators
	}
	if checkpoint && validatorsBytes%common.AddressLength != 0 {
		return errInvalidCheckpointValidators
	}

	// Check MixDigest
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Check UncleHash
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// Check difficulty
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}

	// Verify gas limit
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}

	// Verify base fee
	if err := eip1559.VerifyEIP1559Header(chain.Config(), nil, header); err != nil {
		return err
	}

	// All basic checks passed, verify cascading fields
	return t.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies header fields that depend on previous headers
func (t *Tendermint) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	// Get parent header
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	// Check timestamp (must be at least period seconds after parent)
	if parent.Time+t.config.Period > header.Time {
		return errInvalidTimestamp
	}

	// Verify gasUsed <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	return nil
}

// VerifyUncles verifies that the given block has no uncles (PoS has no uncles)
func (t *Tendermint) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed in Tendermint PoS")
	}
	return nil
}

// Prepare initializes the consensus fields of a block header
func (t *Tendermint) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()

	// Get validator snapshot
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Set coinbase for non-checkpoint blocks
	t.lock.RLock()
	if number%t.config.Epoch != 0 {
		// Gather all the proposals that make sense voting on
		addresses := make([]common.Address, 0, len(t.proposals))
		for address, authorize := range t.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			header.Coinbase = addresses[0]
			if t.proposals[header.Coinbase] {
				copy(header.Nonce[:], nonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}
	}

	// Copy signer protected by mutex
	signer := t.signer
	t.lock.RUnlock()

	// Set difficulty
	header.Difficulty = calcDifficulty(snap, signer)

	// Set extra data
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	// Add validators on checkpoint
	if number%t.config.Epoch == 0 {
		for _, validator := range snap.validators() {
			header.Extra = append(header.Extra, validator[:]...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Set mix digest
	header.MixDigest = common.Hash{}

	// Ensure timestamp has correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + t.config.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	return nil
}

// Finalize runs post-transaction state modifications.
// Tendermint PoS has no block rewards at the execution layer.
func (t *Tendermint) Finalize(chain consensus.ChainHeaderReader, header *types.Header, statedb vm.StateDB, body *types.Body) {
	// No block rewards in Tendermint PoS at the execution layer
	// Rewards are handled at the consensus layer
}

// FinalizeAndAssemble runs post-transaction modifications and assembles the block
func (t *Tendermint) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	if len(body.Withdrawals) > 0 {
		return nil, errors.New("tendermint does not support withdrawals")
	}

	// Finalize block
	t.Finalize(chain, header, statedb, body)

	// Assign the final state root to header
	header.Root = statedb.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the final block for sealing
	return types.NewBlock(header, &types.Body{Transactions: body.Transactions}, receipts, trie.NewStackTrie(nil)), nil
}

// Seal generates a new block with valid consensus seal
func (t *Tendermint) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	number := header.Number.Uint64()

	// Genesis block not sealable
	if number == 0 {
		return errUnknownBlock
	}

	// Don't hold lock while waiting
	t.lock.RLock()
	signer, signFn := t.signer, t.signFn
	t.lock.RUnlock()

	if signFn == nil {
		return errors.New("signing function not set")
	}

	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, authorized := snap.Validators[signer]; !authorized {
		return errUnauthorizedValidator
	}

	// Check if we recently signed
	// Slashing Relaxation: Use the relaxed limit (1/3 instead of 1/2)
	for seen, recent := range snap.Recents {
		if recent == signer {
			limit := uint64(len(snap.Validators)/3 + 1)
			if number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others (relaxed limit)")
				return nil
			}
		}
	}

	// Calculate delay
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// Out-of-turn validators wait a bit
		// Slashing Relaxation: Reduce out-of-turn wiggle room to improve block production stability
		wiggle := time.Duration(len(snap.Validators)/3+1) * time.Duration(t.config.Period) * time.Second / 2
		delay += wiggle

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}

	// Sign the block
	sighash, err := signFn(accounts.Account{Address: signer}, "", SealHash(header).Bytes())
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// Wait for seal or stop
	select {
	case <-stop:
		return nil
	case <-time.After(delay):
	}

	select {
	case results <- block.WithSeal(header):
	default:
		log.Warn("Sealing result not read by miner", "sealhash", SealHash(header))
	}
	return nil
}

// SealHash returns the hash of a block prior to being sealed
func (t *Tendermint) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// CalcDifficulty calculates the difficulty for a new block
func (t *Tendermint) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := t.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	t.lock.RLock()
	signer := t.signer
	t.lock.RUnlock()
	return calcDifficulty(snap, signer)
}

// calcDifficulty returns the difficulty for a new block
func calcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(snap.Number+1, signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// Close terminates any background threads
func (t *Tendermint) Close() error {
	return nil
}

// APIs returns the RPC APIs this consensus engine provides
func (t *Tendermint) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "tendermint",
		Service:   &API{chain: chain, tendermint: t},
	}}
}

// Authorize sets the signer and signing function
func (t *Tendermint) Authorize(signer common.Address, signFn SignerFn) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.signer = signer
	t.signFn = signFn
}

// SealHash returns the hash of a block prior to being sealed
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSealHash(hasher, header)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// encodeSealHash encodes the header for seal hash calculation
func encodeSealHash(hasher io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength],
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		enc = append(enc, header.WithdrawalsHash)
	}
	if header.BlobGasUsed != nil {
		enc = append(enc, header.BlobGasUsed)
	}
	if header.ExcessBlobGas != nil {
		enc = append(enc, header.ExcessBlobGas)
	}
	if header.ParentBeaconRoot != nil {
		enc = append(enc, header.ParentBeaconRoot)
	}
	rlp.Encode(hasher, enc)
}

// ecrecover extracts the Obsidian address from a signed header
func ecrecover(header *types.Header, sigcache *sigLRU) (common.Address, error) {
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address, nil
	}
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// snapshot retrieves the validator snapshot at a given point
func (t *Tendermint) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	for snap == nil {
		// Check in-memory cache
		if s, ok := t.recents.Get(hash); ok {
			snap = s
			break
		}

		// Check on-disk checkpoint
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(t.config, t.signatures, t.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// Genesis block or checkpoint
		if number == 0 || (number%t.config.Epoch == 0 && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()
				validators := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(validators); i++ {
					copy(validators[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				snap = newSnapshot(t.config, t.signatures, number, hash, validators)
				if err := snap.store(t.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		// Get parent header
		var header *types.Header
		if len(parents) > 0 {
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// Reverse headers
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	// Apply headers to snapshot
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	t.recents.Add(snap.Hash, snap)

	// Store checkpoint
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(t.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, nil
}
