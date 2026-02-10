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

// Package tendermint implements the Tendermint-based Proof of Stake consensus engine.
package tendermint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"sync"
	"time"

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
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

const (
	// DefaultBlockTime is the default block time in seconds (2 seconds)
	DefaultBlockTime = 2

	// checkpointInterval is the number of blocks after which to save the validator snapshot
	checkpointInterval = 1024

	// inmemorySnapshots is the number of recent vote snapshots to keep in memory
	inmemorySnapshots = 128

	// inmemorySignatures is the number of recent block signatures to keep in memory
	inmemorySignatures = 4096
)

// sigLRU is the type alias for signature cache
type sigLRU = lru.Cache[common.Hash, common.Address]

// Tendermint PoS protocol constants
var (
	// epochLength is the default number of blocks after which to checkpoint and reset the pending votes
	epochLength = uint64(30000)

	// extraVanity is the fixed number of extra-data prefix bytes reserved for validator vanity
	extraVanity = 32

	// extraSeal is the fixed number of extra-data suffix bytes reserved for validator seal
	extraSeal = crypto.SignatureLength

	// nonceAuthVote is the magic nonce number to vote on adding a new validator
	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff")

	// nonceDropVote is the magic nonce number to vote on removing a validator
	nonceDropVote = hexutil.MustDecode("0x0000000000000000")

	// uncleHash is always Keccak256(RLP([])) as uncles are meaningless in PoS
	uncleHash = types.CalcUncleHash(nil)

	// diffInTurn is the block difficulty for in-turn validators
	diffInTurn = big.NewInt(2)

	// diffNoTurn is the block difficulty for out-of-turn validators
	diffNoTurn = big.NewInt(1)
)

// Various error messages to mark blocks invalid
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the validator vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-checkpoint block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-checkpoint block contains extra validator list")

	// errInvalidCheckpointValidators is returned if a checkpoint block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidCheckpointValidators = errors.New("invalid validator list on checkpoint block")

	// errMismatchingCheckpointValidators is returned if a checkpoint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingCheckpointValidators = errors.New("mismatching validator list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the validator.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errInsufficientStake is returned if a validator doesn't have sufficient stake
	errInsufficientStake = errors.New("insufficient stake for validation")
)

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(account common.Address, mimeType string, data []byte) ([]byte, error)

// Validator represents a PoS validator with stake information
type Validator struct {
	Address common.Address
	Stake   *big.Int
}

// Tendermint is the Tendermint-based PoS consensus engine.
type Tendermint struct {
	config *params.TendermintConfig // Consensus engine configuration parameters
	db     ethdb.Database           // Database to store and retrieve snapshot checkpoints

	recents    *lru.Cache[common.Hash, *Snapshot] // Snapshots for recent block to speed up reorgs
	signatures *sigLRU                            // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer and proposals fields

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Tendermint PoS consensus engine with the initial validators set
// from the genesis block's extra-data.
func New(config *params.TendermintConfig, db ethdb.Database) *Tendermint {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	if conf.Period == 0 {
		conf.Period = DefaultBlockTime
	}
	if conf.MinStake == nil {
		conf.MinStake = big.NewInt(1000000000000000000) // 1 ETH default
	}

	// Allocate the snapshot caches and create the engine
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

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (t *Tendermint) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, t.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (t *Tendermint) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	return t.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (t *Tendermint) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := t.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.
func (t *Tendermint) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % t.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}

	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}

	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// Ensure that the extra-data contains a validator list on checkpoint, but none otherwise
	validatorsBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && validatorsBytes != 0 {
		return errExtraValidators
	}
	if checkpoint && validatorsBytes%common.AddressLength != 0 {
		return errInvalidCheckpointValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}

	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}

	// All basic checks passed, verify cascading fields
	return t.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone
func (t *Tendermint) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+t.config.Period > header.Time {
		return errInvalidTimestamp
	}

	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify the base fee if enabled
	if chain.Config().IsLondon(header.Number) {
		if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
			return err
		}
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := t.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// If the block is a checkpoint block, verify the validator list
	if number%t.config.Epoch == 0 {
		validators := snap.validators()
		extraValidators := make([]byte, len(validators)*common.AddressLength)
		for i, validator := range validators {
			copy(extraValidators[i*common.AddressLength:], validator[:])
		}
		if !bytes.Equal(header.Extra[extraVanity:len(header.Extra)-extraSeal], extraValidators) {
			return errMismatchingCheckpointValidators
		}
	}

	// All basic checks passed, verify the seal and return
	return t.verifySeal(snap, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time
func (t *Tendermint) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := t.recents.Get(hash); ok {
			snap = s
			break
		}

		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(t.config, t.signatures, t.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		// If we're at the genesis, snapshot the initial state.
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(0)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				validators := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(validators); i++ {
					copy(validators[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				snap = newSnapshot(t.config, t.signatures, 0, hash, validators)
				if err := snap.store(t.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", 0, "hash", hash)
				break
			}
		}

		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	t.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(t.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (t *Tendermint) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements.
func (t *Tendermint) verifySeal(snap *Snapshot, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, t.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}

	// Check that the validator has sufficient stake
	if snap.Stakes[signer] == nil || snap.Stakes[signer].Cmp(t.config.MinStake) < 0 {
		return errInsufficientStake
	}

	for seen, recent := range snap.Recents {
		if recent == signer {
			// Validator is among recents, only wait if current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}

	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !t.fakeDiff {
		inturn := snap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (t *Tendermint) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()

	// Assemble the voting snapshot to check which votes make sense
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	t.lock.RLock()

	// Gather all the proposals that make sense voting on
	addresses := make([]common.Address, 0, len(t.proposals))
	for address, authorize := range t.proposals {
		if snap.validVote(address, authorize) {
			addresses = append(addresses, address)
		}
	}
	// If there's pending proposals, cast a vote on them
	if len(addresses) > 0 {
		header.Coinbase = addresses[mrand.Intn(len(addresses))]
		if t.proposals[header.Coinbase] {
			copy(header.Nonce[:], nonceAuthVote)
		} else {
			copy(header.Nonce[:], nonceDropVote)
		}
	}
	t.lock.RUnlock()

	// Set the correct difficulty
	header.Difficulty = calcDifficulty(snap, t.signer)

	// Ensure the extra data has all its components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	if number%t.config.Epoch == 0 {
		for _, validator := range snap.validators() {
			header.Extra = append(header.Extra, validator[:]...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
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

// Finalize implements consensus.Engine, ensuring no uncles are set
func (t *Tendermint) Finalize(chain consensus.ChainHeaderReader, header *types.Header, statedb vm.StateDB, body *types.Body) {
	// No block rewards in Tendermint PoS
	// Just set uncle hash since PoS doesn't have uncles
	header.UncleHash = types.CalcUncleHash(nil)
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// assembling the final block.
func (t *Tendermint) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	t.Finalize(chain, header, statedb, body)

	// Assign the final state root to header.
	header.Root = statedb.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the final block for sealing
	return types.NewBlock(header, body, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks with.
func (t *Tendermint) Authorize(signer common.Address, signFn SignerFn) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.signer = signer
	t.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (t *Tendermint) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Don't hold the signer fields for the entire sealing procedure
	t.lock.RLock()
	signer, signFn := t.signer, t.signFn
	t.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, authorized := snap.Validators[signer]; !authorized {
		return errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only wait if current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Until(time.Unix(int64(header.Time), 0))
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTime
		delay += time.Duration(mrand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}

	// Sign all the things!
	sighash, err := signFn(signer, "application/x-tendermint-header", TendermintRLP(header))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	// Wait until sealing is terminated or delay timeout
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (t *Tendermint) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := t.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, t.signer)
}

func calcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(snap.Number+1, signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (t *Tendermint) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for tendermint.
func (t *Tendermint) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API.
func (t *Tendermint) APIs(chain consensus.ChainHeaderReader) []any {
	return []any{&API{chain: chain, tendermint: t}}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) common.Hash {
	return sealHash(header)
}

func sealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeTendermintSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

// TendermintRLP returns the rlp bytes which needs to be signed for the Tendermint
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
func TendermintRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeTendermintSigHeader(b, header)
	return b.Bytes()
}

func encodeTendermintSigHeader(w io.Writer, header *types.Header) {
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
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *sigLRU) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, ok := sigcache.Get(hash); ok {
		return address, nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// wiggleTime is the random delay added for out-of-turn validators
var wiggleTime = 500 * time.Millisecond

// Propose injects a new authorization proposal that the validator will attempt to
// push through.
func (t *Tendermint) Propose(address common.Address, auth bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.proposals[address] = auth
}

// Discard drops a currently running proposal, stopping the validator from casting
// further votes (either for or against).
func (t *Tendermint) Discard(address common.Address) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.proposals, address)
}
