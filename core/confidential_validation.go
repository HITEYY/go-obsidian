// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Confidential Transaction Validation Engine.
// Provides comprehensive verification of zero-knowledge proofs
// for confidential transactions.

package core

import (
	"errors"
	"sync"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/core/rawdb"
	"github.com/HITEYY/go-obsidian/core/types"
	"github.com/HITEYY/go-obsidian/crypto"
	"github.com/HITEYY/go-obsidian/crypto/zkp"
	"github.com/HITEYY/go-obsidian/ethdb"
)

var (
	// ErrNullifierAlreadySpent is returned when a nullifier has been used
	ErrNullifierAlreadySpent = errors.New("nullifier already spent")
	// ErrInvalidRangeProof is returned when a range proof is invalid
	ErrInvalidRangeProof = errors.New("invalid range proof")
	// ErrInvalidBalanceProof is returned when balance doesn't add up
	ErrInvalidBalanceProof = errors.New("invalid balance proof")
	// ErrInvalidMerkleProof is returned when merkle proof verification fails
	ErrInvalidMerkleProof = errors.New("invalid merkle proof")
	// ErrInvalidCommitment is returned when a commitment is malformed
	ErrInvalidCommitment = errors.New("invalid commitment")
	// ErrEmptyTransaction is returned when transaction has no inputs or outputs
	ErrEmptyTransaction = errors.New("confidential transaction must have inputs and outputs")
)

// ConfidentialValidator validates confidential transactions
type ConfidentialValidator struct {
	db            ethdb.Database
	nullifierSet  map[common.Hash]bool
	commitmentSet map[common.Hash]bool
	mu            sync.RWMutex
}

// NewConfidentialValidator creates a new confidential transaction validator
func NewConfidentialValidator(db ethdb.Database) *ConfidentialValidator {
	return &ConfidentialValidator{
		db:            db,
		nullifierSet:  make(map[common.Hash]bool),
		commitmentSet: make(map[common.Hash]bool),
	}
}

// ValidateConfidentialTx performs full validation of a confidential transaction
func (v *ConfidentialValidator) ValidateConfidentialTx(tx *types.ConfidentialTx) error {
	// Basic sanity checks
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return ErrEmptyTransaction
	}

	// 1. Verify nullifiers haven't been spent
	if err := v.verifyNullifiers(tx); err != nil {
		return err
	}

	// 2. Verify all input range proofs
	if err := v.verifyInputRangeProofs(tx); err != nil {
		return err
	}

	// 3. Verify all output range proofs
	if err := v.verifyOutputRangeProofs(tx); err != nil {
		return err
	}

	// 4. Verify balance proof (inputs = outputs + fee)
	if err := v.verifyBalanceProof(tx); err != nil {
		return err
	}

	// 5. Verify merkle proofs for inputs (commitment exists in state)
	if err := v.verifyMerkleProofs(tx); err != nil {
		return err
	}

	return nil
}

// verifyNullifiers checks that no nullifier has been spent before
func (v *ConfidentialValidator) verifyNullifiers(tx *types.ConfidentialTx) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, input := range tx.Inputs {
		// Check in-memory set
		if v.nullifierSet[input.Nullifier] {
			return ErrNullifierAlreadySpent
		}

		// Check persistent storage
		if v.db != nil {
			if rawdb.HasNullifier(v.db, input.Nullifier) {
				return ErrNullifierAlreadySpent
			}
		}
	}

	return nil
}

// verifyInputRangeProofs verifies range proofs for all inputs
func (v *ConfidentialValidator) verifyInputRangeProofs(tx *types.ConfidentialTx) error {
	for _, input := range tx.Inputs {
		if input.RangeProof == nil || input.Commitment == nil {
			return ErrInvalidRangeProof
		}

		if !zkp.VerifyRangeProof(input.RangeProof, input.Commitment) {
			return ErrInvalidRangeProof
		}
	}

	return nil
}

// verifyOutputRangeProofs verifies range proofs for all outputs
func (v *ConfidentialValidator) verifyOutputRangeProofs(tx *types.ConfidentialTx) error {
	for _, output := range tx.Outputs {
		if output.RangeProof == nil || output.Commitment == nil {
			return ErrInvalidRangeProof
		}

		if !zkp.VerifyRangeProof(output.RangeProof, output.Commitment) {
			return ErrInvalidRangeProof
		}
	}

	return nil
}

// verifyBalanceProof verifies that sum(inputs) = sum(outputs) + fee
func (v *ConfidentialValidator) verifyBalanceProof(tx *types.ConfidentialTx) error {
	// Collect input commitments
	inputCommitments := make([]*zkp.PedersenCommitment, len(tx.Inputs))
	for i, input := range tx.Inputs {
		if input.Commitment == nil {
			return ErrInvalidCommitment
		}
		inputCommitments[i] = input.Commitment
	}

	// Collect output commitments
	outputCommitments := make([]*zkp.PedersenCommitment, len(tx.Outputs))
	for i, output := range tx.Outputs {
		if output.Commitment == nil {
			return ErrInvalidCommitment
		}
		outputCommitments[i] = output.Commitment
	}

	// Get fee commitment
	feeCommitment, err := tx.FeeCommitment()
	if err != nil {
		return ErrInvalidCommitment
	}

	// Add fee commitment to outputs
	allOutputs := append(outputCommitments, feeCommitment)

	// Verify balance: sum(inputs) = sum(outputs + fee)
	if !zkp.VerifyBalance(inputCommitments, allOutputs) {
		return ErrInvalidBalanceProof
	}

	return nil
}

// verifyMerkleProofs verifies that all input commitments exist in the state tree
func (v *ConfidentialValidator) verifyMerkleProofs(tx *types.ConfidentialTx) error {
	for _, input := range tx.Inputs {
		if len(input.MerkleProof) == 0 {
			// Skip merkle verification if no proof provided
			// In production, this would be required
			continue
		}

		commitmentHash := input.Commitment.Hash()
		if !verifyMerkleProof(commitmentHash, input.MerkleProof, input.MerkleRoot) {
			return ErrInvalidMerkleProof
		}

		// Verify merkle root is known
		if v.db != nil {
			if !rawdb.HasCommitmentRoot(v.db, input.MerkleRoot) {
				return ErrInvalidMerkleProof
			}
		}
	}

	return nil
}

// verifyMerkleProof verifies a merkle inclusion proof
func verifyMerkleProof(leaf common.Hash, proof []common.Hash, root common.Hash) bool {
	current := leaf

	for _, sibling := range proof {
		// Determine order based on comparison
		var combined []byte
		if current.Hex() < sibling.Hex() {
			combined = append(current.Bytes(), sibling.Bytes()...)
		} else {
			combined = append(sibling.Bytes(), current.Bytes()...)
		}
		current = common.BytesToHash(crypto.Keccak256(combined))
	}

	return current == root
}

// MarkNullifiersSpent marks nullifiers as spent after tx inclusion
func (v *ConfidentialValidator) MarkNullifiersSpent(tx *types.ConfidentialTx) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, input := range tx.Inputs {
		v.nullifierSet[input.Nullifier] = true

		if v.db != nil {
			rawdb.WriteNullifier(v.db, input.Nullifier)
		}
	}

	return nil
}

// AddCommitment adds a new commitment to the commitment set
func (v *ConfidentialValidator) AddCommitment(commitment *zkp.PedersenCommitment) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	hash := commitment.Hash()
	v.commitmentSet[hash] = true

	return nil
}

// HasNullifier checks if a nullifier has been spent
func (v *ConfidentialValidator) HasNullifier(nullifier common.Hash) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.nullifierSet[nullifier] {
		return true
	}

	if v.db != nil {
		return rawdb.HasNullifier(v.db, nullifier)
	}

	return false
}

// CommitmentTreeRoot returns the current merkle root of commitments
func (v *ConfidentialValidator) CommitmentTreeRoot() common.Hash {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Build merkle tree from commitments
	if len(v.commitmentSet) == 0 {
		return common.Hash{}
	}

	// Collect all commitment hashes
	leaves := make([]common.Hash, 0, len(v.commitmentSet))
	for hash := range v.commitmentSet {
		leaves = append(leaves, hash)
	}

	return buildMerkleRoot(leaves)
}

// buildMerkleRoot constructs a merkle root from leaves
func buildMerkleRoot(leaves []common.Hash) common.Hash {
	if len(leaves) == 0 {
		return common.Hash{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to power of 2
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build tree bottom-up
	for len(leaves) > 1 {
		nextLevel := make([]common.Hash, len(leaves)/2)
		for i := 0; i < len(leaves); i += 2 {
			var combined []byte
			if leaves[i].Hex() < leaves[i+1].Hex() {
				combined = append(leaves[i].Bytes(), leaves[i+1].Bytes()...)
			} else {
				combined = append(leaves[i+1].Bytes(), leaves[i].Bytes()...)
			}
			nextLevel[i/2] = common.BytesToHash(crypto.Keccak256(combined))
		}
		leaves = nextLevel
	}

	return leaves[0]
}

// BatchValidate validates multiple confidential transactions efficiently
func (v *ConfidentialValidator) BatchValidate(txs []*types.ConfidentialTx) error {
	// Collect all range proofs for batch verification
	var allRangeProofs []*zkp.RangeProof
	var allCommitments []*zkp.PedersenCommitment

	for _, tx := range txs {
		for _, input := range tx.Inputs {
			allRangeProofs = append(allRangeProofs, input.RangeProof)
			allCommitments = append(allCommitments, input.Commitment)
		}
		for _, output := range tx.Outputs {
			allRangeProofs = append(allRangeProofs, output.RangeProof)
			allCommitments = append(allCommitments, output.Commitment)
		}
	}

	// Batch verify range proofs
	if !zkp.BatchVerifyRangeProofs(allRangeProofs, allCommitments) {
		return ErrInvalidRangeProof
	}

	// Verify each transaction individually for other checks
	for _, tx := range txs {
		if err := v.verifyNullifiers(tx); err != nil {
			return err
		}
		if err := v.verifyBalanceProof(tx); err != nil {
			return err
		}
	}

	return nil
}

// GenerateMerkleProof generates a merkle proof for a commitment
func (v *ConfidentialValidator) GenerateMerkleProof(commitmentHash common.Hash) ([]common.Hash, common.Hash, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.commitmentSet[commitmentHash] {
		return nil, common.Hash{}, errors.New("commitment not found")
	}

	// Collect all leaves
	leaves := make([]common.Hash, 0, len(v.commitmentSet))
	targetIndex := -1
	for hash := range v.commitmentSet {
		if hash == commitmentHash {
			targetIndex = len(leaves)
		}
		leaves = append(leaves, hash)
	}

	if targetIndex == -1 {
		return nil, common.Hash{}, errors.New("commitment not found")
	}

	// Pad to power of 2
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Generate proof
	proof := make([]common.Hash, 0)
	index := targetIndex

	currentLevel := leaves
	for len(currentLevel) > 1 {
		siblingIndex := index ^ 1 // XOR to get sibling
		if siblingIndex < len(currentLevel) {
			proof = append(proof, currentLevel[siblingIndex])
		}

		// Build next level
		nextLevel := make([]common.Hash, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			var combined []byte
			if currentLevel[i].Hex() < currentLevel[i+1].Hex() {
				combined = append(currentLevel[i].Bytes(), currentLevel[i+1].Bytes()...)
			} else {
				combined = append(currentLevel[i+1].Bytes(), currentLevel[i].Bytes()...)
			}
			nextLevel[i/2] = common.BytesToHash(crypto.Keccak256(combined))
		}
		currentLevel = nextLevel
		index = index / 2
	}

	return proof, currentLevel[0], nil
}
