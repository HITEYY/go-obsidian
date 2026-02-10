// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Database accessors for confidential transaction data.
// Handles storage and retrieval of nullifiers, commitments, and related data.

package rawdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	// nullifierPrefix is the prefix for nullifier storage
	// nullifierPrefix + nullifier hash -> empty (existence check)
	nullifierPrefix = []byte("zkn-")

	// commitmentRootPrefix is the prefix for commitment merkle roots
	// commitmentRootPrefix + root hash -> block number
	commitmentRootPrefix = []byte("zkcr-")

	// commitmentPrefix is the prefix for individual commitments
	// commitmentPrefix + commitment hash -> block number + tx index
	commitmentPrefix = []byte("zkc-")

	// stealthAddressPrefix is the prefix for stealth address indexing
	// stealthAddressPrefix + view tag + ephemeral pub -> commitment hash
	stealthAddressPrefix = []byte("zksa-")
)

// nullifierKey returns the database key for a nullifier
func nullifierKey(nullifier common.Hash) []byte {
	return append(nullifierPrefix, nullifier.Bytes()...)
}

// commitmentRootKey returns the database key for a commitment root
func commitmentRootKey(root common.Hash) []byte {
	return append(commitmentRootPrefix, root.Bytes()...)
}

// commitmentKey returns the database key for a commitment
func commitmentKey(commitment common.Hash) []byte {
	return append(commitmentPrefix, commitment.Bytes()...)
}

// stealthAddressKey returns the database key for a stealth address index entry
func stealthAddressKey(viewTag byte, ephemeralPub []byte) []byte {
	key := make([]byte, 0, len(stealthAddressPrefix)+1+len(ephemeralPub))
	key = append(key, stealthAddressPrefix...)
	key = append(key, viewTag)
	key = append(key, ephemeralPub...)
	return key
}

// HasNullifier checks if a nullifier exists in the database
func HasNullifier(db ethdb.KeyValueReader, nullifier common.Hash) bool {
	has, _ := db.Has(nullifierKey(nullifier))
	return has
}

// WriteNullifier writes a nullifier to the database
func WriteNullifier(db ethdb.KeyValueWriter, nullifier common.Hash) {
	if err := db.Put(nullifierKey(nullifier), []byte{}); err != nil {
		panic("failed to write nullifier: " + err.Error())
	}
}

// DeleteNullifier removes a nullifier from the database (for reorgs)
func DeleteNullifier(db ethdb.KeyValueWriter, nullifier common.Hash) {
	if err := db.Delete(nullifierKey(nullifier)); err != nil {
		panic("failed to delete nullifier: " + err.Error())
	}
}

// HasCommitmentRoot checks if a commitment merkle root exists
func HasCommitmentRoot(db ethdb.KeyValueReader, root common.Hash) bool {
	has, _ := db.Has(commitmentRootKey(root))
	return has
}

// WriteCommitmentRoot writes a commitment merkle root with its block number
func WriteCommitmentRoot(db ethdb.KeyValueWriter, root common.Hash, blockNumber uint64) {
	data := make([]byte, 8)
	data[0] = byte(blockNumber >> 56)
	data[1] = byte(blockNumber >> 48)
	data[2] = byte(blockNumber >> 40)
	data[3] = byte(blockNumber >> 32)
	data[4] = byte(blockNumber >> 24)
	data[5] = byte(blockNumber >> 16)
	data[6] = byte(blockNumber >> 8)
	data[7] = byte(blockNumber)

	if err := db.Put(commitmentRootKey(root), data); err != nil {
		panic("failed to write commitment root: " + err.Error())
	}
}

// ReadCommitmentRootBlock reads the block number for a commitment root
func ReadCommitmentRootBlock(db ethdb.KeyValueReader, root common.Hash) (uint64, bool) {
	data, err := db.Get(commitmentRootKey(root))
	if err != nil || len(data) != 8 {
		return 0, false
	}

	blockNumber := uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 |
		uint64(data[3])<<32 | uint64(data[4])<<24 | uint64(data[5])<<16 |
		uint64(data[6])<<8 | uint64(data[7])

	return blockNumber, true
}

// DeleteCommitmentRoot removes a commitment root (for reorgs)
func DeleteCommitmentRoot(db ethdb.KeyValueWriter, root common.Hash) {
	if err := db.Delete(commitmentRootKey(root)); err != nil {
		panic("failed to delete commitment root: " + err.Error())
	}
}

// CommitmentLocation stores the location of a commitment in the blockchain
type CommitmentLocation struct {
	BlockNumber uint64
	TxIndex     uint32
	OutputIndex uint32
}

// WriteCommitment writes a commitment with its location
func WriteCommitment(db ethdb.KeyValueWriter, commitment common.Hash, loc *CommitmentLocation) {
	data := make([]byte, 16)
	// Block number (8 bytes)
	data[0] = byte(loc.BlockNumber >> 56)
	data[1] = byte(loc.BlockNumber >> 48)
	data[2] = byte(loc.BlockNumber >> 40)
	data[3] = byte(loc.BlockNumber >> 32)
	data[4] = byte(loc.BlockNumber >> 24)
	data[5] = byte(loc.BlockNumber >> 16)
	data[6] = byte(loc.BlockNumber >> 8)
	data[7] = byte(loc.BlockNumber)
	// Tx index (4 bytes)
	data[8] = byte(loc.TxIndex >> 24)
	data[9] = byte(loc.TxIndex >> 16)
	data[10] = byte(loc.TxIndex >> 8)
	data[11] = byte(loc.TxIndex)
	// Output index (4 bytes)
	data[12] = byte(loc.OutputIndex >> 24)
	data[13] = byte(loc.OutputIndex >> 16)
	data[14] = byte(loc.OutputIndex >> 8)
	data[15] = byte(loc.OutputIndex)

	if err := db.Put(commitmentKey(commitment), data); err != nil {
		panic("failed to write commitment: " + err.Error())
	}
}

// ReadCommitmentLocation reads the location of a commitment
func ReadCommitmentLocation(db ethdb.KeyValueReader, commitment common.Hash) (*CommitmentLocation, bool) {
	data, err := db.Get(commitmentKey(commitment))
	if err != nil || len(data) != 16 {
		return nil, false
	}

	return &CommitmentLocation{
		BlockNumber: uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 |
			uint64(data[3])<<32 | uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7]),
		TxIndex: uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		OutputIndex: uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15]),
	}, true
}

// HasCommitment checks if a commitment exists
func HasCommitment(db ethdb.KeyValueReader, commitment common.Hash) bool {
	has, _ := db.Has(commitmentKey(commitment))
	return has
}

// DeleteCommitment removes a commitment (for reorgs)
func DeleteCommitment(db ethdb.KeyValueWriter, commitment common.Hash) {
	if err := db.Delete(commitmentKey(commitment)); err != nil {
		panic("failed to delete commitment: " + err.Error())
	}
}

// WriteStealthAddressIndex indexes a stealth address for scanning
func WriteStealthAddressIndex(db ethdb.KeyValueWriter, viewTag byte, ephemeralPub []byte, commitmentHash common.Hash) {
	if err := db.Put(stealthAddressKey(viewTag, ephemeralPub), commitmentHash.Bytes()); err != nil {
		panic("failed to write stealth address index: " + err.Error())
	}
}

// ReadStealthAddressCommitment reads the commitment for a stealth address
func ReadStealthAddressCommitment(db ethdb.KeyValueReader, viewTag byte, ephemeralPub []byte) (common.Hash, bool) {
	data, err := db.Get(stealthAddressKey(viewTag, ephemeralPub))
	if err != nil || len(data) != 32 {
		return common.Hash{}, false
	}
	return common.BytesToHash(data), true
}

// IterateStealthAddressesByViewTag iterates over all stealth addresses with a given view tag
// This is used for efficient scanning of incoming payments
func IterateStealthAddressesByViewTag(db ethdb.Iteratee, viewTag byte, fn func(ephemeralPub []byte, commitment common.Hash) bool) {
	prefix := append(stealthAddressPrefix, viewTag)
	it := db.NewIterator(prefix, nil)
	defer it.Release()

	for it.Next() {
		key := it.Key()
		value := it.Value()

		// Extract ephemeral pub from key
		ephemeralPub := key[len(prefix):]
		commitment := common.BytesToHash(value)

		if !fn(ephemeralPub, commitment) {
			break
		}
	}
}

// WriteConfidentialTxNullifiers writes all nullifiers from a confidential tx
func WriteConfidentialTxNullifiers(db ethdb.KeyValueWriter, nullifiers []common.Hash) {
	for _, nullifier := range nullifiers {
		WriteNullifier(db, nullifier)
	}
}

// DeleteConfidentialTxNullifiers removes all nullifiers from a confidential tx (for reorgs)
func DeleteConfidentialTxNullifiers(db ethdb.KeyValueWriter, nullifiers []common.Hash) {
	for _, nullifier := range nullifiers {
		DeleteNullifier(db, nullifier)
	}
}

// WriteConfidentialTxOutputs writes all outputs from a confidential tx
func WriteConfidentialTxOutputs(db ethdb.KeyValueWriter, blockNumber uint64, txIndex uint32, 
	commitments []common.Hash, viewTags []byte, ephemeralPubs [][]byte) {
	for i, commitment := range commitments {
		loc := &CommitmentLocation{
			BlockNumber: blockNumber,
			TxIndex:     txIndex,
			OutputIndex: uint32(i),
		}
		WriteCommitment(db, commitment, loc)

		if i < len(viewTags) && i < len(ephemeralPubs) {
			WriteStealthAddressIndex(db, viewTags[i], ephemeralPubs[i], commitment)
		}
	}
}
