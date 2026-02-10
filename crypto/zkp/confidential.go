// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// High-level confidential transaction building utilities.
// Provides helper functions for creating and managing confidential transfers.

package zkp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// ErrEncryptionFailed is returned when encryption fails
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")
)

// ConfidentialNote represents an unspent confidential output
type ConfidentialNote struct {
	Value          *big.Int
	BlindingFactor *BlindingFactor
	Commitment     *PedersenCommitment
	StealthKey     *ecdsa.PrivateKey
	OutputIndex    uint64
	TxHash         common.Hash
}

// ConfidentialTransfer represents a complete confidential transfer
type ConfidentialTransfer struct {
	Inputs  []*ConfidentialNote
	Outputs []*ConfidentialOutput
	Fee     *big.Int
}

// ConfidentialOutput represents a confidential transaction output
type ConfidentialOutput struct {
	Value          *big.Int
	BlindingFactor *BlindingFactor
	Commitment     *PedersenCommitment
	RangeProof     *RangeProof
	StealthAddress *StealthAddress
	EncryptedNote  []byte
}

// CreateConfidentialOutput creates a new confidential output for a recipient
func CreateConfidentialOutput(value *big.Int, recipientMeta *StealthMetaAddress) (*ConfidentialOutput, error) {
	// Generate blinding factor
	bf, err := NewBlindingFactor()
	if err != nil {
		return nil, err
	}

	// Create commitment
	commitment, err := Commit(value, bf)
	if err != nil {
		return nil, err
	}

	// Generate range proof
	rangeProof, err := GenerateRangeProof(value, bf, commitment)
	if err != nil {
		return nil, err
	}

	// Generate stealth address
	stealthAddr, ephemeralKey, err := GenerateStealthAddress(recipientMeta)
	if err != nil {
		return nil, err
	}

	// Encrypt the note (value and blinding factor) for the recipient
	encryptedNote, err := EncryptNote(value, bf, recipientMeta.ViewingPubKey, ephemeralKey)
	if err != nil {
		return nil, err
	}

	return &ConfidentialOutput{
		Value:          value,
		BlindingFactor: bf,
		Commitment:     commitment,
		RangeProof:     rangeProof,
		StealthAddress: stealthAddr,
		EncryptedNote:  encryptedNote,
	}, nil
}

// EncryptNote encrypts the note data (value and blinding factor) for the recipient
func EncryptNote(value *big.Int, bf *BlindingFactor, viewingPubKey *ecdsa.PublicKey, ephemeralKey *ecdsa.PrivateKey) ([]byte, error) {
	// Derive shared secret using ECDH
	sharedX, _ := crypto.S256().ScalarMult(viewingPubKey.X, viewingPubKey.Y, ephemeralKey.D.Bytes())
	sharedSecret := crypto.Keccak256(sharedX.Bytes())

	// Prepare plaintext: value (32 bytes) + blinding factor (32 bytes)
	plaintext := make([]byte, 64)
	valueBytes := value.Bytes()
	copy(plaintext[32-len(valueBytes):32], valueBytes)
	copy(plaintext[32:64], bf.Bytes())

	// Encrypt with AES-GCM
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrEncryptionFailed
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptNote decrypts the note data using the recipient's viewing key
func DecryptNote(encryptedNote []byte, viewingKey *ecdsa.PrivateKey, ephemeralPubBytes []byte) (*big.Int, *BlindingFactor, error) {
	// Decompress ephemeral public key
	ephemeralPub, err := crypto.DecompressPubkey(ephemeralPubBytes)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	// Derive shared secret using ECDH
	sharedX, _ := crypto.S256().ScalarMult(ephemeralPub.X, ephemeralPub.Y, viewingKey.D.Bytes())
	sharedSecret := crypto.Keccak256(sharedX.Bytes())

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	if len(encryptedNote) < gcm.NonceSize() {
		return nil, nil, ErrDecryptionFailed
	}

	nonce := encryptedNote[:gcm.NonceSize()]
	ciphertext := encryptedNote[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	if len(plaintext) != 64 {
		return nil, nil, ErrDecryptionFailed
	}

	// Extract value and blinding factor
	value := new(big.Int).SetBytes(plaintext[:32])
	bf, err := BlindingFactorFromBytes(plaintext[32:64])
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	return value, bf, nil
}

// BuildConfidentialTransfer builds a complete confidential transfer
func BuildConfidentialTransfer(
	inputs []*ConfidentialNote,
	outputs []struct {
		Value     *big.Int
		Recipient *StealthMetaAddress
	},
	fee *big.Int,
) (*ConfidentialTransfer, error) {
	// Verify total input equals total output + fee
	totalInput := big.NewInt(0)
	for _, input := range inputs {
		totalInput.Add(totalInput, input.Value)
	}

	totalOutput := new(big.Int).Set(fee)
	for _, out := range outputs {
		totalOutput.Add(totalOutput, out.Value)
	}

	if totalInput.Cmp(totalOutput) != 0 {
		return nil, errors.New("inputs must equal outputs + fee")
	}

	// Create confidential outputs
	confOutputs := make([]*ConfidentialOutput, len(outputs))
	for i, out := range outputs {
		confOut, err := CreateConfidentialOutput(out.Value, out.Recipient)
		if err != nil {
			return nil, err
		}
		confOutputs[i] = confOut
	}

	return &ConfidentialTransfer{
		Inputs:  inputs,
		Outputs: confOutputs,
		Fee:     fee,
	}, nil
}

// ComputeBalanceBlindingFactor computes the blinding factor for the fee commitment
// such that: sum(input_blindings) = sum(output_blindings) + fee_blinding
func ComputeBalanceBlindingFactor(inputs []*ConfidentialNote, outputs []*ConfidentialOutput) *BlindingFactor {
	// Sum input blinding factors
	var inputSum BlindingFactor
	for _, input := range inputs {
		inputSum = *inputSum.Add(input.BlindingFactor)
	}

	// Sum output blinding factors
	var outputSum BlindingFactor
	for _, output := range outputs {
		outputSum = *outputSum.Add(output.BlindingFactor)
	}

	// fee_blinding = input_sum - output_sum
	return inputSum.Sub(&outputSum)
}

// ScanForPayments scans a list of transactions for payments to a given viewing key
func ScanForPayments(viewingKey *ecdsa.PrivateKey, spendingKey *ecdsa.PrivateKey, 
	viewTags []byte, ephemeralPubs [][]byte, encryptedNotes [][]byte) ([]*ConfidentialNote, error) {
	
	notes := make([]*ConfidentialNote, 0)

	for i := range viewTags {
		// Quick check using view tag
		if !CheckViewTag(viewingKey, ephemeralPubs[i], viewTags[i]) {
			continue
		}

		// Try to decrypt the note
		value, bf, err := DecryptNote(encryptedNotes[i], viewingKey, ephemeralPubs[i])
		if err != nil {
			continue // Not for us
		}

		// Derive stealth private key
		skp := &StealthKeyPair{
			SpendingKey: spendingKey,
			ViewingKey:  viewingKey,
		}
		stealthPrivKey, err := DeriveStealthPrivateKey(skp, ephemeralPubs[i])
		if err != nil {
			continue
		}

		// Create commitment to verify
		commitment, err := Commit(value, bf)
		if err != nil {
			continue
		}

		notes = append(notes, &ConfidentialNote{
			Value:          value,
			BlindingFactor: bf,
			Commitment:     commitment,
			StealthKey:     stealthPrivKey,
			OutputIndex:    uint64(i),
		})
	}

	return notes, nil
}

// GenerateNullifierFromNote generates a nullifier for spending a note
func GenerateNullifierFromNote(note *ConfidentialNote) common.Hash {
	return GenerateNullifier(note.StealthKey, note.OutputIndex)
}

// VerifyNoteOwnership verifies that a note can be spent by the given stealth key
func VerifyNoteOwnership(note *ConfidentialNote) bool {
	// Verify that the commitment matches value and blinding factor
	return note.Commitment.Verify(note.Value, note.BlindingFactor)
}
