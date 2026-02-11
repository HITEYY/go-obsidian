// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Confidential Transaction implementation using Zero-Knowledge Proofs.
// Enables hiding sender, receiver, and transaction amounts while
// maintaining verifiable transaction validity.

package types

import (
	"bytes"
	"errors"
	"io"
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
	"github.com/HITEYY/go-obsidian/crypto/zkp"
	"github.com/HITEYY/go-obsidian/rlp"
	"github.com/holiman/uint256"
)

var (
	// ErrInvalidConfidentialTx is returned when a confidential tx is malformed
	ErrInvalidConfidentialTx = errors.New("invalid confidential transaction")
	// ErrRangeProofVerification is returned when range proof fails
	ErrRangeProofVerification = errors.New("range proof verification failed")
	// ErrBalanceVerification is returned when balance proof fails
	ErrBalanceVerification = errors.New("balance verification failed")
	// ErrNullifierUsed is returned when nullifier has been used
	ErrNullifierUsed = errors.New("nullifier already used")
)

// ConfidentialInput represents an input to a confidential transaction
type ConfidentialInput struct {
	Nullifier        common.Hash              // Prevents double-spending
	Commitment       *zkp.PedersenCommitment  // Commitment to the input value
	RangeProof       *zkp.RangeProof          // Proof that input value is valid
	MerkleProof      []common.Hash            // Proof of inclusion in state tree
	MerkleRoot       common.Hash              // Root of the commitment tree
}

// ConfidentialOutput represents an output of a confidential transaction
type ConfidentialOutput struct {
	StealthAddress *zkp.StealthAddress     // One-time address for recipient
	Commitment     *zkp.PedersenCommitment // Commitment to the output value
	RangeProof     *zkp.RangeProof         // Proof that output value >= 0
	EncryptedData  []byte                  // Encrypted value and blinding factor for recipient
}

// ConfidentialTx represents a zero-knowledge confidential transaction
type ConfidentialTx struct {
	ChainID   *uint256.Int
	Nonce     uint64
	GasTipCap *uint256.Int // maxPriorityFeePerGas
	GasFeeCap *uint256.Int // maxFeePerGas
	Gas       uint64
	
	// Confidential transaction specific fields
	Inputs      []ConfidentialInput  // Hidden inputs with nullifiers
	Outputs     []ConfidentialOutput // Hidden outputs with commitments
	Fee         *uint256.Int         // Transaction fee (public, for miners)
	FeeBlinding []byte               // Blinding factor for fee commitment
	
	// Balance proof
	// Proves: sum(inputs) = sum(outputs) + fee
	BalanceProof []byte
	
	// Optional: encrypted memo for recipient
	EncryptedMemo []byte
	
	// Signature values (signs over the hash of the tx)
	V *uint256.Int
	R *uint256.Int
	S *uint256.Int
}

// copy creates a deep copy of the transaction data
func (tx *ConfidentialTx) copy() TxData {
	cpy := &ConfidentialTx{
		ChainID:       new(uint256.Int).Set(tx.ChainID),
		Nonce:         tx.Nonce,
		GasTipCap:     new(uint256.Int).Set(tx.GasTipCap),
		GasFeeCap:     new(uint256.Int).Set(tx.GasFeeCap),
		Gas:           tx.Gas,
		Fee:           new(uint256.Int).Set(tx.Fee),
		FeeBlinding:   common.CopyBytes(tx.FeeBlinding),
		BalanceProof:  common.CopyBytes(tx.BalanceProof),
		EncryptedMemo: common.CopyBytes(tx.EncryptedMemo),
		V:             new(uint256.Int).Set(tx.V),
		R:             new(uint256.Int).Set(tx.R),
		S:             new(uint256.Int).Set(tx.S),
	}
	
	// Copy inputs
	cpy.Inputs = make([]ConfidentialInput, len(tx.Inputs))
	for i, input := range tx.Inputs {
		cpy.Inputs[i] = ConfidentialInput{
			Nullifier:   input.Nullifier,
			Commitment:  input.Commitment,
			RangeProof:  input.RangeProof,
			MerkleProof: append([]common.Hash(nil), input.MerkleProof...),
			MerkleRoot:  input.MerkleRoot,
		}
	}
	
	// Copy outputs
	cpy.Outputs = make([]ConfidentialOutput, len(tx.Outputs))
	for i, output := range tx.Outputs {
		cpy.Outputs[i] = ConfidentialOutput{
			StealthAddress: output.StealthAddress,
			Commitment:     output.Commitment,
			RangeProof:     output.RangeProof,
			EncryptedData:  common.CopyBytes(output.EncryptedData),
		}
	}
	
	return cpy
}

// TxData interface implementations

func (tx *ConfidentialTx) txType() byte { return ConfidentialTxType }

func (tx *ConfidentialTx) chainID() *big.Int {
	return tx.ChainID.ToBig()
}

func (tx *ConfidentialTx) accessList() AccessList { return nil }

func (tx *ConfidentialTx) data() []byte {
	// Return the balance proof as data
	return tx.BalanceProof
}

func (tx *ConfidentialTx) gas() uint64 { return tx.Gas }

func (tx *ConfidentialTx) gasPrice() *big.Int {
	return tx.GasFeeCap.ToBig()
}

func (tx *ConfidentialTx) gasTipCap() *big.Int {
	return tx.GasTipCap.ToBig()
}

func (tx *ConfidentialTx) gasFeeCap() *big.Int {
	return tx.GasFeeCap.ToBig()
}

func (tx *ConfidentialTx) value() *big.Int {
	// For confidential transactions, value is hidden
	// Return 0 as the public value (actual value is in commitments)
	return big.NewInt(0)
}

func (tx *ConfidentialTx) nonce() uint64 { return tx.Nonce }

func (tx *ConfidentialTx) to() *common.Address {
	// Confidential transactions don't have a public recipient
	// The actual recipients are in the stealth addresses
	return nil
}

func (tx *ConfidentialTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V.ToBig(), tx.R.ToBig(), tx.S.ToBig()
}

func (tx *ConfidentialTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = uint256.MustFromBig(chainID)
	tx.V = uint256.MustFromBig(v)
	tx.R = uint256.MustFromBig(r)
	tx.S = uint256.MustFromBig(s)
}

func (tx *ConfidentialTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := new(big.Int).Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return dst.Add(tip, baseFee)
}

func (tx *ConfidentialTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		ConfidentialTxType,
		[]interface{}{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.inputsHash(),
			tx.outputsHash(),
			tx.Fee,
			tx.BalanceProof,
		},
	)
}

// inputsHash returns the hash of all inputs
func (tx *ConfidentialTx) inputsHash() common.Hash {
	var data []byte
	for _, input := range tx.Inputs {
		data = append(data, input.Nullifier.Bytes()...)
		if input.Commitment != nil {
			data = append(data, input.Commitment.Bytes()...)
		}
	}
	return common.BytesToHash(crypto.Keccak256(data))
}

// outputsHash returns the hash of all outputs
func (tx *ConfidentialTx) outputsHash() common.Hash {
	var data []byte
	for _, output := range tx.Outputs {
		if output.StealthAddress != nil {
			data = append(data, output.StealthAddress.Address.Bytes()...)
		}
		if output.Commitment != nil {
			data = append(data, output.Commitment.Bytes()...)
		}
	}
	return common.BytesToHash(crypto.Keccak256(data))
}

// encode encodes the transaction for RLP
func (tx *ConfidentialTx) encode(w *bytes.Buffer) error {
	return rlp.Encode(w, tx)
}

// decode decodes the transaction from RLP
func (tx *ConfidentialTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// EncodeRLP implements rlp.Encoder
func (tx *ConfidentialTx) EncodeRLP(w io.Writer) error {
	// Encode inputs
	encodedInputs := make([][]byte, len(tx.Inputs))
	for i, input := range tx.Inputs {
		var buf bytes.Buffer
		if err := encodeConfidentialInput(&buf, &input); err != nil {
			return err
		}
		encodedInputs[i] = buf.Bytes()
	}

	// Encode outputs
	encodedOutputs := make([][]byte, len(tx.Outputs))
	for i, output := range tx.Outputs {
		var buf bytes.Buffer
		if err := encodeConfidentialOutput(&buf, &output); err != nil {
			return err
		}
		encodedOutputs[i] = buf.Bytes()
	}

	return rlp.Encode(w, []interface{}{
		tx.ChainID,
		tx.Nonce,
		tx.GasTipCap,
		tx.GasFeeCap,
		tx.Gas,
		encodedInputs,
		encodedOutputs,
		tx.Fee,
		tx.FeeBlinding,
		tx.BalanceProof,
		tx.EncryptedMemo,
		tx.V,
		tx.R,
		tx.S,
	})
}

// DecodeRLP implements rlp.Decoder
func (tx *ConfidentialTx) DecodeRLP(s *rlp.Stream) error {
	var dec struct {
		ChainID       *uint256.Int
		Nonce         uint64
		GasTipCap     *uint256.Int
		GasFeeCap     *uint256.Int
		Gas           uint64
		Inputs        [][]byte
		Outputs       [][]byte
		Fee           *uint256.Int
		FeeBlinding   []byte
		BalanceProof  []byte
		EncryptedMemo []byte
		V             *uint256.Int
		R             *uint256.Int
		S             *uint256.Int
	}
	if err := s.Decode(&dec); err != nil {
		return err
	}

	tx.ChainID = dec.ChainID
	tx.Nonce = dec.Nonce
	tx.GasTipCap = dec.GasTipCap
	tx.GasFeeCap = dec.GasFeeCap
	tx.Gas = dec.Gas
	tx.Fee = dec.Fee
	tx.FeeBlinding = dec.FeeBlinding
	tx.BalanceProof = dec.BalanceProof
	tx.EncryptedMemo = dec.EncryptedMemo
	tx.V = dec.V
	tx.R = dec.R
	tx.S = dec.S

	// Decode inputs
	tx.Inputs = make([]ConfidentialInput, len(dec.Inputs))
	for i, inputBytes := range dec.Inputs {
		if err := decodeConfidentialInput(inputBytes, &tx.Inputs[i]); err != nil {
			return err
		}
	}

	// Decode outputs
	tx.Outputs = make([]ConfidentialOutput, len(dec.Outputs))
	for i, outputBytes := range dec.Outputs {
		if err := decodeConfidentialOutput(outputBytes, &tx.Outputs[i]); err != nil {
			return err
		}
	}

	return nil
}

func encodeConfidentialInput(w *bytes.Buffer, input *ConfidentialInput) error {
	commitmentBytes := []byte{}
	if input.Commitment != nil {
		commitmentBytes = input.Commitment.Bytes()
	}
	
	rangeProofBytes := []byte{}
	if input.RangeProof != nil {
		rangeProofBytes = input.RangeProof.Bytes()
	}

	merkleProofBytes := make([][]byte, len(input.MerkleProof))
	for i, h := range input.MerkleProof {
		merkleProofBytes[i] = h.Bytes()
	}

	return rlp.Encode(w, []interface{}{
		input.Nullifier,
		commitmentBytes,
		rangeProofBytes,
		merkleProofBytes,
		input.MerkleRoot,
	})
}

func decodeConfidentialInput(data []byte, input *ConfidentialInput) error {
	var dec struct {
		Nullifier       common.Hash
		CommitmentBytes []byte
		RangeProofBytes []byte
		MerkleProof     [][]byte
		MerkleRoot      common.Hash
	}
	if err := rlp.DecodeBytes(data, &dec); err != nil {
		return err
	}

	input.Nullifier = dec.Nullifier
	input.MerkleRoot = dec.MerkleRoot

	if len(dec.CommitmentBytes) > 0 {
		commitment, err := zkp.CommitmentFromBytes(dec.CommitmentBytes)
		if err != nil {
			return err
		}
		input.Commitment = commitment
	}

	if len(dec.RangeProofBytes) > 0 {
		rangeProof, err := zkp.RangeProofFromBytes(dec.RangeProofBytes)
		if err != nil {
			return err
		}
		input.RangeProof = rangeProof
	}

	input.MerkleProof = make([]common.Hash, len(dec.MerkleProof))
	for i, b := range dec.MerkleProof {
		input.MerkleProof[i] = common.BytesToHash(b)
	}

	return nil
}

func encodeConfidentialOutput(w *bytes.Buffer, output *ConfidentialOutput) error {
	stealthBytes := []byte{}
	if output.StealthAddress != nil {
		stealthBytes = output.StealthAddress.Bytes()
	}

	commitmentBytes := []byte{}
	if output.Commitment != nil {
		commitmentBytes = output.Commitment.Bytes()
	}

	rangeProofBytes := []byte{}
	if output.RangeProof != nil {
		rangeProofBytes = output.RangeProof.Bytes()
	}

	return rlp.Encode(w, []interface{}{
		stealthBytes,
		commitmentBytes,
		rangeProofBytes,
		output.EncryptedData,
	})
}

func decodeConfidentialOutput(data []byte, output *ConfidentialOutput) error {
	var dec struct {
		StealthBytes    []byte
		CommitmentBytes []byte
		RangeProofBytes []byte
		EncryptedData   []byte
	}
	if err := rlp.DecodeBytes(data, &dec); err != nil {
		return err
	}

	if len(dec.StealthBytes) > 0 {
		stealth, err := zkp.StealthAddressFromBytes(dec.StealthBytes)
		if err != nil {
			return err
		}
		output.StealthAddress = stealth
	}

	if len(dec.CommitmentBytes) > 0 {
		commitment, err := zkp.CommitmentFromBytes(dec.CommitmentBytes)
		if err != nil {
			return err
		}
		output.Commitment = commitment
	}

	if len(dec.RangeProofBytes) > 0 {
		rangeProof, err := zkp.RangeProofFromBytes(dec.RangeProofBytes)
		if err != nil {
			return err
		}
		output.RangeProof = rangeProof
	}

	output.EncryptedData = dec.EncryptedData

	return nil
}

// Nullifiers returns all nullifiers from the transaction inputs
func (tx *ConfidentialTx) Nullifiers() []common.Hash {
	nullifiers := make([]common.Hash, len(tx.Inputs))
	for i, input := range tx.Inputs {
		nullifiers[i] = input.Nullifier
	}
	return nullifiers
}

// OutputCommitments returns all output commitments
func (tx *ConfidentialTx) OutputCommitments() []*zkp.PedersenCommitment {
	commitments := make([]*zkp.PedersenCommitment, len(tx.Outputs))
	for i, output := range tx.Outputs {
		commitments[i] = output.Commitment
	}
	return commitments
}

// StealthAddresses returns all output stealth addresses
func (tx *ConfidentialTx) StealthAddresses() []*zkp.StealthAddress {
	addresses := make([]*zkp.StealthAddress, len(tx.Outputs))
	for i, output := range tx.Outputs {
		addresses[i] = output.StealthAddress
	}
	return addresses
}

// FeeCommitment returns the commitment to the transaction fee
func (tx *ConfidentialTx) FeeCommitment() (*zkp.PedersenCommitment, error) {
	bf, err := zkp.BlindingFactorFromBytes(tx.FeeBlinding)
	if err != nil {
		return nil, err
	}
	return zkp.Commit(tx.Fee.ToBig(), bf)
}

// IsConfidential returns true if this is a confidential transaction
func (tx *ConfidentialTx) IsConfidential() bool {
	return true
}
