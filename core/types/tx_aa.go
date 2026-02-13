// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Native Account Abstraction transaction type (EIP-4337 style).
// Supports UserOperation bundling with Paymaster gas sponsorship.

package types

import (
	"bytes"
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/rlp"
	"github.com/holiman/uint256"
)

// AAUserOpTx represents a native Account Abstraction transaction
// that bundles a UserOperation with optional Paymaster sponsorship.
type AAUserOpTx struct {
	ChainID   *uint256.Int
	Nonce     uint64
	GasTipCap *uint256.Int // maxPriorityFeePerGas
	GasFeeCap *uint256.Int // maxFeePerGas
	Gas       uint64

	// EntryPoint is the native entrypoint address that processes this UserOp
	EntryPoint common.Address

	// UserOperation fields (EIP-4337 compatible)
	Sender               common.Address // The account making the operation
	UserOpNonce          *uint256.Int   // Anti-replay nonce for the UserOp
	InitCode             []byte         // Factory + init data for account creation (empty if account exists)
	CallData             []byte         // Encoded call(s) to execute on the sender account
	CallGasLimit         uint64         // Gas for the main execution call
	VerificationGasLimit uint64         // Gas for verification (validateUserOp)
	PreVerificationGas   uint64         // Gas overhead for bundler
	MaxFeePerGas         *uint256.Int   // Same semantics as EIP-1559
	MaxPriorityFeePerGas *uint256.Int   // Same semantics as EIP-1559

	// Paymaster fields
	PaymasterAddress  common.Address // Zero address means self-sponsored
	PaymasterData     []byte         // Arbitrary data for paymaster validation
	PaymasterGasLimit uint64         // Gas allocated for paymaster validation + postOp

	// Signature over the UserOp hash
	UserOpSignature []byte

	// Tx-level signature (from bundler or sender)
	V *uint256.Int
	R *uint256.Int
	S *uint256.Int
}

func (tx *AAUserOpTx) copy() TxData {
	cpy := &AAUserOpTx{
		Nonce:                tx.Nonce,
		Gas:                  tx.Gas,
		EntryPoint:           tx.EntryPoint,
		Sender:               tx.Sender,
		InitCode:             common.CopyBytes(tx.InitCode),
		CallData:             common.CopyBytes(tx.CallData),
		CallGasLimit:         tx.CallGasLimit,
		VerificationGasLimit: tx.VerificationGasLimit,
		PreVerificationGas:   tx.PreVerificationGas,
		PaymasterAddress:     tx.PaymasterAddress,
		PaymasterData:        common.CopyBytes(tx.PaymasterData),
		PaymasterGasLimit:    tx.PaymasterGasLimit,
		UserOpSignature:      common.CopyBytes(tx.UserOpSignature),
	}
	if tx.ChainID != nil {
		cpy.ChainID = new(uint256.Int).Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap = new(uint256.Int).Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap = new(uint256.Int).Set(tx.GasFeeCap)
	}
	if tx.UserOpNonce != nil {
		cpy.UserOpNonce = new(uint256.Int).Set(tx.UserOpNonce)
	}
	if tx.MaxFeePerGas != nil {
		cpy.MaxFeePerGas = new(uint256.Int).Set(tx.MaxFeePerGas)
	}
	if tx.MaxPriorityFeePerGas != nil {
		cpy.MaxPriorityFeePerGas = new(uint256.Int).Set(tx.MaxPriorityFeePerGas)
	}
	if tx.V != nil {
		cpy.V = new(uint256.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(uint256.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(uint256.Int).Set(tx.S)
	}
	return cpy
}

func (tx *AAUserOpTx) txType() byte           { return AAUserOpTxType }
func (tx *AAUserOpTx) chainID() *big.Int      { return uint256ToBig(tx.ChainID) }
func (tx *AAUserOpTx) accessList() AccessList { return nil }
func (tx *AAUserOpTx) data() []byte           { return tx.CallData }
func (tx *AAUserOpTx) gas() uint64            { return tx.Gas }
func (tx *AAUserOpTx) gasPrice() *big.Int     { return uint256ToBig(tx.GasFeeCap) }
func (tx *AAUserOpTx) gasTipCap() *big.Int    { return uint256ToBig(tx.GasTipCap) }
func (tx *AAUserOpTx) gasFeeCap() *big.Int    { return uint256ToBig(tx.GasFeeCap) }
func (tx *AAUserOpTx) value() *big.Int        { return big.NewInt(0) }
func (tx *AAUserOpTx) nonce() uint64          { return tx.Nonce }
func (tx *AAUserOpTx) to() *common.Address    { return &tx.EntryPoint }

func (tx *AAUserOpTx) rawSignatureValues() (v, r, s *big.Int) {
	return uint256ToBig(tx.V), uint256ToBig(tx.R), uint256ToBig(tx.S)
}

func (tx *AAUserOpTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = uint256.MustFromBig(chainID)
	tx.V = uint256.MustFromBig(v)
	tx.R = uint256.MustFromBig(r)
	tx.S = uint256.MustFromBig(s)
}

func (tx *AAUserOpTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(uint256ToBig(tx.GasFeeCap))
	}
	gasFeeCap := uint256ToBig(tx.GasFeeCap)
	gasTipCap := uint256ToBig(tx.GasTipCap)
	tip := new(big.Int).Sub(gasFeeCap, baseFee)
	if tip.Cmp(gasTipCap) > 0 {
		tip.Set(gasTipCap)
	}
	return dst.Add(tip, baseFee)
}

func (tx *AAUserOpTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		AAUserOpTxType,
		[]interface{}{
			bigOrZero(chainID),
			tx.Nonce,
			uint256OrZero(tx.GasTipCap),
			uint256OrZero(tx.GasFeeCap),
			tx.Gas,
			tx.EntryPoint,
			tx.Sender,
			uint256OrZero(tx.UserOpNonce),
			tx.InitCode,
			tx.CallData,
			tx.CallGasLimit,
			tx.VerificationGasLimit,
			tx.PreVerificationGas,
			uint256OrZero(tx.MaxFeePerGas),
			uint256OrZero(tx.MaxPriorityFeePerGas),
			tx.PaymasterAddress,
			tx.PaymasterData,
			tx.PaymasterGasLimit,
			tx.UserOpSignature,
		},
	)
}

func (tx *AAUserOpTx) encode(w *bytes.Buffer) error {
	return rlp.Encode(w, tx)
}

func (tx *AAUserOpTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// HasPaymaster returns true if a paymaster is sponsoring gas
func (tx *AAUserOpTx) HasPaymaster() bool {
	return tx.PaymasterAddress != (common.Address{})
}

// TotalGasLimit returns the total gas required for the UserOp
func (tx *AAUserOpTx) TotalGasLimit() uint64 {
	return tx.CallGasLimit + tx.VerificationGasLimit + tx.PreVerificationGas + tx.PaymasterGasLimit
}

// UserOpHash returns the hash of the UserOperation fields (used for signature verification)
func (tx *AAUserOpTx) UserOpHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		AAUserOpTxType,
		[]interface{}{
			tx.Sender,
			uint256OrZero(tx.UserOpNonce),
			tx.InitCode,
			tx.CallData,
			tx.CallGasLimit,
			tx.VerificationGasLimit,
			tx.PreVerificationGas,
			uint256OrZero(tx.MaxFeePerGas),
			uint256OrZero(tx.MaxPriorityFeePerGas),
			tx.PaymasterAddress,
			tx.PaymasterData,
			tx.PaymasterGasLimit,
			bigOrZero(chainID),
			tx.EntryPoint,
		},
	)
}

func uint256ToBig(v *uint256.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return v.ToBig()
}

func uint256OrZero(v *uint256.Int) *uint256.Int {
	if v == nil {
		return new(uint256.Int)
	}
	return v
}

func bigOrZero(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return v
}
