// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Package aa implements native Account Abstraction with EIP-4337 style
// UserOperations, EntryPoint processing, and Paymaster gas sponsorship.

package aa

import (
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
)

// UserOperation represents an EIP-4337 compatible user operation.
type UserOperation struct {
	Sender               common.Address `json:"sender"`
	Nonce                *big.Int       `json:"nonce"`
	InitCode             []byte         `json:"initCode"`
	CallData             []byte         `json:"callData"`
	CallGasLimit         uint64         `json:"callGasLimit"`
	VerificationGasLimit uint64         `json:"verificationGasLimit"`
	PreVerificationGas   uint64         `json:"preVerificationGas"`
	MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
	PaymasterAndData     []byte         `json:"paymasterAndData"` // first 20 bytes = paymaster address
	Signature            []byte         `json:"signature"`
}

// PaymasterAddress extracts the paymaster address from PaymasterAndData.
// Returns zero address if no paymaster.
func (op *UserOperation) PaymasterAddress() common.Address {
	if len(op.PaymasterAndData) < 20 {
		return common.Address{}
	}
	return common.BytesToAddress(op.PaymasterAndData[:20])
}

// PaymasterData returns the paymaster-specific data portion.
func (op *UserOperation) PaymasterData() []byte {
	if len(op.PaymasterAndData) <= 20 {
		return nil
	}
	return op.PaymasterAndData[20:]
}

// HasPaymaster returns true if this operation has a paymaster.
func (op *UserOperation) HasPaymaster() bool {
	return len(op.PaymasterAndData) >= 20 && op.PaymasterAddress() != (common.Address{})
}

// TotalGasLimit returns total gas required for the operation.
func (op *UserOperation) TotalGasLimit() uint64 {
	return op.CallGasLimit + op.VerificationGasLimit + op.PreVerificationGas
}

// ValidationResult contains the result of UserOp or Paymaster validation.
type ValidationResult struct {
	ValidAfter  uint64 // Timestamp after which the op is valid (0 = always)
	ValidUntil  uint64 // Timestamp until which the op is valid (0 = forever)
	Aggregator  common.Address
	SigFailed   bool
	ReturnData  []byte
}

// StakeInfo contains staking information for an entity (account, paymaster, factory).
type StakeInfo struct {
	Address       common.Address
	Stake         *big.Int
	UnstakeDelaySec uint32
}

// PaymasterContext holds context data returned by paymaster during validation,
// to be passed to postOp.
type PaymasterContext struct {
	Paymaster common.Address
	Context   []byte
}

// UserOpReceipt contains execution results for a processed UserOperation.
type UserOpReceipt struct {
	UserOpHash    common.Hash    `json:"userOpHash"`
	Sender        common.Address `json:"sender"`
	Paymaster     common.Address `json:"paymaster"`
	Nonce         *big.Int       `json:"nonce"`
	Success       bool           `json:"success"`
	ActualGasCost *big.Int       `json:"actualGasCost"`
	ActualGasUsed uint64         `json:"actualGasUsed"`
	Reason        string         `json:"reason,omitempty"` // Revert reason if failed
	Logs          []byte         `json:"logs"`
}
