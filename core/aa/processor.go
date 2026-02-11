// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Processor integrates the AA EntryPoint into the transaction execution pipeline.
// It converts AAUserOpTx transactions into EntryPoint calls.

package aa

import (
	"fmt"
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/core/types"
	"github.com/HITEYY/go-obsidian/log"
)

// Processor handles the integration of AA transactions into block processing.
type Processor struct {
	entryPoint  *EntryPoint
	paymasters  map[common.Address]*NativePaymaster
	chainID     *big.Int
}

// NewProcessor creates a new AA transaction processor.
func NewProcessor(chainID *big.Int) *Processor {
	return &Processor{
		entryPoint: NewEntryPoint(),
		paymasters: make(map[common.Address]*NativePaymaster),
		chainID:    chainID,
	}
}

// EntryPoint returns the underlying EntryPoint.
func (p *Processor) EntryPoint() *EntryPoint {
	return p.entryPoint
}

// RegisterPaymaster registers a paymaster with the processor.
func (p *Processor) RegisterPaymaster(pm *NativePaymaster) {
	p.paymasters[pm.config.Address] = pm
	p.entryPoint.RegisterPaymasterValidator(pm.config.Address, pm)
}

// ProcessAATransaction handles an AAUserOpTx from the transaction pool.
// Returns the receipt and any error.
func (p *Processor) ProcessAATransaction(statedb StateDB, tx *types.Transaction, beneficiary common.Address) (*UserOpReceipt, error) {
	aaTx, ok := extractAAUserOpTx(tx)
	if !ok {
		return nil, fmt.Errorf("transaction is not an AA UserOp transaction")
	}

	// Convert AAUserOpTx to UserOperation
	op := txToUserOp(aaTx)

	log.Info("Processing AA transaction",
		"sender", op.Sender,
		"nonce", op.Nonce,
		"hasPaymaster", op.HasPaymaster(),
		"totalGas", op.TotalGasLimit(),
	)

	// Process via EntryPoint
	receipts, err := p.entryPoint.HandleOps(statedb, []*UserOperation{op}, beneficiary)
	if err != nil {
		return nil, err
	}
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no receipt produced")
	}

	return receipts[0], nil
}

// ProcessBundledOps processes multiple UserOperations bundled together.
func (p *Processor) ProcessBundledOps(statedb StateDB, ops []*UserOperation, beneficiary common.Address) ([]*UserOpReceipt, error) {
	return p.entryPoint.HandleOps(statedb, ops, beneficiary)
}

// ValidateAATransaction performs pre-execution validation of an AA tx.
// Used by the transaction pool to decide whether to accept the tx.
func (p *Processor) ValidateAATransaction(statedb StateDB, tx *types.Transaction) error {
	aaTx, ok := extractAAUserOpTx(tx)
	if !ok {
		return fmt.Errorf("not an AA transaction")
	}

	op := txToUserOp(aaTx)

	// Basic sanity checks
	if op.Sender == (common.Address{}) {
		return fmt.Errorf("empty sender")
	}
	if op.MaxFeePerGas == nil || op.MaxFeePerGas.Sign() <= 0 {
		return fmt.Errorf("invalid maxFeePerGas")
	}
	if op.TotalGasLimit() == 0 {
		return fmt.Errorf("zero gas limit")
	}

	// Simulate validation
	_, _, err := p.entryPoint.SimulateValidation(statedb, op)
	return err
}

// IsAATransaction returns true if the transaction is an AA UserOp.
func IsAATransaction(tx *types.Transaction) bool {
	return tx.Type() == types.AAUserOpTxType
}

// extractAAUserOpTx extracts the inner AAUserOpTx from a Transaction.
func extractAAUserOpTx(tx *types.Transaction) (*types.AAUserOpTx, bool) {
	if tx.Type() != types.AAUserOpTxType {
		return nil, false
	}
	// Access inner via the public Transaction methods
	inner := &types.AAUserOpTx{
		Sender:   *tx.To(), // EntryPoint address is stored in To
		CallData: tx.Data(),
	}
	// In practice, the inner type would be directly accessible
	// For now, reconstruct from Transaction fields
	return inner, true
}

// txToUserOp converts an AAUserOpTx to a UserOperation.
func txToUserOp(aaTx *types.AAUserOpTx) *UserOperation {
	op := &UserOperation{
		Sender:               aaTx.Sender,
		Nonce:                aaTx.UserOpNonce.ToBig(),
		InitCode:             aaTx.InitCode,
		CallData:             aaTx.CallData,
		CallGasLimit:         aaTx.CallGasLimit,
		VerificationGasLimit: aaTx.VerificationGasLimit,
		PreVerificationGas:   aaTx.PreVerificationGas,
		MaxFeePerGas:         aaTx.MaxFeePerGas.ToBig(),
		MaxPriorityFeePerGas: aaTx.MaxPriorityFeePerGas.ToBig(),
		Signature:            aaTx.UserOpSignature,
	}

	// Encode paymaster and data
	if aaTx.HasPaymaster() {
		pmAndData := make([]byte, 0, 20+len(aaTx.PaymasterData))
		pmAndData = append(pmAndData, aaTx.PaymasterAddress.Bytes()...)
		pmAndData = append(pmAndData, aaTx.PaymasterData...)
		op.PaymasterAndData = pmAndData
	}

	return op
}
