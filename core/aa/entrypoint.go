// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// EntryPoint implements the native EIP-4337 style entrypoint for
// processing UserOperations within the go-obsidian execution layer.

package aa

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
	"github.com/HITEYY/go-obsidian/log"
)

var (
	// Well-known native EntryPoint address (deterministic CREATE2 style)
	NativeEntryPointAddress = common.HexToAddress("0x0000000000000000000000000000000000AA4337")

	ErrInvalidUserOp         = errors.New("invalid user operation")
	ErrValidationFailed      = errors.New("user operation validation failed")
	ErrPaymasterValidation   = errors.New("paymaster validation failed")
	ErrPaymasterDeposit      = errors.New("paymaster deposit insufficient")
	ErrNonceInvalid          = errors.New("invalid user operation nonce")
	ErrGasLimitExceeded      = errors.New("gas limit exceeded for user operation")
	ErrAccountNotDeployed    = errors.New("sender account not deployed and no initCode")
	ErrFactoryFailed         = errors.New("account factory deployment failed")
	ErrPaymasterPostOpFailed = errors.New("paymaster postOp failed")
	ErrInsufficientPrefund   = errors.New("insufficient prefund for user operation")
)

// StateDB is a minimal interface for state access needed by the entrypoint.
type StateDB interface {
	GetBalance(addr common.Address) *big.Int
	SubBalance(addr common.Address, amount *big.Int)
	AddBalance(addr common.Address, amount *big.Int)
	GetNonce(addr common.Address) uint64
	SetNonce(addr common.Address, nonce uint64)
	GetCode(addr common.Address) []byte
	GetCodeHash(addr common.Address) common.Hash
	Exist(addr common.Address) bool
}

// AccountValidator is called on the smart contract account to validate UserOp.
type AccountValidator interface {
	ValidateUserOp(statedb StateDB, op *UserOperation, userOpHash common.Hash, missingAccountFunds *big.Int) (*ValidationResult, error)
}

// PaymasterValidator is called on the paymaster contract to validate and postOp.
type PaymasterValidator interface {
	ValidatePaymasterUserOp(statedb StateDB, op *UserOperation, userOpHash common.Hash, maxCost *big.Int) (*PaymasterContext, *ValidationResult, error)
	PostOp(statedb StateDB, mode PostOpMode, context []byte, actualGasCost *big.Int) error
}

// PostOpMode indicates the reason postOp is called.
type PostOpMode uint8

const (
	PostOpModeOpSucceeded    PostOpMode = iota // UserOp succeeded
	PostOpModeOpReverted                       // UserOp reverted
	PostOpModePostOpReverted                   // PostOp itself reverted (2nd call)
)

// EntryPoint is the native entrypoint processor for Account Abstraction.
type EntryPoint struct {
	address common.Address

	// Registered account validators (by code hash -> validator)
	accountValidators map[common.Hash]AccountValidator

	// Registered paymaster validators (by address -> validator)
	paymasterValidators map[common.Address]PaymasterValidator

	// Deposit ledger: address -> deposited balance for gas
	deposits map[common.Address]*big.Int
}

// NewEntryPoint creates a new native EntryPoint processor.
func NewEntryPoint() *EntryPoint {
	return &EntryPoint{
		address:             NativeEntryPointAddress,
		accountValidators:   make(map[common.Hash]AccountValidator),
		paymasterValidators: make(map[common.Address]PaymasterValidator),
		deposits:            make(map[common.Address]*big.Int),
	}
}

// Address returns the entrypoint address.
func (ep *EntryPoint) Address() common.Address {
	return ep.address
}

// RegisterAccountValidator registers a validator for accounts with a given code hash.
func (ep *EntryPoint) RegisterAccountValidator(codeHash common.Hash, v AccountValidator) {
	ep.accountValidators[codeHash] = v
}

// RegisterPaymasterValidator registers a validator for a specific paymaster address.
func (ep *EntryPoint) RegisterPaymasterValidator(addr common.Address, v PaymasterValidator) {
	ep.paymasterValidators[addr] = v
}

// GetDeposit returns the deposit balance for an address.
func (ep *EntryPoint) GetDeposit(addr common.Address) *big.Int {
	if d, ok := ep.deposits[addr]; ok {
		return new(big.Int).Set(d)
	}
	return big.NewInt(0)
}

// AddDeposit adds to the deposit balance for an address.
func (ep *EntryPoint) AddDeposit(addr common.Address, amount *big.Int) {
	if _, ok := ep.deposits[addr]; !ok {
		ep.deposits[addr] = new(big.Int)
	}
	ep.deposits[addr].Add(ep.deposits[addr], amount)
}

// WithdrawDeposit withdraws from the deposit balance.
func (ep *EntryPoint) WithdrawDeposit(addr common.Address, amount *big.Int) error {
	deposit := ep.GetDeposit(addr)
	if deposit.Cmp(amount) < 0 {
		return fmt.Errorf("withdraw amount %s exceeds deposit %s", amount, deposit)
	}
	ep.deposits[addr].Sub(ep.deposits[addr], amount)
	return nil
}

// HandleOps processes a batch of UserOperations (main entrypoint).
func (ep *EntryPoint) HandleOps(statedb StateDB, ops []*UserOperation, beneficiary common.Address) ([]*UserOpReceipt, error) {
	receipts := make([]*UserOpReceipt, 0, len(ops))

	for _, op := range ops {
		receipt, err := ep.handleSingleOp(statedb, op, beneficiary)
		if err != nil {
			log.Warn("UserOp failed", "sender", op.Sender, "err", err)
			// Failed ops still produce a receipt with success=false
			if receipt == nil {
				receipt = &UserOpReceipt{
					UserOpHash: ep.getUserOpHash(op),
					Sender:     op.Sender,
					Nonce:      op.Nonce,
					Success:    false,
					Reason:     err.Error(),
				}
			}
		}
		receipts = append(receipts, receipt)
	}

	return receipts, nil
}

// handleSingleOp processes one UserOperation through the full lifecycle.
func (ep *EntryPoint) handleSingleOp(statedb StateDB, op *UserOperation, beneficiary common.Address) (*UserOpReceipt, error) {
	if op == nil {
		return nil, ErrInvalidUserOp
	}
	userOpHash := ep.getUserOpHash(op)

	// Phase 1: Validation
	pmCtx, err := ep.validateOp(statedb, op, userOpHash)
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	// Phase 2: Calculate required prefund
	requiredPrefund := ep.calculateRequiredPrefund(op)

	// Phase 3: Charge prefund (from paymaster deposit or sender balance)
	payer := op.Sender
	if op.HasPaymaster() {
		payer = op.PaymasterAddress()
	}

	paymasterDeposit := ep.GetDeposit(payer)
	if paymasterDeposit.Cmp(requiredPrefund) < 0 {
		// Fall back to on-chain balance
		balance := statedb.GetBalance(payer)
		if balance.Cmp(requiredPrefund) < 0 {
			return nil, ErrInsufficientPrefund
		}
		statedb.SubBalance(payer, requiredPrefund)
	} else {
		ep.deposits[payer].Sub(ep.deposits[payer], requiredPrefund)
	}

	// Phase 4: Execute the UserOp calldata
	gasUsed := op.PreVerificationGas + op.VerificationGasLimit // Baseline
	execSuccess := true
	var execReason string

	if len(op.CallData) > 0 {
		// Simulate execution gas consumption
		execGas := ep.estimateCallGas(op)
		execGasUsed := execGas
		if execGas > op.CallGasLimit {
			execSuccess = false
			execReason = "out of gas during execution"
			// Never charge beyond the user-defined call gas limit.
			execGasUsed = op.CallGasLimit
		}
		gasUsed += execGasUsed
	}

	// Phase 5: Calculate actual gas cost
	actualGasCost := new(big.Int).Mul(
		new(big.Int).SetUint64(gasUsed),
		safeBig(op.MaxFeePerGas),
	)
	if actualGasCost.Cmp(requiredPrefund) > 0 {
		actualGasCost = new(big.Int).Set(requiredPrefund)
	}

	// Phase 6: Refund unused gas
	refund := new(big.Int).Sub(requiredPrefund, actualGasCost)
	if refund.Sign() > 0 {
		if op.HasPaymaster() {
			ep.AddDeposit(op.PaymasterAddress(), refund)
		} else {
			statedb.AddBalance(op.Sender, refund)
		}
	}

	// Phase 7: Pay beneficiary (bundler)
	statedb.AddBalance(beneficiary, actualGasCost)

	// Phase 8: Paymaster postOp
	if op.HasPaymaster() && pmCtx != nil {
		mode := PostOpModeOpSucceeded
		if !execSuccess {
			mode = PostOpModeOpReverted
		}
		if pmValidator, ok := ep.paymasterValidators[op.PaymasterAddress()]; ok {
			if err := pmValidator.PostOp(statedb, mode, pmCtx.Context, actualGasCost); err != nil {
				log.Warn("Paymaster postOp failed", "paymaster", op.PaymasterAddress(), "err", err)
			}
		}
	}

	// Increment sender nonce
	ep.incrementNonce(statedb, op)

	receipt := &UserOpReceipt{
		UserOpHash:    userOpHash,
		Sender:        op.Sender,
		Nonce:         op.Nonce,
		Success:       execSuccess,
		ActualGasCost: actualGasCost,
		ActualGasUsed: gasUsed,
		Reason:        execReason,
	}
	if op.HasPaymaster() {
		receipt.Paymaster = op.PaymasterAddress()
	}

	return receipt, nil
}

// validateOp performs validation of a UserOperation.
func (ep *EntryPoint) validateOp(statedb StateDB, op *UserOperation, userOpHash common.Hash) (*PaymasterContext, error) {
	if op == nil || op.Nonce == nil || op.MaxFeePerGas == nil || op.MaxPriorityFeePerGas == nil {
		return nil, ErrInvalidUserOp
	}
	if op.MaxFeePerGas.Sign() <= 0 || op.MaxPriorityFeePerGas.Sign() < 0 {
		return nil, ErrInvalidUserOp
	}

	// 1. Verify sender account exists (or deploy via initCode)
	if !statedb.Exist(op.Sender) || len(statedb.GetCode(op.Sender)) == 0 {
		if len(op.InitCode) == 0 {
			return nil, ErrAccountNotDeployed
		}
		// InitCode: first 20 bytes = factory address, rest = init calldata
		if len(op.InitCode) < 20 {
			return nil, ErrFactoryFailed
		}
		// In a real implementation, this would call the factory contract
		log.Info("Account creation via initCode", "sender", op.Sender, "factory", common.BytesToAddress(op.InitCode[:20]))
	}

	// 2. Validate the nonce
	if err := ep.validateNonce(statedb, op); err != nil {
		return nil, err
	}

	// 3. Validate account signature (call account's validateUserOp)
	codeHash := statedb.GetCodeHash(op.Sender)
	if validator, ok := ep.accountValidators[codeHash]; ok {
		missingFunds := ep.calculateRequiredPrefund(op)
		result, err := validator.ValidateUserOp(statedb, op, userOpHash, missingFunds)
		if err != nil {
			return nil, fmt.Errorf("account validation: %w", err)
		}
		if result.SigFailed {
			return nil, ErrValidationFailed
		}
	}

	// 4. Validate paymaster (if present)
	var pmCtx *PaymasterContext
	if op.HasPaymaster() {
		pmAddr := op.PaymasterAddress()
		maxCost := ep.calculateRequiredPrefund(op)

		if pmValidator, ok := ep.paymasterValidators[pmAddr]; ok {
			ctx, result, err := pmValidator.ValidatePaymasterUserOp(statedb, op, userOpHash, maxCost)
			if err != nil {
				return nil, fmt.Errorf("paymaster validation: %w", err)
			}
			if result.SigFailed {
				return nil, ErrPaymasterValidation
			}
			pmCtx = ctx
		} else {
			// Paymaster not registered, check deposit
			deposit := ep.GetDeposit(pmAddr)
			if deposit.Cmp(maxCost) < 0 {
				return nil, ErrPaymasterDeposit
			}
			pmCtx = &PaymasterContext{
				Paymaster: pmAddr,
				Context:   op.PaymasterData(),
			}
		}
	}

	return pmCtx, nil
}

// validateNonce checks UserOp nonce against stored nonce.
func (ep *EntryPoint) validateNonce(statedb StateDB, op *UserOperation) error {
	if op.Nonce == nil {
		return ErrNonceInvalid
	}
	// EIP-4337 uses a 2D nonce: key (192 bits) + sequence (64 bits)
	// For simplicity, we use the lower 64 bits as sequence
	expected := statedb.GetNonce(op.Sender)
	opNonce := op.Nonce.Uint64()
	if opNonce != expected {
		return fmt.Errorf("%w: expected %d, got %d", ErrNonceInvalid, expected, opNonce)
	}
	return nil
}

// incrementNonce increments the sender's nonce after successful processing.
func (ep *EntryPoint) incrementNonce(statedb StateDB, op *UserOperation) {
	current := statedb.GetNonce(op.Sender)
	statedb.SetNonce(op.Sender, current+1)
}

// calculateRequiredPrefund computes the max gas cost for a UserOp.
func (ep *EntryPoint) calculateRequiredPrefund(op *UserOperation) *big.Int {
	if op == nil {
		return new(big.Int)
	}
	totalGas := op.TotalGasLimit()
	return new(big.Int).Mul(
		new(big.Int).SetUint64(totalGas),
		safeBig(op.MaxFeePerGas),
	)
}

// estimateCallGas estimates gas for call execution (placeholder).
func (ep *EntryPoint) estimateCallGas(op *UserOperation) uint64 {
	// Base cost: 21000 + 16 per non-zero calldata byte + 4 per zero byte
	gas := uint64(21000)
	for _, b := range op.CallData {
		if b == 0 {
			gas += 4
		} else {
			gas += 16
		}
	}
	return gas
}

// getUserOpHash computes the hash of a UserOperation.
func (ep *EntryPoint) getUserOpHash(op *UserOperation) common.Hash {
	if op == nil {
		return common.Hash{}
	}
	// Pack: sender + nonce + hashInitCode + hashCallData + gas limits + paymaster info
	packed := make([]byte, 0, 256)
	packed = append(packed, op.Sender.Bytes()...)
	packed = append(packed, common.BigToHash(safeBig(op.Nonce)).Bytes()...)
	packed = append(packed, crypto.Keccak256(op.InitCode)...)
	packed = append(packed, crypto.Keccak256(op.CallData)...)
	packed = append(packed, common.BigToHash(new(big.Int).SetUint64(op.CallGasLimit)).Bytes()...)
	packed = append(packed, common.BigToHash(new(big.Int).SetUint64(op.VerificationGasLimit)).Bytes()...)
	packed = append(packed, common.BigToHash(new(big.Int).SetUint64(op.PreVerificationGas)).Bytes()...)
	packed = append(packed, common.BigToHash(safeBig(op.MaxFeePerGas)).Bytes()...)
	packed = append(packed, common.BigToHash(safeBig(op.MaxPriorityFeePerGas)).Bytes()...)
	packed = append(packed, crypto.Keccak256(op.PaymasterAndData)...)

	return common.BytesToHash(crypto.Keccak256(packed))
}

// SimulateValidation simulates the validation of a UserOp without executing.
// Used by bundlers to check if an op will be accepted.
func (ep *EntryPoint) SimulateValidation(statedb StateDB, op *UserOperation) (*ValidationResult, *PaymasterContext, error) {
	userOpHash := ep.getUserOpHash(op)
	pmCtx, err := ep.validateOp(statedb, op, userOpHash)
	if err != nil {
		return &ValidationResult{SigFailed: true}, nil, err
	}
	return &ValidationResult{SigFailed: false}, pmCtx, nil
}

func safeBig(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return v
}
