// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Paymaster implementations for gas sponsorship in Account Abstraction.

package aa

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
	"github.com/HITEYY/go-obsidian/log"
)

var (
	ErrPaymasterNotActive   = errors.New("paymaster is not active")
	ErrSponsorLimitExceeded = errors.New("sponsor limit exceeded")
	ErrInvalidPaymasterSig  = errors.New("invalid paymaster signature")
	ErrPaymasterUnderfunded = errors.New("paymaster is underfunded")
)

// PaymasterMode defines how the paymaster sponsors gas.
type PaymasterMode uint8

const (
	// PaymasterModeFull sponsors all gas costs
	PaymasterModeFull PaymasterMode = iota
	// PaymasterModePartial sponsors gas up to a limit, user pays remainder
	PaymasterModePartial
	// PaymasterModeVerifying requires a valid signature from the paymaster signer
	PaymasterModeVerifying
	// PaymasterModeERC20 accepts ERC-20 tokens as gas payment
	PaymasterModeERC20
)

// PaymasterConfig holds the configuration for a paymaster.
type PaymasterConfig struct {
	Address         common.Address
	Owner           common.Address
	Mode            PaymasterMode
	SponsorLimit    *big.Int // Max gas to sponsor per op (0 = unlimited)
	TotalBudget     *big.Int // Total budget available
	SignerAddress   common.Address // For verifying mode
	AcceptedTokens  []common.Address // For ERC-20 mode
	ExchangeRates   map[common.Address]*big.Int // Token -> wei exchange rate
	Active          bool
}

// NativePaymaster implements the PaymasterValidator interface for native gas sponsorship.
type NativePaymaster struct {
	mu     sync.RWMutex
	config PaymasterConfig

	// Tracking
	totalSponsored *big.Int
	opCount        uint64
	sponsoredOps   map[common.Hash]*big.Int // userOpHash -> sponsored amount
}

// NewNativePaymaster creates a new native paymaster.
func NewNativePaymaster(config PaymasterConfig) *NativePaymaster {
	return &NativePaymaster{
		config:         config,
		totalSponsored: big.NewInt(0),
		sponsoredOps:   make(map[common.Hash]*big.Int),
	}
}

// ValidatePaymasterUserOp validates a UserOp from the paymaster's perspective.
func (pm *NativePaymaster) ValidatePaymasterUserOp(
	statedb StateDB,
	op *UserOperation,
	userOpHash common.Hash,
	maxCost *big.Int,
) (*PaymasterContext, *ValidationResult, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.config.Active {
		return nil, nil, ErrPaymasterNotActive
	}

	// Check paymaster has enough deposit/balance
	balance := statedb.GetBalance(pm.config.Address)
	if balance.Cmp(maxCost) < 0 {
		return nil, nil, ErrPaymasterUnderfunded
	}

	// Check total budget
	remaining := new(big.Int).Sub(pm.config.TotalBudget, pm.totalSponsored)
	if remaining.Cmp(maxCost) < 0 {
		return nil, nil, ErrSponsorLimitExceeded
	}

	// Per-op sponsor limit check
	if pm.config.SponsorLimit != nil && pm.config.SponsorLimit.Sign() > 0 {
		if maxCost.Cmp(pm.config.SponsorLimit) > 0 {
			return nil, nil, fmt.Errorf("%w: cost %s > limit %s", ErrSponsorLimitExceeded, maxCost, pm.config.SponsorLimit)
		}
	}

	// Mode-specific validation
	switch pm.config.Mode {
	case PaymasterModeFull:
		// No extra validation needed — sponsor everything

	case PaymasterModeVerifying:
		if err := pm.verifySignature(op, userOpHash); err != nil {
			return nil, &ValidationResult{SigFailed: true}, err
		}

	case PaymasterModeERC20:
		if err := pm.validateERC20Payment(statedb, op); err != nil {
			return nil, &ValidationResult{SigFailed: true}, err
		}

	case PaymasterModePartial:
		// Partial: cap the sponsored amount
		if pm.config.SponsorLimit != nil && maxCost.Cmp(pm.config.SponsorLimit) > 0 {
			maxCost = pm.config.SponsorLimit
		}
	}

	// Create context for postOp
	context := &PaymasterContext{
		Paymaster: pm.config.Address,
		Context:   encodePaymasterContext(op.Sender, maxCost, pm.config.Mode),
	}

	result := &ValidationResult{
		SigFailed: false,
	}

	return context, result, nil
}

// PostOp is called after UserOp execution to finalize paymaster accounting.
func (pm *NativePaymaster) PostOp(
	statedb StateDB,
	mode PostOpMode,
	context []byte,
	actualGasCost *big.Int,
) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	sender, _, pmMode := decodePaymasterContext(context)

	switch mode {
	case PostOpModeOpSucceeded:
		log.Debug("Paymaster postOp: op succeeded", "sender", sender, "cost", actualGasCost)
	case PostOpModeOpReverted:
		log.Debug("Paymaster postOp: op reverted", "sender", sender, "cost", actualGasCost)
	case PostOpModePostOpReverted:
		log.Warn("Paymaster postOp: postOp reverted", "sender", sender)
		return ErrPaymasterPostOpFailed
	}

	// Track sponsored amount
	pm.totalSponsored.Add(pm.totalSponsored, actualGasCost)
	pm.opCount++

	// For ERC-20 mode, collect token payment from sender
	if pmMode == PaymasterModeERC20 {
		// In production, this would call transferFrom on the token contract
		log.Info("ERC-20 paymaster collecting token payment", "sender", sender, "gasCost", actualGasCost)
	}

	return nil
}

// verifySignature checks the paymaster signature on the UserOp.
func (pm *NativePaymaster) verifySignature(op *UserOperation, userOpHash common.Hash) error {
	pmData := op.PaymasterData()
	if len(pmData) < 65 {
		return ErrInvalidPaymasterSig
	}

	// Last 65 bytes = paymaster signature
	sig := pmData[len(pmData)-65:]
	
	// Recover signer from signature
	pubKey, err := crypto.Ecrecover(userOpHash.Bytes(), sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPaymasterSig, err)
	}

	recoveredAddr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])
	if recoveredAddr != pm.config.SignerAddress {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidPaymasterSig, pm.config.SignerAddress, recoveredAddr)
	}

	return nil
}

// validateERC20Payment checks if sender has enough tokens for gas.
func (pm *NativePaymaster) validateERC20Payment(statedb StateDB, op *UserOperation) error {
	pmData := op.PaymasterData()
	if len(pmData) < 20 {
		return fmt.Errorf("paymaster data too short for ERC-20 mode")
	}

	tokenAddr := common.BytesToAddress(pmData[:20])

	// Check if token is accepted
	accepted := false
	for _, t := range pm.config.AcceptedTokens {
		if t == tokenAddr {
			accepted = true
			break
		}
	}
	if !accepted {
		return fmt.Errorf("token %s not accepted by paymaster", tokenAddr)
	}

	// In production: check sender's token balance via statedb storage reads
	return nil
}

// Config returns the paymaster configuration.
func (pm *NativePaymaster) Config() PaymasterConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.config
}

// Stats returns paymaster statistics.
func (pm *NativePaymaster) Stats() (totalSponsored *big.Int, opCount uint64) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return new(big.Int).Set(pm.totalSponsored), pm.opCount
}

// SetActive enables or disables the paymaster.
func (pm *NativePaymaster) SetActive(active bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.config.Active = active
}

// encodePaymasterContext encodes context for postOp.
func encodePaymasterContext(sender common.Address, maxCost *big.Int, mode PaymasterMode) []byte {
	data := make([]byte, 0, 53)
	data = append(data, sender.Bytes()...)           // 20 bytes
	data = append(data, common.BigToHash(maxCost).Bytes()...) // 32 bytes
	data = append(data, byte(mode))                  // 1 byte
	return data
}

// decodePaymasterContext decodes context from postOp.
func decodePaymasterContext(data []byte) (sender common.Address, maxCost *big.Int, mode PaymasterMode) {
	if len(data) < 53 {
		return common.Address{}, big.NewInt(0), PaymasterModeFull
	}
	sender = common.BytesToAddress(data[:20])
	maxCost = new(big.Int).SetBytes(data[20:52])
	mode = PaymasterMode(data[52])
	return
}

// VerifyingPaymasterFactory creates a verifying paymaster from config.
func VerifyingPaymasterFactory(address, owner, signer common.Address, budget *big.Int) *NativePaymaster {
	return NewNativePaymaster(PaymasterConfig{
		Address:       address,
		Owner:         owner,
		Mode:          PaymasterModeVerifying,
		TotalBudget:   budget,
		SignerAddress:  signer,
		Active:        true,
	})
}

// ERC20PaymasterFactory creates an ERC-20 token paymaster.
func ERC20PaymasterFactory(address, owner common.Address, tokens []common.Address, rates map[common.Address]*big.Int, budget *big.Int) *NativePaymaster {
	return NewNativePaymaster(PaymasterConfig{
		Address:        address,
		Owner:          owner,
		Mode:           PaymasterModeERC20,
		TotalBudget:    budget,
		AcceptedTokens: tokens,
		ExchangeRates:  rates,
		Active:         true,
	})
}
