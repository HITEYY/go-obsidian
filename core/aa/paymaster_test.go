// Copyright 2025 The go-obsidian Authors

package aa

import (
	"math/big"
	"testing"

	"github.com/HITEYY/go-obsidian/common"
)

func TestNativePaymasterFull(t *testing.T) {
	pmAddr := common.HexToAddress("0xPM01")
	owner := common.HexToAddress("0xOwner")

	pm := NewNativePaymaster(PaymasterConfig{
		Address:      pmAddr,
		Owner:        owner,
		Mode:         PaymasterModeFull,
		TotalBudget:  big.NewInt(1e18),
		Active:       true,
	})

	statedb := newMockStateDB()
	statedb.balances[pmAddr] = big.NewInt(1e18)

	op := &UserOperation{
		Sender:               common.HexToAddress("0xSender"),
		Nonce:                big.NewInt(0),
		MaxFeePerGas:         big.NewInt(1e9),
		MaxPriorityFeePerGas: big.NewInt(1e8),
		CallGasLimit:         50000,
		VerificationGasLimit: 30000,
		PreVerificationGas:   21000,
		PaymasterAndData:     pmAddr.Bytes(),
	}

	maxCost := big.NewInt(101000 * 1e9)
	ctx, result, err := pm.ValidatePaymasterUserOp(statedb, op, common.Hash{}, maxCost)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if result.SigFailed {
		t.Error("unexpected sig failure")
	}
	if ctx == nil {
		t.Fatal("expected context")
	}
	if ctx.Paymaster != pmAddr {
		t.Error("wrong paymaster in context")
	}
}

func TestNativePaymasterInactive(t *testing.T) {
	pm := NewNativePaymaster(PaymasterConfig{
		Address:     common.HexToAddress("0xPM"),
		TotalBudget: big.NewInt(1e18),
		Active:      false, // inactive
	})

	statedb := newMockStateDB()
	_, _, err := pm.ValidatePaymasterUserOp(statedb, &UserOperation{}, common.Hash{}, big.NewInt(1))
	if err != ErrPaymasterNotActive {
		t.Errorf("expected ErrPaymasterNotActive, got %v", err)
	}
}

func TestNativePaymasterBudgetExceeded(t *testing.T) {
	pmAddr := common.HexToAddress("0xPM")
	pm := NewNativePaymaster(PaymasterConfig{
		Address:     pmAddr,
		TotalBudget: big.NewInt(100), // tiny budget
		Active:      true,
	})

	statedb := newMockStateDB()
	statedb.balances[pmAddr] = big.NewInt(1e18)

	_, _, err := pm.ValidatePaymasterUserOp(statedb, &UserOperation{}, common.Hash{}, big.NewInt(1000))
	if err != ErrSponsorLimitExceeded {
		t.Errorf("expected ErrSponsorLimitExceeded, got %v", err)
	}
}

func TestPaymasterPostOp(t *testing.T) {
	pm := NewNativePaymaster(PaymasterConfig{
		Address:     common.HexToAddress("0xPM"),
		TotalBudget: big.NewInt(1e18),
		Active:      true,
	})

	statedb := newMockStateDB()
	ctx := encodePaymasterContext(common.HexToAddress("0xSender"), big.NewInt(1e15), PaymasterModeFull)

	err := pm.PostOp(statedb, PostOpModeOpSucceeded, ctx, big.NewInt(5e14))
	if err != nil {
		t.Fatalf("postOp failed: %v", err)
	}

	total, count := pm.Stats()
	if total.Cmp(big.NewInt(5e14)) != 0 {
		t.Errorf("total sponsored mismatch: %s", total)
	}
	if count != 1 {
		t.Errorf("op count mismatch: %d", count)
	}
}

func TestPaymasterContextEncodeDecode(t *testing.T) {
	sender := common.HexToAddress("0xABCD")
	maxCost := big.NewInt(12345678)
	mode := PaymasterModeERC20

	encoded := encodePaymasterContext(sender, maxCost, mode)
	dSender, dMaxCost, dMode := decodePaymasterContext(encoded)

	if dSender != sender {
		t.Errorf("sender mismatch: %s vs %s", dSender, sender)
	}
	if dMaxCost.Cmp(maxCost) != 0 {
		t.Errorf("maxCost mismatch: %s vs %s", dMaxCost, maxCost)
	}
	if dMode != mode {
		t.Errorf("mode mismatch: %d vs %d", dMode, mode)
	}
}
