// Copyright 2026 The go-obsidian Authors

package aa

import (
	"math/big"
	"testing"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/core/types"
	"github.com/holiman/uint256"
)

func makeAAUserOpTx() *types.Transaction {
	return types.NewTx(&types.AAUserOpTx{
		ChainID:              uint256.NewInt(1719),
		Nonce:                3,
		GasTipCap:            uint256.NewInt(1),
		GasFeeCap:            uint256.NewInt(1),
		Gas:                  21000,
		EntryPoint:           NativeEntryPointAddress,
		Sender:               common.HexToAddress("0x1111111111111111111111111111111111111111"),
		UserOpNonce:          uint256.NewInt(0),
		InitCode:             []byte{0x01},
		CallData:             []byte{0x02, 0x03},
		CallGasLimit:         50000,
		VerificationGasLimit: 30000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         uint256.NewInt(1),
		MaxPriorityFeePerGas: uint256.NewInt(1),
		UserOpSignature:      []byte{0xbb},
		V:                    uint256.NewInt(0),
		R:                    uint256.NewInt(1),
		S:                    uint256.NewInt(1),
	})
}

func TestExtractAAUserOpTxPreservesFields(t *testing.T) {
	tx := makeAAUserOpTx()
	aaTx, ok := extractAAUserOpTx(tx)
	if !ok {
		t.Fatal("expected AA tx extraction to succeed")
	}
	if aaTx.Sender != common.HexToAddress("0x1111111111111111111111111111111111111111") {
		t.Fatalf("unexpected sender: %s", aaTx.Sender)
	}
	if aaTx.EntryPoint != NativeEntryPointAddress {
		t.Fatalf("unexpected entrypoint: %s", aaTx.EntryPoint)
	}
	if aaTx.UserOpNonce == nil || aaTx.UserOpNonce.Uint64() != 0 {
		t.Fatalf("unexpected userOp nonce: %v", aaTx.UserOpNonce)
	}
	if aaTx.MaxFeePerGas == nil || aaTx.MaxFeePerGas.Uint64() != 1 {
		t.Fatalf("unexpected maxFeePerGas: %v", aaTx.MaxFeePerGas)
	}
}

func TestProcessAATransactionUsesAAUserOpSender(t *testing.T) {
	statedb := newMockStateDB()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	beneficiary := common.HexToAddress("0x2222222222222222222222222222222222222222")

	statedb.balances[sender] = big.NewInt(1_000_000)
	statedb.codes[sender] = []byte{0x60, 0x00}

	p := NewProcessor(big.NewInt(1719))
	receipt, err := p.ProcessAATransaction(statedb, makeAAUserOpTx(), beneficiary)
	if err != nil {
		t.Fatalf("ProcessAATransaction failed: %v", err)
	}
	if receipt.Sender != sender {
		t.Fatalf("receipt sender mismatch: have %s want %s", receipt.Sender, sender)
	}
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("expected sender nonce to increment, got %d", got)
	}
}
