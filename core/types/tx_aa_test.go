// Copyright 2026 The go-obsidian Authors

package types

import (
	"math/big"
	"testing"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
	"github.com/holiman/uint256"
)

func TestAAUserOpTxZeroValueDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value AA tx should not panic: %v", r)
		}
	}()
	tx := NewTx(&AAUserOpTx{})
	_ = tx.Hash()
	_ = tx.ChainId()
	_ = tx.GasFeeCap()
	_, _, _ = tx.RawSignatureValues()
}

func TestAAUserOpTxSenderRecovery(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	chainID := big.NewInt(1719)
	signer := LatestSignerForChainID(chainID)

	tx := MustSignNewTx(key, signer, &AAUserOpTx{
		ChainID:              uint256.MustFromBig(chainID),
		GasTipCap:            uint256.NewInt(1),
		GasFeeCap:            uint256.NewInt(1),
		Gas:                  21000,
		EntryPoint:           common.HexToAddress("0x0000000000000000000000000000000000aa4337"),
		Sender:               common.HexToAddress("0x1111111111111111111111111111111111111111"),
		UserOpNonce:          uint256.NewInt(0),
		CallGasLimit:         50000,
		VerificationGasLimit: 30000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         uint256.NewInt(1),
		MaxPriorityFeePerGas: uint256.NewInt(1),
	})

	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatalf("Sender failed for AA tx: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	if from != want {
		t.Fatalf("sender mismatch: have %s want %s", from, want)
	}
}

func TestAAUserOpReceiptRoundTrip(t *testing.T) {
	receipt := &Receipt{
		Type:              AAUserOpTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 1,
	}
	b, err := receipt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	var dec Receipt
	if err := dec.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if dec.Type != AAUserOpTxType {
		t.Fatalf("type mismatch: have %d want %d", dec.Type, AAUserOpTxType)
	}
}
