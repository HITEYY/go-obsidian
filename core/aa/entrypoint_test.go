// Copyright 2025 The go-obsidian Authors

package aa

import (
	"math/big"
	"testing"

	"github.com/HITEYY/go-obsidian/common"
)

// mockStateDB implements StateDB for testing.
type mockStateDB struct {
	balances map[common.Address]*big.Int
	nonces   map[common.Address]uint64
	codes    map[common.Address][]byte
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{
		balances: make(map[common.Address]*big.Int),
		nonces:   make(map[common.Address]uint64),
		codes:    make(map[common.Address][]byte),
	}
}

func (m *mockStateDB) GetBalance(addr common.Address) *big.Int {
	if b, ok := m.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return big.NewInt(0)
}

func (m *mockStateDB) SubBalance(addr common.Address, amount *big.Int) {
	if _, ok := m.balances[addr]; !ok {
		m.balances[addr] = big.NewInt(0)
	}
	m.balances[addr].Sub(m.balances[addr], amount)
}

func (m *mockStateDB) AddBalance(addr common.Address, amount *big.Int) {
	if _, ok := m.balances[addr]; !ok {
		m.balances[addr] = big.NewInt(0)
	}
	m.balances[addr].Add(m.balances[addr], amount)
}

func (m *mockStateDB) GetNonce(addr common.Address) uint64 {
	return m.nonces[addr]
}

func (m *mockStateDB) SetNonce(addr common.Address, nonce uint64) {
	m.nonces[addr] = nonce
}

func (m *mockStateDB) GetCode(addr common.Address) []byte {
	return m.codes[addr]
}

func (m *mockStateDB) GetCodeHash(addr common.Address) common.Hash {
	code := m.codes[addr]
	if len(code) == 0 {
		return common.Hash{}
	}
	return common.BytesToHash(code[:min(32, len(code))])
}

func (m *mockStateDB) Exist(addr common.Address) bool {
	_, ok := m.balances[addr]
	return ok
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestEntryPointHandleOps_SelfSponsored(t *testing.T) {
	statedb := newMockStateDB()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	beneficiary := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Setup: sender has balance and deployed code
	statedb.balances[sender] = big.NewInt(1e18)
	statedb.codes[sender] = []byte{0x60, 0x00} // minimal bytecode

	ep := NewEntryPoint()

	op := &UserOperation{
		Sender:               sender,
		Nonce:                big.NewInt(0),
		InitCode:             nil,
		CallData:             []byte{0x01, 0x02, 0x03},
		CallGasLimit:         100000,
		VerificationGasLimit: 50000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(1000000000), // 1 gwei
		MaxPriorityFeePerGas: big.NewInt(100000000),
		Signature:            []byte{0xff},
	}

	receipts, err := ep.HandleOps(statedb, []*UserOperation{op}, beneficiary)
	if err != nil {
		t.Fatalf("HandleOps failed: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	receipt := receipts[0]
	if !receipt.Success {
		t.Errorf("expected success, got failure: %s", receipt.Reason)
	}
	if receipt.Sender != sender {
		t.Errorf("wrong sender in receipt")
	}
	if receipt.ActualGasCost.Sign() <= 0 {
		t.Errorf("expected positive gas cost")
	}

	// Nonce should have incremented
	if statedb.GetNonce(sender) != 1 {
		t.Errorf("nonce not incremented, got %d", statedb.GetNonce(sender))
	}

	// Beneficiary should have received gas payment
	if statedb.GetBalance(beneficiary).Sign() <= 0 {
		t.Errorf("beneficiary should have received gas payment")
	}
}

func TestEntryPointHandleOps_PaymasterSponsored(t *testing.T) {
	statedb := newMockStateDB()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	pmAddr := common.HexToAddress("0x3333333333333333333333333333333333333333")
	beneficiary := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Setup
	statedb.balances[sender] = big.NewInt(0) // Sender has NO balance
	statedb.codes[sender] = []byte{0x60, 0x00}

	ep := NewEntryPoint()

	// Fund paymaster deposit
	ep.AddDeposit(pmAddr, big.NewInt(1e18))

	// Build paymaster-sponsored UserOp
	pmAndData := make([]byte, 20)
	copy(pmAndData, pmAddr.Bytes())

	op := &UserOperation{
		Sender:               sender,
		Nonce:                big.NewInt(0),
		CallData:             []byte{0x01},
		CallGasLimit:         50000,
		VerificationGasLimit: 30000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(1000000000),
		MaxPriorityFeePerGas: big.NewInt(100000000),
		PaymasterAndData:     pmAndData,
		Signature:            []byte{0xff},
	}

	receipts, err := ep.HandleOps(statedb, []*UserOperation{op}, beneficiary)
	if err != nil {
		t.Fatalf("HandleOps failed: %v", err)
	}

	receipt := receipts[0]
	if !receipt.Success {
		t.Errorf("expected success, got: %s", receipt.Reason)
	}
	if receipt.Paymaster != pmAddr {
		t.Errorf("expected paymaster %s, got %s", pmAddr, receipt.Paymaster)
	}

	// Paymaster deposit should have decreased
	deposit := ep.GetDeposit(pmAddr)
	if deposit.Cmp(big.NewInt(1e18)) >= 0 {
		t.Errorf("paymaster deposit should have decreased")
	}
}

func TestEntryPointNonceValidation(t *testing.T) {
	statedb := newMockStateDB()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")

	statedb.balances[sender] = big.NewInt(1e18)
	statedb.codes[sender] = []byte{0x60, 0x00}
	statedb.nonces[sender] = 5 // nonce is 5

	ep := NewEntryPoint()

	op := &UserOperation{
		Sender:               sender,
		Nonce:                big.NewInt(3), // Wrong nonce
		CallData:             []byte{0x01},
		CallGasLimit:         50000,
		VerificationGasLimit: 30000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(1000000000),
		MaxPriorityFeePerGas: big.NewInt(100000000),
		Signature:            []byte{0xff},
	}

	receipts, _ := ep.HandleOps(statedb, []*UserOperation{op}, common.Address{})
	if receipts[0].Success {
		t.Errorf("expected failure due to wrong nonce")
	}
}

func TestGetDeposit(t *testing.T) {
	ep := NewEntryPoint()
	addr := common.HexToAddress("0xdead")

	if ep.GetDeposit(addr).Sign() != 0 {
		t.Error("expected zero deposit")
	}

	ep.AddDeposit(addr, big.NewInt(1000))
	if ep.GetDeposit(addr).Cmp(big.NewInt(1000)) != 0 {
		t.Error("deposit mismatch")
	}

	if err := ep.WithdrawDeposit(addr, big.NewInt(500)); err != nil {
		t.Error(err)
	}
	if ep.GetDeposit(addr).Cmp(big.NewInt(500)) != 0 {
		t.Error("deposit after withdraw mismatch")
	}

	if err := ep.WithdrawDeposit(addr, big.NewInt(9999)); err == nil {
		t.Error("expected error for over-withdrawal")
	}
}
