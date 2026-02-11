// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.

package zkp

import (
	"math/big"
	"testing"

	"github.com/HITEYY/go-obsidian/common"
)

func TestPedersenCommitment(t *testing.T) {
	value := big.NewInt(1000)

	// Test commitment creation
	commitment, bf, err := CommitWithRandomness(value)
	if err != nil {
		t.Fatalf("Failed to create commitment: %v", err)
	}

	// Test verification
	if !commitment.Verify(value, bf) {
		t.Error("Commitment verification failed for correct value")
	}

	// Test verification with wrong value
	wrongValue := big.NewInt(999)
	if commitment.Verify(wrongValue, bf) {
		t.Error("Commitment verification should fail for wrong value")
	}

	// Test serialization
	serialized := commitment.Bytes()
	deserialized, err := CommitmentFromBytes(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize commitment: %v", err)
	}
	if !deserialized.Point.Equal(&commitment.Point) {
		t.Error("Deserialized commitment doesn't match original")
	}
}

func TestPedersenHomomorphic(t *testing.T) {
	v1 := big.NewInt(100)
	v2 := big.NewInt(200)

	c1, bf1, _ := CommitWithRandomness(v1)
	c2, bf2, _ := CommitWithRandomness(v2)

	// Test homomorphic addition
	sumCommitment := c1.Add(c2)
	sumBf := bf1.Add(bf2)
	sumValue := new(big.Int).Add(v1, v2)

	if !sumCommitment.Verify(sumValue, sumBf) {
		t.Error("Homomorphic addition verification failed")
	}
}

func TestBalanceVerification(t *testing.T) {
	// Create inputs: 100 + 50 = 150
	v1 := big.NewInt(100)
	v2 := big.NewInt(50)
	c1, bf1, _ := CommitWithRandomness(v1)
	c2, bf2, _ := CommitWithRandomness(v2)

	// Create outputs: 80 + 60 + 10 (fee) = 150
	v3 := big.NewInt(80)
	v4 := big.NewInt(60)
	v5 := big.NewInt(10)
	c3, bf3, _ := CommitWithRandomness(v3)
	c4, bf4, _ := CommitWithRandomness(v4)

	// Compute fee blinding factor to balance
	inputBf := bf1.Add(bf2)
	outputBf := bf3.Add(bf4)
	feeBf := inputBf.Sub(outputBf)

	c5, _ := Commit(v5, feeBf)

	inputs := []*PedersenCommitment{c1, c2}
	outputs := []*PedersenCommitment{c3, c4, c5}

	if !VerifyBalance(inputs, outputs) {
		t.Error("Balance verification failed for valid transaction")
	}

	// Test with unbalanced transaction
	c6, _, _ := CommitWithRandomness(big.NewInt(11)) // Wrong fee
	unbalancedOutputs := []*PedersenCommitment{c3, c4, c6}

	if VerifyBalance(inputs, unbalancedOutputs) {
		t.Error("Balance verification should fail for unbalanced transaction")
	}
}

func TestStealthAddress(t *testing.T) {
	// Generate recipient key pair
	recipientKeys, err := GenerateStealthKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate stealth keys: %v", err)
	}

	metaAddr := recipientKeys.MetaAddress()

	// Generate stealth address
	stealthAddr, _, err := GenerateStealthAddress(metaAddr)
	if err != nil {
		t.Fatalf("Failed to generate stealth address: %v", err)
	}

	// Verify stealth address has valid components
	if stealthAddr.Address == (common.Address{}) {
		t.Error("Stealth address is empty")
	}
	if len(stealthAddr.EphemeralPub) == 0 {
		t.Error("Ephemeral public key is empty")
	}

	// Test serialization
	serialized := stealthAddr.Bytes()
	deserialized, err := StealthAddressFromBytes(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize stealth address: %v", err)
	}
	if deserialized.Address != stealthAddr.Address {
		t.Error("Deserialized stealth address doesn't match original")
	}

	// Test private key derivation
	stealthPrivKey, err := DeriveStealthPrivateKey(recipientKeys, stealthAddr.EphemeralPub)
	if err != nil {
		t.Fatalf("Failed to derive stealth private key: %v", err)
	}
	if stealthPrivKey.D == nil {
		t.Error("Derived private key is nil")
	}

	// Test view tag checking
	if !CheckViewTag(recipientKeys.ViewingKey, stealthAddr.EphemeralPub, stealthAddr.ViewTag) {
		t.Error("View tag check failed for valid stealth address")
	}
}

func TestRangeProof(t *testing.T) {
	value := big.NewInt(1000)
	commitment, bf, _ := CommitWithRandomness(value)

	// Generate range proof
	proof, err := GenerateRangeProof(value, bf, commitment)
	if err != nil {
		t.Fatalf("Failed to generate range proof: %v", err)
	}

	// Verify range proof
	if !VerifyRangeProof(proof, commitment) {
		t.Error("Range proof verification failed for valid proof")
	}

	// Test serialization
	serialized := proof.Bytes()
	deserialized, err := RangeProofFromBytes(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize range proof: %v", err)
	}
	if !VerifyRangeProof(deserialized, commitment) {
		t.Error("Deserialized range proof verification failed")
	}
}

func TestRangeProofOutOfRange(t *testing.T) {
	// Test with value that's too large
	largeValue := new(big.Int).Lsh(big.NewInt(1), 65) // 2^65 > MaxConfidentialValue
	_, _, err := CommitWithRandomness(largeValue)
	if err != ErrValueOverflow {
		t.Error("Should reject value larger than MaxConfidentialValue")
	}

	// Test with negative value
	negValue := big.NewInt(-100)
	_, _, err = CommitWithRandomness(negValue)
	if err != ErrValueOverflow {
		t.Error("Should reject negative value")
	}
}

func TestBatchVerifyRangeProofs(t *testing.T) {
	values := []*big.Int{
		big.NewInt(100),
		big.NewInt(200),
		big.NewInt(300),
	}

	proofs := make([]*RangeProof, len(values))
	commitments := make([]*PedersenCommitment, len(values))

	for i, v := range values {
		c, bf, _ := CommitWithRandomness(v)
		p, _ := GenerateRangeProof(v, bf, c)
		proofs[i] = p
		commitments[i] = c
	}

	if !BatchVerifyRangeProofs(proofs, commitments) {
		t.Error("Batch verification failed for valid proofs")
	}
}

func TestBlindingFactorOperations(t *testing.T) {
	bf1, _ := NewBlindingFactor()
	bf2, _ := NewBlindingFactor()

	// Test serialization
	serialized := bf1.Bytes()
	deserialized, err := BlindingFactorFromBytes(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize blinding factor: %v", err)
	}
	if string(deserialized.Bytes()) != string(bf1.Bytes()) {
		t.Error("Deserialized blinding factor doesn't match original")
	}

	// Test addition
	sum := bf1.Add(bf2)
	if sum == nil {
		t.Error("Blinding factor addition returned nil")
	}

	// Test subtraction
	diff := bf1.Sub(bf2)
	if diff == nil {
		t.Error("Blinding factor subtraction returned nil")
	}
}

func TestConfidentialOutput(t *testing.T) {
	// Generate recipient keys
	recipientKeys, _ := GenerateStealthKeyPair()
	metaAddr := recipientKeys.MetaAddress()

	// Create confidential output
	value := big.NewInt(1000)
	output, err := CreateConfidentialOutput(value, metaAddr)
	if err != nil {
		t.Fatalf("Failed to create confidential output: %v", err)
	}

	// Verify all components are present
	if output.Commitment == nil {
		t.Error("Output commitment is nil")
	}
	if output.RangeProof == nil {
		t.Error("Output range proof is nil")
	}
	if output.StealthAddress == nil {
		t.Error("Output stealth address is nil")
	}
	if len(output.EncryptedNote) == 0 {
		t.Error("Output encrypted note is empty")
	}

	// Verify range proof
	if !VerifyRangeProof(output.RangeProof, output.Commitment) {
		t.Error("Output range proof verification failed")
	}
}

func TestEncryptDecryptNote(t *testing.T) {
	// Generate keys
	recipientKeys, _ := GenerateStealthKeyPair()
	metaAddr := recipientKeys.MetaAddress()

	// Create output (which encrypts the note)
	value := big.NewInt(12345)
	output, _ := CreateConfidentialOutput(value, metaAddr)

	// Decrypt the note
	decryptedValue, decryptedBf, err := DecryptNote(
		output.EncryptedNote,
		recipientKeys.ViewingKey,
		output.StealthAddress.EphemeralPub,
	)
	if err != nil {
		t.Fatalf("Failed to decrypt note: %v", err)
	}

	// Verify decrypted value matches
	if decryptedValue.Cmp(value) != 0 {
		t.Errorf("Decrypted value %v doesn't match original %v", decryptedValue, value)
	}

	// Verify commitment with decrypted blinding factor
	if !output.Commitment.Verify(decryptedValue, decryptedBf) {
		t.Error("Commitment verification failed with decrypted values")
	}
}

func TestNullifierGeneration(t *testing.T) {
	// Generate stealth keys
	recipientKeys, _ := GenerateStealthKeyPair()
	metaAddr := recipientKeys.MetaAddress()
	
	stealthAddr, _, _ := GenerateStealthAddress(metaAddr)
	stealthPrivKey, _ := DeriveStealthPrivateKey(recipientKeys, stealthAddr.EphemeralPub)

	// Generate nullifiers for different output indices
	nullifier1 := GenerateNullifier(stealthPrivKey, 0)
	nullifier2 := GenerateNullifier(stealthPrivKey, 1)

	// Nullifiers should be different for different indices
	if nullifier1 == nullifier2 {
		t.Error("Nullifiers should be different for different output indices")
	}

	// Same inputs should produce same nullifier
	nullifier1Again := GenerateNullifier(stealthPrivKey, 0)
	if nullifier1 != nullifier1Again {
		t.Error("Same inputs should produce same nullifier")
	}
}

// BenchmarkRangeProofGeneration benchmarks range proof generation
func BenchmarkRangeProofGeneration(b *testing.B) {
	value := big.NewInt(1000000)
	commitment, bf, _ := CommitWithRandomness(value)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateRangeProof(value, bf, commitment)
	}
}

// BenchmarkRangeProofVerification benchmarks range proof verification
func BenchmarkRangeProofVerification(b *testing.B) {
	value := big.NewInt(1000000)
	commitment, bf, _ := CommitWithRandomness(value)
	proof, _ := GenerateRangeProof(value, bf, commitment)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyRangeProof(proof, commitment)
	}
}

// BenchmarkPedersenCommit benchmarks Pedersen commitment creation
func BenchmarkPedersenCommit(b *testing.B) {
	value := big.NewInt(1000000)
	bf, _ := NewBlindingFactor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Commit(value, bf)
	}
}

func BenchmarkStealthAddressGeneration(b *testing.B) {
	keys, _ := GenerateStealthKeyPair()
	metaAddr := keys.MetaAddress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateStealthAddress(metaAddr)
	}
}
