// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.

package zkp_test

import (
	"fmt"
	"math/big"

	"github.com/HITEYY/go-obsidian/crypto/zkp"
)

// ExampleConfidentialTransfer demonstrates a complete confidential transfer workflow
func ExampleConfidentialTransfer() {
	// === Setup: Generate keys for sender and recipient ===

	// Sender's stealth keys
	senderKeys, _ := zkp.GenerateStealthKeyPair()
	senderMeta := senderKeys.MetaAddress()

	// Recipient's stealth keys
	recipientKeys, _ := zkp.GenerateStealthKeyPair()
	recipientMeta := recipientKeys.MetaAddress()

	// === Create sender's initial funds (simulating a received payment) ===

	// Sender has 1000 units
	initialValue := big.NewInt(1000)
	senderNote, _ := zkp.CreateConfidentialOutput(initialValue, senderMeta)

	fmt.Println("=== Confidential Transaction Example ===")
	fmt.Printf("Sender's initial balance: %d units (hidden in commitment)\n", initialValue)

	// === Build a transfer: Send 600 to recipient, keep 390, pay 10 fee ===

	transferAmount := big.NewInt(600)
	changeAmount := big.NewInt(390)
	fee := big.NewInt(10)

	// Create output for recipient (600 units)
	recipientOutput, _ := zkp.CreateConfidentialOutput(transferAmount, recipientMeta)

	// Create change output for sender (390 units)
	changeOutput, _ := zkp.CreateConfidentialOutput(changeAmount, senderMeta)

	fmt.Printf("\nTransfer breakdown (all hidden from observers):\n")
	fmt.Printf("  To recipient: %d units\n", transferAmount)
	fmt.Printf("  Change to sender: %d units\n", changeAmount)
	fmt.Printf("  Transaction fee: %d units\n", fee)

	// === Verify balance: inputs = outputs + fee ===

	// The homomorphic property allows us to verify:
	// Commitment(1000, r1) = Commitment(600, r2) + Commitment(390, r3) + Commitment(10, r4)
	// This can be verified WITHOUT knowing the actual amounts!

	// Create fee commitment with balancing blinding factor
	feeBlinding := zkp.ComputeBalanceBlindingFactor(
		[]*zkp.ConfidentialNote{{
			Value:          initialValue,
			BlindingFactor: senderNote.BlindingFactor,
			Commitment:     senderNote.Commitment,
		}},
		[]*zkp.ConfidentialOutput{recipientOutput, changeOutput},
	)
	feeCommitment, _ := zkp.Commit(fee, feeBlinding)

	// Verify balance
	inputs := []*zkp.PedersenCommitment{senderNote.Commitment}
	outputs := []*zkp.PedersenCommitment{
		recipientOutput.Commitment,
		changeOutput.Commitment,
		feeCommitment,
	}

	balanced := zkp.VerifyBalance(inputs, outputs)
	fmt.Printf("\nBalance verification (no amounts revealed): %v\n", balanced)

	// === Recipient scans and finds their payment ===

	// The recipient uses their viewing key to scan for payments
	// They can quickly filter using view tags, then decrypt matching notes

	viewTagMatches := zkp.CheckViewTag(
		recipientKeys.ViewingKey,
		recipientOutput.StealthAddress.EphemeralPub,
		recipientOutput.StealthAddress.ViewTag,
	)
	fmt.Printf("\nRecipient scan - View tag match: %v\n", viewTagMatches)

	// Decrypt the note to learn the amount
	decryptedValue, _, err := zkp.DecryptNote(
		recipientOutput.EncryptedNote,
		recipientKeys.ViewingKey,
		recipientOutput.StealthAddress.EphemeralPub,
	)
	if err == nil {
		fmt.Printf("Recipient decrypted amount: %d units\n", decryptedValue)
	}

	// === Range proofs ensure all values are valid ===

	fmt.Printf("\nRange proof verification:\n")
	fmt.Printf("  Recipient output range proof valid: %v\n",
		zkp.VerifyRangeProof(recipientOutput.RangeProof, recipientOutput.Commitment))
	fmt.Printf("  Change output range proof valid: %v\n",
		zkp.VerifyRangeProof(changeOutput.RangeProof, changeOutput.Commitment))

	// === Summary ===

	fmt.Printf("\n=== Privacy Summary ===\n")
	fmt.Printf("✓ Transaction amounts are hidden (Pedersen commitments)\n")
	fmt.Printf("✓ Sender identity is hidden (one-time stealth addresses)\n")
	fmt.Printf("✓ Recipient identity is hidden (one-time stealth addresses)\n")
	fmt.Printf("✓ Balance is provably correct (homomorphic verification)\n")
	fmt.Printf("✓ Values are provably non-negative (range proofs)\n")

	// Output:
	// === Confidential Transaction Example ===
	// Sender's initial balance: 1000 units (hidden in commitment)
	//
	// Transfer breakdown (all hidden from observers):
	//   To recipient: 600 units
	//   Change to sender: 390 units
	//   Transaction fee: 10 units
	//
	// Balance verification (no amounts revealed): true
	//
	// Recipient scan - View tag match: true
	// Recipient decrypted amount: 600 units
	//
	// Range proof verification:
	//   Recipient output range proof valid: true
	//   Change output range proof valid: true
	//
	// === Privacy Summary ===
	// ✓ Transaction amounts are hidden (Pedersen commitments)
	// ✓ Sender identity is hidden (one-time stealth addresses)
	// ✓ Recipient identity is hidden (one-time stealth addresses)
	// ✓ Balance is provably correct (homomorphic verification)
	// ✓ Values are provably non-negative (range proofs)
}
