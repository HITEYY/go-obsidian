// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Package zkp provides zero-knowledge proof primitives for confidential transactions.
//
// The package implements:
//   - Pedersen Commitments: Hiding values with homomorphic properties
//   - Range Proofs: Proving values are within valid bounds without revealing them
//   - Stealth Addresses: One-time addresses for transaction privacy
//
// These primitives enable confidential transactions where:
//   - Transaction amounts are hidden from observers
//   - Sender and receiver identities are protected via stealth addresses
//   - Transaction validity can still be verified using zero-knowledge proofs
//
// Security relies on the discrete logarithm problem over BN254 curve.
package zkp
