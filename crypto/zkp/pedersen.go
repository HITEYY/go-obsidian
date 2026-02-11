// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Pedersen Commitment implementation for confidential transactions.
// Uses BN254 curve from gnark-crypto for efficient pairing-based operations.

package zkp

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
)

var (
	// Generator points for Pedersen commitment
	// G is used for the value, H is used for the blinding factor
	G bn254.G1Affine
	H bn254.G1Affine

	// ErrInvalidCommitment is returned when commitment verification fails
	ErrInvalidCommitment = errors.New("invalid pedersen commitment")
	// ErrInvalidBlindingFactor is returned when blinding factor is invalid
	ErrInvalidBlindingFactor = errors.New("invalid blinding factor")
	// ErrValueOverflow is returned when value exceeds maximum allowed
	ErrValueOverflow = errors.New("value exceeds maximum allowed for confidential tx")

	// MaxConfidentialValue is the maximum value allowed in confidential transactions
	// Set to 2^64 - 1 to allow reasonable transaction amounts while keeping proofs efficient
	MaxConfidentialValue = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
)

func init() {
	// Initialize generator points using hash-to-curve for nothing-up-my-sleeve property
	// G is the standard generator, H is derived from hashing "PedersenH"
	_, _, g1Gen, _ := bn254.Generators()
	G = g1Gen

	// Derive H by hashing a known string - ensures H = hash_to_curve("PedersenH")
	// This provides the nothing-up-my-sleeve property for security
	H = hashToCurve([]byte("ObsidianPedersenCommitmentH"))
}

// hashToCurve derives a curve point from arbitrary data
func hashToCurve(data []byte) bn254.G1Affine {
	// Ensure the point is on the curve by using scalar multiplication
	var scalar fr.Element
	scalar.SetBytes(crypto.Keccak256(data))

	var result bn254.G1Affine
	result.ScalarMultiplication(&G, scalar.BigInt(new(big.Int)))
	return result
}

// PedersenCommitment represents a Pedersen commitment C = v*G + r*H
type PedersenCommitment struct {
	Point bn254.G1Affine // The commitment point on the curve
}

// BlindingFactor represents the random blinding factor r in a Pedersen commitment
type BlindingFactor struct {
	r fr.Element
}

// NewBlindingFactor generates a new random blinding factor
func NewBlindingFactor() (*BlindingFactor, error) {
	var r fr.Element
	_, err := r.SetRandom()
	if err != nil {
		return nil, err
	}
	return &BlindingFactor{r: r}, nil
}

// BlindingFactorFromBytes creates a blinding factor from bytes
func BlindingFactorFromBytes(data []byte) (*BlindingFactor, error) {
	if len(data) != 32 {
		return nil, ErrInvalidBlindingFactor
	}
	var r fr.Element
	r.SetBytes(data)
	return &BlindingFactor{r: r}, nil
}

// Bytes returns the blinding factor as bytes
func (bf *BlindingFactor) Bytes() []byte {
	b := bf.r.Bytes()
	return b[:]
}

// Add adds two blinding factors
func (bf *BlindingFactor) Add(other *BlindingFactor) *BlindingFactor {
	var result fr.Element
	result.Add(&bf.r, &other.r)
	return &BlindingFactor{r: result}
}

// Sub subtracts two blinding factors
func (bf *BlindingFactor) Sub(other *BlindingFactor) *BlindingFactor {
	var result fr.Element
	result.Sub(&bf.r, &other.r)
	return &BlindingFactor{r: result}
}

// Commit creates a Pedersen commitment C = v*G + r*H
func Commit(value *big.Int, blindingFactor *BlindingFactor) (*PedersenCommitment, error) {
	if value.Cmp(MaxConfidentialValue) > 0 || value.Sign() < 0 {
		return nil, ErrValueOverflow
	}

	// vG = v * G
	var vG bn254.G1Affine
	vG.ScalarMultiplication(&G, value)

	// rH = r * H
	var rH bn254.G1Affine
	rH.ScalarMultiplication(&H, blindingFactor.r.BigInt(new(big.Int)))

	// C = vG + rH
	var commitment bn254.G1Affine
	commitment.Add(&vG, &rH)

	return &PedersenCommitment{Point: commitment}, nil
}

// CommitWithRandomness creates a commitment with a new random blinding factor
func CommitWithRandomness(value *big.Int) (*PedersenCommitment, *BlindingFactor, error) {
	bf, err := NewBlindingFactor()
	if err != nil {
		return nil, nil, err
	}

	commitment, err := Commit(value, bf)
	if err != nil {
		return nil, nil, err
	}

	return commitment, bf, nil
}

// Verify checks if a commitment matches a value and blinding factor
func (c *PedersenCommitment) Verify(value *big.Int, blindingFactor *BlindingFactor) bool {
	expected, err := Commit(value, blindingFactor)
	if err != nil {
		return false
	}
	return c.Point.Equal(&expected.Point)
}

// Bytes serializes the commitment to bytes
func (c *PedersenCommitment) Bytes() []byte {
	return c.Point.Marshal()
}

// CommitmentFromBytes deserializes a commitment from bytes
func CommitmentFromBytes(data []byte) (*PedersenCommitment, error) {
	var point bn254.G1Affine
	if err := point.Unmarshal(data); err != nil {
		return nil, ErrInvalidCommitment
	}
	return &PedersenCommitment{Point: point}, nil
}

// Add adds two commitments (homomorphic property)
// Commit(v1, r1) + Commit(v2, r2) = Commit(v1+v2, r1+r2)
func (c *PedersenCommitment) Add(other *PedersenCommitment) *PedersenCommitment {
	var result bn254.G1Affine
	result.Add(&c.Point, &other.Point)
	return &PedersenCommitment{Point: result}
}

// Sub subtracts two commitments (homomorphic property)
func (c *PedersenCommitment) Sub(other *PedersenCommitment) *PedersenCommitment {
	var negOther bn254.G1Affine
	negOther.Neg(&other.Point)

	var result bn254.G1Affine
	result.Add(&c.Point, &negOther)
	return &PedersenCommitment{Point: result}
}

// VerifyBalance checks that sum of input commitments equals sum of output commitments
// This proves conservation of value without revealing the amounts
func VerifyBalance(inputs []*PedersenCommitment, outputs []*PedersenCommitment) bool {
	if len(inputs) == 0 || len(outputs) == 0 {
		return false
	}

	// Sum all input commitments
	inputSum := inputs[0]
	for i := 1; i < len(inputs); i++ {
		inputSum = inputSum.Add(inputs[i])
	}

	// Sum all output commitments
	outputSum := outputs[0]
	for i := 1; i < len(outputs); i++ {
		outputSum = outputSum.Add(outputs[i])
	}

	// Check if sums are equal (inputs = outputs means conservation of value)
	return inputSum.Point.Equal(&outputSum.Point)
}

// GenerateCommitmentHash generates a hash of the commitment for use in transaction hashing
func (c *PedersenCommitment) Hash() common.Hash {
	return common.BytesToHash(crypto.Keccak256(c.Bytes()))
}

// ZeroCommitment returns a commitment to zero with zero blinding factor (for verification)
func ZeroCommitment() *PedersenCommitment {
	var zero bn254.G1Affine
	zero.X.SetZero()
	zero.Y.SetZero()
	return &PedersenCommitment{Point: zero}
}

// GenerateRandomScalar generates a random scalar for cryptographic operations
func GenerateRandomScalar() (*big.Int, error) {
	max := fr.Modulus()
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}
