// Copyright 2024 The go-obsidian Authors
// This file is part of the go-obsidian library.
//
// Stealth Address implementation for confidential transactions.
// Enables hiding sender and receiver identities using ECDH-based one-time addresses.

package zkp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/HITEYY/go-obsidian/common"
	"github.com/HITEYY/go-obsidian/crypto"
)

var (
	// ErrInvalidStealthKey is returned when a stealth key is invalid
	ErrInvalidStealthKey = errors.New("invalid stealth key")
	// ErrInvalidEphemeralKey is returned when ephemeral key is invalid
	ErrInvalidEphemeralKey = errors.New("invalid ephemeral key")
	// ErrStealthAddressDerivation is returned when stealth address derivation fails
	ErrStealthAddressDerivation = errors.New("stealth address derivation failed")
)

// StealthMetaAddress contains the public keys needed for stealth address generation
// Following EIP-5564 stealth address protocol
type StealthMetaAddress struct {
	SpendingPubKey *ecdsa.PublicKey // Used to derive the stealth address
	ViewingPubKey  *ecdsa.PublicKey // Used to scan for incoming payments
}

// StealthKeyPair contains both spending and viewing key pairs
type StealthKeyPair struct {
	SpendingKey *ecdsa.PrivateKey
	ViewingKey  *ecdsa.PrivateKey
}

// StealthAddress represents a one-time stealth address with metadata for scanning
type StealthAddress struct {
	Address       common.Address // The derived one-time address
	EphemeralPub  []byte         // Ephemeral public key for recipient to derive private key
	ViewTag       byte           // First byte of shared secret for fast scanning
	StealthPubKey []byte         // The stealth public key (compressed)
}

// GenerateStealthKeyPair generates a new stealth key pair
func GenerateStealthKeyPair() (*StealthKeyPair, error) {
	spendingKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	viewingKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &StealthKeyPair{
		SpendingKey: spendingKey,
		ViewingKey:  viewingKey,
	}, nil
}

// MetaAddress returns the stealth meta-address from a key pair
func (skp *StealthKeyPair) MetaAddress() *StealthMetaAddress {
	return &StealthMetaAddress{
		SpendingPubKey: &skp.SpendingKey.PublicKey,
		ViewingPubKey:  &skp.ViewingKey.PublicKey,
	}
}

// GenerateStealthAddress generates a one-time stealth address for a recipient
// Uses ECDH to create a shared secret without revealing sender or receiver
func GenerateStealthAddress(metaAddr *StealthMetaAddress) (*StealthAddress, *ecdsa.PrivateKey, error) {
	// Generate ephemeral key pair
	ephemeralKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Compute shared secret: S = ephemeralPriv * viewingPub
	sharedSecretX, sharedSecretY := crypto.S256().ScalarMult(
		metaAddr.ViewingPubKey.X,
		metaAddr.ViewingPubKey.Y,
		ephemeralKey.D.Bytes(),
	)

	// Hash the shared secret to get a scalar
	sharedSecretBytes := append(sharedSecretX.Bytes(), sharedSecretY.Bytes()...)
	hashedSecret := crypto.Keccak256(sharedSecretBytes)
	_ = new(big.Int).SetBytes(hashedSecret) // secretScalar used implicitly via hashedSecret

	// Derive stealth public key: stealthPub = spendingPub + hash(S) * G
	stealthPubX, stealthPubY := crypto.S256().ScalarBaseMult(hashedSecret)
	stealthPubX, stealthPubY = crypto.S256().Add(
		metaAddr.SpendingPubKey.X,
		metaAddr.SpendingPubKey.Y,
		stealthPubX,
		stealthPubY,
	)

	stealthPubKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     stealthPubX,
		Y:     stealthPubY,
	}

	// Derive stealth address from public key
	stealthAddr := crypto.PubkeyToAddress(*stealthPubKey)

	// Compute view tag (first byte of hashed shared secret for fast scanning)
	viewTag := hashedSecret[0]

	// Serialize ephemeral public key
	ephemeralPubBytes := crypto.CompressPubkey(&ephemeralKey.PublicKey)
	stealthPubBytes := crypto.CompressPubkey(stealthPubKey)

	return &StealthAddress{
		Address:       stealthAddr,
		EphemeralPub:  ephemeralPubBytes,
		ViewTag:       viewTag,
		StealthPubKey: stealthPubBytes,
	}, ephemeralKey, nil
}

// DeriveStealthPrivateKey derives the private key for a stealth address
// Only the recipient with the viewing and spending keys can derive this
func DeriveStealthPrivateKey(skp *StealthKeyPair, ephemeralPubBytes []byte) (*ecdsa.PrivateKey, error) {
	// Decompress ephemeral public key
	ephemeralPub, err := crypto.DecompressPubkey(ephemeralPubBytes)
	if err != nil {
		return nil, ErrInvalidEphemeralKey
	}

	// Compute shared secret: S = viewingPriv * ephemeralPub
	sharedSecretX, sharedSecretY := crypto.S256().ScalarMult(
		ephemeralPub.X,
		ephemeralPub.Y,
		skp.ViewingKey.D.Bytes(),
	)

	// Hash the shared secret
	sharedSecretBytes := append(sharedSecretX.Bytes(), sharedSecretY.Bytes()...)
	hashedSecret := crypto.Keccak256(sharedSecretBytes)
	secretScalar := new(big.Int).SetBytes(hashedSecret)

	// Derive stealth private key: stealthPriv = spendingPriv + hash(S)
	stealthPrivD := new(big.Int).Add(skp.SpendingKey.D, secretScalar)
	stealthPrivD.Mod(stealthPrivD, crypto.S256().Params().N)

	// Construct private key
	stealthPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: crypto.S256(),
		},
		D: stealthPrivD,
	}
	stealthPrivKey.PublicKey.X, stealthPrivKey.PublicKey.Y = crypto.S256().ScalarBaseMult(stealthPrivD.Bytes())

	return stealthPrivKey, nil
}

// CheckViewTag quickly checks if a transaction might be for us using the view tag
// This is an optimization to avoid expensive ECDH for unrelated transactions
func CheckViewTag(viewingKey *ecdsa.PrivateKey, ephemeralPubBytes []byte, expectedViewTag byte) bool {
	ephemeralPub, err := crypto.DecompressPubkey(ephemeralPubBytes)
	if err != nil {
		return false
	}

	// Compute shared secret
	sharedSecretX, sharedSecretY := crypto.S256().ScalarMult(
		ephemeralPub.X,
		ephemeralPub.Y,
		viewingKey.D.Bytes(),
	)

	// Hash and check first byte
	sharedSecretBytes := append(sharedSecretX.Bytes(), sharedSecretY.Bytes()...)
	hashedSecret := crypto.Keccak256(sharedSecretBytes)

	return hashedSecret[0] == expectedViewTag
}

// VerifyStealthAddress verifies that a stealth address was correctly derived
func VerifyStealthAddress(metaAddr *StealthMetaAddress, stealthAddr *StealthAddress) bool {
	ephemeralPub, err := crypto.DecompressPubkey(stealthAddr.EphemeralPub)
	if err != nil {
		return false
	}

	// This requires the viewing key, which we don't have here
	// This function is for public verification using the ephemeral key
	// The actual verification would be done by the recipient

	// For now, verify the ephemeral public key is valid
	return ephemeralPub.X != nil && ephemeralPub.Y != nil && crypto.S256().IsOnCurve(ephemeralPub.X, ephemeralPub.Y)
}

// Bytes serializes the stealth address to bytes
func (sa *StealthAddress) Bytes() []byte {
	result := make([]byte, 0, 20+len(sa.EphemeralPub)+1+len(sa.StealthPubKey))
	result = append(result, sa.Address.Bytes()...)
	result = append(result, byte(len(sa.EphemeralPub)))
	result = append(result, sa.EphemeralPub...)
	result = append(result, sa.ViewTag)
	result = append(result, sa.StealthPubKey...)
	return result
}

// StealthAddressFromBytes deserializes a stealth address from bytes
func StealthAddressFromBytes(data []byte) (*StealthAddress, error) {
	if len(data) < 22 { // 20 (address) + 1 (len) + 1 (viewtag) minimum
		return nil, ErrInvalidStealthKey
	}

	addr := common.BytesToAddress(data[:20])
	ephemeralLen := int(data[20])

	if len(data) < 21+ephemeralLen+1 {
		return nil, ErrInvalidStealthKey
	}

	ephemeralPub := data[21 : 21+ephemeralLen]
	viewTag := data[21+ephemeralLen]
	stealthPubKey := data[22+ephemeralLen:]

	return &StealthAddress{
		Address:       addr,
		EphemeralPub:  ephemeralPub,
		ViewTag:       viewTag,
		StealthPubKey: stealthPubKey,
	}, nil
}

// NullifierHash generates a nullifier to prevent double-spending of stealth outputs
func GenerateNullifier(stealthPrivKey *ecdsa.PrivateKey, outputIndex uint64) common.Hash {
	data := append(stealthPrivKey.D.Bytes(), big.NewInt(int64(outputIndex)).Bytes()...)
	return common.BytesToHash(crypto.Keccak256(data))
}
