// Copyright 2025 The go-obsidian Authors
// This file is part of the go-obsidian library.

/*
Package aa implements native Account Abstraction for go-obsidian.

This package provides EIP-4337 compatible Account Abstraction at the protocol
level, enabling smart contract wallets to initiate transactions without requiring
EOA (Externally Owned Account) signatures for gas payment.

# Architecture

The system consists of three main components:

1. EntryPoint - The native singleton that processes UserOperations. It handles
   validation, execution, and gas accounting for all AA transactions.

2. Paymaster - Gas sponsorship contracts that can pay for users' gas fees.
   Supports multiple modes: full sponsorship, verifying (signed), ERC-20 token
   payment, and partial sponsorship.

3. Processor - Integration layer that connects the AA system to go-obsidian's
   transaction processing pipeline, handling AAUserOpTx (type 0x06) transactions.

# Transaction Flow

	User creates UserOperation
	    → Bundler wraps in AAUserOpTx (type 0x06)
	        → Block builder includes in block
	            → EntryPoint.HandleOps processes:
	                1. Validate account (nonce, signature, initCode)
	                2. Validate paymaster (if present)
	                3. Charge prefund (from paymaster or sender)
	                4. Execute callData on sender account
	                5. Refund unused gas
	                6. Pay beneficiary (bundler)
	                7. Call paymaster.postOp (if applicable)

# Paymaster Modes

  - Full: Sponsors all gas unconditionally
  - Verifying: Requires off-chain signature from paymaster signer
  - ERC20: Accepts ERC-20 tokens as gas payment
  - Partial: Sponsors up to a configured limit
*/
package aa
