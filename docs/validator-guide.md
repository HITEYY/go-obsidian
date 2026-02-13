# Obsidian Validator & Staking Guide

This guide provides technical instructions on how to participate as a validator in the Obsidian network, including account generation and staking procedures.

## 1. Generating a Validator Address

In the Obsidian network, a `VALIDATOR_ADDRESS` is a standard Ethereum-compatible EOA (Externally Owned Account). This address is used to sign blocks and receive rewards.

### Using the Geth CLI

The easiest way to generate a new validator address is using the `geth` binary built from the `go-obsidian` repository.

1.  **Build the project:**
    ```bash
    make geth
    ```
2.  **Create a new account:**
    ```bash
    ./build/bin/geth account new --datadir ./data
    ```
3.  **Note your address:**
    The command will output your public address (e.g., `0x71C7656EC7ab88b098defB751B7401B5f6d8976F`). This is your `VALIDATOR_ADDRESS`.
4.  **Backup your Keystore:**
    The secret key is stored in the `keystore` directory within your `--datadir`. Ensure this file is backed up securely.

---

## 2. Staking on the Obsidian Network

Obsidian uses a Tendermint-based Proof-of-Stake (PoS) consensus mechanism. To become an active validator, you must be "authorized" by the existing validator set through a voting process.

### Minimum Requirements
*   **Chain ID:** 1719
*   **Minimum Stake:** 1 OBS (1,000,000,000,000,000,000 Wei)
*   **Block Period:** 2 seconds

### Authorization Process (Staking)

Currently, the Obsidian network utilizes a voting-based authorization system (similar to Clique but adapted for Tendermint). Existing validators vote to include new addresses into the validator set.

#### step 1: Start your Node
Run your node with the validator address unlocked. Note that while `--miner.etherbase` is technically deprecated in vanilla Geth for Post-Merge, it is used in Obsidian to identify the coinbase for voting.

```bash
./build/bin/geth \
  --datadir ./data \
  --networkid 1719 \
  --mine \
  --miner.etherbase "0xYOUR_VALIDATOR_ADDRESS" \
  --unlock "0xYOUR_VALIDATOR_ADDRESS" \
  --password password.txt \
  --allow-insecure-unlock
```

#### Step 2: Proposing a New Validator
To join the validator set, an existing authorized validator must "propose" your address. This is done via the `tendermint_propose` RPC method.

**In the Geth Console:**
```javascript
// To authorize a new validator
clique.propose("0xNEW_VALIDATOR_ADDRESS", true)

// To deauthorize an existing validator
clique.propose("0xOLD_VALIDATOR_ADDRESS", false)
```
*Note: The `clique` namespace is preserved in the console for compatibility with existing tooling, mapping to the Tendermint consensus engine.*

#### Step 3: Voting Tally
*   A proposal requires more than **50% (majority)** of the current validator set to vote for it.
*   Votes are cast by validators including the proposal in the `Nonce` and `Coinbase` fields of the blocks they sign.
*   Once the majority threshold is reached, the address is immediately added to the validator set and initialized with the minimum stake.

### Checking Validator Status

You can check the current status of validators and your own node's standing using the following console commands:

```javascript
// Get list of all current authorized validators
clique.getSnapshot().validators

// Check the status of your own validator
clique.status()
```

The `status()` command returns:
*   `authorized`: Whether your node is currently part of the validator set.
*   `inturn`: Whether it is currently your node's turn to propose a block.

---

## Technical Reference

*   **Consensus Implementation:** `consensus/tendermint`
*   **Snapshots & Voting Logic:** `consensus/tendermint/snapshot.go`
*   **RPC API:** `tendermint` namespace (mapped to `clique` in JS console)
*   **Default Epoch:** 30,000 blocks (votes are reset every epoch)
