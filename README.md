# Go Obsidian

Golang execution layer implementation of the **Obsidian (OBS)** protocol.

Obsidian is a high-performance, privacy-focused blockchain built upon the robust foundations of Go Ethereum, enhanced with Tendermint-based PoS consensus and Zero-Knowledge (ZK) primitives.

## Key Specifications

| Parameter | Value |
| :--- | :--- |
| **Chain ID** | 1719 |
| **Native Token** | Obsidian (OBS) |
| **Consensus Engine** | Tendermint PoS |
| **Block Time** | 2 Seconds |
| **Epoch Length** | 30,000 Blocks (~16.7 Hours) |
| **Initial Supply** | 1,000,000,000 OBS |
| **Primary Holder** | `0xd2cf3765c2e600f13470ed71aaab0ee3aa37f90a` |

## Features

- **Tendermint PoS**: Replacing traditional Proof-of-Work with a fast, deterministic consensus engine for near-instant finality.
- **ZK Confidential Transactions**: Built-in support for zero-knowledge proofs to enable privacy-preserving asset transfers.
- **EVM Compatibility**: Full compatibility with existing Ethereum smart contracts and tooling.
- **Multi-Architecture Support**: Official Docker images provided for both `amd64` and `arm64`.

## Building the Source

Building the Obsidian client requires **Go (version 1.24 or later)** and a C compiler.

1. Install dependencies.
2. Clone the repository.
3. Run the build command:

```shell
make geth
```

To build the full suite of utilities (including `abigen`, `bootnode`, `clef`, etc.):

```shell
make all
```

## Running Obsidian

The main entry point is the `geth` binary. 

### Basic Start
```shell
$ geth console
```

### Docker Quick Start
Automated multi-arch builds are available on Docker Hub:

```shell
docker run -d --name obsidian-node \
           -v /path/to/data:/root \
           -p 8545:8545 -p 30303:30303 \
           yuchanshin/go-obsidian:latest
```

## Programmatic Interface

Obsidian supports the standard Ethereum JSON-RPC APIs over HTTP, WebSockets, and IPC.

- **HTTP**: `--http` (default: `localhost:8545`)
- **WebSocket**: `--ws` (default: `localhost:8546`)
- **APIs**: `eth, net, web3, personal, txpool, debug`

## Continuous Integration

This project uses a unified GitHub Actions pipeline for:
- **Linting**: golangci-lint (v1.64+)
- **Testing**: Parallel Unit, ZK, and Core package tests.
- **Deployment**: Automatic multi-arch Docker builds and pushes to Docker Hub upon successful verification.

## License

The Obsidian library (code outside of the `cmd` directory) is licensed under the [GNU Lesser General Public License v3.0](./COPYING.LESSER).
The Obsidian binaries (code inside the `cmd` directory) are licensed under the [GNU General Public License v3.0](./COPYING).
