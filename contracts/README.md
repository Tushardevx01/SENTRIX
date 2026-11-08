# SENTRIX Decentralized Threat Registry Smart Contracts

This directory contains the Solidity smart contract implementation, compilation scripts, and generated EVM bytecode/ABI artifacts for SENTRIX Module C (**Decentralized Threat Registry**).

## Structure

```
contracts/
├── ThreatRegistry.sol       # Solidity 0.8.20 smart contract
├── ThreatRegistry.json      # Compiled EVM bytecode, ABI, and compiler metadata
├── compile.js               # Standalone solc 0.8.20 compiler script
└── README.md                # Contract architecture and deployment guide
```

## Contract Overview (`ThreatRegistry.sol`)

- **Solidity Version:** `^0.8.20`
- **License:** MIT
- **Purpose:** Immutable, tamper-evident on-chain anchoring of cybersecurity threat intelligence reports.
- **Zero-PII Architecture:** Sensitive message contents, credentials, and victim information are never published on-chain. Only deterministic canonical SHA-256 commitments (`bytes32`), severity scores, categories, and cryptographic signatures are recorded.

### Functions

```solidity
// Register a verified threat report hash
function registerThreat(
    bytes32 reportHash,
    string calldata category,
    uint8 severityScore,
    string calldata metadataUri
) external returns (uint256 reportId);

// Query and verify whether a threat commitment exists on-chain
function verifyThreat(bytes32 reportHash)
    external
    view
    returns (
        bool exists,
        address reporter,
        uint256 timestamp,
        string memory category,
        uint8 severityScore,
        string memory metadataUri
    );

// Return total number of registered threats
function getRecordCount() external view returns (uint256);
```

## Compilation

The contracts are compiled using the project's native Node.js compilation script:

```bash
# From repository root:
node contracts/compile.js
```

This compiles `ThreatRegistry.sol` with `solc` (0.8.20, optimizer runs: 200) and produces the JSON artifact `ThreatRegistry.json` containing:
- `abi`: Full contract Interface ABI
- `bytecode`: Deployed EVM creation bytecode

## Deployment & Execution

SENTRIX supports dual-mode execution via `apps/api/src/services/blockchainService.ts`:
1. **Live On-Chain Mode:** When connected to an active EVM node (`BLOCKCHAIN_RPC_URL` or Hardhat node at `http://127.0.0.1:8545`), the service dynamically deploys or connects to `THREAT_REGISTRY_CONTRACT_ADDRESS`, mines transactions with an automated `NonceManager`, and records the verified `txHash` and `blockNumber`.
2. **Simulated Cryptographic Ledger Mode:** When an EVM RPC node is unreachable, the system automatically falls back to an offline deterministic SHA-256 cryptographic ledger with `status: "SIMULATED"` and `isSimulated: true`.
