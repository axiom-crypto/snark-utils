# snark-utils

A Rust library for working with SNARK (Succinct Non-interactive ARgument of Knowledge) verification keys and proofs, built on top of Halo2 and snark-verifier.

## Features

- Serialization and deserialization of verifying keys for on-chain use
- Utilities for handling SNARK proofs and verification
- Support for aggregation circuits
- Integration with Halo2-based zero-knowledge proofs
- EVM proof verification capabilities

## Usage

Here's a basic example of verifying a proof:

```rust
use snark_utils::{verify_axiom_proof, vkey::OnchainVerifyingKey};
// Read the verifying key from bytes
let onchain_vk = OnchainVerifyingKey::read(&mut reader)?;
// Verify the proof
verify_axiom_proof(onchain_vk, &proof, &public_values)?;
```
