# monachan.org

<div align="center">

![Header](assets/header.gif)

[![Website][ico-website]][link-website]
[![Twitter][ico-twitter]][link-twitter]

</div>

## Overview

> **THE RISC-V PRIVATE PROVING RUNTIME**

**MONACHAN.ORG** is a **privacy runtime** for executing **RISC-V programs** under **verifiable confidentiality**.  
It uses **zkSNARK-based proof generation** to prove correct execution of programs without exposing inputs, state, or outputs.  

Inspired by **Monero** and **Zcash**, it extends privacy from *payments* to *computation*, enabling developers to build systems that are both **trustless** and **confidential**.

## Problem / Solution

### The Problem

Existing privacy technologies like **Monero** and **Zcash** protect *transactions*, not *computation*.  
They ensure confidential payments and balances, but they don’t support private logic, state transitions, or data processing.  

Developers today face hard limitations:
- Application logic and user data are fully visible during execution.  
- Privacy systems are domain-specific (e.g., shielded transactions) and non-generalizable.  
- Building verifiable private computation still requires deep cryptographic expertise.  

There is no open, general-purpose framework for **private, verifiable computation**.

### The Solution

**MONACHAN.ORG** introduces a **RISC-V privacy runtime** that combines:
- **Deterministic program execution**, ensuring verifiable reproducibility.  
- **zkSNARK-based proofs**, guaranteeing correctness without revealing data.  
- **Optimized cryptographic precompiles**, enabling real-world performance for privacy workloads.  

This architecture allows developers to build applications such as:
- **Private data collaboration** — compute on encrypted data without disclosure.  
- **Private AI inference** — run models on confidential inputs verifiably.  
- **Private DeFi** — enable on-chain logic without revealing user state.  
- **Confidential rollups and bridges** — bridge ecosystems with strong privacy guarantees.  

MONACHAN.ORG extends privacy from **value** to **computation**, forming the foundation for a new class of decentralized, private applications.

## Getting Started

- **Example Template**: [monachan-project-template](https://github.com/Monero-Chan-Foundation/monerochan-project-template) — Get started with a ready-to-use project template

## Architecture

| Component | Description |
|------------|--------------|
| **RISC-V Runtime** | Deterministic execution environment for private workloads |
| **Proof Engine** | Generates zkSNARK proofs of correct execution |
| **Precompiles** | Optimized primitives for signature and hash verification |
| **Host Interface** | Rust API for program execution and proof verification |

## Cryptographic Capabilities

### Signature Verification
- **Secp256r1 / ECDSA** — Private verification for traditional signatures  
- **Ed25519** — Privacy-preserving signature verification  
- **RSA (BigInt)** — Confidential interoperability with legacy systems  

### Hash Functions
- **Keccak**, **SHA-256**, **Blake3** — Hash primitives optimized for proof systems

## Performance

MONACHAN.ORG achieves **order-of-magnitude performance improvements** for privacy workloads through optimized arithmetic and RISC-V precompiles.  
The runtime is engineered for:
- Private rollups and bridges  
- Privacy-preserving DeFi  
- Private AI and data collaboration  
- Cross-domain confidential computation  

[ico-website]: https://img.shields.io/website?up_color=blue&up_message=-chan&url=https%3A%2F%2F-chan.org
[ico-twitter]: https://img.shields.io/badge/@MoneroChanSOL-1DA1F2.svg?style=flat-square&logo=x&label=Twitter

[link-website]: https://monachan.org/
[link-twitter]: https://twitter.com/MonaChanSOL



