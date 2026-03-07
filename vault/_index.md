---
title: Vault Index
type: meta
created: 2026-03-07
tags: [index]
---

# Vultisig Share Decoder — Knowledge Vault

## Discoveries
- [[dkls-vault-has-two-keyshares]] — DKLS vaults have separate ECDSA + EdDSA keyshares
- [[dkls-detection-reshare-prefix-bug]] — ResharePrefix is not a reliable DKLS indicator

## Patterns
- [[dkls-key-export-protocol]] — Step-by-step DKLS/Schnorr key export via go-wrappers

## Architecture
- [[data-flow]] — End-to-end recovery data flow (input → detection → reconstruction → derivation)

## Features
- [[full-restructure]] — Package rename, cleanup, community-tools consolidation (planned)
- [[cli-skill]] — Package CLI for distribution as a reusable skill (planned)
