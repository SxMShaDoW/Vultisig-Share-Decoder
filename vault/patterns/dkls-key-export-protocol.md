---
title: DKLS/Schnorr Key Export Protocol Pattern
type: pattern
created: 2026-03-07
tags: [dkls, schnorr, key-export, go-wrappers]
---

# DKLS/Schnorr Key Export Protocol

## Problem
Need to reconstruct private keys from TSS keyshares using the DKLS (ECDSA) or Schnorr (EdDSA) protocols.

## Solution

Both protocols follow identical steps (just different function prefixes):

```go
// 1. Parse first keyshare
firstHandle, _ := session.DklsKeyshareFromBytes(keyshareData[0])

// 2. Get metadata from first keyshare
publicKey, _ := session.DklsKeysharePublicKey(firstHandle)
chainCode, _ := session.DklsKeyshareChainCode(firstHandle)

// 3. Create export receiver session
exportSession, setupMsg, _ := session.DklsKeyExportReceiverNew(firstHandle, partyIDs)

// 4. For each additional keyshare, create exporter messages
for idx, data := range keyshareData[1:] {
    handle, _ := session.DklsKeyshareFromBytes(data)
    msg, _, _ := session.DklsKeyExporter(handle, partyIDs[idx+1], setupMsg)
    msgs = append(msgs, msg)
}

// 5. Feed messages to receiver, check for completion
for _, msg := range msgs {
    finished, _ := session.DklsKeyExportReceiverInputMessage(exportSession, msg)
    if finished {
        privateKey, _ = session.DklsKeyExportReceiverFinish(exportSession)
        break
    }
}
```

For EdDSA/Schnorr, replace `Dkls` prefix with `Schnorr` in all function names.

## Related Discoveries
- [[dkls-vault-has-two-keyshares]]
