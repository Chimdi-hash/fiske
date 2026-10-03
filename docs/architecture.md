# Fiske Architecture & State Machine

The Fiske protocol fundamentally shifts access control from rigid, developer-defined bytecode to dynamic, intent-driven structures. This document outlines the core architectural decisions, data storage models, and the lifecycle state machine.

## 1. Storage Model

Fiske leverages `genlayer.storage.TreeMap` to maintain O(log N) state access. 
Storage is highly decoupled and segmented into four core indexes:
- `anchor_records (TreeMap[str, str])`: Maps `anc-` identifiers to JSON payloads.
- `grant_records (TreeMap[str, str])`: Maps `fsk-` identifiers to JSON payloads.
- `latest_anchor_by_owner (TreeMap[str, str])`: Reverse lookup index for EOAs.
- `latest_grant_by_holder (TreeMap[str, str])`: Reverse lookup index for grantees.

### Cryptographic Identifier Generation
To prevent ID spoofing and guarantee uniqueness, Fiske employs a Merkle-like hashing approach for ID generation. All IDs are prefixed (`anc-` or `fsk-`) and deterministic based on the underlying payload structure, nonce, block timestamp, and creator.

```python
# Example of ID derivation
hash_record = _compute_hash("anchor", core_data)
anchor_id = "anc-" + _compute_hash("anchor-id", {
    "nonce": nonce, "anchor_owner": owner,
    "time_created": now, "hash_record": hash_record,
})
```

## 2. Health & Lifecycle State Machine

Permissions in Fiske are entirely lazy-evaluated at runtime. Instead of maintaining active pointers and doing costly garbage collection when a node is revoked, Fiske traces the ancestry path recursively (up to `LIMIT_DEPTH = 5`) whenever an action is verified.

A node can be in one of the following health states:
- `STATE_ACTIVE`: The node is valid, unexpired, unrevoked, and its entire upstream chain to the Anchor is healthy.
- `STATE_EXPIRED`: The block timestamp exceeds the node's `time_expiry`.
- `STATE_REVOKED`: The node was manually nullified via `revoke_grant()` by its immediate issuer.
- `STATE_BROKEN_CHAIN`: A fatal state indicating that while the target node itself may be technically valid, an upstream parent or the Root Anchor has been revoked/expired.
- `STATE_INVALID`: A fallback state indicating cryptographic data corruption or structural flaws (e.g., branching depth exceeds constraints).

### Ancestry Resolution
When `verify_action()` is called, Fiske executes `_verify_ancestry_health()`. This traverses the graph backwards from the `grant_id` to the Root `anchor_id`. If any intermediate hop fails the `_evaluate_node_health()` check, the entire branch is instantly severed.
