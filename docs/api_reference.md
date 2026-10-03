# Fiske API Reference

This document outlines the public interface for the Fiske intelligent contract. Methods are decorated with either `@gl.public.write` for state-modifying consensus operations, or `@gl.public.view` for deterministic reads.

## Write Operations

### `establish_anchor`
Creates a root authority anchor.
```python
@gl.public.write
def establish_anchor(self, scope_text: str, can_branch: bool, time_expiry: u256) -> str
```
- **scope_text**: The absolute maximal boundary of this permission graph.
- **can_branch**: If `True`, grants derived from this anchor can be sub-granted.
- **time_expiry**: Unix timestamp for expiration, or `0` for indefinite.
- **Returns**: The unique `anc-...` identifier string.

### `issue_grant`
Assigns a subset permission from an existing anchor or grant.
```python
@gl.public.write
def issue_grant(self, upstream_ref: str, holder: str, scope_text: str, can_branch: bool, time_expiry: u256) -> str
```
- **upstream_ref**: The parent ID (`anc-...` or `fsk-...`).
- **holder**: The 42-character hex address receiving the grant.
- **scope_text**: Must be semantically contained by the `upstream_ref` scope. Evaluated by LLM consensus.
- **can_branch**: Whether the `holder` can create downstream grants.
- **Returns**: The unique `fsk-...` identifier string.

### `revoke_grant`
Immediately invalidates a grant and all its downstream dependents.
```python
@gl.public.write
def revoke_grant(self, grant_id: str) -> None
```
- **grant_id**: ID of the grant to revoke. Caller MUST be the original `issuer` of the grant.

### `invalidate_anchor`
Immediately invalidates a root anchor and the entire tree of grants derived from it.
```python
@gl.public.write
def invalidate_anchor(self, anchor_id: str) -> None
```
- **anchor_id**: ID of the anchor. Caller MUST be the `anchor_owner`.

### `verify_action`
The core execution check. Validates a proposed action against the live state of the grant.
```python
@gl.public.write
def verify_action(self, grant_id: str, action_scope: str) -> str
```
- **grant_id**: The grant the holder intends to exercise.
- **action_scope**: Natural language description of the requested action.
- **Returns**: `"APPROVED"`, `"DENIED"`, or `"UNRESOLVED"`.

---

## View Operations

### `inspect_anchor(anchor_id: str) -> dict`
Returns the raw JSON metadata and live evaluated `chain_health` of an anchor.

### `inspect_grant(grant_id: str) -> dict`
Returns the raw JSON metadata and deeply-evaluated `chain_health` of a grant.

### `is_grant_live(grant_id: str) -> bool`
Fast boolean check confirming the entire upstream ancestry is active.

### Reverse Lookups
- `get_owner_latest_anchor(owner_address: str) -> str`
- `get_holder_latest_grant(holder_address: str) -> str`
- `my_latest_anchor() -> str`
- `my_latest_grant() -> str`
