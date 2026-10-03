import pytest
from conftest import BOB, CHARLIE, expect_error, stored

def test_establish_anchor(env):
    anchor_id = env.create_anchor(scope="Full protocol control")
    
    # Verify the anchor was created successfully
    assert anchor_id.startswith("anc-")
    
    # Inspect the anchor via view method
    info = env.contract.inspect_anchor(anchor_id)
    assert info["anchor_owner"] == env.gl.message.sender_address
    assert info["scope_text"] == "Full protocol control"
    assert info["is_live"] is True
    assert info["can_branch"] is True

def test_issue_grant(env):
    anchor_id = env.create_anchor(scope="Manage marketing budget up to $50k")
    
    # Issue a downstream grant
    grant_id = env.create_grant(
        upstream_id=anchor_id,
        holder=BOB,
        scope="Manage social media ads up to $10k",
        status="CONTAINED"
    )
    
    assert grant_id.startswith("fsk-")
    
    info = env.contract.inspect_grant(grant_id)
    assert info["issuer"] == env.gl.message.sender_address
    assert info["holder"] == BOB
    assert info["scope_text"] == "Manage social media ads up to $10k"
    assert info["is_live"] is True

def test_issue_grant_rejected_by_llm(env):
    anchor_id = env.create_anchor(scope="Manage marketing budget up to $50k")
    
    # Try to issue a grant that expands the scope
    with pytest.raises(Exception) as excinfo:
        env.create_grant(
            upstream_id=anchor_id,
            holder=BOB,
            scope="Manage software engineering team",
            status="NOT_CONTAINED"
        )
    
    assert "SCOPE_NOT_CONTAINED" in str(excinfo.value)

def test_verify_action_success(env):
    anchor_id = env.create_anchor(scope="Manage marketing budget up to $50k")
    grant_id = env.create_grant(
        upstream_id=anchor_id,
        holder=BOB,
        scope="Manage social media ads up to $10k",
        status="CONTAINED"
    )
    
    # The action is contained within the grant
    env.set_status("CONTAINED")
    
    # Must be called by the holder!
    env.set_sender(BOB)
    result = env.contract.verify_action(grant_id, "Pay $500 for Facebook Ads")
    assert result == "APPROVED"

def test_verify_action_denies_non_holder(env):
    anchor_id = env.create_anchor(scope="Manage marketing budget up to $50k")
    grant_id = env.create_grant(
        upstream_id=anchor_id,
        holder=BOB,
        scope="Manage social media ads up to $10k",
        status="CONTAINED"
    )
    
    # The action is contained within the grant
    env.set_status("CONTAINED")
    
    # Caller is currently ALICE (who created it, but is not the holder)
    env.set_sender(CHARLIE)
    result = env.contract.verify_action(grant_id, "Pay $500 for Facebook Ads")
    
    # Even though it's contained, the caller is not the holder, so it should be DENIED
    assert result == "DENIED"

def test_revoke_grant_invalidates_downstream(env):
    anchor_id = env.create_anchor(scope="Full Treasury")
    grant_id = env.create_grant(anchor_id, BOB, scope="Half Treasury", status="CONTAINED")
    
    # Revoke the grant
    env.contract.revoke_grant(grant_id)
    
    info = env.contract.inspect_grant(grant_id)
    assert info["is_live"] is False
    assert info["chain_health"] == "REVOKED"
    
    # Verify action should be denied if grant is revoked
    result = env.contract.verify_action(grant_id, "Pay $1")
    assert result == "DENIED"
