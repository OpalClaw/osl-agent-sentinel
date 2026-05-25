"""Unit tests for action signing and verification."""

from __future__ import annotations

from sentinel.identity.signing import ActionSigner, ActionVerifier
from sentinel.models.action import Action, ActionType
from sentinel.utils.crypto import generate_ed25519_keypair


def _action() -> Action:
    return Action(
        agent_did="did:test:agent-1",
        type=ActionType.TOOL_CALL,
        tool="http.get",
        intent="fetch homepage",
        arguments={"url": "https://example.com"},
        tenant_id="t1",
    )


def test_sign_and_verify_roundtrip() -> None:
    private, public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    signed = signer.sign(_action())
    assert verifier.verify(signed, public)


def test_tampered_action_fails_verification() -> None:
    private, public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    signed = signer.sign(_action())
    signed.args = {"url": "https://evil.example.com"}
    assert not verifier.verify(signed, public)


def test_wrong_key_fails_verification() -> None:
    private, _ = generate_ed25519_keypair()
    _, other_public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    signed = signer.sign(_action())
    assert not verifier.verify(signed, other_public)


def test_key_id_is_deterministic() -> None:
    private, _ = generate_ed25519_keypair()
    signer_a = ActionSigner(private)
    signer_b = ActionSigner(private)
    assert signer_a.key_id == signer_b.key_id
    assert signer_a.key_id.startswith("k_")
