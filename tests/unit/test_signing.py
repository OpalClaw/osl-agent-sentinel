"""Unit tests for action signing and verification."""

from __future__ import annotations

import pytest

from sentinel.identity.signing import ActionSigner, ActionVerifier
from sentinel.models.action import Action, ActionType
from sentinel.utils.crypto import generate_ed25519_keypair


def test_sign_and_verify_roundtrip():
    private, public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    action = Action(type=ActionType.TOOL_CALL, tool="http.get", intent="x", args={"k": "v"}, tenant_id="t1")
    signed = signer.sign(action)
    assert verifier.verify(signed, public)


def test_tampered_action_fails_verification():
    private, public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    action = Action(type=ActionType.TOOL_CALL, tool="http.get", intent="x", args={"k": "v"}, tenant_id="t1")
    signed = signer.sign(action)
    signed.args = {"k": "tampered"}
    assert not verifier.verify(signed, public)


def test_wrong_key_fails_verification():
    private, _ = generate_ed25519_keypair()
    _, other_public = generate_ed25519_keypair()
    signer = ActionSigner(private)
    verifier = ActionVerifier()
    action = Action(type=ActionType.TOOL_CALL, tool="http.get", intent="x", args={"k": "v"}, tenant_id="t1")
    signed = signer.sign(action)
    assert not verifier.verify(signed, other_public)
