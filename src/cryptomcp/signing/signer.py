"""Tool description signing and verification using Ed25519 + SHA-256."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from cryptomcp.signing.keys import KeyPair


@dataclass(frozen=True)
class SignedToolDescriptor:
    tool: dict[str, Any]
    tool_hash: str
    signature: str
    publisher_id: str
    public_key: str
    timestamp: float
    version: str

    def to_bundle(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "integrity": {
                "hash_algorithm": "SHA-256",
                "tool_hash": self.tool_hash,
                "signature_algorithm": "Ed25519",
                "signature": self.signature,
                "publisher_id": self.publisher_id,
                "public_key": self.public_key,
                "signed_at": self.timestamp,
                "version": self.version,
            },
        }

    @classmethod
    def from_bundle(cls, bundle: dict[str, Any]) -> SignedToolDescriptor:
        integrity = bundle["integrity"]
        return cls(
            tool=bundle["tool"],
            tool_hash=integrity["tool_hash"],
            signature=integrity["signature"],
            publisher_id=integrity["publisher_id"],
            public_key=integrity["public_key"],
            timestamp=integrity["signed_at"],
            version=integrity["version"],
        )


def canonicalize(tool: dict[str, Any]) -> str:
    return json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_tool_hash(tool: dict[str, Any]) -> str:
    canonical = canonicalize(tool)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ToolSigner:
    def __init__(self, key_pair: KeyPair, publisher_id: str) -> None:
        self.key_pair = key_pair
        self.publisher_id = publisher_id

    def sign(self, tool: dict[str, Any], version: str = "1.0.0") -> SignedToolDescriptor:
        tool_hash = compute_tool_hash(tool)
        signed = self.key_pair.signing_key.sign(
            tool_hash.encode("utf-8"),
            encoder=HexEncoder,
        )
        signature = signed.signature.decode()

        return SignedToolDescriptor(
            tool=tool,
            tool_hash=tool_hash,
            signature=signature,
            publisher_id=self.publisher_id,
            public_key=self.key_pair.public_key_hex,
            timestamp=time.time(),
            version=version,
        )


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    hash_matches: bool
    signature_valid: bool
    publisher_authenticated: bool
    baseline_matches: bool | None
    error: str | None = None


class ToolVerifier:
    def __init__(self, approved_baselines: dict[str, str] | None = None) -> None:
        self.approved_baselines = approved_baselines or {}

    def verify(
        self,
        descriptor: SignedToolDescriptor,
        trusted_keys: dict[str, str] | None = None,
    ) -> VerificationResult:
        recomputed_hash = compute_tool_hash(descriptor.tool)
        hash_matches = recomputed_hash == descriptor.tool_hash

        try:
            verify_key = VerifyKey(descriptor.public_key.encode(), encoder=HexEncoder)
            verify_key.verify(
                descriptor.tool_hash.encode("utf-8"),
                bytes.fromhex(descriptor.signature),
            )
            signature_valid = True
        except (BadSignatureError, Exception):
            signature_valid = False

        publisher_authenticated = True
        if trusted_keys:
            expected_key = trusted_keys.get(descriptor.publisher_id)
            publisher_authenticated = expected_key == descriptor.public_key

        baseline_matches = None
        tool_name = descriptor.tool.get("name", "")
        if tool_name in self.approved_baselines:
            baseline_matches = self.approved_baselines[tool_name] == recomputed_hash

        valid = hash_matches and signature_valid and publisher_authenticated
        if baseline_matches is not None:
            valid = valid and baseline_matches

        error = None
        if not hash_matches:
            error = "Tool description was modified after signing (hash mismatch)"
        elif not signature_valid:
            error = "Invalid Ed25519 signature"
        elif not publisher_authenticated:
            error = f"Publisher '{descriptor.publisher_id}' not in trusted registry"
        elif baseline_matches is False:
            error = "Tool description changed since initial approval (rug-pull detected)"

        return VerificationResult(
            valid=valid,
            hash_matches=hash_matches,
            signature_valid=signature_valid,
            publisher_authenticated=publisher_authenticated,
            baseline_matches=baseline_matches,
            error=error,
        )
