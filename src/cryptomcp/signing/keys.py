"""Ed25519 key pair generation and management."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder


@dataclass(frozen=True)
class KeyPair:
    signing_key: SigningKey
    verify_key: VerifyKey

    @property
    def public_key_hex(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode()

    @property
    def private_key_hex(self) -> str:
        return self.signing_key.encode(encoder=HexEncoder).decode()


def generate_key_pair() -> KeyPair:
    signing_key = SigningKey.generate()
    return KeyPair(signing_key=signing_key, verify_key=signing_key.verify_key)


def load_signing_key(hex_key: str) -> SigningKey:
    return SigningKey(hex_key.encode(), encoder=HexEncoder)


def load_verify_key(hex_key: str) -> VerifyKey:
    return VerifyKey(hex_key.encode(), encoder=HexEncoder)


def save_key_pair(key_pair: KeyPair, directory: Path, publisher_id: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    meta = {
        "publisher_id": publisher_id,
        "public_key": key_pair.public_key_hex,
        "algorithm": "Ed25519",
    }
    (directory / f"{publisher_id}.pub.hex").write_text(key_pair.public_key_hex)
    (directory / f"{publisher_id}.key.hex").write_text(key_pair.private_key_hex)
    (directory / f"{publisher_id}.meta.json").write_text(json.dumps(meta, indent=2))


def load_key_pair(directory: Path, publisher_id: str) -> KeyPair:
    pub_hex = (directory / f"{publisher_id}.pub.hex").read_text().strip()
    priv_hex = (directory / f"{publisher_id}.key.hex").read_text().strip()
    signing_key = load_signing_key(priv_hex)
    verify_key = load_verify_key(pub_hex)
    return KeyPair(signing_key=signing_key, verify_key=verify_key)
