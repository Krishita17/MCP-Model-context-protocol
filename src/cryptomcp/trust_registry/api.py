"""FastAPI-based Trust Registry for MCP publisher certificate management."""

from __future__ import annotations

import hashlib
import json
import time
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="CryptoMCP Trust Registry",
    description="Publisher authentication and certificate management for MCP tool ecosystems",
    version="0.1.0",
)


class CertificateStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class PublisherRegistration(BaseModel):
    publisher_id: str = Field(..., min_length=3, max_length=128)
    organization: str
    public_key: str = Field(..., min_length=64, max_length=128)
    contact_email: str
    tool_namespaces: list[str] = Field(default_factory=list)


class PublisherCertificate(BaseModel):
    publisher_id: str
    organization: str
    public_key: str
    certificate_hash: str
    status: CertificateStatus
    issued_at: float
    expires_at: float
    tool_namespaces: list[str]
    revocation_reason: str | None = None


class RegistryStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._publishers: dict[str, PublisherCertificate] = {}
        self._revocation_list: list[str] = []
        self._db_path = db_path

    def register(self, reg: PublisherRegistration) -> PublisherCertificate:
        if reg.publisher_id in self._publishers:
            existing = self._publishers[reg.publisher_id]
            if existing.status == CertificateStatus.ACTIVE:
                raise ValueError(f"Publisher '{reg.publisher_id}' already registered")

        cert_data = json.dumps(
            {
                "publisher_id": reg.publisher_id,
                "public_key": reg.public_key,
                "organization": reg.organization,
            },
            sort_keys=True,
        )
        cert_hash = hashlib.sha256(cert_data.encode()).hexdigest()

        now = time.time()
        cert = PublisherCertificate(
            publisher_id=reg.publisher_id,
            organization=reg.organization,
            public_key=reg.public_key,
            certificate_hash=cert_hash,
            status=CertificateStatus.ACTIVE,
            issued_at=now,
            expires_at=now + (365 * 24 * 3600),
            tool_namespaces=reg.tool_namespaces,
        )
        self._publishers[reg.publisher_id] = cert
        return cert

    def get(self, publisher_id: str) -> PublisherCertificate | None:
        return self._publishers.get(publisher_id)

    def verify(self, publisher_id: str, public_key: str) -> bool:
        cert = self._publishers.get(publisher_id)
        if cert is None:
            return False
        if cert.status != CertificateStatus.ACTIVE:
            return False
        if cert.expires_at < time.time():
            return False
        return cert.public_key == public_key

    def revoke(self, publisher_id: str, reason: str) -> PublisherCertificate:
        cert = self._publishers.get(publisher_id)
        if cert is None:
            raise ValueError(f"Publisher '{publisher_id}' not found")
        cert = PublisherCertificate(
            **{**cert.model_dump(), "status": CertificateStatus.REVOKED, "revocation_reason": reason}
        )
        self._publishers[publisher_id] = cert
        self._revocation_list.append(publisher_id)
        return cert

    def list_publishers(self) -> list[PublisherCertificate]:
        return list(self._publishers.values())


registry = RegistryStore()


@app.post("/publishers", response_model=PublisherCertificate)
async def register_publisher(reg: PublisherRegistration) -> PublisherCertificate:
    try:
        return registry.register(reg)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/publishers/{publisher_id}", response_model=PublisherCertificate)
async def get_publisher(publisher_id: str) -> PublisherCertificate:
    cert = registry.get(publisher_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Publisher not found")
    return cert


@app.get("/publishers/{publisher_id}/verify")
async def verify_publisher(publisher_id: str, public_key: str) -> dict[str, Any]:
    valid = registry.verify(publisher_id, public_key)
    return {"publisher_id": publisher_id, "valid": valid}


@app.post("/publishers/{publisher_id}/revoke")
async def revoke_publisher(publisher_id: str, reason: str = "unspecified") -> PublisherCertificate:
    try:
        return registry.revoke(publisher_id, reason)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/publishers", response_model=list[PublisherCertificate])
async def list_publishers() -> list[PublisherCertificate]:
    return registry.list_publishers()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "cryptomcp-trust-registry"}
