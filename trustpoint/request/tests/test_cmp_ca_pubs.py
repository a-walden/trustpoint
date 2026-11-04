# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the optional CMP ``caPubs`` content of IP responses."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]

from request.message_responder.ca_pubs import CA_PUBS_FILE_ENV, build_ca_pubs, load_ca_pubs_certificates

if TYPE_CHECKING:
    from pathlib import Path


def _self_signed(common_name: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=5))
        .sign(key, hashes.SHA256())
    )


def _pem(*certs: x509.Certificate) -> bytes:
    return b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def test_unset_env_yields_no_ca_pubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CA_PUBS_FILE_ENV, raising=False)
    assert load_ca_pubs_certificates() == []


def test_missing_or_invalid_file_is_ignored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(CA_PUBS_FILE_ENV, str(tmp_path / 'missing.pem'))
    assert load_ca_pubs_certificates() == []
    bad = tmp_path / 'bad.pem'
    bad.write_text('not a pem')
    monkeypatch.setenv(CA_PUBS_FILE_ENV, str(bad))
    assert load_ca_pubs_certificates() == []


def test_bundle_is_loaded_in_order(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    first, second = _self_signed('Management-Root-CA'), _self_signed('Second-CA')
    bundle = tmp_path / 'bundle.pem'
    bundle.write_bytes(_pem(first, second))
    monkeypatch.setenv(CA_PUBS_FILE_ENV, str(bundle))
    assert [c.subject.rfc4514_string() for c in load_ca_pubs_certificates()] == [
        'CN=Management-Root-CA',
        'CN=Second-CA',
    ]


def test_ca_pubs_survive_a_der_round_trip() -> None:
    certificates = [_self_signed('Management-Root-CA'), _self_signed('Second-CA')]
    body = rfc4210.PKIBody()
    body['ip'] = rfc4210.CertRepMessage().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )
    body['ip']['caPubs'] = build_ca_pubs(certificates)
    decoded, _ = decoder.decode(encoder.encode(body), asn1Spec=rfc4210.PKIBody())
    assert len(decoded['ip']['caPubs']) == 2


def test_empty_ca_pubs_still_encodes() -> None:
    body = rfc4210.PKIBody()
    body['ip'] = rfc4210.CertRepMessage().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )
    body['ip']['caPubs'] = build_ca_pubs([])
    assert encoder.encode(body)
