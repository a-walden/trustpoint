# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Optional CMP ``caPubs`` content for IP responses.

RFC 4210 lets an IP (initialization response) carry ``caPubs``: CA certificates the
requester should trust. SZTO uses it to hand an enrolling edge proxy the root of the
management CA, so the proxy can verify the Onboarding Service's TLS server certificate
without any out-of-band step. The IP of a MAC-protected (challenge-password)
enrollment is itself authenticated by the one-time secret, so what arrives in
``caPubs`` is authenticated.

The certificates are read from a PEM bundle named by ``TRUSTPOINT_CMP_CA_PUBS_FILE``.
When the variable is unset, or the file is missing or invalid, ``caPubs`` stays empty
exactly as before (a warning is logged for the invalid cases).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder  # type: ignore[import-untyped]
from pyasn1.type import constraint, tag, univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]

CA_PUBS_FILE_ENV = 'TRUSTPOINT_CMP_CA_PUBS_FILE'

logger = logging.getLogger(__name__)


def load_ca_pubs_certificates() -> list[x509.Certificate]:
    """Load the configured ``caPubs`` certificates; an empty list when not configured."""
    path = os.environ.get(CA_PUBS_FILE_ENV, '').strip()
    if not path:
        return []
    try:
        return x509.load_pem_x509_certificates(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        logger.warning('Ignoring %s=%s: %s', CA_PUBS_FILE_ENV, path, exc)
        return []


def build_ca_pubs(certificates: list[x509.Certificate]) -> univ.SequenceOf:
    """Build the ``caPubs`` field of a CertRepMessage (empty when no certificates)."""
    ca_pubs = univ.SequenceOf().subtype(
        sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX),
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
    )
    for certificate in certificates:
        asn1_certificate, _ = decoder.decode(
            certificate.public_bytes(encoding=Encoding.DER), asn1Spec=rfc4210.CMPCertificate()
        )
        ca_pubs.append(asn1_certificate)
    return ca_pubs
