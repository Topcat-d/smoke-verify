"""smoke-verify — offline verifier for smoke.attestation.v0 action logs.

Verifier ONLY: this package can prove a log was not altered after commitment;
it cannot produce one. The writer SDK is a separate, private component — by
design, so relying parties never need to trust (or even possess) producer code
to check a chain.
"""
from .anchor import ANCHOR_TYPE, AnchorResult, check_anchor, make_anchor
from .chainio import UnknownVersionError, detect_version, load_chain, verify_log_any
from .diff import ChainDiff, FieldDelta, diff_chains
from .envelope import (
    HEADER_TYPE,
    AttestationEnvelopeV0,
    ChainHeaderV0,
    PublicKeyRefV0,
    SignatureV0,
)
from .keys import spki_fingerprint
from .localize import FieldChange, LocalizeResult, localize_entry
from .schema import (
    ACTORS,
    DOMAIN_TAG,
    EVENT_TYPES,
    RECORD_FIELDS,
    VERSION,
    AttestationError,
    AttestationRecordV0,
    canonicalize,
    sha256_hex,
    signed_digest,
)
from .verify import VerifyResult, verify_chain, verify_log
from .witness import (
    GitMirrorWitness,
    TSAClient,
    WitnessCheck,
    verify_anchor_witnesses,
)

__version__ = "0.1.0"

__all__ = [
    "ACTORS",
    "ANCHOR_TYPE",
    "AnchorResult",
    "AttestationEnvelopeV0",
    "AttestationError",
    "AttestationRecordV0",
    "ChainDiff",
    "ChainHeaderV0",
    "DOMAIN_TAG",
    "EVENT_TYPES",
    "FieldChange",
    "FieldDelta",
    "GitMirrorWitness",
    "HEADER_TYPE",
    "LocalizeResult",
    "PublicKeyRefV0",
    "RECORD_FIELDS",
    "SignatureV0",
    "TSAClient",
    "UnknownVersionError",
    "VERSION",
    "VerifyResult",
    "WitnessCheck",
    "canonicalize",
    "check_anchor",
    "detect_version",
    "diff_chains",
    "load_chain",
    "localize_entry",
    "make_anchor",
    "sha256_hex",
    "signed_digest",
    "spki_fingerprint",
    "verify_anchor_witnesses",
    "verify_chain",
    "verify_log",
    "verify_log_any",
]
