"""Pure-Python OpenSSH public key and principal validation utilities."""

import base64
import hashlib
import re
import struct
from dataclasses import dataclass

ALLOWED_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}

MIN_RSA_BITS = 2048
MAX_PUBLIC_KEY_LENGTH = 8192
PRINCIPAL_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$")
IDENTITY_RE = re.compile(r"^[a-zA-Z0-9_.@+-]{1,128}$")
VALIDITY_RE = re.compile(r"^\+?[1-9][0-9]{0,4}[smhdw]$")


class SSHValidationError(ValueError):
    """Raised when an SSH public key, principal, or identity fails validation."""


@dataclass(frozen=True)
class ParsedSSHPublicKey:
    key_type: str
    normalized_key: str
    fingerprint_sha256: str


def _read_ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise SSHValidationError("Truncated SSH key wire payload.")
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    offset += 4
    if length > len(blob) - offset:
        raise SSHValidationError("Malformed SSH key length field.")
    return blob[offset : offset + length], offset + length


def validate_ssh_public_key(raw_key: str) -> ParsedSSHPublicKey:
    """Validate an OpenSSH public key string and return its normalized form and SHA256 fingerprint."""
    if not isinstance(raw_key, str):
        raise SSHValidationError("Public key must be a string.")

    stripped = raw_key.strip()
    if not stripped or len(stripped) > MAX_PUBLIC_KEY_LENGTH:
        raise SSHValidationError("Public key is empty or exceeds maximum length.")
    if "\n" in stripped or "\r" in stripped or "\x00" in stripped:
        raise SSHValidationError("Public key must be a single line with no control characters.")

    parts = stripped.split()
    if len(parts) < 2:
        raise SSHValidationError("Public key must include key type and base64 payload.")

    # Reject authorized_keys options placed before the key type.
    key_type = parts[0]
    if key_type not in ALLOWED_KEY_TYPES:
        raise SSHValidationError(
            f"Unsupported or disallowed key type '{key_type}'. Allowed: {', '.join(sorted(ALLOWED_KEY_TYPES))}."
        )

    key_b64 = parts[1]
    try:
        blob = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise SSHValidationError("Public key payload is not valid base64.") from exc

    if not blob:
        raise SSHValidationError("Public key payload is empty.")

    wire_type_bytes, offset = _read_ssh_string(blob, 0)
    try:
        wire_type = wire_type_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SSHValidationError("Invalid SSH wire key type.") from exc

    if wire_type != key_type:
        raise SSHValidationError("Key type prefix does not match encoded key payload.")

    if key_type == "ssh-rsa":
        exponent, offset = _read_ssh_string(blob, offset)
        modulus, offset = _read_ssh_string(blob, offset)
        if not exponent or not modulus:
            raise SSHValidationError("Invalid RSA public key parameters.")
        modulus_int = int.from_bytes(modulus, "big")
        if modulus_int.bit_length() < MIN_RSA_BITS:
            raise SSHValidationError(f"RSA key must be at least {MIN_RSA_BITS} bits.")
    elif key_type == "ssh-ed25519":
        pubkey_bytes, offset = _read_ssh_string(blob, offset)
        if len(pubkey_bytes) != 32:
            raise SSHValidationError("Invalid Ed25519 public key length.")
    elif key_type.startswith("ecdsa-sha2-"):
        curve_name, offset = _read_ssh_string(blob, offset)
        point, offset = _read_ssh_string(blob, offset)
        expected_curve = key_type.removeprefix("ecdsa-sha2-").encode("ascii")
        if curve_name != expected_curve or not point:
            raise SSHValidationError("ECDSA curve does not match key type.")

    if offset != len(blob):
        raise SSHValidationError("Unexpected trailing bytes in SSH public key payload.")

    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    normalized = f"{key_type} {key_b64}"
    return ParsedSSHPublicKey(
        key_type=key_type,
        normalized_key=normalized,
        fingerprint_sha256=f"SHA256:{digest}",
    )


def validate_principal(principal: str) -> str:
    """Validate an SSH certificate principal name."""
    if not isinstance(principal, str) or not PRINCIPAL_RE.match(principal):
        raise SSHValidationError(f"Invalid SSH principal name: {principal!r}")
    return principal


def validate_identity(identity: str) -> str:
    """Validate an SSH certificate key ID / identity string."""
    if not isinstance(identity, str) or not IDENTITY_RE.match(identity):
        raise SSHValidationError(f"Invalid SSH certificate identity: {identity!r}")
    return identity


def validate_validity(validity: str) -> str:
    """Validate an OpenSSH relative validity interval such as '+24h' or '+1d'."""
    if not isinstance(validity, str) or not VALIDITY_RE.match(validity):
        raise SSHValidationError(f"Invalid certificate validity specification: {validity!r}")
    return validity
