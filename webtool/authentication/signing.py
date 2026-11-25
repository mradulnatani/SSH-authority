"""Client for the isolated CA signing service."""

from datetime import datetime, timedelta
import re

from django.conf import settings
import requests

VALIDITY_UNIT_RE = re.compile(r"^\+?([1-9][0-9]{0,4})([smhdw])$")


class CASigningError(RuntimeError):
    """Raised when the CA signer service fails or is misconfigured."""


def parse_validity_timedelta(validity: str) -> timedelta:
    """Convert an OpenSSH relative validity interval (e.g. '+24h', '+1d') to a timedelta."""
    match = VALIDITY_UNIT_RE.match(validity.strip())
    if not match:
        raise CASigningError(f"Unsupported SSH_CERT_VALIDITY value: {validity!r}")
    amount = int(match.group(1))
    unit = match.group(2)
    multipliers = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
    }
    return multipliers[unit]


def request_certificate_signature(
    *,
    public_key: str,
    identity: str,
    principals: list[str],
    validity: str,
    serial: int | None = None,
) -> dict:
    """Call the CA signer HTTP service to sign an SSH public key."""
    if not settings.CA_SIGNER_TOKEN:
        raise CASigningError("CA_SIGNER_TOKEN is not configured.")

    payload = {
        "public_key": public_key,
        "identity": identity,
        "principals": principals,
        "validity": validity,
    }
    if serial is not None:
        payload["serial"] = serial

    try:
        resp = requests.post(
            f"{settings.CA_SIGNER_URL}/sign",
            json=payload,
            headers={"X-CA-Signer-Token": settings.CA_SIGNER_TOKEN},
            timeout=10,
        )
    except requests.RequestException as exc:
        raise CASigningError(f"CA signer unreachable: {exc}") from exc

    if resp.status_code != 200:
        try:
            err_detail = resp.json().get("error", resp.text)
        except ValueError:
            err_detail = resp.text
        raise CASigningError(f"CA signer returned {resp.status_code}: {err_detail}")

    data = resp.json()
    if "certificate" not in data:
        raise CASigningError("CA signer response missing 'certificate'.")

    if data.get("valid_to"):
        data["valid_until_dt"] = datetime.fromisoformat(data["valid_to"])
    else:
        data["valid_until_dt"] = None
    return data


def check_ca_signer_health() -> bool:
    """Return True if the CA signer reports healthy."""
    try:
        resp = requests.get(f"{settings.CA_SIGNER_URL}/healthz", timeout=3)
        return resp.status_code == 200
    except requests.RequestException:
        return False
