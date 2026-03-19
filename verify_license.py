"""Local verification of a license key — mirrors what ServiceNow will do."""
import json
import base64
import hashlib
import sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

CERT_PATH = "certs/certificate.crt"
LICENSE_PATH = "license.key"


def b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def verify_license():
    # Load certificate
    with open(CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    # Load token
    with open(LICENSE_PATH, "r") as f:
        token = f.read().strip()

    parts = token.split(".")
    if len(parts) != 3:
        print("FAIL: Token must have 3 parts (header.payload.signature)")
        sys.exit(1)

    header_b64, payload_b64, signature_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    signature = b64url_decode(signature_b64)

    print("=== License Verification ===")

    # 1. Check certificate fingerprint matches (hash base64 DER string, not raw binary)
    with open(CERT_PATH, "r") as f:
        pem_text = f.read()
    der_b64 = pem_text.replace("-----BEGIN CERTIFICATE-----", "") \
                      .replace("-----END CERTIFICATE-----", "") \
                      .replace("\n", "").replace("\r", "").strip()
    cert_fp = hashlib.sha256(der_b64.encode("utf-8")).hexdigest()
    token_fp = header.get("x5t#S256", "")
    if cert_fp != token_fp:
        print("FAIL: Certificate fingerprint mismatch!")
        print(f"  Token expects : {token_fp}")
        print(f"  Cert has      : {cert_fp}")
        sys.exit(1)
    print(f"[PASS] Certificate fingerprint matches: {cert_fp[:16]}...")

    # 2. Check certificate expiry
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        print(f"FAIL: Certificate is not valid at current time ({now.isoformat()})")
        print(f"  Valid from : {cert.not_valid_before_utc}")
        print(f"  Valid to   : {cert.not_valid_after_utc}")
        sys.exit(1)
    print(f"[PASS] Certificate is valid (expires {cert.not_valid_after_utc.date()})")

    # 3. Verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        cert.public_key().verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        print("[PASS] Signature is valid")
    except Exception as e:
        print(f"FAIL: Signature verification failed — {e}")
        sys.exit(1)

    # 4. Display payload
    print(f"\n=== License Data ===")
    for k, v in payload.items():
        print(f"  {k}: {v}")

    print("\nLicense is VALID.")


if __name__ == "__main__":
    verify_license()
