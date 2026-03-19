import json
import base64
import hashlib
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

CERT_PATH = "certs/certificate.crt"
KEY_PATH = "certs/private.key"
LICENSE_DATA_PATH = "license_data.json"
OUTPUT_PATH = "license.key"


def load_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cert_fingerprint_sha256(cert_path):
    """SHA256 fingerprint of the base64 DER string (PEM body without headers).
    This matches what ServiceNow GlideDigest.getSHA256Hex() produces
    when hashing the same base64 string — avoids binary corruption issues."""
    with open(cert_path, "r") as f:
        pem = f.read()
    # Strip PEM armor and whitespace to get pure base64 DER string
    der_b64 = pem.replace("-----BEGIN CERTIFICATE-----", "") \
                  .replace("-----END CERTIFICATE-----", "") \
                  .replace("\n", "").replace("\r", "").strip()
    return hashlib.sha256(der_b64.encode("utf-8")).hexdigest()


def b64url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding (JWT style)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_license():
    # Load cert + key
    cert = load_certificate(CERT_PATH)
    private_key = load_private_key(KEY_PATH)

    # Verify the private key matches the certificate
    cert_pub_bytes = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_pub_bytes != key_pub_bytes:
        print("ERROR: Private key does not match the certificate.")
        sys.exit(1)

    # Build header — ties this license to a specific certificate
    header = {
        "alg": "RS256",
        "typ": "LICENSE",
        "x5t#S256": cert_fingerprint_sha256(CERT_PATH),  # cert thumbprint
        "sub": cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
    }

    # Load license payload
    with open(LICENSE_DATA_PATH, "r") as f:
        license_data = json.load(f)

    # Encode parts (deterministic JSON)
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(license_data, separators=(",", ":")).encode())

    # Sign: header.payload
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = b64url_encode(signature)

    # Final token
    token = f"{header_b64}.{payload_b64}.{signature_b64}"

    # Write to file
    with open(OUTPUT_PATH, "w") as f:
        f.write(token)

    # Display info
    print("=== License Key Generated ===")
    print(f"Certificate : {header['sub']}")
    print(f"Fingerprint : {header['x5t#S256']}")
    print(f"Cert Valid  : {header['not_before']} to {header['not_after']}")
    print(f"Customer    : {license_data['customer_name']}")
    print(f"Instance    : {license_data['instance_id']}")
    print(f"Expires     : {license_data['expires_at']}")
    print(f"Output      : {OUTPUT_PATH}")
    print(f"\nToken ({len(token)} chars):")
    print(token)


if __name__ == "__main__":
    generate_license()
