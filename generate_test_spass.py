"""
Generate a test .spass file for testing the converter.
"""

import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_test_spass(output_path: str, password: str) -> None:
    """Create a test .spass file with sample data."""

    # Sample data in Samsung Pass format
    # Format: header, flags, then tables separated by "next_table"
    test_data = b"""samsung_pass_export
version:1
origin_url;username_value;password_value
aHR0cHM6Ly9leGFtcGxlLmNvbQ==;dGVzdHVzZXI=;cGFzc3dvcmQxMjM=
aHR0cHM6Ly9naXRodWIuY29t;Z2l0dXNlcg==;Z2l0cGFzczQ1Ng==
aHR0cHM6Ly9nb29nbGUuY29t;bXllbWFpbEBnbWFpbC5jb20=;c2VjdXJlcGFzczc4OQ==
next_table
reserved_5;name_on_card;card_number;expiration_month;expiration_year;security_code
TXkgVmlzYQ==;Sm9obiBEb2U=;NDExMTExMTExMTExMTExMQ==;MTI=;MjAyNg==;MTIz
next_table
name;street_address;city;postal_code;country_code
Sm9obiBEb2U=;MTIzIE1haW4gU3RyZWV0;TmV3IFlvcms=;MTAwMDE=;VVM=
next_table
note_title;note_detail
TXkgU2VjcmV0IE5vdGU=;VGhpcyBpcyBhIHNlY3JldCBub3RlIGNvbnRlbnQ=
V2lGaSBQYXNzd29yZA==;TXlXaUZpUGFzc3dvcmQxMjM=
"""

    # Encryption parameters (must match the converter)
    salt = os.urandom(20)
    iv = os.urandom(16)

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=70000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())

    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(test_data) + padder.finalize()

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine: salt + iv + ciphertext
    encrypted_bytes = salt + iv + ciphertext

    # Base64 encode
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode("utf-8")

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(encrypted_base64)

    print(f"✓ Created test .spass file: {output_path}")
    print(f"  Password: {password}")
    print()
    print("Test data includes:")
    print("  - 3 login credentials (example.com, github.com, google.com)")
    print("  - 1 credit card (Visa)")
    print("  - 1 address (New York)")
    print("  - 2 secure notes")


if __name__ == "__main__":
    create_test_spass("test_export.spass", "testpassword123")
