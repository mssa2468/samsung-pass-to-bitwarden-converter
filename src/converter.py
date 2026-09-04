"""
Samsung Pass to Bitwarden Converter
A utility to decrypt Samsung Pass exports and convert them to Bitwarden format.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

EXPORT_FILENAME = "bitwarden_export.json"
TABLE_MARKERS = (
    b"note_title",
    b"origin_url",
    b"name_on_card",
    b"card_number_encrypted",
    b"street_address",
    b"full_name",
)
LOGIN_TYPE = 1
NOTE_TYPE = 2
CARD_TYPE = 3
IDENTITY_TYPE = 4


@dataclass(frozen=True)
class CryptoConfig:
    """Cryptographic configuration parameters"""

    SALT_BYTES: int = 20
    ITERATION_COUNT: int = 70000
    KEY_LENGTH: int = 32
    BLOCK_SIZE: int = 128


class DecryptionError(Exception):
    """Custom exception for decryption-related errors"""


class PathValidationError(Exception):
    """Custom exception for path validation errors"""


def _strip_quotes(path_str: str) -> str:
    """Strip whitespace and one layer of matching quotes (Windows drag-and-drop)."""
    s = path_str.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _totp_uri(otp_json: str) -> str:
    """Build an otpauth URI from Samsung's OTP JSON blob; "" when unusable."""
    try:
        data = json.loads(otp_json) if otp_json else {}
        secret = re.sub(r"\s+", "", str(data.get("secret", ""))).upper()
        if not secret:
            return ""
        label = quote(str(data.get("name") or data.get("issuer") or "Samsung Pass"))
        uri = f"otpauth://totp/{label}?secret={secret}"
        if data.get("issuer"):
            uri += f"&issuer={quote(str(data['issuer']))}"
        digits = str(data.get("digits", "6"))
        period = str(data.get("period", "30"))
        uri += f"&algorithm={data.get('algo', 'SHA1')}&digits={digits if digits.isdigit() else '6'}"
        return uri + f"&period={period if period.isdigit() else '30'}"
    except (ValueError, AttributeError):
        return ""


def _card_number(row: dict[str, str]) -> str:
    """Card PAN from plaintext-format columns; "" when encrypted/unreadable."""
    for key in ("card_number", "card_number_encrypted"):
        digits = re.sub(r"[\s-]", "", row.get(key, ""))
        if digits.isdigit() and len(digits) >= 12:
            return digits
    return ""


def validate_spass_path(path_str: str) -> Path:
    """Validate that the given path is a valid .spass file.

    Args:
        path_str: The path string to validate

    Returns:
        Path object if valid

    Raises:
        PathValidationError: If the path is invalid
    """
    path_str = _strip_quotes(path_str)

    if not path_str:
        raise PathValidationError(
            "No file path provided. Please enter the path to your .spass file."
        )

    path = Path(path_str)

    if not path.exists():
        raise PathValidationError(
            f"File not found: {path}\nPlease check that the file path is correct."
        )

    if path.is_dir():
        raise PathValidationError(
            f"'{path}' is a directory, not a file.\n"
            "Please provide the path to your .spass file, not a folder.\n"
            "Example: C:\\Users\\YourName\\Downloads\\samsung_pass_export.spass"
        )

    if path.suffix.lower() != ".spass":
        raise PathValidationError(
            f"File '{path.name}' does not have a .spass extension.\n"
            "Please select the exported Samsung Pass file (ending in .spass)."
        )

    try:
        with path.open("rb"):
            pass
    except OSError as e:
        raise PathValidationError(
            f"Cannot read file: {path}\nPlease check file permissions."
        ) from e

    return path


class BitwardenConverter:
    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()

    def decrypt_spass(self, encrypted_data: str, password: str) -> bytes:
        """Decrypt Samsung Pass encrypted data"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
        except binascii.Error as e:
            raise DecryptionError(f"File is not valid encoded data (it may be corrupt): {e}") from e
        if len(encrypted_bytes) < self.config.SALT_BYTES + 32:
            raise DecryptionError("File too short to be a valid .spass export.")
        try:
            salt = encrypted_bytes[: self.config.SALT_BYTES]
            iv = encrypted_bytes[self.config.SALT_BYTES : self.config.SALT_BYTES + 16]
            ciphertext = encrypted_bytes[self.config.SALT_BYTES + 16 :]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config.KEY_LENGTH,
                salt=salt,
                iterations=self.config.ITERATION_COUNT,
            )
            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(self.config.BLOCK_SIZE).unpadder()
            return unpadder.update(decrypted) + unpadder.finalize()
        except Exception as e:
            raise DecryptionError(
                f"Could not decrypt - the password is likely incorrect: {e!s}"
            ) from e

    @staticmethod
    def safe_decode(field: bytes | None, encoding: str = "utf-8") -> str:
        """Safely decode bytes to string ("&&&NULL&&&" placeholders become "")."""
        if not field:
            return ""
        if field.strip() == b"&&&NULL&&&":  # Samsung null marker (b64decode would mangle it)
            return ""
        try:
            padded = field + b"=" * (-len(field) % 4)
            decoded = base64.b64decode(padded).decode(encoding, errors="ignore")
        except Exception:
            decoded = field.decode(encoding, errors="ignore")
        return "" if decoded == "&&&NULL&&&" else decoded

    def parse_table(self, table_data: list[bytes]) -> list[dict[str, str]]:
        """Parse a single table from decrypted data into list of dicts"""
        if not table_data:
            return []

        # Headers are plaintext field names; only row values are base64-encoded.
        # safe_decode would mangle short headers that are valid base64 ("name" -> "", "city" -> "r+r").
        header = [
            field.decode("utf-8", errors="ignore") for field in table_data[0].strip().split(b";")
        ]
        rows = []

        for line in table_data[1:]:
            if line.strip():
                fields = [self.safe_decode(field) for field in line.strip().split(b";")]
                # Ensure row length matches header
                fields.extend([""] * (len(header) - len(fields)))
                row_dict = dict(zip(header, fields[: len(header)], strict=False))
                rows.append(row_dict)

        return rows

    def parse_tables(
        self, data: list[bytes]
    ) -> tuple[
        list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]
    ]:
        """Parse all tables from decrypted data, identified by header columns."""
        segments: list[list[bytes]] = []
        current_table: list[bytes] = []
        for line in data:
            if line.strip() in (b"next_table\r", b"next_table"):
                segments.append(current_table)
                current_table = []
            else:
                current_table.append(line)
        segments.append(current_table)

        credentials: list[dict[str, str]] = []
        cards: list[dict[str, str]] = []
        addresses: list[dict[str, str]] = []
        notes: list[dict[str, str]] = []
        for segment in segments:
            # The header is the first line naming a known column. Markers contain
            # "_", which never appears in base64 row data, so rows can't match.
            # Preamble lines ("32", flags, "samsung_pass_export") never match either.
            start = next(
                (i for i, line in enumerate(segment) if any(m in line for m in TABLE_MARKERS)),
                None,
            )
            if start is None:
                continue
            rows = self.parse_table(segment[start:])
            if not rows:
                continue
            columns = set(rows[0])
            if "note_title" in columns:
                notes = rows
            elif "origin_url" in columns:
                credentials = rows
            elif "name_on_card" in columns or "card_number_encrypted" in columns:
                cards = rows
            elif "street_address" in columns or "full_name" in columns:
                addresses = rows
        return (credentials, cards, addresses, notes)

    def create_bitwarden_item(self, item_type: int, name: str, **kwargs: Any) -> dict[str, Any]:
        """Create a single Bitwarden item"""
        return {"type": item_type, "name": name, **kwargs}

    def create_bitwarden_export(
        self,
        credentials: list[dict[str, str]],
        cards: list[dict[str, str]],
        addresses: list[dict[str, str]],
        notes: list[dict[str, str]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Create complete Bitwarden export"""
        items: list[dict[str, Any]] = []

        items.extend(
            self.create_bitwarden_item(
                LOGIN_TYPE,
                row.get("title", "") or row.get("origin_url", ""),
                notes=row.get("credential_memo", ""),
                login={
                    "uris": [{"uri": row.get("origin_url", "")}],
                    "username": row.get("username_value", ""),
                    "password": row.get("password_value", ""),
                    "totp": _totp_uri(row.get("otp", "")),
                },
            )
            for row in credentials
            if row.get("origin_url") or row.get("username_value") or row.get("password_value")
        )

        items.extend(
            self.create_bitwarden_item(
                NOTE_TYPE,
                row.get("note_title", ""),
                secureNote={},
                notes=row.get("note_detail", ""),
            )
            for row in notes
            if row.get("note_title") or row.get("note_detail")
        )

        items.extend(
            self.create_bitwarden_item(
                CARD_TYPE,
                row.get("reserved_5", "") or row.get("name_on_card", ""),
                card={
                    "cardholderName": row.get("name_on_card", ""),
                    "number": _card_number(row),
                    "expMonth": row.get("expiration_month", ""),
                    "expYear": row.get("expiration_year", ""),
                    "code": row.get("card_security_code", row.get("security_code", "")),
                },
            )
            for row in cards
        )

        items.extend(
            self.create_bitwarden_item(
                IDENTITY_TYPE,
                row.get("full_name", row.get("name", "")),
                identity={
                    "firstName": row.get("full_name", row.get("name", "")),
                    "address1": row.get("street_address", ""),
                    "city": row.get("city", ""),
                    "state": row.get("state", ""),
                    "postalCode": row.get("zipcode", row.get("postal_code", "")),
                    "country": row.get("country_code", ""),
                    "phone": row.get("phone_number", ""),
                    "email": row.get("email", ""),
                },
            )
            for row in addresses
        )

        return {"items": items}

    def process_file(
        self, spass_path: str | Path, password: str
    ) -> dict[str, list[dict[str, Any]]]:
        """Process the entire .spass file"""
        # Validate path first
        validated_path = validate_spass_path(str(spass_path))

        encrypted_data = validated_path.read_text(encoding="utf-8").strip()

        decrypted_data = self.decrypt_spass(encrypted_data, password)
        tables = self.parse_tables(decrypted_data.split(b"\n"))
        return self.create_bitwarden_export(*tables)


def write_bitwarden_export(
    spass_path: str | Path, export_data: dict[str, list[dict[str, Any]]]
) -> Path:
    """Write Bitwarden JSON next to the Samsung Pass export."""
    output_path = Path(_strip_quotes(str(spass_path))).with_name(EXPORT_FILENAME)
    output_path.write_text(json.dumps(export_data, indent=2) + "\n", encoding="utf-8")
    return output_path


def main(spass_path: str | None = None, password: str | None = None) -> None:
    """Main execution function"""
    import argparse

    try:
        if spass_path is None and password is None and len(sys.argv) > 1:
            parser = argparse.ArgumentParser(
                description="Convert Samsung Pass export to Bitwarden JSON"
            )
            parser.add_argument("spass_file", nargs="?", help="Path to the .spass file")
            parser.add_argument("-p", "--password", help="Export password (else prompted securely)")
            args = parser.parse_args()
            spass_path = args.spass_file
            password = args.password
        if spass_path is None:
            print("\n=== Samsung Pass to Bitwarden Converter ===\n")
            print("Tip: You can drag and drop the .spass file into this window.\n")
            spass_path = input("Enter .spass file path: ").strip()

        if password is None:
            password = getpass("Enter password: ")

        converter = BitwardenConverter()
        export_data = converter.process_file(spass_path, password)  # validates path once
        output_path = write_bitwarden_export(spass_path, export_data)

        print("\n✓ Export successful!")
        print(f"  Output file: {output_path}")
        print(f"  Items exported: {len(export_data['items'])}")

    except PathValidationError as e:
        print(f"\n✗ Path Error:\n  {e}")
        sys.exit(1)
    except DecryptionError as e:
        print(f"\n✗ Decryption Error:\n  {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e!s}")
        sys.exit(1)


if __name__ == "__main__":
    main()
