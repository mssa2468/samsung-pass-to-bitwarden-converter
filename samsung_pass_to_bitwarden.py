"""
Samsung Pass to Bitwarden Converter
A utility to decrypt Samsung Pass exports and convert them to Bitwarden format.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class CryptoConfig:
    """Cryptographic configuration parameters"""

    SALT_BYTES: int = 20
    ITERATION_COUNT: int = 70000
    KEY_LENGTH: int = 32
    BLOCK_SIZE: int = 128


class DecryptionError(Exception):
    """Custom exception for decryption-related errors"""

    pass


class PathValidationError(Exception):
    """Custom exception for path validation errors"""

    pass


def validate_spass_path(path_str: str) -> Path:
    """Validate that the given path is a valid .spass file.

    Args:
        path_str: The path string to validate

    Returns:
        Path object if valid

    Raises:
        PathValidationError: If the path is invalid
    """
    # Strip quotes (from drag-and-drop on Windows)
    path_str = path_str.strip().strip('"').strip("'")

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

    # Check if file is readable
    if not os.access(path, os.R_OK):
        raise PathValidationError(f"Cannot read file: {path}\nPlease check file permissions.")

    return path


class BitwardenConverter:
    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()

    def decrypt_spass(self, encrypted_data: str, password: str) -> bytes:
        """Decrypt Samsung Pass encrypted data"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            salt = encrypted_bytes[: self.config.SALT_BYTES]
            iv = encrypted_bytes[self.config.SALT_BYTES : self.config.SALT_BYTES + 16]
            ciphertext = encrypted_bytes[self.config.SALT_BYTES + 16 :]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config.KEY_LENGTH,
                salt=salt,
                iterations=self.config.ITERATION_COUNT,
                backend=default_backend(),
            )
            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(self.config.BLOCK_SIZE).unpadder()
            return unpadder.update(decrypted) + unpadder.finalize()
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e!s}") from e

    @staticmethod
    def safe_decode(field: bytes, encoding: str = "utf-8") -> str:
        """Safely decode bytes to string"""
        if not field:
            return ""
        try:
            padded = field + b"=" * (-len(field) % 4)
            return base64.b64decode(padded).decode(encoding, errors="ignore")
        except Exception:
            return field.decode(encoding, errors="ignore")

    def parse_table(self, table_data: list[bytes]) -> list[dict[str, str]]:
        """Parse a single table from decrypted data into list of dicts"""
        if not table_data:
            return []

        header = [self.safe_decode(field) for field in table_data[0].strip().split(b";")]
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
        """Parse all tables from decrypted data"""
        tables: list[list[dict[str, str]]] = []
        current_table: list[bytes] = []

        for line in data[2:]:  # Skip header and flags
            if line.strip() in (b"next_table\r", b"next_table"):
                if current_table:
                    tables.append(self.parse_table(current_table))
                    current_table = []
            else:
                current_table.append(line)

        if current_table:
            tables.append(self.parse_table(current_table))

        # Ensure we always return 4 tables
        while len(tables) < 4:
            tables.append([])

        return (tables[0], tables[1], tables[2], tables[3])

    def create_bitwarden_item(self, item_type: int, name: str, **kwargs: Any) -> dict[str, Any]:
        """Create a single Bitwarden item"""
        item: dict[str, Any] = {"type": item_type, "name": name}
        item.update(kwargs)
        return item

    def create_bitwarden_export(
        self,
        credentials: list[dict[str, str]],
        cards: list[dict[str, str]],
        addresses: list[dict[str, str]],
        notes: list[dict[str, str]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Create complete Bitwarden export"""
        items: list[dict[str, Any]] = []

        # Process login credentials
        for row in credentials:
            items.append(
                self.create_bitwarden_item(
                    1,
                    row.get("origin_url", ""),
                    login={
                        "uris": [{"uri": row.get("origin_url", "")}],
                        "username": row.get("username_value", ""),
                        "password": row.get("password_value", ""),
                    },
                )
            )

        # Process secure notes
        for row in notes:
            items.append(
                self.create_bitwarden_item(
                    2,
                    row.get("note_title", ""),
                    secureNote={},
                    notes=row.get("note_detail", ""),
                )
            )

        # Process payment cards
        for row in cards:
            items.append(
                self.create_bitwarden_item(
                    3,
                    row.get("reserved_5", ""),
                    card={
                        "cardholderName": row.get("name_on_card", ""),
                        "number": row.get("card_number", row.get("qݞzr", "")),
                        "expMonth": row.get("expiration_month", ""),
                        "expYear": row.get("expiration_year", ""),
                        "code": row.get("security_code", ""),
                    },
                )
            )

        # Process addresses
        for row in addresses:
            items.append(
                self.create_bitwarden_item(
                    4,
                    row.get("~e", row.get("name", "")),
                    identity={
                        "firstName": row.get("~e", row.get("name", "")),
                        "address1": row.get("street_address", ""),
                        "city": row.get("r+r", row.get("city", "")),
                        "postalCode": row.get("*\\", row.get("postal_code", "")),
                        "country": row.get("country_code", ""),
                    },
                )
            )

        return {"items": items}

    def process_file(
        self, spass_path: str | Path, password: str
    ) -> dict[str, list[dict[str, Any]]]:
        """Process the entire .spass file"""
        # Validate path first
        validated_path = validate_spass_path(str(spass_path))

        with open(validated_path, encoding="utf-8") as f:
            encrypted_data = f.read().strip()

        decrypted_data = self.decrypt_spass(encrypted_data, password)
        tables = self.parse_tables(decrypted_data.split(b"\n"))
        return self.create_bitwarden_export(*tables)


def main(spass_path: str | None = None, password: str | None = None) -> None:
    """Main execution function"""
    try:
        if spass_path is None:
            print("\n=== Samsung Pass to Bitwarden Converter ===\n")
            print("Tip: You can drag and drop the .spass file into this window.\n")
            spass_path = input("Enter .spass file path: ").strip()

        if password is None:
            password = getpass("Enter password: ")

        converter = BitwardenConverter()
        export_data = converter.process_file(spass_path, password)

        output_path = Path(spass_path).with_name("bitwarden_export.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        print("\n✓ Export successful!")
        print(f"  Output file: {output_path}")
        print(f"  Items exported: {len(export_data['items'])}")

    except PathValidationError as e:
        print(f"\n✗ Path Error:\n  {e}")
        sys.exit(1)
    except DecryptionError as e:
        print(f"\n✗ Decryption Error:\n  {e}")
        print("\n  This usually means the password is incorrect.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e!s}")
        sys.exit(1)


if __name__ == "__main__":
    main()
