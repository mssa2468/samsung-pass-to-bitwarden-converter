"""
Samsung Pass to Bitwarden Converter
A utility to decrypt Samsung Pass exports and convert them to Bitwarden format.
"""

import base64
import json
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

import pandas as pd
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


class BitwardenConverter:
    def __init__(self, config: CryptoConfig = CryptoConfig()):
        self.config = config

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

            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(self.config.BLOCK_SIZE).unpadder()
            return unpadder.update(decrypted) + unpadder.finalize()
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")

    @staticmethod
    def safe_decode(field: bytes, encoding: str = "utf-8") -> str:
        """Safely decode bytes to string"""
        if not field:
            return ""
        try:
            padded = field + b"=" * (-len(field) % 4)
            return base64.b64decode(padded).decode(encoding, errors="ignore")
        except:
            return field.decode(encoding, errors="ignore")

    def parse_table(self, table_data: List[bytes]) -> pd.DataFrame:
        """Parse a single table from decrypted data"""
        if not table_data:
            return pd.DataFrame()

        header = [
            self.safe_decode(field) for field in table_data[0].strip().split(b";")
        ]
        rows = []

        for line in table_data[1:]:
            if line.strip():
                fields = [self.safe_decode(field) for field in line.strip().split(b";")]
                # Ensure row length matches header
                fields.extend([""] * (len(header) - len(fields)))
                rows.append(fields[: len(header)])

        return pd.DataFrame(rows, columns=header)

    def parse_tables(
        self, data: List[bytes]
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Parse all tables from decrypted data"""
        tables = []
        current_table = []

        for line in data[2:]:  # Skip header and flags
            if line.strip() in (b"next_table\r", b"next_table"):
                if current_table:
                    tables.append(self.parse_table(current_table))
                    current_table = []
            else:
                current_table.append(line)

        if current_table:
            tables.append(self.parse_table(current_table))

        # Ensure we always return 4 DataFrames
        return tuple(tables + [pd.DataFrame()] * (4 - len(tables)))

    def create_bitwarden_item(
        self, item_type: int, name: str, **kwargs
    ) -> Dict[str, Any]:
        """Create a single Bitwarden item"""
        item = {"type": item_type, "name": name}
        item.update(kwargs)
        return item

    def create_bitwarden_export(
        self,
        credentials: pd.DataFrame,
        cards: pd.DataFrame,
        addresses: pd.DataFrame,
        notes: pd.DataFrame,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Create complete Bitwarden export"""
        items = []

        # Process login credentials
        if not credentials.empty:
            for _, row in credentials.iterrows():
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
        if not notes.empty:
            for _, row in notes.iterrows():
                items.append(
                    self.create_bitwarden_item(
                        2,
                        row.get("note_title", ""),
                        secureNote={},
                        notes=row.get("note_detail", ""),
                    )
                )

        # Process payment cards
        if not cards.empty:
            for _, row in cards.iterrows():
                items.append(
                    self.create_bitwarden_item(
                        3,
                        row.get("reserved_5", ""),
                        card={
                            "cardholderName": row.get("name_on_card", ""),
                            "number": row.get("qݞzr", ""),
                            "expMonth": row.get("expiration_month", ""),
                            "expYear": row.get("expiration_year", ""),
                            "code": row.get("security_code", ""),
                        },
                    )
                )

        # Process addresses
        if not addresses.empty:
            for _, row in addresses.iterrows():
                items.append(
                    self.create_bitwarden_item(
                        4,
                        row.get("~e", ""),
                        identity={
                            "firstName": row.get("~e", ""),
                            "address1": row.get("street_address", ""),
                            "city": row.get("r+r", ""),
                            "postalCode": row.get("*\\", ""),
                            "country": row.get("country_code", ""),
                        },
                    )
                )

        return {"items": items}

    def process_file(
        self, spass_path: str, password: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Process the entire .spass file"""
        with open(spass_path, "r", encoding="utf-8") as f:
            encrypted_data = f.read().strip()

        decrypted_data = self.decrypt_spass(encrypted_data, password)
        tables = self.parse_tables(decrypted_data.split(b"\n"))
        return self.create_bitwarden_export(*tables)


def main(spass_path: Optional[str] = None, password: Optional[str] = None):
    """Main execution function"""
    try:
        spass_path = spass_path or input("Enter .spass file path: ").strip()
        password = password or getpass("Enter password: ")

        converter = BitwardenConverter()
        export_data = converter.process_file(spass_path, password)

        output_path = Path(spass_path).with_name("bitwarden_export.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        print(f"Export successful: {output_path}")

    except Exception as e:
        print(f"Error: {str(e)}")
        raise


if __name__ == "__main__":
    main()
