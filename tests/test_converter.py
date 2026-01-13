"""
Tests for Samsung Pass to Bitwarden Converter
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from samsung_pass_to_bitwarden import (
    BitwardenConverter,
    CryptoConfig,
    DecryptionError,
    PathValidationError,
    validate_spass_path,
)


class TestPathValidation:
    """Tests for path validation function"""

    def test_empty_path_raises_error(self) -> None:
        """Test that empty path raises PathValidationError"""
        with pytest.raises(PathValidationError, match="No file path provided"):
            validate_spass_path("")

    def test_whitespace_path_raises_error(self) -> None:
        """Test that whitespace-only path raises PathValidationError"""
        with pytest.raises(PathValidationError, match="No file path provided"):
            validate_spass_path("   ")

    def test_nonexistent_file_raises_error(self) -> None:
        """Test that non-existent file raises PathValidationError"""
        with pytest.raises(PathValidationError, match="File not found"):
            validate_spass_path("/path/that/does/not/exist.spass")

    def test_directory_path_raises_error(self, tmp_path: Path) -> None:
        """Test that directory path raises PathValidationError with helpful message"""
        with pytest.raises(PathValidationError, match="is a directory, not a file"):
            validate_spass_path(str(tmp_path))

    def test_wrong_extension_raises_error(self, tmp_path: Path) -> None:
        """Test that non-.spass file raises PathValidationError"""
        wrong_file = tmp_path / "test.txt"
        wrong_file.write_text("test")
        with pytest.raises(PathValidationError, match="does not have a .spass extension"):
            validate_spass_path(str(wrong_file))

    def test_valid_spass_file_returns_path(self, tmp_path: Path) -> None:
        """Test that valid .spass file returns Path object"""
        spass_file = tmp_path / "test.spass"
        spass_file.write_text("encrypted_data")
        result = validate_spass_path(str(spass_file))
        assert result == spass_file

    def test_strips_quotes_from_path(self, tmp_path: Path) -> None:
        """Test that quotes are stripped from path (Windows drag-and-drop)"""
        spass_file = tmp_path / "test.spass"
        spass_file.write_text("encrypted_data")
        # Test with double quotes
        result = validate_spass_path(f'"{spass_file}"')
        assert result == spass_file

    def test_strips_single_quotes_from_path(self, tmp_path: Path) -> None:
        """Test that single quotes are stripped from path"""
        spass_file = tmp_path / "test.spass"
        spass_file.write_text("encrypted_data")
        result = validate_spass_path(f"'{spass_file}'")
        assert result == spass_file


class TestBitwardenConverter:
    """Tests for BitwardenConverter class"""

    def test_default_config(self) -> None:
        """Test default crypto configuration"""
        converter = BitwardenConverter()
        assert converter.config.SALT_BYTES == 20
        assert converter.config.ITERATION_COUNT == 70000
        assert converter.config.KEY_LENGTH == 32
        assert converter.config.BLOCK_SIZE == 128

    def test_custom_config(self) -> None:
        """Test custom crypto configuration"""
        config = CryptoConfig(SALT_BYTES=16, ITERATION_COUNT=50000)
        converter = BitwardenConverter(config)
        assert converter.config.SALT_BYTES == 16
        assert converter.config.ITERATION_COUNT == 50000

    def test_safe_decode_empty_field(self) -> None:
        """Test safe_decode with empty input"""
        assert BitwardenConverter.safe_decode(b"") == ""
        assert BitwardenConverter.safe_decode(None) == ""  # type: ignore[arg-type]

    def test_safe_decode_regular_bytes(self) -> None:
        """Test safe_decode with regular bytes"""
        result = BitwardenConverter.safe_decode(b"hello")
        # May be base64 decoded or returned as-is depending on format
        assert isinstance(result, str)

    def test_parse_table_empty(self) -> None:
        """Test parsing empty table data"""
        converter = BitwardenConverter()
        result = converter.parse_table([])
        assert result == []

    def test_parse_table_header_only(self) -> None:
        """Test parsing table with header only"""
        converter = BitwardenConverter()
        result = converter.parse_table([b"col1;col2;col3"])
        assert result == []

    def test_parse_table_with_data(self) -> None:
        """Test parsing table with header and data rows"""
        converter = BitwardenConverter()
        table_data = [
            b"name;value",
            b"test;data",
        ]
        result = converter.parse_table(table_data)
        assert len(result) == 1
        # Values are base64 decoded, so check structure
        assert "name" in result[0] or len(result[0]) == 2

    def test_create_bitwarden_item_login(self) -> None:
        """Test creating a login-type Bitwarden item"""
        converter = BitwardenConverter()
        item = converter.create_bitwarden_item(
            1,
            "example.com",
            login={"username": "user", "password": "pass"},
        )
        assert item["type"] == 1
        assert item["name"] == "example.com"
        assert item["login"]["username"] == "user"

    def test_create_bitwarden_item_secure_note(self) -> None:
        """Test creating a secure note Bitwarden item"""
        converter = BitwardenConverter()
        item = converter.create_bitwarden_item(
            2,
            "My Note",
            secureNote={},
            notes="Secret content",
        )
        assert item["type"] == 2
        assert item["name"] == "My Note"
        assert item["notes"] == "Secret content"

    def test_create_bitwarden_export_empty(self) -> None:
        """Test creating export with empty data"""
        converter = BitwardenConverter()
        result = converter.create_bitwarden_export([], [], [], [])
        assert result == {"items": []}

    def test_create_bitwarden_export_with_credentials(self) -> None:
        """Test creating export with credential data"""
        converter = BitwardenConverter()
        credentials = [
            {
                "origin_url": "https://example.com",
                "username_value": "user@example.com",
                "password_value": "secret123",
            }
        ]
        result = converter.create_bitwarden_export(credentials, [], [], [])
        assert len(result["items"]) == 1
        assert result["items"][0]["type"] == 1
        assert result["items"][0]["login"]["username"] == "user@example.com"

    def test_create_bitwarden_export_with_notes(self) -> None:
        """Test creating export with notes data"""
        converter = BitwardenConverter()
        notes = [{"note_title": "My Secret", "note_detail": "Secret info"}]
        result = converter.create_bitwarden_export([], [], [], notes)
        assert len(result["items"]) == 1
        assert result["items"][0]["type"] == 2
        assert result["items"][0]["notes"] == "Secret info"


class TestDecryption:
    """Tests for decryption functionality"""

    def test_decryption_with_invalid_data_raises_error(self) -> None:
        """Test that invalid encrypted data raises DecryptionError"""
        converter = BitwardenConverter()
        with pytest.raises(DecryptionError):
            converter.decrypt_spass("not_valid_base64!!!", "password")

    def test_decryption_with_wrong_password_raises_error(self) -> None:
        """Test that wrong password raises DecryptionError (padding error)"""
        converter = BitwardenConverter()
        # Create some valid base64 but with wrong structure
        fake_data = base64.b64encode(b"a" * 100).decode()
        with pytest.raises(DecryptionError):
            converter.decrypt_spass(fake_data, "wrong_password")


class TestProcessFile:
    """Tests for full file processing"""

    def test_process_file_validates_path(self, tmp_path: Path) -> None:
        """Test that process_file validates path before processing"""
        converter = BitwardenConverter()
        with pytest.raises(PathValidationError, match="is a directory"):
            converter.process_file(str(tmp_path), "password")

    def test_process_file_with_invalid_content(self, tmp_path: Path) -> None:
        """Test processing file with invalid content raises DecryptionError"""
        spass_file = tmp_path / "invalid.spass"
        spass_file.write_text("invalid_encrypted_content")
        converter = BitwardenConverter()
        with pytest.raises(DecryptionError):
            converter.process_file(str(spass_file), "password")


class TestIntegration:
    """Integration tests"""

    def test_full_export_structure(self) -> None:
        """Test that export has correct Bitwarden structure"""
        converter = BitwardenConverter()
        credentials = [
            {
                "origin_url": "https://site1.com",
                "username_value": "user1",
                "password_value": "pass1",
            },
            {
                "origin_url": "https://site2.com",
                "username_value": "user2",
                "password_value": "pass2",
            },
        ]
        notes = [{"note_title": "Note1", "note_detail": "Content1"}]
        cards = [
            {
                "reserved_5": "My Card",
                "name_on_card": "John Doe",
                "card_number": "1234567890123456",
                "expiration_month": "12",
                "expiration_year": "2025",
                "security_code": "123",
            }
        ]
        addresses = [
            {
                "name": "Home",
                "street_address": "123 Main St",
                "city": "Springfield",
                "postal_code": "12345",
                "country_code": "US",
            }
        ]

        result = converter.create_bitwarden_export(credentials, cards, addresses, notes)

        assert "items" in result
        assert len(result["items"]) == 5  # 2 logins + 1 note + 1 card + 1 address

        # Verify each type is present
        types = [item["type"] for item in result["items"]]
        assert types.count(1) == 2  # logins
        assert types.count(2) == 1  # note
        assert types.count(3) == 1  # card
        assert types.count(4) == 1  # address
