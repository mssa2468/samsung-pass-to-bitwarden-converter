"""
Tests for Samsung Pass to Bitwarden Converter
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from src.converter import (
    BitwardenConverter,
    CryptoConfig,
    DecryptionError,
    PathValidationError,
    validate_spass_path,
    write_bitwarden_export,
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
        with pytest.raises(PathValidationError, match=r"does not have a \.spass extension"):
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

    def test_parse_table_keeps_short_plaintext_headers(self) -> None:
        """Headers like 'name'/'city' are plaintext, not base64 ('city' decodes to 'r+r')."""
        converter = BitwardenConverter()
        result = converter.parse_table([b"name;city", b"Sm9obiBEb2U=;TmV3IFlvcms="])
        assert result == [{"name": "John Doe", "city": "New York"}]

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

    def test_empty_credential_rows_are_skipped(self) -> None:
        """Rows with no URL, username, or password add clutter, not value."""
        converter = BitwardenConverter()
        credentials = [
            {"origin_url": "", "username_value": "", "password_value": ""},
            {"origin_url": "https://example.com", "username_value": "u", "password_value": "p"},
        ]
        result = converter.create_bitwarden_export(credentials, [], [], [])
        assert len(result["items"]) == 1
        assert result["items"][0]["login"]["username"] == "u"


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
        with pytest.raises(DecryptionError, match="password is likely incorrect"):
            converter.decrypt_spass(fake_data, "wrong_password")

    def test_corrupt_data_message_differs_from_wrong_password(self) -> None:
        """Bad encoding reports corruption, not a wrong password."""
        converter = BitwardenConverter()
        with pytest.raises(DecryptionError, match="corrupt"):
            converter.decrypt_spass("abc", "password")


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

    def test_write_bitwarden_export_strips_quoted_path(self, tmp_path: Path) -> None:
        """Test writing the export beside a quoted .spass path."""
        spass_file = tmp_path / "quoted.spass"
        spass_file.write_text("encrypted_data")

        output_path = write_bitwarden_export(f'"{spass_file}"', {"items": []})

        assert output_path == tmp_path / "bitwarden_export.json"
        assert output_path.read_text(encoding="utf-8") == '{\n  "items": []\n}\n'


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


class TestRealFormat:
    """Real Samsung Pass exports: header block, header-identified tables, real columns."""

    def test_tables_identified_by_header_not_position(self) -> None:
        """A leading 'false' flags line must not shift logins into card slots."""
        converter = BitwardenConverter()
        data = [
            b"32",
            b"true;true;true;true",
            b"false",
            b"_id;origin_url;username_value;password_value",
            b"MQ==;aHR0cHM6Ly9leGFtcGxlLmNvbQ==;dXNlcg==;cGFzcw==",
            b"next_table",
            b"_id;note_title;note_detail",
            b"MQ==;dGl0bGU=;ZGV0YWls",
        ]
        credentials, cards, addresses, notes = converter.parse_tables(data)
        assert [r["origin_url"] for r in credentials] == ["https://example.com"]
        assert cards == [] and addresses == []
        assert [(r["note_title"], r["note_detail"]) for r in notes] == [("title", "detail")]

    def test_null_placeholder_becomes_empty(self) -> None:
        """Samsung writes &&&NULL&&& for nulls; it must not leak into the export."""
        assert BitwardenConverter.safe_decode(b"&&&NULL&&&") == ""
        converter = BitwardenConverter()
        rows = converter.parse_table([b"a;b", b"eA==;" + b"&&&NULL&&&"])
        assert rows == [{"a": "x", "b": ""}]

    def test_real_column_names_mapped(self) -> None:
        """full_name/zipcode/card_security_code are the real column names."""
        converter = BitwardenConverter()
        result = converter.create_bitwarden_export(
            [
                {
                    "title": "AdAway",
                    "origin_url": "https://a.example",
                    "username_value": "u",
                    "password_value": "p",
                }
            ],
            [{"reserved_5": "", "name_on_card": "jack", "card_security_code": "123"}],
            [{"full_name": "Jane", "zipcode": "10001"}],
            [{"note_title": "", "note_detail": ""}],
        )
        by_type = {item["type"]: item for item in result["items"]}
        assert by_type[1]["name"] == "AdAway"
        assert by_type[3]["name"] == "jack"  # falls back to holder name
        assert by_type[3]["card"]["code"] == "123"
        assert by_type[4]["identity"]["firstName"] == "Jane"
        assert by_type[4]["identity"]["postalCode"] == "10001"
        assert 2 not in by_type  # empty note skipped

    def test_otp_blob_becomes_totp_uri(self) -> None:
        """Samsung's OTP JSON maps to a Bitwarden TOTP URI; garbage maps to ''."""
        converter = BitwardenConverter()
        otp = '{"algo":"SHA1","digits":6,"issuer":"2FAS","name":"Test","period":30,"secret":"JBSWY3DPEHPK3PXP"}'
        result = converter.create_bitwarden_export(
            [
                {
                    "origin_url": "https://a.example",
                    "username_value": "u",
                    "password_value": "p",
                    "otp": otp,
                }
            ],
            [],
            [],
            [],
        )
        totp = result["items"][0]["login"]["totp"]
        assert totp.startswith("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")
        assert "issuer=2FAS" in totp and "digits=6" in totp and "period=30" in totp
        bad = converter.create_bitwarden_export(
            [
                {
                    "origin_url": "https://a.example",
                    "username_value": "u",
                    "password_value": "p",
                    "otp": "not-json",
                }
            ],
            [],
            [],
            [],
        )
        assert bad["items"][0]["login"]["totp"] == ""

    def test_card_number_only_when_digits(self) -> None:
        """Plaintext PANs map; encrypted blobs must not leak into the number field."""
        converter = BitwardenConverter()
        ok = converter.create_bitwarden_export(
            [], [{"name_on_card": "jack", "card_number_encrypted": "123456789123456789"}], [], []
        )
        assert ok["items"][0]["card"]["number"] == "123456789123456789"
        encrypted = converter.create_bitwarden_export(
            [],
            [{"name_on_card": "jack", "card_number_encrypted": "q80=v8Y€2;\x00\x01binary"}],
            [],
            [],
        )
        assert encrypted["items"][0]["card"]["number"] == ""
