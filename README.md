# Samsung Pass to Bitwarden Converter

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Convert Samsung Pass exports (`.spass` files) to Bitwarden-compatible JSON format.

## ✨ Features

- 🔐 Decrypts Samsung Pass encrypted exports (AES-256-CBC)
- 📋 Converts logins, secure notes, payment cards, and addresses
- 🖥️ GUI and command-line interfaces
- ✅ Comprehensive error messages

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Installation

```bash
# Clone the repository
git clone https://github.com/mssa2468/samsung-pass-to-bitwarden-converter
cd samsung-pass-to-bitwarden-converter

# Install dependencies with uv
uv sync

# Or with pip
pip install cryptography
```

### Usage

#### GUI Mode (Recommended)

```bash
uv run python gui.py
```

1. Click **Browse** to select your `.spass` file
2. Enter your export password
3. Click **Convert to Bitwarden**
4. Import the generated `bitwarden_export.json` into Bitwarden

#### Command Line

```bash
uv run python samsung_pass_to_bitwarden.py
```

## 📱 Exporting from Samsung Pass

1. Open **Samsung Pass** on your device
2. Go to **Settings** → **Export data**
3. Select the data to export (passwords, cards, addresses, notes)
4. Set a password for the export
5. Transfer the `.spass` file to your computer

## 🔧 Troubleshooting

### PermissionError: Permission denied

```
PermissionError: [Errno 13] Permission denied: 'C:\Users\...\Python'
```

**Cause**: You entered a folder path instead of the `.spass` file.

**Solution**: Enter the full path to your `.spass` file, for example:
```
C:\Users\YourName\Downloads\samsung_pass_export.spass
```

### Decryption Error

**Cause**: Incorrect password.

**Solution**: Double-check the password you set when exporting from Samsung Pass.

## 🛠️ Development

```bash
# Install all dependencies (including dev)
uv sync --all-extras

# Run tests
uv run pytest

# Run linter
uv run ruff check .

# Run type checker
uv run ty check

# Format code
uv run ruff format .
```

## 📁 Project Structure

```
samsung-pass-to-bitwarden-converter/
├── samsung_pass_to_bitwarden.py  # Core converter logic
├── gui.py                        # Tkinter GUI
├── tests/
│   └── test_converter.py         # Test suite
├── pyproject.toml                # Project configuration
├── uv.lock                       # Dependency lock file
├── LICENSE                       # MIT License
└── README.md
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file.

## ⚠️ Disclaimer

This tool is not affiliated with Samsung or Bitwarden. Use at your own risk. Always backup your data before conversion.
