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

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Installation

```bash
git clone https://github.com/mssa2468/samsung-pass-to-bitwarden-converter
cd samsung-pass-to-bitwarden-converter
uv sync
```

### Usage

#### GUI Mode

```bash
uv run python src/gui.py
```

#### Command Line

```bash
uv run python src/converter.py
```

## 📱 Exporting from Samsung Pass

1. Open **Samsung Pass** → **Settings** → **Export data**
2. Select data to export and set a password
3. Transfer `.spass` file to your computer

## 🔧 Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ty check
```

## 📁 Project Structure

```
├── src/
│   ├── converter.py    # Core converter logic
│   └── gui.py          # Tkinter GUI
├── scripts/
│   └── generate_test_spass.py
├── tests/
│   └── test_converter.py
├── pyproject.toml
└── README.md
```

## 📄 License

MIT License - see [LICENSE](LICENSE)
