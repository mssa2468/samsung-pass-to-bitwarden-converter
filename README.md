# Samsung Pass to Bitwarden Converter

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Convert Samsung Pass exports (`.spass` files) to Bitwarden-compatible JSON format.

## ✨ Features

- 🔐 Decrypts Samsung Pass encrypted exports (AES-256-CBC)
- 📋 Converts logins (with TOTP), secure notes, payment cards, and addresses
- 🖥️ GUI: file picker, drag-and-drop, remembers last folder, open-output-folder button
- ⌨️ CLI: `spass-convert file.spass -p <password>`, or interactive prompts
- ⚠️ Errors tell a wrong password apart from a corrupt file
- 🧹 Skips empty rows and Samsung `&&&NULL&&&` placeholders so Bitwarden stays clean

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

Drag-and-drop in the GUI needs `tkinterdnd2`, installed automatically by `uv sync`.
Without it the app still runs, just without drop support.

### Usage

#### GUI Mode

```bash
uv run spass-gui
```

Drop a `.spass` file onto the window (or Browse), enter the export password,
and click Convert. The result lands next to the input as `bitwarden_export.json`.

#### Command Line

```bash
uv run spass-convert <file.spass> -p <password>
uv run spass-convert  # interactive prompts
```

## 📱 Exporting from Samsung Pass

1. Open **Samsung Pass** → **Settings** → **Export data**
2. Select data to export and set a password
3. Transfer `.spass` file to your computer

## 📥 Importing into Bitwarden

1. Open Bitwarden → **File** → **Import data**
2. Format: **Bitwarden (json)**, pick `bitwarden_export.json`
3. Check that logins, cards, identities, and TOTP codes arrived, then delete the `.spass` file and the JSON

## 🩺 Troubleshooting

| Message | Meaning |
|---|---|
| `password is likely incorrect` | Wrong export password — try again |
| `not valid encoded data (it may be corrupt)` | File is damaged or not a real `.spass` export |
| `File too short to be a valid .spass export` | Truncated/incomplete download |
| `File not found` / `is a directory` | Check the path (quotes from drag-and-drop are handled) |

## 📝 Notes

- Card numbers map only when readable as digits; truly encrypted PANs are left empty rather than importing garbage.
- `*.spass` files are git-ignored — never commit real exports.
- Last browsed folder is remembered in `~/.spass-converter.json`.

## 🔧 Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
```

Test fixtures: `uv run python scripts/generate_test_spass.py` (needs `PYTHONPATH=.`)
creates a sample `test_export.spass` (`testpassword123`).

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
