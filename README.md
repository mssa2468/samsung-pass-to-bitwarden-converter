# Samsung Pass to Bitwarden Converter

Samsung Pass to Bitwarden Converter is a Python utility designed to decrypt Samsung Pass exports (.spass files) and convert them into a Bitwarden-compatible JSON format. This tool handles various types of data stored in Samsung Pass, including login credentials, secure notes, payment cards, and addresses, transforming them into corresponding Bitwarden item types.

Key features of the converter include:

1. Decryption of Samsung Pass encrypted data using AES-CBC encryption
2. Parsing of multiple data tables from the decrypted content
3. Conversion of Samsung Pass data structures to Bitwarden-compatible formats
4. Support for different item types: logins, secure notes, payment cards, and identities
5. Error handling for common issues during decryption and parsing

The script utilizes several Python libraries, including `cryptography` for decryption, `pandas` for data manipulation, and built-in modules for file handling and user input. It provides a command-line interface for users to input the .spass file path and the export password, making it accessible for users with basic command-line knowledge.

The converter is structured with a main `BitwardenConverter` class that encapsulates the core functionality, including methods for decryption, table parsing, and Bitwarden item creation. This design allows for easy maintenance and potential future enhancements.

Overall, this tool serves as a bridge for users transitioning from Samsung Pass to Bitwarden, simplifying the process of migrating their sensitive data between password management systems.
.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone this repository or download the script file.

2. Install the required Python packages:

```bash
pip install cryptography pandas
```

## Exporting Samsung Pass Data

To export your Samsung Pass data:

1. Open the Samsung Pass app on your device.
2. Go to Settings > Export data.
3. Choose the data you want to export (passwords, cards, addresses, notes).
4. Set a password for the export file (you'll need this later).
5. Save the .spass file to your device.
6. Transfer the .spass file to the computer where you'll run the script.

## Usage

1. Place the .spass file in the same directory as the script or note its full path.

2. Run the script:

```bash
python samsung_pass_to_bitwarden.py
```

3. When prompted, enter the path to your .spass file and the password you set during export.

4. The script will generate a `bitwarden_export.json` file in the same directory.

## Features

- Decrypts Samsung Pass encrypted data using AES-CBC encryption.
- Handles various data types: login credentials, secure notes, payment cards, and addresses.
- Converts Samsung Pass data format to Bitwarden-compatible JSON structure.
- Provides error handling for common issues during decryption and parsing.

## Common Issues and Solutions

### FileNotFoundError

If you encounter:
```
FileNotFoundError: [Errno 2] No such file or directory: 'path/to/file.spass'
```
**Solution**: Ensure the .spass file path is correct and the file exists in the specified location.

### Decryption Error

If you see:
```
Error decrypting file: Padding is incorrect.
```
**Solution**: This usually occurs when the provided password is incorrect. Double-check your password and try again.

### Not Enough Tables Found

If you get:
```
Error: Not enough tables found in the decrypted data.
```
**Solution**: This error suggests that the .spass file might be corrupted or in an unexpected format. Try re-exporting your data from Samsung Pass.

### UnicodeDecodeError

If you encounter:
```
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte
```
**Solution**: This error might occur if the decrypted data contains non-UTF-8 characters. The script uses error handling to ignore such characters, but if the issue persists, you may need to modify the `safe_decode` function to handle specific encodings.

## Contributing

Contributions to improve the script or add new features are welcome. Please feel free to submit pull requests or open issues for any bugs or enhancements.

## License

This project is open-source and available under the MIT License.

## Disclaimer

This tool is not officially associated with Samsung or Bitwarden. Use it at your own risk and always ensure you have backups of your data before performing any conversions.
