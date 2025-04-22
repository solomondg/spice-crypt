# SpiceCrypt

A specialized Python library for working with LTSpice encrypted models.

## Installation

```bash
pip install spice-crypt
```

Or install from source:

```bash
git clone https://github.com/bayou-bits/spice-crypt.git
cd spice-crypt
pip install -e .
```

## Requirements

- Python 3.6 or higher
- NumPy 1.20.0 or higher

## Command Line Usage

SpiceCrypt provides a command-line interface for decrypting LTSpice encrypted files:

### Decrypting an LTSpice Encrypted File

```bash
# Automatically detect LTSpice format and decrypt
spice-decrypt path/to/encrypted_file.CIR

# Decrypt with verbose output
spice-decrypt --verbose path/to/encrypted_file.CIR

# Specify an output file
spice-decrypt -o output.cir path/to/encrypted_file.CIR

# Force overwrite if output file exists
spice-decrypt -f -o output.cir path/to/encrypted_file.CIR

# If no output file is specified, results are printed to stdout
spice-decrypt path/to/encrypted_file.CIR
```

### Working with Raw Hex Data

```bash
# Process as raw hex data (not LTSpice format)
spice-decrypt --raw path/to/hex_file.txt
```

### File Format

SpiceCrypt supports standard LTSpice encrypted files which have this structure:

```
* LTspice Encrypted File
* 
* This encrypted file has been supplied by a 3rd
* party vendor that does not wish to publicize
* the technology used to implement this library.
* 
* Begin:
  A7 CD 92 6F EA 22 42 3D 95 5E D2 59 B6 03 E5 31
  67 06 C2 AF 8A BB 32 98 00 15 89 AF C1 15 0C D9
  ...additional hex data...
* End 1032371916 1759126504
```

## License

This source code is proprietary and confidential. It is provided under the terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC and the recipient. Any unauthorized use, copying, modification, or distribution is strictly prohibited.

Contact joe.sylve@gmail.com for licensing information.