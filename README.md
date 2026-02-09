<p align="center"><img src="https://raw.githubusercontent.com/talder/xyops-toolbox/refs/heads/main/logo.png" height="108" alt="Logo"/></p>
<h1 align="center">xyOps Toolbox</h1>

# xyOps Toolbox Plugin

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/talder/xyops-toolbox/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-14.0+-green.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

A versatile xyOps Event Plugin containing a collection of utility tools for generating tokens, UUIDs, hashes, QR codes, ASCII art, validating IBANs, and generating secure passphrases.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first. By using this plugin, you acknowledge that you have read, understood, and accepted this disclaimer.

## Quick Start

1. **Install the plugin** in xyOps (copy to plugins directory or install from Marketplace)
2. **Add the Toolbox event** to any job
3. **Select a tool** from the toolset dropdown
4. **Configure parameters** specific to the selected tool
5. **Run the job** - your data is generated!

## Features

### Available Tools

| Tool | Description | Output |
|------|-------------|--------|
| **Token Generator** | Generate random tokens/strings with customizable character sets | Tokens, table |
| **UUID Generator** | Generate UUIDs in various versions (v1, v4, v6, v7, nil, max) | UUIDs, table |
| **Hash Text** | Hash text using 8 algorithms (MD5, SHA1, SHA256, SHA512, etc.) | Hash table |
| **QR Code Generator** | Generate QR codes with custom colors and error correction | PNG file, preview |
| **ASCII Art Generator** | Convert text to ASCII art with 40+ fonts | TXT file, preview |
| **IBAN Validator** | Validate international bank account numbers (70+ countries) | Validation table |
| **Passphrase Generator** | Generate secure, memorable passphrases | Passphrases, table |

### Core Features

- **Cross-Platform** - Works on Linux, Windows, and macOS
- **Cryptographically Secure** - Uses Node.js crypto module for random generation
- **Input Data Support** - Most tools can accept data from previous workflow steps
- **Visual Output** - Results displayed in xyOps UI tables
- **File Output** - QR codes and ASCII art saved as files

## Installation

### From xyOps Marketplace

1. Navigate to xyOps Marketplace
2. Search for "Toolbox"
3. Click Install

### Manual Installation

1. Clone or download this repository
2. Copy the plugin folder to your xyOps plugins directory
3. Restart xyOps or refresh the plugins list

```bash
cd /opt/xyops/plugins
git clone https://github.com/talder/xyops-toolbox.git
```

### NPX (Direct Run)

```bash
npx -y github:talder/xyops-toolbox
```

---

## Tools Reference

### 🔑 Token Generator

Generate random tokens/strings with customizable character sets. Perfect for API keys, secrets, and random identifiers.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Length | Number | 64 | Token length (1-1024) |
| Include Uppercase | Checkbox | ✓ | Include A-Z |
| Include Lowercase | Checkbox | ✓ | Include a-z |
| Include Numbers | Checkbox | ✓ | Include 0-9 |
| Include Symbols | Checkbox | ✗ | Include !()_+-=[]{}\|;:,.? |
| Number of Tokens | Number | 1 | How many tokens to generate (1-100) |

**Example Output:**

```json
{
  "tool": "Token Generator",
  "tokens": ["bx2uab1GYc1P6zfpLHyqaSrKDxXxJxfa9i8xKOS5MudGPWSoRybTKPJeDQWV6Do8"],
  "count": 1,
  "length": 64,
  "characterSets": ["uppercase", "lowercase", "numbers"]
}
```

---

### 🆔 UUID Generator

Generate Universally Unique Identifiers in various versions.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| UUID Version | Select | v4 | v1, v4, v6, v7, nil, or max |
| Format | Select | standard | Output format |
| Number of UUIDs | Number | 1 | How many UUIDs to generate (1-100) |

**UUID Versions:**

- **v1** - Time-based: Uses current timestamp and node identifier
- **v4** - Random: Cryptographically random (most common)
- **v6** - Reordered Time-based: Like v1 but sortable (draft RFC)
- **v7** - Unix Epoch Time-based: Uses Unix timestamp (draft RFC)
- **nil** - All zeros: `00000000-0000-0000-0000-000000000000`
- **max** - All ones: `ffffffff-ffff-ffff-ffff-ffffffffffff`

**Output Formats:**

- **standard** - Lowercase with dashes: `550e8400-e29b-41d4-a716-446655440000`
- **uppercase** - Uppercase with dashes: `550E8400-E29B-41D4-A716-446655440000`
- **nodashes** - No dashes: `550e8400e29b41d4a716446655440000`
- **urn** - URN format: `urn:uuid:550e8400-e29b-41d4-a716-446655440000`

---

### #️⃣ Hash Text

Hash a text string using multiple algorithms simultaneously.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Use text field or job input data |
| Text to Hash | Textarea | - | The text to hash |
| Input Data Path | Text | - | Dot-notation path for input data (e.g. `user.password`) |
| Digest Encoding | Select | hex | Output encoding: hex, base64, or binary |

**Supported Algorithms:**

- MD5 (128-bit)
- SHA1 (160-bit)
- SHA224 (224-bit)
- SHA256 (256-bit)
- SHA384 (384-bit)
- SHA512 (512-bit)
- SHA3-256 (256-bit)
- RIPEMD160 (160-bit)

**Example Output:**

```json
{
  "tool": "Hash Text",
  "input": "Hello World",
  "encoding": "hex",
  "hashes": {
    "MD5": "b10a8db164e0754105b7a99be72e3fe5",
    "SHA1": "0a4d55a8d778e5022fab701977c5d840bbc486d0",
    "SHA256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
  }
}
```

---

### 📱 QR Code Generator

Generate QR codes for URLs or text with customizable appearance.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Use text field or job input data |
| Text / URL | Textarea | - | Content to encode |
| Input Data Path | Text | - | Dot-notation path for input data |
| Foreground Color | Color | #000000 | QR code module color |
| Background Color | Color | #ffffff | Background color |
| Error Resistance | Select | M | L(7%), M(15%), Q(25%), H(30%) recovery |
| Image Size | Number | 256 | PNG dimensions in pixels (64-1024) |
| Output Filename | Text | qrcode.png | Name of the output file |

**Output:** PNG image file attached to the job.

---

### 🎨 ASCII Art Generator

Convert text to ASCII art using the FIGlet library.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Use text field or job input data |
| Text | Textarea | - | Text to convert |
| Input Data Path | Text | - | Dot-notation path for input data |
| Font | Select | Standard | FIGlet font (40+ options) |
| Horizontal Layout | Select | default | fitted, full, or default |
| Vertical Layout | Select | default | fitted, full, or default |
| Max Width | Number | 80 | Maximum character width (40-200) |

**Available Fonts (selection):**
Standard, Banner, Big, Block, Bubble, Digital, Doom, Epic, Graffiti, Isometric, Larry 3D, Letters, Ogre, Slant, Small, Speed, Star Wars, Stop, and many more.

**Output:** TXT file attached to the job with ASCII art preview.

---

### 🏦 IBAN Validator

Validate International Bank Account Numbers using MOD-97 checksum.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Use text field or job input data |
| IBAN | Text | - | The IBAN to validate |
| Input Data Path | Text | - | Dot-notation path for input data |

**Validates:**
- Basic format (2 letters + 2 digits + alphanumeric BBAN)
- Country code (70+ countries supported)
- Length per country specifications
- MOD-97 checksum verification

**Supported Countries (selection):**
Austria, Belgium, Bulgaria, Croatia, Cyprus, Czech Republic, Denmark, Estonia, Finland, France, Germany, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Luxembourg, Malta, Netherlands, Poland, Portugal, Romania, Slovakia, Slovenia, Spain, Sweden, United Kingdom, and 40+ more.

**Example Output:**

```json
{
  "tool": "IBAN Validator",
  "valid": true,
  "iban": "DE89370400440532013000",
  "formatted": "DE89 3704 0044 0532 0130 00",
  "countryCode": "DE",
  "countryName": "Germany",
  "checkDigits": "89",
  "bban": "370400440532013000"
}
```

---

### 🔐 Passphrase Generator

Generate secure, memorable passphrases using random word combinations.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Number of Words | Number | 4 | Words in passphrase (3-10) |
| Max Word Length | Number | 8 | Maximum characters per word (3-15) |
| Separator | Select | hyphen | hyphen, space, dot, underscore, none |
| Capitalize Words | Checkbox | ✓ | Capitalize first letter of each word |
| Include Number | Checkbox | ✓ | Add a random number (0-99) |
| Include Symbol | Checkbox | ✗ | Add a random symbol (!@#$%^&*) |
| Count | Number | 1 | How many passphrases to generate (1-20) |

**Features:**
- **2000+ word dictionary** - EFF-inspired English wordlist
- **Entropy calculation** - Shows estimated bits of entropy
- **Strength indicator** - Weak/Fair/Strong/Very Strong/Excellent
- **Configurable word length** - Filter words by maximum length

**Example Output:**

```json
{
  "tool": "Passphrase Generator",
  "passphrases": ["Correct-Horse-Battery-42-Staple"],
  "count": 1,
  "wordCount": 4,
  "entropy": 62,
  "strength": "Strong"
}
```

**Strength Ratings:**
- ⚠️ **Weak** - < 40 bits entropy
- 🔶 **Fair** - 40-59 bits entropy
- 🔷 **Strong** - 60-79 bits entropy
- ✅ **Very Strong** - 80-99 bits entropy
- 🛡️ **Excellent** - 100+ bits entropy

---

## Output Data

The plugin outputs structured data that can be used by downstream events in a workflow:

| Tool | Output Fields |
|------|---------------|
| Token Generator | `data.tokens`, `data.count`, `data.length` |
| UUID Generator | `data.uuids`, `data.count`, `data.version` |
| Hash Text | `data.hashes`, `data.input`, `data.encoding` |
| QR Code | `data.filename`, `data.size`, `data.content` |
| ASCII Art | `data.filename`, `data.font`, `data.asciiArt` |
| IBAN Validator | `data.valid`, `data.iban`, `data.countryName` |
| Passphrase | `data.passphrases`, `data.entropy`, `data.strength` |

All tools output `data.tool` containing the tool name used.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|----------|
| `qrcode` | ^1.5.3 | QR code generation |
| `figlet` | ^1.7.0 | ASCII art generation |

Dependencies are bundled and automatically installed when running via NPX.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Ideas for New Tools

- Base64 Encoder/Decoder
- URL Encoder/Decoder
- JSON Formatter/Validator
- Regex Tester
- Lorem Ipsum Generator
- Color Converter (HEX/RGB/HSL)
- Timestamp Converter

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Tim Alderweireldt**
- Plugin: xyOps Toolbox
- Year: 2026

---

## Version History

### v1.0.0 (2026-02-09)
- Initial release
- Token Generator - random string generation
- UUID Generator - v1, v4, v6, v7, nil, max
- Hash Text - 8 hash algorithms
- QR Code Generator - PNG with custom colors
- ASCII Art Generator - 40+ FIGlet fonts
- IBAN Validator - 70+ countries, MOD-97 checksum
- Passphrase Generator - 2000+ word dictionary with entropy calculation

---

**Need help?** Open an issue on GitHub or contact the author.

**Found this useful?** Star the repository and share with your team!
