<p align="center"><img src="https://raw.githubusercontent.com/talder/xyops-toolbox/refs/heads/main/logo.png" height="108" alt="Logo"/></p>
<h1 align="center">xyOps Toolbox</h1>

# xyOps Toolbox Plugin

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/talder/xyops-toolbox/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-14.0+-green.svg)](https://nodejs.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

A comprehensive xyOps Event Plugin containing 21 utility tools for data generation, validation, encoding, conversion, and syntax checking.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Tools Overview](#tools-overview)
- [Generator Tools](#generator-tools)
- [Encoding Tools](#encoding-tools)
- [Conversion Tools](#conversion-tools)
- [Text Tools](#text-tools)
- [Validation Tools](#validation-tools)
- [Syntax Tools](#syntax-tools)
- [Output Data Reference](#output-data-reference)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)
- [Version History](#version-history)

---

## Quick Start

1. Install the plugin in xyOps (copy to plugins directory or install from Marketplace)
2. Add the Toolbox event to any job
3. Select a tool from the dropdown menu
4. Configure parameters specific to the selected tool
5. Run the job

---

## Installation

### From xyOps Marketplace

1. Navigate to xyOps Marketplace
2. Search for "Toolbox"
3. Click Install

### Manual Installation

```bash
cd /opt/xyops/plugins
git clone https://github.com/talder/xyops-toolbox.git
```

### NPX (Direct Run)

```bash
npx -y github:talder/xyops-toolbox
```

---

## Tools Overview

| Category | Tool | Description |
|----------|------|-------------|
| **Generators** | Token Generator | Random tokens with customizable character sets |
| | UUID Generator | UUIDs v1, v4, v6, v7, nil, max |
| | Passphrase Generator | Secure memorable passphrases |
| | Lorem Ipsum Generator | Placeholder text in multiple formats |
| | QR Code Generator | QR codes with custom styling |
| | Barcode Generator | Code 128 and Code 39 barcodes |
| | Fake Data Generator | Realistic test data |
| **Encoding** | Base64 Encoder/Decoder | Base64 encoding and decoding |
| | URL Encoder/Decoder | URL-safe encoding and decoding |
| | Hash Text | 8 hash algorithms |
| **Conversion** | Timestamp Converter | Unix/ISO/human-readable timestamps |
| | Color Converter | HEX, RGB, HSL color formats |
| | String Case Converter | 9 case formats |
| | Image Converter | Format conversion and resizing |
| **Text** | JSON Formatter | Prettify, minify, validate JSON |
| | Slug Generator | URL-friendly slugs |
| | Text Statistics | Word count, reading time |
| **Validation** | IBAN Validator | 70+ country validation |
| | Email Validator | RFC 5322 validation |
| | Credit Card Validator | Luhn algorithm validation |
| **Syntax** | Syntax Validator | Validate and format 9 file formats |

---

## Generator Tools

### Token Generator

Generate cryptographically secure random tokens with customizable character sets.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Length | Number | 64 | Token length (1-1024 characters) |
| Include Uppercase | Checkbox | Yes | Include A-Z |
| Include Lowercase | Checkbox | Yes | Include a-z |
| Include Numbers | Checkbox | Yes | Include 0-9 |
| Include Symbols | Checkbox | No | Include special characters |
| Number of Tokens | Number | 1 | Tokens to generate (1-100) |

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

**Use Cases:**
- API key generation
- Session tokens
- Password reset tokens
- Random identifiers

---

### UUID Generator

Generate Universally Unique Identifiers in multiple versions and formats.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| UUID Version | Select | v4 | v1, v4, v6, v7, nil, or max |
| Format | Select | standard | Output format |
| Number of UUIDs | Number | 1 | UUIDs to generate (1-100) |

**UUID Versions:**

| Version | Description | Use Case |
|---------|-------------|----------|
| v1 | Time-based with MAC address | When ordering by time matters |
| v4 | Cryptographically random | General purpose (most common) |
| v6 | Reordered time-based | Database-friendly, sortable |
| v7 | Unix epoch time-based | Modern applications, sortable |
| nil | All zeros | Placeholder, null representation |
| max | All ones | Maximum value representation |

**Output Formats:**

| Format | Example |
|--------|--------|
| standard | `550e8400-e29b-41d4-a716-446655440000` |
| uppercase | `550E8400-E29B-41D4-A716-446655440000` |
| nodashes | `550e8400e29b41d4a716446655440000` |
| urn | `urn:uuid:550e8400-e29b-41d4-a716-446655440000` |

---

### Passphrase Generator

Generate secure, human-memorable passphrases using random word combinations.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Number of Words | Number | 4 | Words per passphrase (3-10) |
| Max Word Length | Number | 8 | Maximum characters per word (3-15) |
| Separator | Select | hyphen | hyphen, space, dot, underscore, none |
| Capitalize Words | Checkbox | Yes | Capitalize first letter |
| Include Number | Checkbox | Yes | Add random number (0-99) |
| Include Symbol | Checkbox | No | Add random symbol |
| Count | Number | 1 | Passphrases to generate (1-20) |

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

| Rating | Entropy | Recommendation |
|--------|---------|----------------|
| Weak | < 40 bits | Not recommended |
| Fair | 40-59 bits | Low-security applications |
| Strong | 60-79 bits | Most applications |
| Very Strong | 80-99 bits | High-security applications |
| Excellent | 100+ bits | Maximum security |

---

### Lorem Ipsum Generator

Generate placeholder text in multiple formats for design and development.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Output Type | Select | paragraphs | paragraphs, sentences, or words |
| Count | Number | 3 | Number of units to generate |
| Start with Lorem Ipsum | Checkbox | Yes | Begin with classic opening |

**Example Output:**

```json
{
  "tool": "Lorem Ipsum Generator",
  "type": "paragraphs",
  "count": 3,
  "text": "Lorem ipsum dolor sit amet...",
  "characterCount": 1247
}
```

**Output Files:**
- `lorem-ipsum.txt` - Plain text file
- `lorem-ipsum.md` - Markdown formatted file

---

### QR Code Generator

Generate QR codes for URLs, text, or data with customizable appearance.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Text / URL | Textarea | - | Content to encode |
| Input Data Path | Text | - | Dot-notation path for input data |
| Foreground Color | Color | #000000 | QR code color |
| Background Color | Color | #ffffff | Background color |
| Error Resistance | Select | M | L(7%), M(15%), Q(25%), H(30%) |
| Image Size | Number | 256 | PNG dimensions (64-1024 pixels) |
| Output Filename | Text | qrcode.png | Output file name |

**Error Correction Levels:**

| Level | Recovery Capacity | Use Case |
|-------|-------------------|----------|
| L | 7% | Clean environments |
| M | 15% | Standard use (recommended) |
| Q | 25% | Industrial environments |
| H | 30% | Damaged/dirty conditions |

---

### Barcode Generator

Generate industry-standard barcodes as SVG files.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Barcode Type | Select | code128 | Code 128 or Code 39 |
| Barcode Text | Text | - | Text to encode |

**Supported Formats:**

| Format | Character Set | Use Case |
|--------|---------------|----------|
| Code 128 | Full ASCII (0-127) | General purpose, compact |
| Code 39 | A-Z, 0-9, special chars | Industrial, automotive |

**Example Output:**

```json
{
  "tool": "Barcode Generator",
  "type": "code128",
  "text": "PRODUCT-12345",
  "file": "barcode-code128.svg"
}
```

---

### Fake Data Generator

Generate realistic fake data for testing and development purposes.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Type | Select | person | Type of data to generate |
| Count | Number | 1 | Records to generate (1-100) |

**Data Types:**

| Type | Fields Generated |
|------|------------------|
| Person | name, email, phone, address, date of birth |
| Contact | first name, last name, email, phone |
| Address | street, city, state, zip, country |
| Company | company name, contact, email, phone |
| Employee | name, email, job title, company, phone |

**Example Output (Person):**

```json
{
  "tool": "Fake Data Generator",
  "type": "person",
  "count": 1,
  "data": [
    {
      "name": "James Smith",
      "email": "james.smith@gmail.com",
      "phone": "+1 (555) 123-4567",
      "address": "1234 Main St, New York, NY 10001",
      "dob": "1985-03-15"
    }
  ]
}
```

---

## Encoding Tools

### Base64 Encoder/Decoder

Encode text to Base64 or decode Base64 to text.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | encode | encode or decode |
| Data Source | Select | field | Text field or job input data |
| Input Text | Textarea | - | Text to encode/decode |
| Input Data Path | Text | - | Dot-notation path for input data |

**Example - Encoding:**

Input: `Hello World`
Output: `SGVsbG8gV29ybGQ=`

**Example - Decoding:**

Input: `SGVsbG8gV29ybGQ=`
Output: `Hello World`

---

### URL Encoder/Decoder

Encode special characters for URLs or decode URL-encoded strings.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | encode | encode or decode |
| Data Source | Select | field | Text field or job input data |
| Input Text | Textarea | - | Text to encode/decode |
| Input Data Path | Text | - | Dot-notation path for input data |

**Example - Encoding:**

Input: `Hello World & Special=Characters`
Output: `Hello%20World%20%26%20Special%3DCharacters`

---

### Hash Text

Generate cryptographic hashes using multiple algorithms simultaneously.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Text to Hash | Textarea | - | Text to hash |
| Input Data Path | Text | - | Dot-notation path for input data |
| Digest Encoding | Select | hex | hex, base64, or binary |

**Supported Algorithms:**

| Algorithm | Output Length | Security Level |
|-----------|---------------|----------------|
| MD5 | 128-bit | Legacy only |
| SHA1 | 160-bit | Legacy only |
| SHA224 | 224-bit | Moderate |
| SHA256 | 256-bit | Recommended |
| SHA384 | 384-bit | High |
| SHA512 | 512-bit | High |
| SHA3-256 | 256-bit | Modern |
| RIPEMD160 | 160-bit | Blockchain |

**Example Output:**

```json
{
  "tool": "Hash Text",
  "input": "Hello World",
  "encoding": "hex",
  "hashes": {
    "MD5": "b10a8db164e0754105b7a99be72e3fe5",
    "SHA256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    "SHA512": "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27..."
  }
}
```

---

## Conversion Tools

### Timestamp Converter

Convert between Unix timestamps, ISO 8601, and human-readable date formats.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | toUnix | Conversion mode |
| Data Source | Select | field | Text field or job input data |
| Input Value | Text | - | Timestamp or date string |
| Input Data Path | Text | - | Dot-notation path for input data |

**Modes:**

| Mode | Input | Output |
|------|-------|--------|
| toUnix | Date string or ISO | Unix timestamp (seconds) |
| toUnixMs | Date string or ISO | Unix timestamp (milliseconds) |
| toISO | Unix timestamp | ISO 8601 format |
| toHuman | Unix timestamp | Human-readable format |
| now | (none) | Current time in all formats |

**Example Output (now mode):**

```json
{
  "tool": "Timestamp Converter",
  "mode": "now",
  "unix": 1739628000,
  "unixMs": 1739628000000,
  "iso": "2026-02-15T15:00:00.000Z",
  "human": "February 15, 2026 at 3:00:00 PM UTC"
}
```

---

### Color Converter

Convert colors between HEX, RGB, and HSL formats.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Input Format | Select | hex | HEX, RGB, or HSL |
| Data Source | Select | field | Text field or job input data |
| Color Value | Text | - | Color in specified format |
| Input Data Path | Text | - | Dot-notation path for input data |

**Input Format Examples:**

| Format | Example Inputs |
|--------|----------------|
| HEX | `#FF5733`, `FF5733`, `#F53` |
| RGB | `rgb(255, 87, 51)`, `255, 87, 51` |
| HSL | `hsl(11, 100%, 60%)`, `11, 100, 60` |

**Example Output:**

```json
{
  "tool": "Color Converter",
  "inputFormat": "hex",
  "input": "#FF5733",
  "hex": "#FF5733",
  "rgb": "rgb(255, 87, 51)",
  "hsl": "hsl(11, 100%, 60%)",
  "red": 255,
  "green": 87,
  "blue": 51
}
```

---

### String Case Converter

Convert text between 9 different case formats.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Target Case | Select | lower | Desired case format |
| Data Source | Select | field | Text field or job input data |
| Input Text | Textarea | - | Text to convert |
| Input Data Path | Text | - | Dot-notation path for input data |

**Supported Case Formats:**

| Format | Example Output |
|--------|----------------|
| lowercase | `hello world` |
| UPPERCASE | `HELLO WORLD` |
| Title Case | `Hello World` |
| Sentence case | `Hello world` |
| camelCase | `helloWorld` |
| PascalCase | `HelloWorld` |
| snake_case | `hello_world` |
| kebab-case | `hello-world` |
| CONSTANT_CASE | `HELLO_WORLD` |

---

### Image Converter

Convert images between formats and resize them.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Input File | Text | - | Path to input image |
| Output Format | Select | png | PNG, JPEG, BMP, GIF, TIFF |
| Resize Mode | Select | none | Resize method |
| Width / Percentage | Number | - | Target width or percentage |
| Height | Number | - | Target height (for some modes) |

**Resize Modes:**

| Mode | Description |
|------|-------------|
| No Resize | Convert format only |
| By Width | Resize to width, maintain aspect ratio |
| By Height | Resize to height, maintain aspect ratio |
| Exact Dimensions | Resize to exact width and height |
| By Percentage | Scale by percentage (e.g., 50 = 50%) |

**Example Output:**

```json
{
  "tool": "Image Converter",
  "inputFile": "photo.jpg",
  "outputFile": "photo-converted.png",
  "originalWidth": 1920,
  "originalHeight": 1080,
  "newWidth": 800,
  "newHeight": 450,
  "outputFormat": "png",
  "fileSize": 245678
}
```

---

## Text Tools

### JSON Formatter

Prettify, minify, or validate JSON data.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Mode | Select | prettify | prettify, minify, or validate |
| Data Source | Select | field | Text field or job input data |
| JSON Input | Textarea | - | JSON to process |
| Input Data Path | Text | - | Dot-notation path for input data |

**Modes:**

| Mode | Description |
|------|-------------|
| Prettify | Format with indentation for readability |
| Minify | Remove whitespace for compact output |
| Validate | Check validity without modifying |

**Example - Prettify:**

Input:
```json
{"name":"John","age":30,"city":"New York"}
```

Output:
```json
{
  "name": "John",
  "age": 30,
  "city": "New York"
}
```

---

### Slug Generator

Generate URL-friendly slugs from text.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Input Text | Text | - | Text to convert |
| Input Data Path | Text | - | Dot-notation path for input data |
| Separator | Select | hyphen | hyphen, underscore, or none |
| Lowercase | Checkbox | Yes | Convert to lowercase |
| Max Length | Number | 0 | Maximum length (0 = unlimited) |

**Example:**

Input: `Hello World! This is a Test.`
Output: `hello-world-this-is-a-test`

**Features:**
- Removes diacritics (accents)
- Replaces spaces and special characters
- Removes consecutive separators
- Trims separators from ends

---

### Text Statistics

Analyze text for various metrics including word count and reading time.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Input Text | Textarea | - | Text to analyze |
| Input Data Path | Text | - | Dot-notation path for input data |

**Metrics Calculated:**

| Metric | Description |
|--------|-------------|
| Characters | Total character count |
| Characters (no spaces) | Characters excluding whitespace |
| Words | Word count |
| Sentences | Sentence count |
| Paragraphs | Paragraph count |
| Lines | Line count |
| Average Word Length | Mean word length in characters |
| Reading Time | Estimated time at 200 WPM |
| Speaking Time | Estimated time at 150 WPM |

---

## Validation Tools

### IBAN Validator

Validate International Bank Account Numbers using MOD-97 checksum verification.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| IBAN | Text | - | IBAN to validate |
| Input Data Path | Text | - | Dot-notation path for input data |

**Validation Checks:**
- Format validation (2 letters + 2 digits + alphanumeric BBAN)
- Country code verification (70+ countries)
- Length validation per country specification
- MOD-97 checksum verification

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

**Supported Countries:**
Austria, Belgium, Bulgaria, Croatia, Cyprus, Czech Republic, Denmark, Estonia, Finland, France, Germany, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Luxembourg, Malta, Netherlands, Poland, Portugal, Romania, Slovakia, Slovenia, Spain, Sweden, United Kingdom, Switzerland, Norway, and 40+ additional countries.

---

### Email Validator

Validate email addresses according to RFC 5322 specifications.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Email Address | Text | - | Email to validate |
| Input Data Path | Text | - | Dot-notation path for input data |

**Validation Checks:**
- Presence of @ symbol
- Valid local part (before @)
- Valid domain (after @)
- TLD presence
- Length limits (local: 64, domain: 253 characters)
- No consecutive dots
- No leading/trailing dots in local part

**Example Output:**

```json
{
  "tool": "Email Validator",
  "email": "user@example.com",
  "valid": true,
  "localPart": "user",
  "domain": "example.com",
  "tld": "com",
  "issues": []
}
```

---

### Credit Card Validator

Validate credit card numbers using the Luhn algorithm and detect card type.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Data Source | Select | field | Text field or job input data |
| Card Number | Text | - | Card number to validate |
| Input Data Path | Text | - | Dot-notation path for input data |

**Detected Card Types:**

| Type | Prefix | Length |
|------|--------|--------|
| Visa | 4 | 13, 16, 19 |
| Mastercard | 51-55 | 16 |
| American Express | 34, 37 | 15 |
| Discover | 6011, 65 | 16 |
| Diners Club | 300-305, 36, 38 | 14, 16 |
| JCB | 3528-3589 | 16-19 |
| UnionPay | 62 | 16 |

**Example Output:**

```json
{
  "tool": "Credit Card Validator",
  "maskedNumber": "4111********1111",
  "cardType": "Visa",
  "valid": true,
  "length": 16
}
```

**Security Note:** Card numbers are masked in output. The tool only validates structure; it does not verify with payment processors.

---

## Syntax Tools

### Syntax Validator & Formatter

Validate structure and format files in 9 different formats with lint-style warnings and optional pretty-print output.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Format | Select | JSON | File format to validate |
| Data Source | Select | field | Text field, file, or job input |
| Content | Textarea | - | Content to validate |
| File Path | Text | - | Path to file (when source is 'file') |
| Input Data Path | Text | - | Dot-notation path for input data |
| Save Formatted File | Checkbox | No | Save pretty-printed output file |

**Supported Formats:**

| Format | Validation | Pretty-Print | Lint Checks |
|--------|------------|--------------|-------------|
| JSON | Parse errors | Yes | Depth, key count |
| XML | Parse errors | Yes | Declaration, namespace |
| YAML | Tabs, structure | Basic cleanup | Indentation, boolean values |
| Markdown | Code blocks | Passthrough | Heading hierarchy, links |
| CSV | Column consistency | Re-export | Quotes, delimiter detection |
| TOML | Syntax, types | Passthrough | Unquoted strings |
| HTML | Tag matching | Basic indent | DOCTYPE, alt, lang, charset |
| INI | Syntax | Passthrough | Section/key validation |
| Properties | Syntax | Passthrough | Special characters |

**Validation Details by Format:**

**JSON:**
- Parse validation using native parser
- Calculates nesting depth and property count
- Pretty-prints with indentation

**XML:**
- Full parse validation
- Element and attribute counting
- Warns if XML declaration is missing
- Warns about default namespace usage

**YAML:**
- Detects tabs (not allowed in YAML)
- Validates indentation consistency (recommends 2-space)
- Warns about unquoted boolean-like values (yes/no/on/off)
- Warns about multiple colons in unquoted values

**Markdown:**
- Detects unclosed code blocks
- Validates heading hierarchy (warns if levels skip)
- Checks for missing space after heading markers
- Validates links for proper format
- Warns about excessive trailing whitespace

**CSV:**
- Auto-detects delimiter (comma, semicolon, tab, pipe)
- Validates column count consistency across rows
- Detects unbalanced quotes

**HTML:**
- Validates tag matching (opening/closing)
- Handles self-closing tags correctly
- Warns about missing DOCTYPE
- Warns about missing lang attribute on html tag
- Warns about images without alt attributes
- Warns about missing charset meta tag

**Example Output:**

```json
{
  "tool": "Syntax Validator",
  "format": "json",
  "valid": true,
  "errors": [],
  "warnings": [],
  "errorCount": 0,
  "warningCount": 0,
  "stats": {
    "type": "Object",
    "depth": 2,
    "keys": 5
  },
  "inputSize": 156,
  "outputFiles": []
}
```

**Example with Errors (CSV):**

```json
{
  "tool": "Syntax Validator",
  "format": "csv",
  "valid": false,
  "errors": ["Row 3: Column count mismatch (expected 4, got 3)"],
  "warnings": ["Row 5: Unbalanced quotes"],
  "stats": {
    "rows": 10,
    "columns": 4,
    "delimiter": "Comma"
  }
}
```

**Output Files (when Save Formatted File is enabled):**
- `formatted.json`, `formatted.xml`, etc.
- Uses original filename if input was from file (e.g., `config.formatted.json`)

---

## Output Data Reference

All tools output structured data accessible to downstream workflow events via `data.*` paths.

| Tool | Key Output Fields |
|------|-------------------|
| Token Generator | `data.tokens`, `data.count`, `data.length` |
| UUID Generator | `data.uuids`, `data.count`, `data.version` |
| Passphrase Generator | `data.passphrases`, `data.entropy`, `data.strength` |
| Lorem Ipsum Generator | `data.text`, `data.type`, `data.count` |
| QR Code Generator | `data.filename`, `data.size`, `data.content` |
| Barcode Generator | `data.file`, `data.type`, `data.text` |
| Fake Data Generator | `data.data`, `data.type`, `data.count` |
| Base64 Encoder/Decoder | `data.output`, `data.mode` |
| URL Encoder/Decoder | `data.output`, `data.mode` |
| Hash Text | `data.hashes`, `data.input`, `data.encoding` |
| Timestamp Converter | `data.unix`, `data.iso`, `data.human` |
| Color Converter | `data.hex`, `data.rgb`, `data.hsl` |
| String Case Converter | `data.output`, `data.targetCase` |
| Image Converter | `data.outputFile`, `data.newWidth`, `data.newHeight` |
| JSON Formatter | `data.output`, `data.valid`, `data.mode` |
| Slug Generator | `data.slug`, `data.length` |
| Text Statistics | `data.words`, `data.characters`, `data.readingMinutes` |
| IBAN Validator | `data.valid`, `data.iban`, `data.countryName` |
| Email Validator | `data.valid`, `data.email`, `data.domain` |
|| Credit Card Validator | `data.valid`, `data.cardType`, `data.maskedNumber` |
|| Syntax Validator | `data.valid`, `data.errors`, `data.warnings`, `data.stats` |

All tools include `data.tool` containing the tool name.

---

## Dependencies

| Package | Version | Purpose | Runtime |
|---------|---------|---------|--------|
| `qrcode` | ^1.5.3 | QR code generation | Node.js only |

The PowerShell implementation has no external dependencies and uses only .NET Framework classes.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on both Node.js and PowerShell runtimes
5. Submit a pull request

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author

**Tim Alderweireldt**
- Plugin: xyOps Toolbox
- Year: 2026

---

## Version History

### v2.1.0 (2026-02-15)
- Split network and healthcare tools into separate plugins:
  - Network tools moved to **xyOps-network** plugin
  - Healthcare tools (HL7) moved to **xyOps-healthcare** plugin
- Reduced to 21 utility tools for focused functionality

### v2.0.0 (2026-02-15)
- Added 15 new tools (PowerShell implementation)
- Syntax Validator & Formatter (JSON, XML, YAML, Markdown, CSV, TOML, HTML, INI, Properties)
- Base64 Encoder/Decoder
- URL Encoder/Decoder
- Timestamp Converter
- JSON Formatter
- String Case Converter (9 formats)
- Color Converter (HEX/RGB/HSL)
- Image Converter with resizing
- Slug Generator
- Text Statistics
- Credit Card Validator with card type detection
- Email Validator (RFC 5322)
- Barcode Generator (Code 128, Code 39)
- Fake Data Generator (5 data types)
- Lorem Ipsum file export

### v1.0.0 (2026-02-09)
- Initial release
- Token Generator
- UUID Generator (v1, v4, v6, v7, nil, max)
- Hash Text (8 algorithms)
- QR Code Generator
- IBAN Validator (70+ countries)
- Passphrase Generator

---

**Need help?** Open an issue on GitHub or contact the author.
