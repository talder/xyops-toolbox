# xkOps Toolbox

A xyOps Event Plugin containing utility tools for generating tokens, UUIDs, and more.

## Installation

Import the plugin into xyOps using the `xyops.json` manifest, or run directly:

```bash
npx -y github:talder/xkops-toolbox
```

## Tools

### Token Generator

Generate random tokens/strings with customizable character sets.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Length | Number | 64 | Token length (1-1024) |
| Include Uppercase | Checkbox | ✓ | Include A-Z |
| Include Lowercase | Checkbox | ✓ | Include a-z |
| Include Numbers | Checkbox | ✓ | Include 0-9 |
| Include Symbols | Checkbox | ✗ | Include !@#$%^&*()_+-=[]{}|;:,.<>? |
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

### UUID Generator

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

**Example Output:**

```json
{
  "tool": "UUID Generator",
  "uuids": ["550e8400-e29b-41d4-a716-446655440000"],
  "count": 1,
  "version": "v4",
  "versionName": "v4 (Random)",
  "format": "standard",
  "formatName": "Standard (lowercase)"
}
```

## Output

The plugin outputs data that can be used by downstream events in a workflow:

- `data.tokens` - Array of generated tokens (Token Generator)
- `data.uuids` - Array of generated UUIDs (UUID Generator)
- `data.tool` - Name of the tool that was used
- `data.count` - Number of items generated

A visual table is also displayed in the xyOps UI showing the generated values.

## License

MIT License - (c) 2026 Tim Alderweireldt
