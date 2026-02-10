#requires -Version 7.0
<#!
xyOps Toolbox Event Plugin (PowerShell 7)
A collection of utility tools for xyOps including:
- Token Generator
- UUID Generator (v1, v4, v6, v7, nil, max)
- Hash Text (MD5, SHA1, SHA256, SHA384, SHA512; others best-effort)
- QR Code Generator (requires QRCoder.dll next to this script)
- Passphrase Generator (uses wordlist.txt if present, otherwise a small fallback list)
- IBAN Validator
- Lorem Ipsum Generator
- ASCII Art (simple boxed text fallback)

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\toolbox.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description)
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function ConvertTo-HexString {
  param([byte[]]$Bytes)
  ($Bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-RandomBytes {
  param([int]$Length)
  $data = New-Object byte[] ($Length)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($data)
  return $data
}

function Get-NestedValue {
  param($Object, [string]$Path)
  if (-not $Path -or ($Path.Trim() -eq '')) { return $Object }
  $cur = $Object
  foreach ($part in $Path.Split('.')) {
    if ($null -eq $cur) { return $null }
    if ($cur -is [System.Collections.IDictionary]) {
      if (-not $cur.Contains($part)) { return $null }
      $cur = $cur[$part]
    }
    else {
      $cur = $cur.PSObject.Properties[$part].Value
    }
  }
  return $cur
}

# Safe parameter getter - returns default if property doesn't exist
function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

# ------------------------- Token Generator -------------------------
function Invoke-TokenGenerator {
  param($Params)
  Write-XYProgress 0.1 'Validating parameters...'

  $length = [Math]::Min(1024, [Math]::Max(1, [int](Get-Param $Params 'tokenLength' 64)))
  $count  = [Math]::Min(100,  [Math]::Max(1, [int](Get-Param $Params 'tokenCount' 1)))

  $includeUpper = if ($Params.PSObject.Properties.Name -contains 'includeUppercase') { [bool]$Params.includeUppercase } else { $true }
  $includeLower = if ($Params.PSObject.Properties.Name -contains 'includeLowercase') { [bool]$Params.includeLowercase } else { $true }
  $includeNum   = if ($Params.PSObject.Properties.Name -contains 'includeNumbers')   { [bool]$Params.includeNumbers   } else { $true }
  $includeSym   = if ($Params.PSObject.Properties.Name -contains 'includeSymbols')   { [bool]$Params.includeSymbols   } else { $false }

  $chars = ''
  if ($includeUpper) { $chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }
  if ($includeLower) { $chars += 'abcdefghijklmnopqrstuvwxyz' }
  if ($includeNum)   { $chars += '0123456789' }
  if ($includeSym)   { $chars += '!@#$%^&*()_+-=[]{}|;:,.<>?' }
  if ($chars.Length -eq 0) { throw 'At least one character set must be selected' }

  Write-XYProgress 0.3 "Generating $count token(s)..."
  $tokens = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $count; $i++) {
    $bytes = Get-RandomBytes -Length $length
    $sb = New-Object System.Text.StringBuilder ($length)
    for ($j = 0; $j -lt $length; $j++) {
      [void]$sb.Append($chars[ $bytes[$j] % $chars.Length ])
    }
    $tokens.Add($sb.ToString())
    if ($count -gt 1) { Write-XYProgress (0.3 + (0.6 * ($i + 1) / $count)) "Generated $($i+1) of $count tokens..." }
  }

  Write-XYProgress 0.95 'Finalizing...'
  $charSets = @()
  if ($includeUpper) { $charSets += 'uppercase' }
  if ($includeLower) { $charSets += 'lowercase' }
  if ($includeNum)   { $charSets += 'numbers' }
  if ($includeSym)   { $charSets += 'symbols' }

  # table for UI
  Write-XY @{ table = @{ title='Generated Tokens'; header=@('#','Token'); rows = @($tokens | ForEach-Object -Begin { $n=0 } -Process { $n++; @($n, $_) }); caption = "Generated $count token(s) with length $length using: $([string]::Join(', ', $charSets))" } }

  [pscustomobject]@{ tool = 'Token Generator'; tokens = $tokens; count = $count; length = $length; characterSets = $charSets }
}

# ------------------------- UUID Generators -------------------------
function Format-UUIDComponents {
  param([uint32]$timeLow, [uint16]$timeMid, [uint16]$timeHiAndVersion, [uint16]$clockSeq, [byte[]]$node)
  $hex = {
    param($n, $len)
    ("{0:X$len}" -f $n).ToLower()
  }
  $nodeHex = ConvertTo-HexString -Bytes $node
  return & $hex $timeLow 8 + '-' + (& $hex $timeMid 4) + '-' + (& $hex $timeHiAndVersion 4) + '-' + (& $hex $clockSeq 4) + '-' + $nodeHex
}

function ConvertTo-BigInteger { param([object]$n) return [System.Numerics.BigInteger]::Parse($n.ToString()) }
function Get-PowerOfTwo { param([int]$bits) return [System.Numerics.BigInteger]::Pow([System.Numerics.BigInteger]::Parse('2'), $bits) }

function New-UUIDv1 {
  $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $greg  = ConvertTo-BigInteger 122192928000000000
  $ts    = (ConvertTo-BigInteger $nowMs) * (ConvertTo-BigInteger 10000) + $greg  # 100-ns since 1582

  $mod32 = Get-PowerOfTwo 32
  $mod16 = Get-PowerOfTwo 16

  $timeLow = [uint32]([System.Numerics.BigInteger]::Remainder($ts, $mod32))
  $ts2 = [System.Numerics.BigInteger]::Divide($ts, $mod32)
  $timeMid = [uint16]([System.Numerics.BigInteger]::Remainder($ts2, $mod16))
  $ts3 = [System.Numerics.BigInteger]::Divide($ts2, $mod16)
  $timeHiAndVersion = [uint16]([System.Numerics.BigInteger]::Remainder($ts3, (Get-PowerOfTwo 12)))
  $timeHiAndVersion = ($timeHiAndVersion -band 0x0fff) -bor 0x1000

  $clockSeq = ([int]([BitConverter]::ToUInt16((Get-RandomBytes 2),0)) -band 0x3fff) -bor 0x8000
  $node = Get-RandomBytes 6
  $node[0] = $node[0] -bor 0x01  # set multicast bit

  return Format-UUIDComponents $timeLow $timeMid $timeHiAndVersion $clockSeq $node
}

function New-UUIDv4 {
  $bytes = Get-RandomBytes 16
  $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x40  # version 4
  $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80  # RFC 4122 variant
  $hex = ConvertTo-HexString $bytes
  return ($hex.Substring(0,8) + '-' + $hex.Substring(8,4) + '-' + $hex.Substring(12,4) + '-' + $hex.Substring(16,4) + '-' + $hex.Substring(20))
}

function New-UUIDv6 {
  $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $greg  = ConvertTo-BigInteger 122192928000000000
  $ts    = (ConvertTo-BigInteger $nowMs) * (ConvertTo-BigInteger 10000) + $greg

  $shr28 = [System.Numerics.BigInteger]::Divide($ts, (Get-PowerOfTwo 28))
  $timeHigh = [uint32]([System.Numerics.BigInteger]::Remainder($shr28, (Get-PowerOfTwo 32)))
  $shr12 = [System.Numerics.BigInteger]::Divide($ts, (Get-PowerOfTwo 12))
  $timeMid = [uint16]([System.Numerics.BigInteger]::Remainder($shr12, (Get-PowerOfTwo 16)))
  $timeLowAndVersion = [uint16]([System.Numerics.BigInteger]::Remainder($ts, (Get-PowerOfTwo 12)))
  $timeLowAndVersion = ($timeLowAndVersion -band 0x0fff) -bor 0x6000

  $clockSeq = ([int]([BitConverter]::ToUInt16((Get-RandomBytes 2),0)) -band 0x3fff) -bor 0x8000
  $node = Get-RandomBytes 6; $node[0] = $node[0] -bor 0x01

  return Format-UUIDComponents $timeHigh $timeMid $timeLowAndVersion $clockSeq $node
}

function New-UUIDv7 {
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $bytes = New-Object byte[] 16
  # first 6 bytes: big-endian ms timestamp
  $bytes[0] = [byte] (($now -shr 40) -band 0xFF)
  $bytes[1] = [byte] (($now -shr 32) -band 0xFF)
  $bytes[2] = [byte] (($now -shr 24) -band 0xFF)
  $bytes[3] = [byte] (($now -shr 16) -band 0xFF)
  $bytes[4] = [byte] (($now -shr 8)  -band 0xFF)
  $bytes[5] = [byte] ($now -band 0xFF)
  # fill remaining with random
  (Get-RandomBytes 10).CopyTo($bytes, 6)
  # set version/variant
  $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x70
  $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80
  $hex = ConvertTo-HexString $bytes
  return ($hex.Substring(0,8) + '-' + $hex.Substring(8,4) + '-' + $hex.Substring(12,4) + '-' + $hex.Substring(16,4) + '-' + $hex.Substring(20))
}

function Format-UUID {
  param([string]$uuid, [string]$format)
  switch ($format) {
    'uppercase' { return $uuid.ToUpperInvariant() }
    'nodashes'  { return $uuid.Replace('-', '') }
    'urn'       { return "urn:uuid:$uuid" }
    default     { return $uuid.ToLowerInvariant() }
  }
}

function Invoke-UUIDGenerator {
  param($Params)
  Write-XYProgress 0.1 'Validating parameters...'
  $version = (Get-Param $Params 'uuidVersion' 'v4').ToString()
  $format  = (Get-Param $Params 'uuidFormat' 'standard').ToString()
  $count   = [Math]::Min(100, [Math]::Max(1, [int](Get-Param $Params 'uuidCount' 1)))

  $map = @{ v1 = 'New-UUIDv1'; v4 = 'New-UUIDv4'; v6 = 'New-UUIDv6'; v7 = 'New-UUIDv7'; nil = 'nil'; max = 'max' }
  if (-not $map.ContainsKey($version)) { throw "Unknown UUID version: $version" }

  Write-XYProgress 0.3 "Generating $count UUID(s) ($version)..."
  $uuids = New-Object System.Collections.Generic.List[string]
  for ($i=0; $i -lt $count; $i++) {
    switch ($version) {
      'nil' { $u = '00000000-0000-0000-0000-000000000000' }
      'max' { $u = 'ffffffff-ffff-ffff-ffff-ffffffffffff' }
      default { $u = & (Get-Command $map[$version] -CommandType Function) }
    }
    $uuids.Add((Format-UUID $u $format))
    if ($count -gt 1) { Write-XYProgress (0.3 + (0.6 * ($i + 1) / $count)) "Generated $($i+1) of $count UUIDs..." }
  }

  Write-XYProgress 0.95 'Finalizing...'
  $versionNames = @{ v1='v1 (Time-based)'; v4='v4 (Random)'; v6='v6 (Reordered Time-based)'; v7='v7 (Unix Epoch Time-based)'; nil='Nil (All zeros)'; max='Max (All ones)' }
  $formatNames  = @{ standard='Standard (lowercase)'; uppercase='Uppercase'; nodashes='No dashes'; urn='URN format' }

  Write-XY @{ table = @{ title='Generated UUIDs'; header=@('#','UUID'); rows = @($uuids | ForEach-Object -Begin { $n=0 } -Process { $n++; @($n, $_) }); caption = "Generated $count $($versionNames[$version]) UUID(s) in $($formatNames[$format]) format" } }

  [pscustomobject]@{ tool='UUID Generator'; uuids=$uuids; count=$count; version=$version; versionName=$versionNames[$version]; format=$format; formatName=$formatNames[$format] }
}

# ------------------------- Hash Text -------------------------
function Get-HashBytes {
  param([string]$Text, [string]$Algorithm)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  switch ($Algorithm) {
    'md5'     { $algo = [System.Security.Cryptography.MD5]::Create() }
    'sha1'    { $algo = [System.Security.Cryptography.SHA1]::Create() }
    'sha256'  { $algo = [System.Security.Cryptography.SHA256]::Create() }
    'sha384'  { $algo = [System.Security.Cryptography.SHA384]::Create() }
    'sha512'  { $algo = [System.Security.Cryptography.SHA512]::Create() }
    'ripemd160' { try { $algo = [System.Security.Cryptography.RIPEMD160]::Create() } catch { $algo = $null } }
    'sha224'  { $algo = $null } # Not available in .NET without external libs
    'sha3'    { $algo = $null } # Not available in .NET without external libs
    default   { $algo = $null }
  }
  if ($null -eq $algo) { return $null }
  try { return $algo.ComputeHash($bytes) } finally { $algo.Dispose() }
}

function ConvertTo-EncodedString {
  param([byte[]]$Bytes, [string]$Encoding)
  switch ($Encoding) {
    'hex'    { return ConvertTo-HexString $Bytes }
    'base64' { return [Convert]::ToBase64String($Bytes) }
    'binary' { return [System.Text.Encoding]::ASCII.GetString($Bytes) }
    default  { return ConvertTo-HexString $Bytes }
  }
}

$HASH_ALGOS = @(
  @{ id='md5'; name='MD5' },
  @{ id='sha1'; name='SHA1' },
  @{ id='sha256'; name='SHA256' },
  @{ id='sha224'; name='SHA224' },
  @{ id='sha512'; name='SHA512' },
  @{ id='sha384'; name='SHA384' },
  @{ id='sha3'; name='SHA3-256' },
  @{ id='ripemd160'; name='RIPEMD160' }
)

function Invoke-HashText {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source   = Get-Param $Params 'hashSource' 'field'
  $encoding = Get-Param $Params 'hashEncoding' 'hex'
  $text = ''

  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $dataPath = Get-Param $Params 'hashDataPath' ''
    $val = Get-NestedValue $inputData $dataPath
    if ($null -eq $val) { throw "Data path '$dataPath' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  }
  else { $text = Get-Param $Params 'hashInput' '' }

  Write-XYProgress 0.2 'Computing hashes...'
  $hashes = @{}
  $rows = @()
  for ($i=0; $i -lt $HASH_ALGOS.Count; $i++) {
    $algo = $HASH_ALGOS[$i]
    $bytes = Get-HashBytes -Text $text -Algorithm $algo.id
    if ($null -eq $bytes) { $digest = "[Not supported]" }
    else { $digest = ConvertTo-EncodedString -Bytes $bytes -Encoding $encoding }
    $hashes[$algo.id] = $digest
    $rows += ,@($algo.name, $digest)
    Write-XYProgress (0.2 + (0.7 * ($i+1) / $HASH_ALGOS.Count)) "Computed $($algo.name)..."
  }

  Write-XYProgress 0.95 'Finalizing...'
  $encodingNames = @{ hex='Hexadecimal (base 16)'; base64='Base64'; binary='Binary (raw)' }
  Write-XY @{ table = @{ title='Hash Results'; header=@('Algorithm','Hash'); rows=$rows; caption="Hashed $($text.Length) character(s) using $($encodingNames[$encoding]) encoding" } }

  [pscustomobject]@{ tool='Hash Text'; inputLength=$text.Length; encoding=$encoding; encodingName=$encodingNames[$encoding]; hashes = $hashes }
}

# ------------------------- QR Code Generator (Pure PowerShell) -------------------------
# Complete QR Code implementation with Reed-Solomon ECC - supports byte mode, version 1-4
# No external dependencies required

# Galois Field GF(2^8) operations for Reed-Solomon
$script:GF_EXP = New-Object int[] 512
$script:GF_LOG = New-Object int[] 256
$script:GF_INIT = $false

function Initialize-GaloisField {
  if ($script:GF_INIT) { return }
  [int]$x = 1
  for ([int]$i = 0; $i -lt 255; $i++) {
    $script:GF_EXP[$i] = $x
    $script:GF_LOG[$x] = $i
    $x = $x -shl 1
    if ($x -band 0x100) { $x = $x -bxor 0x11D }
  }
  for ([int]$i = 255; $i -lt 512; $i++) {
    [int]$idx = $i - 255
    $script:GF_EXP[$i] = $script:GF_EXP[$idx]
  }
  $script:GF_INIT = $true
}

function Get-GFMultiply([int]$a, [int]$b) {
  if ($a -eq 0 -or $b -eq 0) { return 0 }
  return $script:GF_EXP[$script:GF_LOG[$a] + $script:GF_LOG[$b]]
}

function Get-RSGenerator([int]$nsym) {
  Initialize-GaloisField
  # Generator polynomial g(x) = (x + α^0)(x + α^1)...(x + α^(nsym-1))
  # Stored with coefficients from highest to lowest degree
  [int[]]$g = New-Object int[] ($nsym + 1)
  $g[0] = 1
  for ([int]$i = 0; $i -lt $nsym; $i++) {
    # Multiply by (x + α^i)
    for ([int]$j = $i + 1; $j -gt 0; $j--) {
      [int]$jm1 = $j - 1
      if ($g[$jm1] -ne 0) {
        $g[$j] = $g[$j] -bxor (Get-GFMultiply $g[$jm1] $script:GF_EXP[$i])
      }
    }
  }
  return $g
}

function Get-RSEncode([int[]]$data, [int]$nsym) {
  Initialize-GaloisField
  [int[]]$gen = Get-RSGenerator $nsym
  [int[]]$feedback = New-Object int[] $nsym
  
  for ([int]$i = 0; $i -lt $data.Length; $i++) {
    [int]$coef = $data[$i] -bxor $feedback[0]
    # Shift feedback register
    for ([int]$j = 0; $j -lt ($nsym - 1); $j++) {
      [int]$jp1 = $j + 1
      $feedback[$j] = $feedback[$jp1]
    }
    $feedback[$nsym - 1] = 0
    # Add generator polynomial contribution
    if ($coef -ne 0) {
      for ([int]$j = 0; $j -lt $nsym; $j++) {
        [int]$gidx = $j + 1
        $feedback[$j] = $feedback[$j] -bxor (Get-GFMultiply $coef $gen[$gidx])
      }
    }
  }
  return $feedback
}

# QR Code parameters for all ECC levels (L, M, Q, H)
# ECC codewords per version and level
$script:QR_ECCBYTES = @{
  1 = @{ L=7;  M=10; Q=13; H=17 }
  2 = @{ L=10; M=16; Q=22; H=28 }
  3 = @{ L=15; M=26; Q=36; H=44 }
  4 = @{ L=20; M=18; Q=26; H=16 }
}
# Data codewords capacity per version and level
$script:QR_DATACAP = @{
  1 = @{ L=19; M=16; Q=13; H=9  }
  2 = @{ L=34; M=28; Q=22; H=16 }
  3 = @{ L=55; M=44; Q=34; H=26 }
  4 = @{ L=80; M=64; Q=48; H=36 }
}
# Max text bytes in byte mode (data capacity - 2 bytes overhead for mode+length)
$script:QR_TEXTCAP = @{
  1 = @{ L=17; M=14; Q=11; H=7  }
  2 = @{ L=32; M=26; Q=20; H=14 }
  3 = @{ L=53; M=42; Q=32; H=24 }
  4 = @{ L=78; M=62; Q=46; H=34 }
}

# Format info strings for each ECC level and mask (pre-computed with BCH and XOR mask)
$script:QR_FORMAT_INFO = @{
  L = @('111011111000100','111001011110011','111110110101010','111100010011101','110011000101111','110001100011000','110110001000001','110100101110110')
  M = @('101010000010010','101000100100101','101111001111100','101101101001011','100010111111001','100000011001110','100111110010111','100101010100000')
  Q = @('011010101011111','011000001101000','011111100110001','011101000000110','010010010110100','010000110000011','010111011011010','010101111101101')
  H = @('001011010001001','001001110111110','001110011100111','001100111010000','000011101100010','000001001010101','000110100001100','000100000111011')
}

function Get-QRVersion([int]$Length, [string]$ECC = 'M') {
  foreach ($v in 1..4) {
    if ($Length -le $script:QR_TEXTCAP[$v][$ECC]) { return $v }
  }
  throw "Text too long for QR code with ECC $ECC (max $($script:QR_TEXTCAP[4][$ECC]) bytes)"
}

function ConvertTo-QRDataBytes([string]$Text, [int]$Version, [string]$ECC = 'M') {
  [byte[]]$textBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  [int]$dataCap = $script:QR_DATACAP[$Version][$ECC]
  [int]$textLen = $textBytes.Length
  
  # Build bit stream
  $bits = New-Object System.Collections.Generic.List[int]
  
  # Mode indicator: 0100 (byte mode)
  $bits.Add(0); $bits.Add(1); $bits.Add(0); $bits.Add(0)
  
  # Character count (8 bits for versions 1-9)
  for ([int]$i = 7; $i -ge 0; $i--) { $bits.Add(($textLen -shr $i) -band 1) }
  
  # Data bytes (8 bits each)
  for ([int]$i = 0; $i -lt $textLen; $i++) {
    [int]$b = $textBytes[$i]
    for ([int]$j = 7; $j -ge 0; $j--) { $bits.Add(($b -shr $j) -band 1) }
  }
  
  # Terminator (up to 4 zeros)
  [int]$totalDataBits = $dataCap * 8
  [int]$termLen = [Math]::Min(4, $totalDataBits - $bits.Count)
  for ([int]$i = 0; $i -lt $termLen; $i++) { $bits.Add(0) }
  
  # Pad to byte boundary
  while (($bits.Count % 8) -ne 0) { $bits.Add(0) }
  
  # Convert bits to bytes
  $result = New-Object System.Collections.Generic.List[int]
  for ([int]$i = 0; $i -lt $bits.Count; $i += 8) {
    [int]$b = 0
    for ([int]$j = 0; $j -lt 8; $j++) { $b = ($b -shl 1) -bor $bits[$i + $j] }
    $result.Add($b)
  }
  
  # Pad bytes (alternating 236, 17)
  [int]$padIdx = 0
  while ($result.Count -lt $dataCap) {
    $result.Add($(if (($padIdx % 2) -eq 0) { 236 } else { 17 }))
    $padIdx++
  }
  
  return $result.ToArray()
}

function New-QRMatrix([int]$Version) {
  [int]$size = 17 + $Version * 4
  $matrix = New-Object 'int[,]' $size, $size
  $fixed = New-Object 'bool[,]' $size, $size
  for ($i = 0; $i -lt $size; $i++) { for ($j = 0; $j -lt $size; $j++) { $matrix[$i,$j] = 0 } }
  return @{ m = $matrix; f = $fixed; size = $size }
}

function Set-QRModule($M, [int]$r, [int]$c, [int]$val, [bool]$fix = $true) {
  [int]$sz = $M.size
  if ($r -ge 0 -and $r -lt $sz -and $c -ge 0 -and $c -lt $sz) {
    $M.m[$r,$c] = $val
    $M.f[$r,$c] = $fix
  }
}

function Set-QRFinderPattern($M, [int]$row, [int]$col) {
  for ($r = -1; $r -le 7; $r++) {
    for ($c = -1; $c -le 7; $c++) {
      $inOuter = ($r -eq 0 -or $r -eq 6 -or $c -eq 0 -or $c -eq 6)
      $inInner = ($r -ge 2 -and $r -le 4 -and $c -ge 2 -and $c -le 4)
      $val = if ($r -eq -1 -or $r -eq 7 -or $c -eq -1 -or $c -eq 7) { 0 } elseif ($inOuter -or $inInner) { 1 } else { 0 }
      Set-QRModule $M ($row + $r) ($col + $c) $val
    }
  }
}

function Set-QRTimingPatterns($M) {
  [int]$sz = $M.size
  for ($i = 8; $i -lt ($sz - 8); $i++) {
    $val = if ($i % 2 -eq 0) { 1 } else { 0 }
    Set-QRModule $M 6 $i $val
    Set-QRModule $M $i 6 $val
  }
}

# Alignment pattern positions for versions 2-4
$script:QR_ALIGN_POS = @{
  2 = @(6, 18)
  3 = @(6, 22)
  4 = @(6, 26)
}

function Set-QRAlignmentPattern($M, [int]$row, [int]$col) {
  # 5x5 pattern with center at (row, col)
  for ([int]$r = -2; $r -le 2; $r++) {
    for ([int]$c = -2; $c -le 2; $c++) {
      [int]$val = if ([Math]::Abs($r) -eq 2 -or [Math]::Abs($c) -eq 2 -or ($r -eq 0 -and $c -eq 0)) { 1 } else { 0 }
      Set-QRModule $M ($row + $r) ($col + $c) $val
    }
  }
}

function Set-QRAlignmentPatterns($M, [int]$Version) {
  if ($Version -lt 2) { return }
  $positions = $script:QR_ALIGN_POS[$Version]
  if (-not $positions) { return }
  
  # For versions 2-6, there's only one alignment pattern (not overlapping with finders)
  # It's at the intersection of the last two positions, but not where finders are
  foreach ($row in $positions) {
    foreach ($col in $positions) {
      # Skip if this would overlap with a finder pattern (top-left, top-right, bottom-left)
      [int]$sz = $M.size
      $skipTopLeft = ($row -lt 9 -and $col -lt 9)
      $skipTopRight = ($row -lt 9 -and $col -gt ($sz - 9))
      $skipBottomLeft = ($row -gt ($sz - 9) -and $col -lt 9)
      if (-not ($skipTopLeft -or $skipTopRight -or $skipBottomLeft)) {
        Set-QRAlignmentPattern $M $row $col
      }
    }
  }
}

function Set-QRFormatInfo($M, [int]$mask, [string]$ECC = 'M') {
  [int]$sz = $M.size
  # Get format info for this ECC level and mask
  $fmtStr = $script:QR_FORMAT_INFO[$ECC][$mask]
  [int[]]$bits = @()
  for ([int]$i = 0; $i -lt 15; $i++) { $bits += [int]($fmtStr[$i].ToString()) }
  
  # Format info locations around top-left finder (bits 0-14)
  # Horizontal strip at row 8: columns 0,1,2,3,4,5, (skip 6), 7,8
  Set-QRModule $M 8 0 $bits[0]
  Set-QRModule $M 8 1 $bits[1]
  Set-QRModule $M 8 2 $bits[2]
  Set-QRModule $M 8 3 $bits[3]
  Set-QRModule $M 8 4 $bits[4]
  Set-QRModule $M 8 5 $bits[5]
  Set-QRModule $M 8 7 $bits[6]
  Set-QRModule $M 8 8 $bits[7]
  
  # Vertical strip at col 8: rows 0,1,2,3,4,5, (skip 6), 7,8
  Set-QRModule $M 0 8 $bits[14]
  Set-QRModule $M 1 8 $bits[13]
  Set-QRModule $M 2 8 $bits[12]
  Set-QRModule $M 3 8 $bits[11]
  Set-QRModule $M 4 8 $bits[10]
  Set-QRModule $M 5 8 $bits[9]
  Set-QRModule $M 7 8 $bits[8]
  
  # Second copy - horizontal at row 8, right side
  [int]$rightStart = $sz - 8
  Set-QRModule $M 8 ($rightStart + 0) $bits[7]
  Set-QRModule $M 8 ($rightStart + 1) $bits[8]
  Set-QRModule $M 8 ($rightStart + 2) $bits[9]
  Set-QRModule $M 8 ($rightStart + 3) $bits[10]
  Set-QRModule $M 8 ($rightStart + 4) $bits[11]
  Set-QRModule $M 8 ($rightStart + 5) $bits[12]
  Set-QRModule $M 8 ($rightStart + 6) $bits[13]
  Set-QRModule $M 8 ($rightStart + 7) $bits[14]
  
  # Second copy - vertical at col 8, bottom
  [int]$bottomStart = $sz - 7
  Set-QRModule $M ($bottomStart + 0) 8 $bits[6]
  Set-QRModule $M ($bottomStart + 1) 8 $bits[5]
  Set-QRModule $M ($bottomStart + 2) 8 $bits[4]
  Set-QRModule $M ($bottomStart + 3) 8 $bits[3]
  Set-QRModule $M ($bottomStart + 4) 8 $bits[2]
  Set-QRModule $M ($bottomStart + 5) 8 $bits[1]
  Set-QRModule $M ($bottomStart + 6) 8 $bits[0]
  
  # Dark module is always at (4*version + 9, 8) = (size-8, 8) and always dark
  Set-QRModule $M ($sz - 8) 8 1
}

function Write-QRData($M, [int[]]$data, [int]$mask) {
  [int]$size = $M.size
  [int]$bitIdx = 0
  [int]$totalBits = $data.Count * 8
  [bool]$upward = $true
  
  for ([int]$col = $size - 1; $col -ge 1; $col -= 2) {
    if ($col -eq 6) { $col = 5 }
    $rowRange = if ($upward) { ($size - 1)..0 } else { 0..($size - 1) }
    foreach ($row in $rowRange) {
      for ([int]$c = 0; $c -lt 2; $c++) {
        [int]$cc = $col - $c
        if (-not $M.f[$row, $cc]) {
          [int]$bit = 0
          if ($bitIdx -lt $totalBits) {
            [int]$byteIdx = [Math]::Floor($bitIdx / 8)
            [int]$bitPos = 7 - ($bitIdx % 8)
            $bit = ($data[$byteIdx] -shr $bitPos) -band 1
          }
          # Apply mask
          [bool]$masked = switch ($mask) {
            0 { (($row + $cc) % 2) -eq 0 }
            1 { ($row % 2) -eq 0 }
            2 { ($cc % 3) -eq 0 }
            3 { (($row + $cc) % 3) -eq 0 }
            4 { (([Math]::Floor($row / 2) + [Math]::Floor($cc / 3)) % 2) -eq 0 }
            5 { ((($row * $cc) % 2) + (($row * $cc) % 3)) -eq 0 }
            6 { (((($row * $cc) % 2) + (($row * $cc) % 3)) % 2) -eq 0 }
            7 { (((($row + $cc) % 2) + (($row * $cc) % 3)) % 2) -eq 0 }
          }
          if ($masked) { $bit = 1 - $bit }
          $M.m[$row, $cc] = $bit
          $bitIdx++
        }
      }
    }
    $upward = -not $upward
  }
}

function Get-QRPenalty($M) {
  [int]$penalty = 0
  [int]$size = $M.size
  # Rule 1: consecutive modules in row/column
  for ([int]$i = 0; $i -lt $size; $i++) {
    [int]$rowCount = 1; [int]$colCount = 1
    for ([int]$j = 1; $j -lt $size; $j++) {
      [int]$jm1 = $j - 1
      if ($M.m[$i,$j] -eq $M.m[$i,$jm1]) { $rowCount++ } else { if ($rowCount -ge 5) { $penalty += $rowCount - 2 }; $rowCount = 1 }
      if ($M.m[$j,$i] -eq $M.m[$jm1,$i]) { $colCount++ } else { if ($colCount -ge 5) { $penalty += $colCount - 2 }; $colCount = 1 }
    }
    if ($rowCount -ge 5) { $penalty += $rowCount - 2 }
    if ($colCount -ge 5) { $penalty += $colCount - 2 }
  }
  # Rule 4: proportion of dark modules
  [int]$dark = 0
  for ([int]$i = 0; $i -lt $size; $i++) { for ([int]$j = 0; $j -lt $size; $j++) { if ($M.m[$i,$j] -eq 1) { $dark++ } } }
  [int]$percent = [Math]::Floor(($dark * 100) / ($size * $size))
  $penalty += [Math]::Abs($percent - 50) * 2
  return $penalty
}

function New-QRCode([string]$Text, [string]$ECC = 'M') {
  [int]$version = Get-QRVersion $Text.Length $ECC
  [int[]]$dataBytes = ConvertTo-QRDataBytes $Text $version $ECC
  [int]$eccCount = $script:QR_ECCBYTES[$version][$ECC]
  [int[]]$eccBytes = Get-RSEncode $dataBytes $eccCount
  # Combine data and ECC bytes
  [int[]]$allBytes = New-Object int[] ($dataBytes.Length + $eccBytes.Length)
  for ([int]$i = 0; $i -lt $dataBytes.Length; $i++) { $allBytes[$i] = $dataBytes[$i] }
  for ([int]$i = 0; $i -lt $eccBytes.Length; $i++) { $allBytes[$dataBytes.Length + $i] = $eccBytes[$i] }
  
  # Try all masks and pick best
  [int]$bestMask = 0
  [int]$bestPenalty = [int]::MaxValue
  $bestMatrix = $null
  
  for ([int]$mask = 0; $mask -lt 8; $mask++) {
    $M = New-QRMatrix $version
    [int]$sz = $M.size
    Set-QRFinderPattern $M 0 0
    Set-QRFinderPattern $M 0 ($sz - 7)
    Set-QRFinderPattern $M ($sz - 7) 0
    Set-QRTimingPatterns $M
    Set-QRAlignmentPatterns $M $version
    Set-QRFormatInfo $M $mask $ECC
    Write-QRData $M $allBytes $mask
    $penalty = Get-QRPenalty $M
    if ($penalty -lt $bestPenalty) {
      $bestPenalty = $penalty
      $bestMask = $mask
      $bestMatrix = $M
    }
  }
  return $bestMatrix
}

# CRC32 lookup table (initialized once at script load)
$Global:PNG_CRC32_TABLE = $null

function Get-PngCrc32 {
  param([byte[]]$Data)
  # Initialize CRC32 lookup table if needed
  if ($null -eq $Global:PNG_CRC32_TABLE) {
    $Global:PNG_CRC32_TABLE = New-Object long[] 256
    for ($n = 0; $n -lt 256; $n++) {
      [long]$c = $n
      for ($k = 0; $k -lt 8; $k++) {
        if (($c -band 1) -eq 1) { $c = 0xEDB88320L -bxor ($c -shr 1) }
        else { $c = $c -shr 1 }
      }
      $Global:PNG_CRC32_TABLE[$n] = $c
    }
  }
  [long]$crc = 0xFFFFFFFFL
  foreach ($b in $Data) {
    $idx = [int](($crc -bxor $b) -band 0xFF)
    $crc = $Global:PNG_CRC32_TABLE[$idx] -bxor ($crc -shr 8)
  }
  return [long](($crc -bxor 0xFFFFFFFFL) -band 0xFFFFFFFFL)
}

function ConvertTo-HexColor([string]$hex) {
  # Parse #RRGGBB or RRGGBB to RGB bytes
  $hex = $hex.TrimStart('#')
  if ($hex.Length -eq 6) {
    [byte]$r = [Convert]::ToByte($hex.Substring(0,2), 16)
    [byte]$g = [Convert]::ToByte($hex.Substring(2,2), 16)
    [byte]$b = [Convert]::ToByte($hex.Substring(4,2), 16)
    return @($r, $g, $b)
  }
  return @([byte]0, [byte]0, [byte]0)
}

function ConvertTo-PngBytes {
  param($M, [int]$Scale, [string]$Foreground = '#000000', [string]$Background = '#ffffff')
  [int]$qrSize = $M.size
  [int]$margin = 4
  [int]$imgSize = ($qrSize + $margin * 2) * $Scale
  
  # Parse colors
  $fgColor = ConvertTo-HexColor $Foreground
  $bgColor = ConvertTo-HexColor $Background
  
  $png = New-Object System.Collections.Generic.List[byte]
  
  # PNG Signature
  @(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) | ForEach-Object { $png.Add([byte]$_) }
  
  # Helper to write chunk
  $writeChunk = {
    param([string]$Type, [byte[]]$Data)
    $len = if ($Data) { $Data.Length } else { 0 }
    $png.Add([byte](($len -shr 24) -band 0xFF))
    $png.Add([byte](($len -shr 16) -band 0xFF))
    $png.Add([byte](($len -shr 8) -band 0xFF))
    $png.Add([byte]($len -band 0xFF))
    $typeBytes = [System.Text.Encoding]::ASCII.GetBytes($Type)
    $typeBytes | ForEach-Object { $png.Add($_) }
    if ($Data -and $Data.Length -gt 0) { $Data | ForEach-Object { $png.Add($_) } }
    $crcData = New-Object System.Collections.Generic.List[byte]
    $typeBytes | ForEach-Object { $crcData.Add($_) }
    if ($Data) { $Data | ForEach-Object { $crcData.Add($_) } }
    $crc = Get-PngCrc32 -Data $crcData.ToArray()
    $png.Add([byte](($crc -shr 24) -band 0xFF))
    $png.Add([byte](($crc -shr 16) -band 0xFF))
    $png.Add([byte](($crc -shr 8) -band 0xFF))
    $png.Add([byte]($crc -band 0xFF))
  }
  
  # IHDR chunk - 8-bit RGB
  $ihdr = New-Object System.Collections.Generic.List[byte]
  $ihdr.Add([byte](($imgSize -shr 24) -band 0xFF))
  $ihdr.Add([byte](($imgSize -shr 16) -band 0xFF))
  $ihdr.Add([byte](($imgSize -shr 8) -band 0xFF))
  $ihdr.Add([byte]($imgSize -band 0xFF))
  $ihdr.Add([byte](($imgSize -shr 24) -band 0xFF))
  $ihdr.Add([byte](($imgSize -shr 16) -band 0xFF))
  $ihdr.Add([byte](($imgSize -shr 8) -band 0xFF))
  $ihdr.Add([byte]($imgSize -band 0xFF))
  $ihdr.Add([byte]8)   # Bit depth: 8
  $ihdr.Add([byte]2)   # Color type: 2 = RGB
  $ihdr.Add([byte]0)   # Compression
  $ihdr.Add([byte]0)   # Filter
  $ihdr.Add([byte]0)   # Interlace
  & $writeChunk 'IHDR' $ihdr.ToArray()
  
  # Build raw image data (RGB)
  $rawData = New-Object System.Collections.Generic.List[byte]
  for ([int]$y = 0; $y -lt $imgSize; $y++) {
    $rawData.Add([byte]0)  # Filter type: None
    for ([int]$x = 0; $x -lt $imgSize; $x++) {
      [int]$qx = [Math]::Floor($x / $Scale) - $margin
      [int]$qy = [Math]::Floor($y / $Scale) - $margin
      $color = $bgColor  # Background by default (margin)
      if ($qx -ge 0 -and $qx -lt $qrSize -and $qy -ge 0 -and $qy -lt $qrSize) {
        $color = if ($M.m[$qy, $qx] -eq 1) { $fgColor } else { $bgColor }
      }
      $rawData.Add($color[0])  # R
      $rawData.Add($color[1])  # G
      $rawData.Add($color[2])  # B
    }
  }
  
  # Compress with DeflateStream
  $ms = New-Object System.IO.MemoryStream
  $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionLevel]::Optimal)
  $ds.Write($rawData.ToArray(), 0, $rawData.Count)
  $ds.Close()
  $compressed = $ms.ToArray()
  $ms.Close()
  
  # IDAT chunk (zlib wrapper)
  $idat = New-Object System.Collections.Generic.List[byte]
  $idat.Add([byte]0x78); $idat.Add([byte]0x9C)
  $compressed | ForEach-Object { $idat.Add($_) }
  # Adler32 checksum
  [long]$a = 1; [long]$b = 0
  $rawBytes = $rawData.ToArray()
  for ($i = 0; $i -lt $rawBytes.Length; $i++) {
    $a = ($a + [long]$rawBytes[$i]) % 65521
    $b = ($b + $a) % 65521
  }
  [long]$adler = ($b -shl 16) -bor $a
  $idat.Add([byte](($adler -shr 24) -band 0xFF))
  $idat.Add([byte](($adler -shr 16) -band 0xFF))
  $idat.Add([byte](($adler -shr 8) -band 0xFF))
  $idat.Add([byte]($adler -band 0xFF))
  & $writeChunk 'IDAT' $idat.ToArray()
  
  # IEND chunk
  & $writeChunk 'IEND' $null
  
  return $png.ToArray()
}

function Invoke-QRCode {
  param($Params, $JobInput, [string]$Cwd)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.qrSource ?? 'field')
  $text = ''
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $dataPath = ($Params.qrDataPath ?? '')
    $val = Get-NestedValue $inputData $dataPath
    if ($null -eq $val) { throw "Data path '$dataPath' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.qrText ?? '') }
  if (-not $text) { throw 'No text or URL provided for QR code' }

  $size = [Math]::Min(1024, [Math]::Max(64, [int]($Params.qrSize ?? 256)))
  $filename = ($Params.qrFilename ?? 'qrcode.png')
  if (-not $filename.EndsWith('.png')) { $filename = [System.IO.Path]::ChangeExtension($filename, '.png') }
  $filePath = Join-Path $Cwd $filename
  
  # Get colors (default black on white)
  $foreground = ($Params.qrForeground ?? '#000000')
  $background = ($Params.qrBackground ?? '#ffffff')
  
  # Get error correction level (L, M, Q, H)
  $errorLevel = ($Params.qrErrorLevel ?? 'M').ToUpper()
  if ($errorLevel -notin @('L','M','Q','H')) { $errorLevel = 'M' }
  $errorNames = @{ L='Low (~7%)'; M='Medium (~15%)'; Q='Quartile (~25%)'; H='High (~30%)' }

  Write-XYProgress 0.3 "Generating QR code with ECC level $errorLevel..."
  $M = New-QRCode $text $errorLevel
  [int]$qrSize = $M.size
  [int]$version = ($qrSize - 17) / 4

  Write-XYProgress 0.7 'Generating PNG image...'
  $scale = [Math]::Max(1, [int]($size / ($qrSize + 8)))
  $pngBytes = ConvertTo-PngBytes -M $M -Scale $scale -Foreground $foreground -Background $background
  [System.IO.File]::WriteAllBytes($filePath, $pngBytes)

  $fi = Get-Item -LiteralPath $filePath
  Write-XYProgress 0.95 'Finalizing...'

  $displayContent = if ($text.Length -gt 50) { $text.Substring(0,50) + '...' } else { $text }
  $actualSize = ($qrSize + 8) * $scale

  $result = [pscustomobject]@{ tool='QR Code Generator'; text=$text; textLength=$text.Length; filename=$filename; fileSize=$fi.Length; size=$actualSize; version=$version; errorLevel=$errorLevel; errorLevelName=$errorNames[$errorLevel]; foreground=$foreground; background=$background }

  Write-XY @{ files = @($filename) }
  Write-XY @{ table = @{ title='QR Code Generated'; header=@('Property','Value'); rows=@(@('Content', $displayContent), @('QR Version', "$version ($qrSize x $qrSize modules)"), @('Image Size',"${actualSize}x${actualSize} pixels"), @('Error Correction',$errorNames[$errorLevel]), @('Colors',"$foreground on $background"), @('File',$filename), @('File Size',"$($fi.Length) bytes")); caption = "QR code saved as $filename (pure PowerShell with Reed-Solomon ECC)" } }

  return $result
}

# ------------------------- Passphrase Generator -------------------------
$PP_SYMBOLS = '!@#$%^&*'

function Get-WordList {
  $path = Join-Path $PSScriptRoot 'wordlist.txt'
  if (Test-Path $path) { return Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } }
  # small fallback list (add your own wordlist.txt for more variety)
  return @('alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu','apple','banana','cherry','grape','lemon','mango','orange','peach','pear','plum','berry','cloud','river','mountain','forest','ocean','desert','valley','meadow','sun','moon','star','sky','storm','breeze','snow','rain','fog','stone','metal','silver','gold','copper','iron','steam','spark','flame','ember','shadow','light')
}

function New-Passphrase {
  param(
    [int]$WordCount,
    [int]$MaxWordLength,
    [ValidateSet('hyphen','space','dot','underscore','none')] [string]$Separator,
    [bool]$Capitalize,
    [bool]$IncludeNumber,
    [bool]$IncludeSymbol
  )
  $words = Get-WordList | Where-Object { $_.Length -ge 3 -and $_.Length -le $MaxWordLength }
  if ($words.Count -lt 100) { throw "Not enough words with max length $MaxWordLength. Provide a larger wordlist.txt or increase max length." }

  $sel = New-Object System.Collections.Generic.List[string]
  for ($i=0; $i -lt $WordCount; $i++) {
    $w = $words[ [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($words.Count) ]
    if ($Capitalize) { $w = $w.Substring(0,1).ToUpper() + $w.Substring(1) }
    $sel.Add($w)
  }

  $sepMap = @{ hyphen='-'; space=' '; dot='.'; underscore = '_'; none='' }
  $sep = $sepMap[$Separator]
  $pass = ($sel -join $sep)

  if ($IncludeNumber) {
    $num = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(100)
    $parts = if ($sep) { $pass.Split($sep) } else { [string[]]$sel }
    $pos = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($parts.Length + 1)
    $pass = ($parts[0..($pos-1)] + @($num.ToString()) + $parts[$pos..($parts.Length-1)]) -join $sep
  }
  if ($IncludeSymbol) {
    $sym = $PP_SYMBOLS[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($PP_SYMBOLS.Length)]
    $pos = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($pass.Length + 1)
    $pass = $pass.Insert($pos, [string]$sym)
  }
  return $pass
}

function Measure-Entropy {
  param([int]$WordCount,[int]$Pool,[bool]$IncludeNumber,[bool]$IncludeSymbol)
  $e = $WordCount * [Math]::Log($Pool, 2)
  if ($IncludeNumber) { $e += [Math]::Log(100,2) + [Math]::Log($WordCount + 1,2) }
  if ($IncludeSymbol) { $e += [Math]::Log($PP_SYMBOLS.Length,2) + [Math]::Log(50,2) }
  [Math]::Round($e)
}

function Get-StrengthRating {
  param([int]$Entropy)
  if ($Entropy -lt 40) { return @{ rating='Weak'; symbol='⚠️' } }
  if ($Entropy -lt 60) { return @{ rating='Fair'; symbol='🔶' } }
  if ($Entropy -lt 80) { return @{ rating='Strong'; symbol='🔷' } }
  if ($Entropy -lt 100){ return @{ rating='Very Strong'; symbol='✅' } }
  return @{ rating='Excellent'; symbol='🛡️' }
}

function Invoke-PassphraseGenerator {
  param($Params)
  Write-XYProgress 0.1 'Validating parameters...'
  $wordCount = [Math]::Min(10, [Math]::Max(3, [int]($Params.ppWordCount ?? 4)))
  $maxLen    = [Math]::Min(15, [Math]::Max(3, [int]($Params.ppMaxWordLength ?? 8)))
  $sep       = ($Params.ppSeparator ?? 'hyphen')
  $cap       = if ($Params.PSObject.Properties.Name -contains 'ppCapitalize')   { [bool]$Params.ppCapitalize }   else { $true }
  $incNum    = if ($Params.PSObject.Properties.Name -contains 'ppIncludeNumber'){ [bool]$Params.ppIncludeNumber } else { $true }
  $incSym    = if ($Params.PSObject.Properties.Name -contains 'ppIncludeSymbol'){ [bool]$Params.ppIncludeSymbol } else { $false }
  $count     = [Math]::Min(20, [Math]::Max(1, [int]($Params.ppCount ?? 1)))

  $pool = (Get-WordList | Where-Object { $_.Length -ge 3 -and $_.Length -le $maxLen }).Count
  if ($pool -lt 100) { throw "Not enough words with max length $maxLen. Provide wordlist.txt or increase max length." }

  Write-XYProgress 0.3 "Generating $count passphrase(s)..."
  $options = @{ WordCount=$wordCount; MaxWordLength=$maxLen; Separator=$sep; Capitalize=$cap; IncludeNumber=$incNum; IncludeSymbol=$incSym }
  $list = for ($i=0; $i -lt $count; $i++) {
    Write-XYProgress (0.3 + (0.6 * ($i+1) / $count)) "Generated $($i+1) of $count..."
    New-Passphrase @options
  }

  Write-XYProgress 0.95 'Finalizing...'
  $entropy = Measure-Entropy -WordCount $wordCount -Pool $pool -IncludeNumber:$incNum -IncludeSymbol:$incSym
  $strength = Get-StrengthRating $entropy

  $rows = @(); $i=0; foreach ($pp in $list) { $i++; $rows += ,@($i,$pp,$pp.Length) }
  Write-XY @{ table = @{ title='Generated Passphrases'; header=@('#','Passphrase','Length'); rows=$rows; caption = "${($strength.symbol)} ${($strength.rating)} | $wordCount words | ~${entropy} bits entropy | Word pool: $pool" } }

  [pscustomobject]@{ tool='Passphrase Generator'; passphrases=$list; count=$count; wordCount=$wordCount; maxWordLength=$maxLen; separator=$sep; capitalize=$cap; includeNumber=$incNum; includeSymbol=$incSym; wordPoolSize=$pool; entropy=$entropy; strength=$strength.rating }
}

# ------------------------- IBAN Validator -------------------------
$IBAN_LENGTHS = [ordered]@{
  AL=28; AD=24; AT=20; AZ=28; BH=22; BY=28; BE=16; BA=20; BR=29;
  BG=22; CR=22; HR=21; CY=28; CZ=24; DK=18; DO=28; TL=23; EE=20;
  EG=29; SV=28; FO=18; FI=18; FR=27; GE=22; DE=22; GI=23; GR=27;
  GL=18; GT=28; HU=28; IS=26; IQ=23; IE=22; IL=23; IT=27; JO=30;
  KZ=20; XK=20; KW=30; LV=21; LB=28; LY=25; LI=21; LT=20; LU=20;
  MK=19; MT=31; MR=27; MU=30; MC=27; MD=24; ME=22; NL=18; NO=15;
  PK=24; PS=29; PL=28; PT=25; QA=29; RO=24; LC=32; SM=27; ST=25;
  SA=24; RS=22; SC=31; SK=24; SI=19; ES=24; SD=18; SE=24; CH=21;
  TN=24; TR=26; UA=29; AE=23; GB=22; VA=22; VG=24
}
$COUNTRY_NAMES = @{ AL='Albania'; AD='Andorra'; AT='Austria'; AZ='Azerbaijan'; BH='Bahrain'; BY='Belarus'; BE='Belgium'; BA='Bosnia and Herzegovina'; BR='Brazil'; BG='Bulgaria'; CR='Costa Rica'; HR='Croatia'; CY='Cyprus'; CZ='Czech Republic'; DK='Denmark'; DO='Dominican Republic'; TL='East Timor'; EE='Estonia'; EG='Egypt'; SV='El Salvador'; FO='Faroe Islands'; FI='Finland'; FR='France'; GE='Georgia'; DE='Germany'; GI='Gibraltar'; GR='Greece'; GL='Greenland'; GT='Guatemala'; HU='Hungary'; IS='Iceland'; IQ='Iraq'; IE='Ireland'; IL='Israel'; IT='Italy'; JO='Jordan'; KZ='Kazakhstan'; XK='Kosovo'; KW='Kuwait'; LV='Latvia'; LB='Lebanon'; LY='Libya'; LI='Liechtenstein'; LT='Lithuania'; LU='Luxembourg'; MK='North Macedonia'; MT='Malta'; MR='Mauritania'; MU='Mauritius'; MC='Monaco'; MD='Moldova'; ME='Montenegro'; NL='Netherlands'; NO='Norway'; PK='Pakistan'; PS='Palestine'; PL='Poland'; PT='Portugal'; QA='Qatar'; RO='Romania'; LC='Saint Lucia'; SM='San Marino'; ST='Sao Tome and Principe'; SA='Saudi Arabia'; RS='Serbia'; SC='Seychelles'; SK='Slovakia'; SI='Slovenia'; ES='Spain'; SD='Sudan'; SE='Sweden'; CH='Switzerland'; TN='Tunisia'; TR='Turkey'; UA='Ukraine'; AE='United Arab Emirates'; GB='United Kingdom'; VA='Vatican City'; VG='British Virgin Islands' }

function Test-IBAN {
  param([string]$Iban)
  $clean = ($Iban -replace '\s','').ToUpperInvariant()
  if (-not ($clean -match '^[A-Z]{2}[0-9]{2}[A-Z0-9]+$')) { return @{ valid=$false; error='Invalid IBAN format. Must start with 2 letters, 2 digits, then alphanumeric characters.' } }
  $cc = $clean.Substring(0,2); $check = $clean.Substring(2,2); $bban = $clean.Substring(4)
  if (-not $IBAN_LENGTHS.Contains($cc)) { return @{ valid=$false; error="Unknown country code: $cc" } }
  $expected = $IBAN_LENGTHS[$cc]
  if ($clean.Length -ne $expected) { return @{ valid=$false; error="Invalid length for $cc. Expected $expected characters, got $($clean.Length)." } }
  $rearr = $clean.Substring(4) + $clean.Substring(0,4)
  $num = ($rearr.ToCharArray() | ForEach-Object { if ($_ -match '[0-9]') { [string]$_ } else { ([int][byte][char]$_ - 55).ToString() } }) -join ''
  # MOD-97 with big integer division
  $remainder = 0
  foreach ($d in $num.ToCharArray()) { $remainder = (($remainder * 10) + [int]$d) % 97 }
  if ($remainder -ne 1) { return @{ valid=$false; error='Invalid check digits. The IBAN checksum verification failed.' } }
  $formatted = ($clean -split '(.{4})' | Where-Object { $_ -ne '' }) -join ' '
  return @{ valid=$true; iban=$clean; formatted=$formatted; countryCode=$cc; countryName=($COUNTRY_NAMES[$cc] ?? $cc); checkDigits=$check; bban=$bban; length=$clean.Length }
}

function Invoke-IBANValidator {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.ibanSource ?? 'field')
  $iban = ''
  if ($source -eq 'input') {
    $inputData = $JobInput.data; if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.ibanDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $iban = [string]$val
  } else { $iban = [string]($Params.ibanInput ?? '') }
  if (-not $iban) { throw 'No IBAN provided' }
  Write-XYProgress 0.5 'Validating IBAN...'
  $validation = Test-IBAN $iban
  Write-XYProgress 0.95 'Finalizing...'
  $table = if ($validation.valid) {
    @{ title='IBAN Validation Result'; header=@('Property','Value'); rows=@(@('Status','✓ Valid IBAN'), @('Formatted',$validation.formatted), @('Country',"$($validation.countryName) ($($validation.countryCode))"), @('Check Digits',$validation.checkDigits), @('BBAN',$validation.bban), @('Length',"$($validation.length) characters")); caption='IBAN is valid and passes MOD-97 checksum verification' }
  } else {
    @{ title='IBAN Validation Result'; header=@('Property','Value'); rows=@(@('Status','✗ Invalid IBAN'), @('Input',$iban), @('Error',$validation.error)); caption='IBAN validation failed' }
  }
  Write-XY @{ table = $table }
  [pscustomobject]@{ tool='IBAN Validator'; input=$iban } + $validation
}

# ------------------------- Lorem Ipsum -------------------------
$LOREM = @('lorem','ipsum','dolor','sit','amet','consectetur','adipiscing','elit','sed','do','eiusmod','tempor','incididunt','ut','labore','et','dolore','magna','aliqua','enim','ad','minim','veniam','quis','nostrud','exercitation','ullamco','laboris','nisi','aliquip','ex','ea','commodo','consequat','duis','aute','irure','in','reprehenderit','voluptate','velit','esse','cillum','fugiat','nulla','pariatur','excepteur','sint','occaecat','cupidatat','non','proident','sunt','culpa','qui','officia','deserunt','mollit','anim','id','est','laborum','ac','accumsan','aliquet','aliquam','ante','aptent','arcu','at','auctor','augue','bibendum','blandit','condimentum','congue','cras','curabitur','cursus','dapibus','diam','dictum','dictumst','dignissim','dis','donec','egestas','eget','eleifend','elementum','eros','etiam','eu','euismod','facilisi','facilisis','fames','faucibus','felis','fermentum','feugiat','fringilla','fusce','gravida','habitant','habitasse','hac','hendrerit','himenaeos','iaculis','imperdiet','inceptos','integer','interdum','justo','lacinia','lacus','laoreet','lectus','leo','libero','ligula','litora','lobortis','luctus','maecenas','massa','mattis','mauris','metus','mi','morbi','nam','nascetur','natoque','nec','neque','nibh','nisl','nullam','nunc','odio','orci','ornare','parturient','pellentesque','penatibus','per','pharetra','phasellus','placerat','platea','porta','porttitor','posuere','potenti','praesent','pretium','primis','proin','pulvinar','purus','quam','quisque','rhoncus','ridiculus','risus','rutrum','sagittis','sapien','scelerisque','semper','senectus','sociosqu','sodales','sollicitudin','suscipit','suspendisse','taciti','tellus','tempus','tincidunt','torquent','tortor','tristique','turpis','ultrices','ultricies','urna','varius','vehicula','vel','venenatis','vestibulum','vitae','vivamus','viverra','volutpat','vulputate')

function New-LoremSentence {
  param([int]$WordsPerSentence,[bool]$StartWithLorem,[bool]$IsFirstSentence)
  $count = [Math]::Max(3, [Math]::Min(50, $WordsPerSentence))
  $arr = New-Object System.Collections.Generic.List[string]
  for ($i=0; $i -lt $count; $i++) {
    if ($StartWithLorem -and $IsFirstSentence -and $i -lt 2) {
      $word = if ($i -eq 0) { 'Lorem' } else { 'ipsum' }
      $arr.Add($word)
    } else {
      $w = $LOREM[ [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($LOREM.Count) ]
      if ($i -eq 0) { $w = $w.Substring(0,1).ToUpper() + $w.Substring(1) }
      $arr.Add($w)
    }
  }
  return ($arr -join ' ') + '.'
}

function New-LoremParagraph {
  param([int]$SentencesPerParagraph,[int]$WordsPerSentence,[bool]$StartWithLorem,[bool]$IsFirstParagraph)
  $sc = [Math]::Max(1, [Math]::Min(20, $SentencesPerParagraph))
  $sentences = for ($i=0; $i -lt $sc; $i++) { New-LoremSentence -WordsPerSentence $WordsPerSentence -StartWithLorem $StartWithLorem -IsFirstSentence:($IsFirstParagraph -and $i -eq 0) }
  return ($sentences -join ' ')
}

function Invoke-LoremIpsum {
  param($Params)
  Write-XYProgress 0.1 'Validating parameters...'
  $paragraphs = [Math]::Min(50, [Math]::Max(1, [int]($Params.loremParagraphs ?? 3)))
  $spp        = [Math]::Min(20, [Math]::Max(1, [int]($Params.loremSentences ?? 4)))
  $wps        = [Math]::Min(50, [Math]::Max(3, [int]($Params.loremWords ?? 10)))
  $start      = if ($Params.PSObject.Properties.Name -contains 'loremStartWithLorem') { [bool]$Params.loremStartWithLorem } else { $true }
  $asHtml     = if ($Params.PSObject.Properties.Name -contains 'loremAsHtml') { [bool]$Params.loremAsHtml } else { $false }

  Write-XYProgress 0.3 "Generating $paragraphs paragraph(s)..."
  $pars = for ($i=0; $i -lt $paragraphs; $i++) { Write-XYProgress (0.3 + (0.6 * ($i+1) / $paragraphs)) "Generated $($i+1) of $paragraphs paragraphs..."; New-LoremParagraph -SentencesPerParagraph $spp -WordsPerSentence $wps -StartWithLorem $start -IsFirstParagraph:($i -eq 0) }

  Write-XYProgress 0.95 'Finalizing...'
  $text = if ($asHtml) { ($pars | ForEach-Object { "<p>$_</p>" }) -join [Environment]::NewLine } else { ($pars -join ([Environment]::NewLine + [Environment]::NewLine)) }
  $totalWords = ($pars | ForEach-Object { ($_ -split '\s+').Length } | Measure-Object -Sum).Sum
  $totalSentences = ($pars | ForEach-Object { ($_ -split '\.').Count - 1 } | Measure-Object -Sum).Sum

  Write-XY @{ text = @{ title='Generated Lorem Ipsum'; content=$text; caption = "${paragraphs} paragraph(s) | ${totalSentences} sentences | ${totalWords} words | ${text.Length} characters$([string]::IsNullOrEmpty(($asHtml)) ? '' : ' (HTML)')" } }
  [pscustomobject]@{ tool='Lorem Ipsum Generator'; text=$text; paragraphs=$paragraphs; sentencesPerParagraph=$spp; wordsPerSentence=$wps; startWithLorem=$start; asHtml=$asHtml; totalWords=$totalWords; totalSentences=$totalSentences; totalCharacters=$text.Length }
}

# ------------------------- Main -------------------------
try {
  $job = Read-JobFromStdin
  $params = $job.params
  $tool = if ($params.PSObject.Properties.Name -contains 'tool') { $params.tool } else { 'tokenGenerator' }
  $cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { [string]$job.cwd } else { (Get-Location).Path }
  $jobInput = if ($job.PSObject.Properties.Name -contains 'input') { $job.input } else { @{} }

  $result = $null
  switch ($tool) {
    'tokenGenerator' { $result = Invoke-TokenGenerator -Params $params }
    'uuidGenerator'  { $result = Invoke-UUIDGenerator -Params $params }
    'hashText'       { $result = Invoke-HashText -Params $params -JobInput $jobInput }
    'qrCode'         { $result = Invoke-QRCode -Params $params -JobInput $jobInput -Cwd $cwd }
    'ibanValidator'  { $result = Invoke-IBANValidator -Params $params -JobInput $jobInput }
    'passphrase'     { $result = Invoke-PassphraseGenerator -Params $params }
    'loremIpsum'     { $result = Invoke-LoremIpsum -Params $params }
    default          { throw "Unknown tool: $tool" }
  }

  Write-XYSuccess -Data $result -Description ("{0} completed successfully" -f $result.tool)
  [Console]::Out.Flush()
  exit 0
}
catch {
  Write-XYError -Code 1 -Description ($_.Exception.Message)
  [Console]::Out.Flush()
  exit 1
}
