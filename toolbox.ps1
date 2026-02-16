#requires -Version 7.0
# Copyright (c) 2026 Tim Alderweireldt. All rights reserved.
<#!
xyOps Toolbox Event Plugin (PowerShell 7)
A collection of utility tools for xyOps including:
- Token Generator
- UUID Generator (v1, v4, v6, v7, nil, max)
- Hash Text (MD5, SHA1, SHA256, SHA384, SHA512; others best-effort)
- QR Code Generator (pure PowerShell with Reed-Solomon ECC)
- Passphrase Generator (uses wordlist.txt if present, otherwise a small fallback list)
- IBAN Validator
- Lorem Ipsum Generator

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

  # table for UI - use unary comma to prevent array flattening
  $rows = @()
  for ($i = 0; $i -lt $tokens.Count; $i++) {
    $rows += ,@(($i + 1), $tokens[$i])
  }
  Write-XY @{ table = @{ title='Generated Tokens'; header=@('#','Token'); rows=$rows; caption = "Generated $count token(s) with length $length using: $([string]::Join(', ', $charSets))" } }

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
  $versionRaw = Get-Param $Params 'uuidVersion' 'v4'
  $version = if ($null -eq $versionRaw) { 'v4' } else { $versionRaw.ToString() }
  $formatRaw = Get-Param $Params 'uuidFormat' 'standard'
  $format = if ($null -eq $formatRaw) { 'standard' } else { $formatRaw.ToString() }
  $countRaw = Get-Param $Params 'uuidCount' 1
  $count = [Math]::Min(100, [Math]::Max(1, [int]$(if ($null -eq $countRaw) { 1 } else { $countRaw })))

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

  # Build rows with unary comma to prevent array flattening
  $rows = @()
  for ($i = 0; $i -lt $uuids.Count; $i++) {
    $rows += ,@(($i + 1), $uuids[$i])
  }
  Write-XY @{ table = @{ title='Generated UUIDs'; header=@('#','UUID'); rows=$rows; caption = "Generated $count $($versionNames[$version]) UUID(s) in $($formatNames[$format]) format" } }

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

  $result
}

# ------------------------- Passphrase Generator -------------------------
$PP_SYMBOLS = '!@#$%^&*'

function Get-WordList {
  # Comprehensive English wordlist with words from 3 to 8 characters
  return @(
    # 3-letter words
    'ace','act','add','age','ago','aid','aim','air','all','and','ant','any','ape','apt','arc','are','ark','arm','art','ask','ate','bad','bag','bar','bat','bay','bed','bee','bet','big','bin','bit','box','boy','bud','bug','bun','bus','but','buy','cab','can','cap','car','cat','caw','cob','cod','cog','cop','cot','cow','cry','cub','cud','cue','cup','cut','dad','dam','day','den','dew','did','die','dig','dim','din','dip','dog','don','dot','dry','dub','dud','due','dug','dye','ear','eat','egg','ego','elf','elk','elm','end','era','eve','eye','fan','far','fat','fax','fed','fee','few','fib','fig','fin','fir','fit','fix','fly','foe','fog','for','fox','fry','fun','fur','gag','gap','gas','gel','gem','get','gig','gin','git','god','got','gum','gun','gut','guy','gym','had','has','hat','hay','hem','hen','her','hew','hex','hid','him','hip','his','hit','hog','hop','hot','how','hub','hue','hug','hum','hut','ice','ill','ink','inn','ion','its','ivy','jab','jag','jam','jar','jaw','jay','jet','jig','job','jog','jot','joy','jug','keg','ken','key','kid','kin','kit','lab','lad','lag','lap','law','lax','lay','lea','leg','let','lid','lie','lip','lit','log','lot','low','mad','man','map','mat','maw','max','may','men','met','mid','mix','mob','mod','mom','mop','mud','mug','nab','nag','nap','net','new','nil','nip','nit','nod','nor','not','now','nun','nut','oak','oar','oat','odd','off','oft','oil','old','one','opt','orb','ore','our','out','owe','owl','own','pad','pal','pan','pap','par','pat','paw','pax','pay','pea','peg','pen','pep','per','pet','pew','pie','pig','pin','pip','pit','ply','pod','pop','pot','pox','pro','pry','pub','pug','pun','pup','pus','put','rag','ram','ran','rap','rat','raw','ray','red','rep','rib','rid','rig','rim','rip','rob','rod','roe','rot','row','rub','rug','rum','run','rut','rye','sac','sad','sag','sap','sat','saw','sax','say','sea','see','set','sew','sex','she','shy','sin','sip','sir','sis','sit','six','ska','sky','sly','sob','sod','son','sop','sot','sow','sox','soy','spa','spy','sty','sub','sum','sun','sup','tab','tad','tag','tan','tap','tar','tax','tea','ten','the','thy','tic','tie','tin','tip','toe','ton','too','top','tot','tow','toy','try','tub','tug','two','urn','use','van','vet','vex','via','vie','vow','wad','wag','wan','war','was','wax','way','web','wed','wee','wet','who','why','wig','win','wit','woe','wok','won','woo','wow','yak','yam','yap','yaw','yea','yen','yes','yet','yew','yin','you','yow','yup','zap','zed','zee','zen','zoo','zoo',

    # 4-letter words
    'able','acid','aged','also','area','army','away','baby','back','ball','band','bank','base','bath','beat','been','beer','bell','belt','best','bill','bird','bite','blow','blue','boat','body','bomb','bond','bone','book','boot','bore','born','boss','both','bowl','boxy','boys','brag','brat','bred','brew','brim','bulb','bulk','bull','bump','burn','burst','buye','cafe','cage','cake','call','calm','came','camp','cane','cape','card','care','cart','case','cash','cast','cave','cell','cent','chap','chat','chef','chew','chin','chip','chop','cite','city','clad','clam','clap','class','claw','clay','clip','club','clue','coal','coat','code','coil','coin','cold','colo','comb','come','cook','cool','cope','copy','cord','core','cork','cost','cozy','crab','cram','crew','crop','crow','cube','cult','curb','cure','curl','cute','dang','dare','dark','dart','dash','data','date','dawn','days','dead','deaf','deal','dean','dear','debt','deck','deer','demo','dent','desk','dial','dice','died','diet','dime','dine','dire','dirt','disc','dish','disk','dive','dock','doll','dome','done','door','dope','dose','down','doze','drag','draw','drew','drip','drop','drub','drug','drum','dual','duck','dude','duel','dues','dull','dumb','dump','dune','dunk','dupe','dusk','dust','duty','each','earl','earn','earth','ease','east','easy','echo','edge','edit','eggs','egos','else','emit','envy','even','ever','evil','exam','exit','face','fact','fade','fail','fair','fake','fall','fame','fang','fare','farm','fast','fate','fawn','fear','feat','feed','feel','feet','fell','felt','fern','fest','feud','fiat','fief','file','fill','film','find','fine','fire','firm','fish','fist','five','flag','flak','flap','flat','flaw','flax','flay','flea','fled','flee','flew','flex','flip','flit','flog','flop','flow','flue','flux','foal','foam','foci','foil','fold','folk','fond','font','food','fool','foot','ford','fore','fork','form','fort','foul','four','fowl','foxy','frat','fray','free','fresh','frie','frog','from','fuel','full','fume','fund','funk','fury','fuse','fuss','fuzz','gait','gala','game','gang','garb','gash','gate','gave','gawk','gaze','gear','geek','gene','germ','gift','girl','give','glad','glee','glen','glow','glue','glum','glut','gnaw','goal','goat','goes','gold','golf','gone','gong','good','goof','gore','gory','gown','grab','gram','gray','grew','grey','grid','grin','grip','grit','grow','grub','guam','guar','guess','guest','guide','guild','guilt','guise','gulf','gull','gulp','guru','gush',

    # 5-letter words
    'about','above','abuse','actor','acute','admit','adopt','adult','after','again','agent','agree','ahead','alarm','album','alert','alike','alive','allow','alone','along','alter','among','anger','angle','angry','apart','apple','apply','arena','argue','arise','array','aside','asset','audio','audit','avoid','award','aware','badly','baker','bases','basic','basis','beach','began','begin','begun','being','below','bench','billy','birth','black','blame','blind','block','blood','board','boost','booth','bound','brain','brand','bread','break','breed','brief','bring','broad','broke','brown','build','built','buyer','cable','calif','carry','catch','cause','chain','chair','chart','chase','cheap','check','chest','chief','child','china','choir','choose','chronic','church','cigar','claim','class','clean','clear','click','clock','close','coach','coast','could','count','court','cover','craft','crash','cream','crime','cross','crowd','crown','curve','cycle','daily','dance','dated','dealt','death','debut','delay','depth','doing','doubt','dozen','draft','drama','drawn','dream','dress','drill','drink',

    # 6-letter words
    'accept','access','accuse','achieve','acquire','across','acting','action','active','actual','advice','advise','affect','afford','aftermath','against','agency','agenda','almost','already','although','always','amazing','amount','analyst','ancient','another','anxiety','anybody','anything','anytime','apparent','approach','approval','argument','artistic','assembly','athletic','attitude','attorney','audience','authority','available','average','backward','bacteria','baseball','beautiful','because','becoming','bedroom','behavior','believe','benefit','besides','between','billion','birthday','boundary','brother','building','business','calendar','campaign','capacity','capital','captain','capture','careful','carrying','category','caution','celebrate','cellular','cemetery','certainly',

    # 7-letter words
    'ability','absence','academy','account','accuracy','achieve','acquire','address','advance','adverse','advisory','advocate','aircraft','alcohol','although','amazing','analyst','ancient','another','anxiety','anybody','anything','anytime','apparent','approach','approval','argument','artistic','assembly','athletic','attitude','attorney','audience','authority','available','average','backward','bacteria','baseball','beautiful','because','becoming','bedroom','behavior','believe','benefit','besides','between','billion','birthday','boundary','brother','building','business','calendar','campaign','capacity','capital','captain','capture','careful','carrying','category','caution','celebrate','cellular','cemetery','certainly',

    # 8-letter words
    'absolute','academic','accepted','accident','according','accounting','accuracy','achievement','acknowledge','acquire','acquisition','activity','actually','additional','adequate','adjustment','administration','advantage','adventure','advertising','advisable','advisory','advocate','aesthetic','affecting','affection','affiliate','affirmative','affordable','afternoon','afterward','against','aggressive','agreement','agricultural','alcoholic','algorithm','alliance','although','altogether','amazing','ambassador','amendment','ammunition','amongst','amounted','analysis','ancestor','ancient','anderson','announce','annual','another','answering','antibody','anybody','anything','anywhere','apparent','apparently','appealing','appearance','appetite','application','appointment','appreciate','approach','appropriate','approval','approximately','architect','argument','arise','arrangement','arrival','artistic','assembly','athletic','attaching','attempt','attend','attention','attitude','attorney','attract','auction','audience','author','authority','available','average','avoid','awaiting','background','bacteria','baseball','beautiful','because','becoming','bedroom','behavior','believe','benefit'

  )
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
    $num = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(100).ToString()
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($sep) { $parts.AddRange([string[]]$pass.Split($sep)) } else { $parts.AddRange([string[]]$sel) }
    $pos = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($parts.Count + 1)
    $parts.Insert($pos, $num)
    $pass = $parts -join $sep
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
  if ($Entropy -lt 40) { return @{ rating='Weak'; symbol='[!]' } }
  if ($Entropy -lt 60) { return @{ rating='Fair'; symbol='[~]' } }
  if ($Entropy -lt 80) { return @{ rating='Strong'; symbol='[+]' } }
  if ($Entropy -lt 100){ return @{ rating='Very Strong'; symbol='[++]' } }
  return @{ rating='Excellent'; symbol='[*]' }
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
  Write-XY @{ table = @{ title='Generated Passphrases'; header=@('#','Passphrase','Length'); rows=$rows; caption = "$($strength.symbol) $($strength.rating) | $wordCount words | ~$entropy bits entropy | Word pool: $pool" } }

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
    @{ title='IBAN Validation Result'; header=@('Property','Value'); rows=@(@('Status','[OK] Valid IBAN'), @('Formatted',$validation.formatted), @('Country',"$($validation.countryName) ($($validation.countryCode))"), @('Check Digits',$validation.checkDigits), @('BBAN',$validation.bban), @('Length',"$($validation.length) characters")); caption='IBAN is valid and passes MOD-97 checksum verification' }
  } else {
    @{ title='IBAN Validation Result'; header=@('Property','Value'); rows=@(@('Status','[X] Invalid IBAN'), @('Input',$iban), @('Error',$validation.error)); caption='IBAN validation failed' }
  }
  Write-XY @{ table = $table }
  $result = @{ tool='IBAN Validator'; input=$iban }
  $result += $validation
  [pscustomobject]$result
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
  param($Params, [string]$Cwd)
  Write-XYProgress 0.1 'Validating parameters...'
  $paragraphs = [Math]::Min(50, [Math]::Max(1, [int]($Params.loremParagraphs ?? 3)))
  $spp        = [Math]::Min(20, [Math]::Max(1, [int]($Params.loremSentences ?? 4)))
  $wps        = [Math]::Min(50, [Math]::Max(3, [int]($Params.loremWords ?? 10)))
  $start      = if ($Params.PSObject.Properties.Name -contains 'loremStartWithLorem') { [bool]$Params.loremStartWithLorem } else { $true }
  $asHtml     = if ($Params.PSObject.Properties.Name -contains 'loremAsHtml') { [bool]$Params.loremAsHtml } else { $false }

  Write-XYProgress 0.3 "Generating $paragraphs paragraph(s)..."
  $pars = for ($i=0; $i -lt $paragraphs; $i++) { Write-XYProgress (0.3 + (0.6 * ($i+1) / $paragraphs)) "Generated $($i+1) of $paragraphs paragraphs..."; New-LoremParagraph -SentencesPerParagraph $spp -WordsPerSentence $wps -StartWithLorem $start -IsFirstParagraph:($i -eq 0) }

  Write-XYProgress 0.9 'Saving files...'
  $text = if ($asHtml) { ($pars | ForEach-Object { "<p>$_</p>" }) -join [Environment]::NewLine } else { ($pars -join ([Environment]::NewLine + [Environment]::NewLine)) }
  $totalWords = ($pars | ForEach-Object { ($_ -split '\s+').Length } | Measure-Object -Sum).Sum
  $totalSentences = ($pars | ForEach-Object { ($_ -split '\.').Count - 1 } | Measure-Object -Sum).Sum

  # Save as .txt file
  $txtFilename = 'lorem-ipsum.txt'
  $txtPath = Join-Path $Cwd $txtFilename
  [System.IO.File]::WriteAllText($txtPath, $text, [System.Text.Encoding]::UTF8)

  # Save as .md file (with header)
  $mdFilename = 'lorem-ipsum.md'
  $mdPath = Join-Path $Cwd $mdFilename
  $mdContent = "# Lorem Ipsum`n`n$text"
  [System.IO.File]::WriteAllText($mdPath, $mdContent, [System.Text.Encoding]::UTF8)

  Write-XYProgress 0.95 'Finalizing...'

  # Output files for xyOps download
  Write-XY @{ files = @($txtFilename, $mdFilename) }

  Write-XY @{ text = @{ title='Generated Lorem Ipsum'; content=$text; caption = "$paragraphs paragraph(s) | $totalSentences sentences | $totalWords words | $($text.Length) characters$(if ($asHtml) { ' (HTML)' } else { '' })" } }
  [pscustomobject]@{ tool='Lorem Ipsum Generator'; text=$text; paragraphs=$paragraphs; sentencesPerParagraph=$spp; wordsPerSentence=$wps; startWithLorem=$start; asHtml=$asHtml; totalWords=$totalWords; totalSentences=$totalSentences; totalCharacters=$text.Length; files=@($txtFilename, $mdFilename) }
}

# ------------------------- Base64 Encoder/Decoder -------------------------
function Invoke-Base64 {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $mode = ($Params.base64Mode ?? 'encode')
  $source = ($Params.base64Source ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.base64DataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.base64Input ?? '') }
  
  if (-not $text) { throw 'No input text provided' }
  
  Write-XYProgress 0.5 "$(if ($mode -eq 'encode') { 'Encoding' } else { 'Decoding' }) text..."
  
  $output = ''
  $success = $true
  $errorMsg = ''
  
  try {
    if ($mode -eq 'encode') {
      $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
      $output = [Convert]::ToBase64String($bytes)
    } else {
      $bytes = [Convert]::FromBase64String($text)
      $output = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
  } catch {
    $success = $false
    $errorMsg = $_.Exception.Message
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  if ($success) {
    Write-XY @{ table = @{ title="Base64 $(if ($mode -eq 'encode') { 'Encoded' } else { 'Decoded' })"; header=@('Property','Value'); rows=@(@('Mode', $(if ($mode -eq 'encode') { 'Encode' } else { 'Decode' })), @('Input Length', "$($text.Length) characters"), @('Output Length', "$($output.Length) characters"), @('Output', $(if ($output.Length -gt 100) { $output.Substring(0,100) + '...' } else { $output }))); caption="Successfully $(if ($mode -eq 'encode') { 'encoded' } else { 'decoded' }) text" } }
    [pscustomobject]@{ tool='Base64 Encoder/Decoder'; mode=$mode; input=$text; output=$output; inputLength=$text.Length; outputLength=$output.Length; success=$true }
  } else {
    Write-XY @{ table = @{ title='Base64 Error'; header=@('Property','Value'); rows=@(@('Mode', $(if ($mode -eq 'encode') { 'Encode' } else { 'Decode' })), @('Error', $errorMsg)); caption='Operation failed' } }
    [pscustomobject]@{ tool='Base64 Encoder/Decoder'; mode=$mode; input=$text; success=$false; error=$errorMsg }
  }
}

# ------------------------- URL Encoder/Decoder -------------------------
function Invoke-UrlEncode {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $mode = ($Params.urlMode ?? 'encode')
  $source = ($Params.urlSource ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.urlDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.urlInput ?? '') }
  
  if (-not $text) { throw 'No input text provided' }
  
  Write-XYProgress 0.5 "$(if ($mode -eq 'encode') { 'Encoding' } else { 'Decoding' }) URL..."
  
  $output = if ($mode -eq 'encode') {
    [System.Uri]::EscapeDataString($text)
  } else {
    [System.Uri]::UnescapeDataString($text)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ table = @{ title="URL $(if ($mode -eq 'encode') { 'Encoded' } else { 'Decoded' })"; header=@('Property','Value'); rows=@(@('Mode', $(if ($mode -eq 'encode') { 'Encode' } else { 'Decode' })), @('Input', $(if ($text.Length -gt 80) { $text.Substring(0,80) + '...' } else { $text })), @('Output', $(if ($output.Length -gt 80) { $output.Substring(0,80) + '...' } else { $output }))); caption="Successfully $(if ($mode -eq 'encode') { 'encoded' } else { 'decoded' }) URL" } }
  [pscustomobject]@{ tool='URL Encoder/Decoder'; mode=$mode; input=$text; output=$output; inputLength=$text.Length; outputLength=$output.Length }
}

# ------------------------- Timestamp Converter -------------------------
function Invoke-TimestampConverter {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $mode = ($Params.tsMode ?? 'now')
  $source = ($Params.tsSource ?? 'field')
  $inputValue = ''
  
  if ($mode -ne 'now') {
    if ($source -eq 'input') {
      $inputData = $JobInput.data
      if (-not $inputData) { throw 'No input data available from previous job' }
      $path = ($Params.tsDataPath ?? '')
      $val = Get-NestedValue $inputData $path
      if ($null -eq $val) { throw "Data path '$path' not found in input data" }
      $inputValue = [string]$val
    } else { $inputValue = ($Params.tsInput ?? '') }
  }
  
  Write-XYProgress 0.5 'Converting timestamp...'
  
  $dt = $null
  $parseError = ''
  
  switch ($mode) {
    'now' { $dt = [DateTimeOffset]::UtcNow }
    'unix' {
      try {
        $unixSeconds = [long]$inputValue
        $dt = [DateTimeOffset]::FromUnixTimeSeconds($unixSeconds)
      } catch { $parseError = "Invalid Unix timestamp: $inputValue" }
    }
    'unixms' {
      try {
        $unixMs = [long]$inputValue
        $dt = [DateTimeOffset]::FromUnixTimeMilliseconds($unixMs)
      } catch { $parseError = "Invalid Unix milliseconds timestamp: $inputValue" }
    }
    'iso' {
      try {
        $dt = [DateTimeOffset]::Parse($inputValue)
      } catch { $parseError = "Invalid ISO 8601 date: $inputValue" }
    }
    default { $parseError = "Unknown mode: $mode" }
  }
  
  if ($parseError) { throw $parseError }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $unixSec = $dt.ToUnixTimeSeconds()
  $unixMs = $dt.ToUnixTimeMilliseconds()
  $iso = $dt.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
  $isoUtc = $dt.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $human = $dt.ToString('dddd, MMMM d, yyyy h:mm:ss tt')
  $humanUtc = $dt.UtcDateTime.ToString('dddd, MMMM d, yyyy h:mm:ss tt') + ' UTC'
  
  $rows = @(
    @('Unix Timestamp (seconds)', $unixSec.ToString()),
    @('Unix Timestamp (milliseconds)', $unixMs.ToString()),
    @('ISO 8601', $iso),
    @('ISO 8601 (UTC)', $isoUtc),
    @('Human Readable', $human),
    @('Human Readable (UTC)', $humanUtc)
  )
  
  Write-XY @{ table = @{ title='Timestamp Conversion'; header=@('Format','Value'); rows=$rows; caption="Converted from $(if ($mode -eq 'now') { 'current time' } else { $mode })" } }
  [pscustomobject]@{ tool='Timestamp Converter'; mode=$mode; input=$(if ($mode -eq 'now') { 'now' } else { $inputValue }); unixSeconds=$unixSec; unixMilliseconds=$unixMs; iso8601=$iso; iso8601Utc=$isoUtc; humanReadable=$human; humanReadableUtc=$humanUtc }
}

# ------------------------- JSON Formatter -------------------------
function Invoke-JsonFormatter {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $mode = ($Params.jsonMode ?? 'prettify')
  $source = ($Params.jsonSource ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.jsonDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.jsonInput ?? '') }
  
  if (-not $text) { throw 'No JSON input provided' }
  
  Write-XYProgress 0.5 'Processing JSON...'
  
  $parsed = $null
  $output = ''
  $valid = $true
  $errorMsg = ''
  
  try {
    $parsed = $text | ConvertFrom-Json -ErrorAction Stop
    $output = switch ($mode) {
      'prettify' { $parsed | ConvertTo-Json -Depth 20 }
      'minify'   { $parsed | ConvertTo-Json -Depth 20 -Compress }
      'validate' { $parsed | ConvertTo-Json -Depth 20 }
    }
  } catch {
    $valid = $false
    $errorMsg = $_.Exception.Message
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $modeNames = @{ prettify='Prettify'; minify='Minify'; validate='Validate' }
  
  if ($valid) {
    # Show full output for small results, truncate at 10KB for very large outputs
    $preview = if ($output.Length -gt 10000) { $output.Substring(0,10000) + "`n... [truncated, full output in data]" } else { $output }
    Write-XY @{ table = @{ title='JSON Result'; header=@('Property','Value'); rows=@(@('Mode', $modeNames[$mode]), @('Valid', '[OK] Yes'), @('Input Size', "$($text.Length) chars"), @('Output Size', "$($output.Length) chars")); caption='JSON is valid' } }
    Write-XY @{ text = @{ title='Output'; content=$preview; caption='' } }
    [pscustomobject]@{ tool='JSON Formatter'; mode=$mode; valid=$true; input=$text; output=$output; inputLength=$text.Length; outputLength=$output.Length }
  } else {
    Write-XY @{ table = @{ title='JSON Result'; header=@('Property','Value'); rows=@(@('Mode', $modeNames[$mode]), @('Valid', '[X] No'), @('Error', $errorMsg)); caption='JSON is invalid' } }
    [pscustomobject]@{ tool='JSON Formatter'; mode=$mode; valid=$false; error=$errorMsg }
  }
}

# ------------------------- String Case Converter -------------------------
function Invoke-CaseConverter {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $targetCase = ($Params.caseType ?? 'lower')
  $source = ($Params.caseSource ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.caseDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.caseInput ?? '') }
  
  if (-not $text) { throw 'No input text provided' }
  
  Write-XYProgress 0.5 'Converting case...'
  
  $output = switch ($targetCase) {
    'lower'     { $text.ToLowerInvariant() }
    'upper'     { $text.ToUpperInvariant() }
    'title'     { (Get-Culture).TextInfo.ToTitleCase($text.ToLower()) }
    'sentence'  { if ($text.Length -gt 0) { $text.Substring(0,1).ToUpper() + $text.Substring(1).ToLower() } else { '' } }
    'camel'     { $words = $text -split '[\s_-]+'; $first = $true; ($words | ForEach-Object { if ($first) { $first = $false; $_.ToLower() } else { (Get-Culture).TextInfo.ToTitleCase($_.ToLower()) } }) -join '' }
    'pascal'    { $words = $text -split '[\s_-]+'; ($words | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_.ToLower()) }) -join '' }
    'snake'     { ($text -creplace '([A-Z])', '_$1' -replace '[\s-]+', '_').ToLower().Trim('_') -replace '__+', '_' }
    'kebab'     { ($text -creplace '([A-Z])', '-$1' -replace '[\s_]+', '-').ToLower().Trim('-') -replace '--+', '-' }
    'constant'  { ($text -creplace '([A-Z])', '_$1' -replace '[\s-]+', '_').ToUpper().Trim('_') -replace '__+', '_' }
    default     { $text }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $caseNames = @{ lower='lowercase'; upper='UPPERCASE'; title='Title Case'; sentence='Sentence case'; camel='camelCase'; pascal='PascalCase'; snake='snake_case'; kebab='kebab-case'; constant='CONSTANT_CASE' }
  
  Write-XY @{ table = @{ title='Case Conversion'; header=@('Property','Value'); rows=@(@('Target Case', $caseNames[$targetCase]), @('Input', $(if ($text.Length -gt 50) { $text.Substring(0,50) + '...' } else { $text })), @('Output', $(if ($output.Length -gt 50) { $output.Substring(0,50) + '...' } else { $output }))); caption="Converted to $($caseNames[$targetCase])" } }
  [pscustomobject]@{ tool='String Case Converter'; targetCase=$targetCase; input=$text; output=$output }
}

# ------------------------- Color Converter -------------------------
function Invoke-ColorConverter {
  param($Params, $JobInput, [string]$Cwd)
  Write-XYProgress 0.1 'Validating parameters...'
  $inputFormat = ($Params.colorInputFormat ?? 'hex')
  $source = ($Params.colorSource ?? 'field')
  $colorInput = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.colorDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $colorInput = [string]$val
  } else { $colorInput = ($Params.colorInput ?? '') }
  
  if (-not $colorInput) { throw 'No color input provided' }
  
  Write-XYProgress 0.5 'Converting color...'
  
  $r = 0; $g = 0; $b = 0
  
  switch ($inputFormat) {
    'hex' {
      $hex = $colorInput -replace '^#', ''
      if ($hex.Length -eq 3) { $hex = "$($hex[0])$($hex[0])$($hex[1])$($hex[1])$($hex[2])$($hex[2])" }
      if ($hex.Length -ne 6) { throw "Invalid HEX color: $colorInput" }
      $r = [Convert]::ToInt32($hex.Substring(0,2), 16)
      $g = [Convert]::ToInt32($hex.Substring(2,2), 16)
      $b = [Convert]::ToInt32($hex.Substring(4,2), 16)
    }
    'rgb' {
      $match = [regex]::Match($colorInput, 'rgb\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)')
      if (-not $match.Success) {
        $parts = $colorInput -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        if ($parts.Count -ge 3) { $r = [int]$parts[0]; $g = [int]$parts[1]; $b = [int]$parts[2] }
        else { throw "Invalid RGB color: $colorInput" }
      } else {
        $r = [int]$match.Groups[1].Value; $g = [int]$match.Groups[2].Value; $b = [int]$match.Groups[3].Value
      }
    }
    'hsl' {
      $match = [regex]::Match($colorInput, 'hsl\s*\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)')
      if (-not $match.Success) {
        $parts = $colorInput -split '[,\s]+' | Where-Object { $_ -match '^[\d.]+' }
        if ($parts.Count -ge 3) { $h = [double]($parts[0] -replace '%',''); $s = [double]($parts[1] -replace '%','')/100; $l = [double]($parts[2] -replace '%','')/100 }
        else { throw "Invalid HSL color: $colorInput" }
      } else {
        $h = [double]$match.Groups[1].Value; $s = [double]$match.Groups[2].Value/100; $l = [double]$match.Groups[3].Value/100
      }
      # HSL to RGB conversion
      if ($s -eq 0) { $r = $g = $b = [int]($l * 255) }
      else {
        $hueToRgb = { param($p, $q, $t) if ($t -lt 0) { $t += 1 }; if ($t -gt 1) { $t -= 1 }; if ($t -lt 1/6) { return $p + ($q - $p) * 6 * $t }; if ($t -lt 1/2) { return $q }; if ($t -lt 2/3) { return $p + ($q - $p) * (2/3 - $t) * 6 }; return $p }
        $q = if ($l -lt 0.5) { $l * (1 + $s) } else { $l + $s - $l * $s }
        $p = 2 * $l - $q
        $r = [int]([Math]::Round((& $hueToRgb $p $q ($h/360 + 1/3)) * 255))
        $g = [int]([Math]::Round((& $hueToRgb $p $q ($h/360)) * 255))
        $b = [int]([Math]::Round((& $hueToRgb $p $q ($h/360 - 1/3)) * 255))
      }
    }
  }
  
  $r = [Math]::Max(0, [Math]::Min(255, $r)); $g = [Math]::Max(0, [Math]::Min(255, $g)); $b = [Math]::Max(0, [Math]::Min(255, $b))
  
  # Convert to all formats
  $hex = '#{0:X2}{1:X2}{2:X2}' -f $r, $g, $b
  $rgb = "rgb($r, $g, $b)"
  $maxC = [Math]::Max($r, [Math]::Max($g, $b)) / 255; $minC = [Math]::Min($r, [Math]::Min($g, $b)) / 255
  $l = ($maxC + $minC) / 2; $s = 0; $h = 0
  if ($maxC -ne $minC) {
    $d = $maxC - $minC
    $s = if ($l -gt 0.5) { $d / (2 - $maxC - $minC) } else { $d / ($maxC + $minC) }
    $rn = $r/255; $gn = $g/255; $bn = $b/255
    if ($rn -eq $maxC) { $h = (($gn - $bn) / $d + $(if ($gn -lt $bn) { 6 } else { 0 })) * 60 }
    elseif ($gn -eq $maxC) { $h = (($bn - $rn) / $d + 2) * 60 }
    else { $h = (($rn - $gn) / $d + 4) * 60 }
  }
  $hsl = "hsl($([Math]::Round($h)), $([Math]::Round($s * 100))%, $([Math]::Round($l * 100))%)"
  
  Write-XYProgress 0.9 'Generating color swatch...'
  
  # Generate color swatch PNG
  Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
  $swatchSize = 100
  $swatch = New-Object System.Drawing.Bitmap($swatchSize, $swatchSize)
  $graphics = [System.Drawing.Graphics]::FromImage($swatch)
  $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($r, $g, $b))
  $graphics.FillRectangle($brush, 0, 0, $swatchSize, $swatchSize)
  # Add border
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(200, 200, 200), 2)
  $graphics.DrawRectangle($pen, 0, 0, $swatchSize - 1, $swatchSize - 1)
  $brush.Dispose(); $pen.Dispose(); $graphics.Dispose()
  
  $filename = "color-swatch-$($hex.Replace('#', '')).png"
  $filepath = Join-Path $Cwd $filename
  $swatch.Save($filepath, [System.Drawing.Imaging.ImageFormat]::Png)
  $swatch.Dispose()
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ files = @($filename) }
  Write-XY @{ table = @{ title='Color Conversion'; header=@('Format','Value'); rows=@(@('HEX', $hex), @('RGB', $rgb), @('HSL', $hsl), @('Red', $r), @('Green', $g), @('Blue', $b)); caption="Converted from $inputFormat" } }
  [pscustomobject]@{ tool='Color Converter'; inputFormat=$inputFormat; input=$colorInput; hex=$hex; rgb=$rgb; hsl=$hsl; red=$r; green=$g; blue=$b; swatchFile=$filename }
}

# ------------------------- Image Converter -------------------------
function Invoke-ImageConverter {
  param($Params, $JobInput, [string]$Cwd)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $source = ($Params.imgSource ?? 'field')
  $outputFormat = ($Params.imgOutputFormat ?? 'png')
  $resize = ($Params.imgResize ?? 'none')
  $width = [int]($Params.imgWidth ?? 0)
  $height = [int]($Params.imgHeight ?? 0)
  $inputFile = ''
  
  switch ($source) {
    'files' {
      # Get file from job input files array
      $fileIndex = [int]($Params.imgFileIndex ?? 0)
      if (-not $JobInput.files -or $JobInput.files.Count -eq 0) { throw 'No input files available from job' }
      if ($fileIndex -ge $JobInput.files.Count) { throw "File index $fileIndex out of range ($($JobInput.files.Count) files available)" }
      $fileObj = $JobInput.files[$fileIndex]
      # File object has properties: id, date, filename, size, username - extract the filename
      if ($fileObj -is [string]) {
        $inputFile = $fileObj
      } elseif ($fileObj.PSObject.Properties.Name -contains 'filename') {
        $inputFile = $fileObj.filename
      } else {
        $inputFile = [string]$fileObj
      }
    }
    'input' {
      # Get file path from job input data
      $inputData = $JobInput.data
      if (-not $inputData) { throw 'No input data available from previous job' }
      $dataPath = ($Params.imgDataPath ?? '')
      $val = Get-NestedValue $inputData $dataPath
      if ($null -eq $val) { throw "Data path '$dataPath' not found in input data" }
      $inputFile = [string]$val
    }
    default {
      # Use text field
      $inputFile = ($Params.imgInput ?? '')
    }
  }
  
  if (-not $inputFile) { throw 'No input file specified' }
  
  # Ensure inputFile is a string
  $inputFile = [string]$inputFile
  $inputPath = if ([System.IO.Path]::IsPathRooted($inputFile)) { $inputFile } else { Join-Path $Cwd $inputFile }
  if (-not (Test-Path $inputPath)) { throw "Input file not found: $inputFile" }
  
  Write-XYProgress 0.3 'Loading image...'
  
  # Load image using .NET
  Add-Type -AssemblyName System.Drawing -ErrorAction Stop
  $img = [System.Drawing.Image]::FromFile($inputPath)
  $origWidth = $img.Width; $origHeight = $img.Height
  
  Write-XYProgress 0.5 'Processing image...'
  
  $newWidth = $origWidth; $newHeight = $origHeight
  
  if ($resize -eq 'dimensions' -and $width -gt 0 -and $height -gt 0) {
    $newWidth = $width; $newHeight = $height
  } elseif ($resize -eq 'width' -and $width -gt 0) {
    $newWidth = $width; $newHeight = [int]($origHeight * ($width / $origWidth))
  } elseif ($resize -eq 'height' -and $height -gt 0) {
    $newHeight = $height; $newWidth = [int]($origWidth * ($height / $origHeight))
  } elseif ($resize -eq 'percent' -and $width -gt 0) {
    $scale = $width / 100; $newWidth = [int]($origWidth * $scale); $newHeight = [int]($origHeight * $scale)
  }
  
  $outputImg = $img
  if ($newWidth -ne $origWidth -or $newHeight -ne $origHeight) {
    $outputImg = New-Object System.Drawing.Bitmap($newWidth, $newHeight)
    $graphics = [System.Drawing.Graphics]::FromImage($outputImg)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.DrawImage($img, 0, 0, $newWidth, $newHeight)
    $graphics.Dispose()
  }
  
  Write-XYProgress 0.8 'Saving image...'
  
  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($inputFile)
  $outputFile = "$baseName-converted.$outputFormat"
  $outputPath = Join-Path $Cwd $outputFile
  
  $format = switch ($outputFormat) {
    'png'  { [System.Drawing.Imaging.ImageFormat]::Png }
    'jpg'  { [System.Drawing.Imaging.ImageFormat]::Jpeg }
    'jpeg' { [System.Drawing.Imaging.ImageFormat]::Jpeg }
    'bmp'  { [System.Drawing.Imaging.ImageFormat]::Bmp }
    'gif'  { [System.Drawing.Imaging.ImageFormat]::Gif }
    'tiff' { [System.Drawing.Imaging.ImageFormat]::Tiff }
    default { [System.Drawing.Imaging.ImageFormat]::Png }
  }
  
  $outputImg.Save($outputPath, $format)
  $fileInfo = Get-Item $outputPath
  
  if ($outputImg -ne $img) { $outputImg.Dispose() }
  $img.Dispose()
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ files = @($outputFile) }
  Write-XY @{ table = @{ title='Image Converted'; header=@('Property','Value'); rows=@(@('Input File', $inputFile), @('Output File', $outputFile), @('Original Size', "${origWidth}x${origHeight}"), @('New Size', "${newWidth}x${newHeight}"), @('Output Format', $outputFormat.ToUpper()), @('File Size', "$($fileInfo.Length) bytes")); caption="Image converted to $($outputFormat.ToUpper())" } }
  [pscustomobject]@{ tool='Image Converter'; inputFile=$inputFile; outputFile=$outputFile; originalWidth=$origWidth; originalHeight=$origHeight; newWidth=$newWidth; newHeight=$newHeight; outputFormat=$outputFormat; fileSize=$fileInfo.Length }
}

# ------------------------- Slug Generator -------------------------
function Invoke-SlugGenerator {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.slugSource ?? 'field')
  $separator = ($Params.slugSeparator ?? '-')
  $lowercase = ($Params.slugLowercase ?? 'true') -eq 'true'
  $maxLength = [int]($Params.slugMaxLength ?? 0)
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.slugDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = [string]$val
  } else { $text = ($Params.slugInput ?? '') }
  
  if (-not $text) { throw 'No input text provided' }
  
  Write-XYProgress 0.5 'Generating slug...'
  
  # Normalize unicode and remove diacritics
  $normalized = $text.Normalize([System.Text.NormalizationForm]::FormD)
  $slug = ($normalized -replace '\p{M}', '').Trim()
  
  # Replace non-alphanumeric with separator
  $slug = $slug -replace '[^a-zA-Z0-9]+', $separator
  $slug = $slug.Trim($separator)
  
  # Remove consecutive separators
  $slug = $slug -replace "[$separator]+", $separator
  
  if ($lowercase) { $slug = $slug.ToLowerInvariant() }
  if ($maxLength -gt 0 -and $slug.Length -gt $maxLength) {
    $slug = $slug.Substring(0, $maxLength).TrimEnd($separator)
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ table = @{ title='Slug Generated'; header=@('Property','Value'); rows=@(@('Input', $(if ($text.Length -gt 50) { $text.Substring(0,50) + '...' } else { $text })), @('Slug', $slug), @('Separator', $separator), @('Lowercase', $(if ($lowercase) { 'Yes' } else { 'No' })), @('Length', $slug.Length)); caption='URL-safe slug generated' } }
  [pscustomobject]@{ tool='Slug Generator'; input=$text; slug=$slug; separator=$separator; lowercase=$lowercase; length=$slug.Length }
}

# ------------------------- Text Statistics -------------------------
function Invoke-TextStatistics {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.statsSource ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.statsDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.statsInput ?? '') }
  
  if (-not $text) { throw 'No input text provided' }
  
  Write-XYProgress 0.5 'Analyzing text...'
  
  $charCount = $text.Length
  $charNoSpaces = ($text -replace '\s', '').Length
  $words = @($text -split '\s+' | Where-Object { $_.Length -gt 0 })
  $wordCount = $words.Count
  $lines = @($text -split "`n")
  $lineCount = $lines.Count
  $sentences = @($text -split '[.!?]+' | Where-Object { $_.Trim().Length -gt 0 })
  $sentenceCount = $sentences.Count
  $paragraphs = @($text -split "`n\s*`n" | Where-Object { $_.Trim().Length -gt 0 })
  $paragraphCount = $paragraphs.Count
  
  # Average word length
  $avgWordLength = if ($wordCount -gt 0) { [Math]::Round(($words | ForEach-Object { $_.Length } | Measure-Object -Average).Average, 1) } else { 0 }
  
  # Reading time (200 words/minute)
  $readingMinutes = [Math]::Ceiling($wordCount / 200)
  
  # Speaking time (150 words/minute)
  $speakingMinutes = [Math]::Ceiling($wordCount / 150)
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ table = @{ title='Text Statistics'; header=@('Metric','Value'); rows=@(@('Characters', $charCount), @('Characters (no spaces)', $charNoSpaces), @('Words', $wordCount), @('Sentences', $sentenceCount), @('Paragraphs', $paragraphCount), @('Lines', $lineCount), @('Avg Word Length', "$avgWordLength chars"), @('Reading Time', "~$readingMinutes min"), @('Speaking Time', "~$speakingMinutes min")); caption='Text analysis complete' } }
  [pscustomobject]@{ tool='Text Statistics'; characters=$charCount; charactersNoSpaces=$charNoSpaces; words=$wordCount; sentences=$sentenceCount; paragraphs=$paragraphCount; lines=$lineCount; avgWordLength=$avgWordLength; readingMinutes=$readingMinutes; speakingMinutes=$speakingMinutes }
}

# ------------------------- Credit Card Validator -------------------------
function Invoke-CreditCardValidator {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.ccSource ?? 'field')
  $cardNumber = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.ccDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $cardNumber = [string]$val
  } else { $cardNumber = ($Params.ccInput ?? '') }
  
  if (-not $cardNumber) { throw 'No card number provided' }
  
  Write-XYProgress 0.5 'Validating card...'
  
  # Remove spaces, dashes
  $cleaned = $cardNumber -replace '[\s-]', ''
  
  # Check if numeric only
  if ($cleaned -notmatch '^\d+$') { throw 'Card number must contain only digits' }
  
  # Luhn algorithm validation
  $digits = $cleaned.ToCharArray() | ForEach-Object { [int]::Parse($_) }
  $sum = 0; $alt = $false
  for ($i = $digits.Length - 1; $i -ge 0; $i--) {
    $d = $digits[$i]
    if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }
    $sum += $d; $alt = -not $alt
  }
  $isValid = ($sum % 10) -eq 0
  
  # Detect card type by prefix and length
  $cardType = 'Unknown'
  $len = $cleaned.Length
  if ($cleaned -match '^4' -and ($len -eq 13 -or $len -eq 16 -or $len -eq 19)) { $cardType = 'Visa' }
  elseif ($cleaned -match '^5[1-5]' -and $len -eq 16) { $cardType = 'Mastercard' }
  elseif ($cleaned -match '^(34|37)' -and $len -eq 15) { $cardType = 'American Express' }
  elseif ($cleaned -match '^6(?:011|5)' -and $len -eq 16) { $cardType = 'Discover' }
  elseif ($cleaned -match '^3(?:0[0-5]|[68])' -and ($len -eq 14 -or $len -eq 16)) { $cardType = "Diners Club" }
  elseif ($cleaned -match '^35(?:2[89]|[3-8])' -and ($len -ge 16 -and $len -le 19)) { $cardType = 'JCB' }
  elseif ($cleaned -match '^62' -and $len -eq 16) { $cardType = 'UnionPay' }
  
  # Mask card number
  $masked = if ($len -ge 8) { $cleaned.Substring(0,4) + ('*' * ($len - 8)) + $cleaned.Substring($len - 4) } else { '*' * $len }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $validText = if ($isValid) { '[OK] Valid (Luhn check passed)' } else { '[X] Invalid (Luhn check failed)' }
  Write-XY @{ table = @{ title='Credit Card Validation'; header=@('Property','Value'); rows=@(@('Masked Number', $masked), @('Card Type', $cardType), @('Valid', $validText), @('Length', $len)); caption=$(if ($isValid) { 'Card number is valid' } else { 'Card number is invalid' }) } }
  [pscustomobject]@{ tool='Credit Card Validator'; maskedNumber=$masked; cardType=$cardType; valid=$isValid; length=$len }
}

# ------------------------- Email Validator -------------------------
function Invoke-EmailValidator {
  param($Params, $JobInput)
  Write-XYProgress 0.1 'Validating parameters...'
  $source = ($Params.emailSource ?? 'field')
  $email = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $path = ($Params.emailDataPath ?? '')
    $val = Get-NestedValue $inputData $path
    if ($null -eq $val) { throw "Data path '$path' not found in input data" }
    $email = [string]$val
  } else { $email = ($Params.emailInput ?? '') }
  
  if (-not $email) { throw 'No email address provided' }
  
  Write-XYProgress 0.5 'Validating email...'
  
  $email = $email.Trim()
  $isValid = $false; $localPart = ''; $domain = ''; $tld = ''
  $issues = [System.Collections.Generic.List[string]]::new()
  
  # RFC 5322 simplified regex
  $emailRegex = '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
  
  if ($email -match '@') {
    $parts = $email -split '@'
    if ($parts.Count -eq 2) {
      $localPart = $parts[0]; $domain = $parts[1]
      if ($domain -match '\.([a-zA-Z]{2,})$') { $tld = $Matches[1] }
    }
  }
  
  if ($email -match $emailRegex) {
    $isValid = $true
    if ($localPart.Length -gt 64) { $issues.Add('Local part exceeds 64 chars'); $isValid = $false }
    if ($domain.Length -gt 253) { $issues.Add('Domain exceeds 253 chars'); $isValid = $false }
    if ($localPart.StartsWith('.') -or $localPart.EndsWith('.')) { $issues.Add('Local part starts/ends with dot'); $isValid = $false }
    if ($localPart -match '\.\.') { $issues.Add('Local part has consecutive dots'); $isValid = $false }
  } else {
    if (-not ($email -match '@')) { $issues.Add('Missing @ symbol') }
    elseif ($parts.Count -ne 2) { $issues.Add('Multiple @ symbols') }
    elseif (-not $localPart) { $issues.Add('Empty local part') }
    elseif (-not $domain) { $issues.Add('Empty domain') }
    elseif (-not ($domain -match '\.')) { $issues.Add('Domain missing TLD') }
    else { $issues.Add('Invalid format') }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $validText = if ($isValid) { '[OK] Valid' } else { '[X] Invalid' }
  $issueText = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }
  Write-XY @{ table = @{ title='Email Validation'; header=@('Property','Value'); rows=@(@('Email', $email), @('Valid', $validText), @('Local Part', $(if ($localPart) { $localPart } else { 'N/A' })), @('Domain', $(if ($domain) { $domain } else { 'N/A' })), @('TLD', $(if ($tld) { $tld } else { 'N/A' })), @('Issues', $issueText)); caption=$(if ($isValid) { 'Email address is valid' } else { 'Email address is invalid' }) } }
  [pscustomobject]@{ tool='Email Validator'; email=$email; valid=$isValid; localPart=$localPart; domain=$domain; tld=$tld; issues=$issues.ToArray() }
}


# ------------------------- Barcode Generator -------------------------
function Invoke-BarcodeGenerator {
  param($Params, $JobInput, [string]$Cwd)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $barcodeType = ($Params.barcodeType ?? 'code128')
  $source = ($Params.barcodeSource ?? 'field')
  $text = ''
  
  if ($source -eq 'input') {
    $inputData = $JobInput.data
    if (-not $inputData) { throw 'No input data available from previous job' }
    $dataPath = ($Params.barcodeDataPath ?? '')
    $val = Get-NestedValue $inputData $dataPath
    if ($null -eq $val) { throw "Data path '$dataPath' not found in input data" }
    $text = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
  } else { $text = ($Params.barcodeText ?? '') }
  
  if (-not $text) { throw 'No barcode text provided' }
  
  Write-XYProgress 0.5 'Generating barcode...'
  
  $svg = ''
  $filename = "barcode-$barcodeType.svg"
  
  switch ($barcodeType) {
    'code128' {
      # Code 128 encoding (subset B for printable ASCII) - use case-sensitive hashtable
      $patterns = [System.Collections.Hashtable]::new([StringComparer]::Ordinal)
      # Special characters and numbers
      $patterns[' ']='11011001100'; $patterns['!']='11001101100'; $patterns['"']='11001100110'
      $patterns['#']='10010011000'; $patterns['$']='10010001100'; $patterns['%']='10001001100'
      $patterns['&']='10011001000'; $patterns["'"]='10011000100'; $patterns['(']='10001100100'
      $patterns[')']='11001001000'; $patterns['*']='11001000100'; $patterns['+']='11000100100'
      $patterns[',']='10110011100'; $patterns['-']='10011011100'; $patterns['.']='10011001110'
      $patterns['/']='10111001100'; $patterns['0']='10011101100'; $patterns['1']='10011100110'
      $patterns['2']='11001110010'; $patterns['3']='11001011100'; $patterns['4']='11001001110'
      $patterns['5']='11011100100'; $patterns['6']='11001110100'; $patterns['7']='11101101110'
      $patterns['8']='11101001100'; $patterns['9']='11100101100'; $patterns[':']='11100100110'
      $patterns[';']='11101100100'; $patterns['<']='11100110100'; $patterns['=']='11100110010'
      $patterns['>']='11011011000'; $patterns['?']='11011000110'; $patterns['@']='11000110110'
      # Uppercase letters
      $patterns['A']='10100011000'; $patterns['B']='10001011000'; $patterns['C']='10001000110'
      $patterns['D']='10110001000'; $patterns['E']='10001101000'; $patterns['F']='10001100010'
      $patterns['G']='11010001000'; $patterns['H']='11000101000'; $patterns['I']='11000100010'
      $patterns['J']='10110111000'; $patterns['K']='10110001110'; $patterns['L']='10001101110'
      $patterns['M']='10111011000'; $patterns['N']='10111000110'; $patterns['O']='10001110110'
      $patterns['P']='11101110110'; $patterns['Q']='11010001110'; $patterns['R']='11000101110'
      $patterns['S']='11011101000'; $patterns['T']='11011100010'; $patterns['U']='11011101110'
      $patterns['V']='11101011000'; $patterns['W']='11101000110'; $patterns['X']='11100010110'
      $patterns['Y']='11101101000'; $patterns['Z']='11101100010'; $patterns['[']='11100011010'
      $patterns['\']='11101111010'; $patterns[']']='11001000010'; $patterns['^']='11110001010'
      $patterns['_']='10100110000'; $patterns['`']='10100001100'
      # Lowercase letters
      $patterns['a']='10010110000'; $patterns['b']='10010000110'; $patterns['c']='10000101100'
      $patterns['d']='10000100110'; $patterns['e']='10110010000'; $patterns['f']='10110000100'
      $patterns['g']='10011010000'; $patterns['h']='10011000010'; $patterns['i']='10000110100'
      $patterns['j']='10000110010'; $patterns['k']='11000010010'; $patterns['l']='11001010000'
      $patterns['m']='11110111010'; $patterns['n']='11000010100'; $patterns['o']='10001111010'
      $patterns['p']='10100111100'; $patterns['q']='10010111100'; $patterns['r']='10010011110'
      $patterns['s']='10111100100'; $patterns['t']='10011110100'; $patterns['u']='10011110010'
      $patterns['v']='11110100100'; $patterns['w']='11110010100'; $patterns['x']='11110010010'
      $patterns['y']='11011011110'; $patterns['z']='11011110110'; $patterns['{']='11110110110'
      $patterns['|']='10101111000'; $patterns['}']='10100011110'; $patterns['~']='10001011110'
      $startB = '11010010000'; $stop = '1100011101011'
      $checksum = 104 # Start B value
      $encoded = $startB
      for ($i = 0; $i -lt $text.Length; $i++) {
        $c = $text[$i]
        if ($patterns.ContainsKey([string]$c)) {
          $encoded += $patterns[[string]$c]
          $val = [int][char]$c - 32
          $checksum += $val * ($i + 1)
        }
      }
      $checkVal = $checksum % 103
      $checkChar = [char]($checkVal + 32)
      if ($patterns.ContainsKey([string]$checkChar)) { $encoded += $patterns[[string]$checkChar] }
      $encoded += $stop
      
      # Generate SVG
      $barWidth = 2; $height = 80; $width = $encoded.Length * $barWidth + 20
      $svg = "<svg xmlns='http://www.w3.org/2000/svg' width='$width' height='$($height + 30)' viewBox='0 0 $width $($height + 30)'>"
      $svg += "<rect width='100%' height='100%' fill='white'/>"
      $x = 10
      foreach ($bit in $encoded.ToCharArray()) {
        if ($bit -eq '1') { $svg += "<rect x='$x' y='10' width='$barWidth' height='$height' fill='black'/>" }
        $x += $barWidth
      }
      $svg += "<text x='$($width/2)' y='$($height + 25)' text-anchor='middle' font-family='monospace' font-size='12'>$([System.Security.SecurityElement]::Escape($text))</text>"
      $svg += "</svg>"
    }
    'code39' {
      $patterns = @{
        '0'='101001101101'; '1'='110100101011'; '2'='101100101011'; '3'='110110010101'; '4'='101001101011'
        '5'='110100110101'; '6'='101100110101'; '7'='101001011011'; '8'='110100101101'; '9'='101100101101'
        'A'='110101001011'; 'B'='101101001011'; 'C'='110110100101'; 'D'='101011001011'; 'E'='110101100101'
        'F'='101101100101'; 'G'='101010011011'; 'H'='110101001101'; 'I'='101101001101'; 'J'='101011001101'
        'K'='110101010011'; 'L'='101101010011'; 'M'='110110101001'; 'N'='101011010011'; 'O'='110101101001'
        'P'='101101101001'; 'Q'='101010110011'; 'R'='110101011001'; 'S'='101101011001'; 'T'='101011011001'
        'U'='110010101011'; 'V'='100110101011'; 'W'='110011010101'; 'X'='100101101011'; 'Y'='110010110101'
        'Z'='100110110101'; '-'='100101011011'; '.'='110010101101'; ' '='100110101101'; '*'='100101101101'
        '$'='100100100101'; '/'='100100101001'; '+'='100101001001'; '%'='101001001001'
      }
      $textUpper = "*$($text.ToUpper())*"
      $encoded = ''
      foreach ($c in $textUpper.ToCharArray()) {
        if ($patterns.ContainsKey([string]$c)) { $encoded += $patterns[[string]$c] + '0' }
      }
      
      $barWidth = 2; $height = 80; $width = $encoded.Length * $barWidth + 20
      $svg = "<svg xmlns='http://www.w3.org/2000/svg' width='$width' height='$($height + 30)' viewBox='0 0 $width $($height + 30)'>"
      $svg += "<rect width='100%' height='100%' fill='white'/>"
      $x = 10
      foreach ($bit in $encoded.ToCharArray()) {
        if ($bit -eq '1') { $svg += "<rect x='$x' y='10' width='$barWidth' height='$height' fill='black'/>" }
        $x += $barWidth
      }
      $svg += "<text x='$($width/2)' y='$($height + 25)' text-anchor='middle' font-family='monospace' font-size='12'>$([System.Security.SecurityElement]::Escape($text.ToUpper()))</text>"
      $svg += "</svg>"
    }
  }
  
  Write-XYProgress 0.7 'Saving SVG...'
  
  $svgFilename = "barcode-$barcodeType.svg"
  $pngFilename = "barcode-$barcodeType.png"
  $svgPath = Join-Path $Cwd $svgFilename
  $pngPath = Join-Path $Cwd $pngFilename
  
  $svg | Out-File -FilePath $svgPath -Encoding UTF8 -NoNewline
  
  Write-XYProgress 0.85 'Generating PNG...'
  
  # Generate PNG using System.Drawing
  Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
  $barWidth = 2
  $height = 80
  $margin = 10
  $textHeight = 25
  $imgWidth = $encoded.Length * $barWidth + ($margin * 2)
  $imgHeight = $height + $margin + $textHeight
  
  $bitmap = New-Object System.Drawing.Bitmap($imgWidth, $imgHeight)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.Clear([System.Drawing.Color]::White)
  
  # Draw bars
  $blackBrush = [System.Drawing.Brushes]::Black
  $x = $margin
  foreach ($bit in $encoded.ToCharArray()) {
    if ($bit -eq '1') {
      $graphics.FillRectangle($blackBrush, $x, $margin, $barWidth, $height)
    }
    $x += $barWidth
  }
  
  # Draw text
  $font = New-Object System.Drawing.Font('Consolas', 10)
  $textBrush = [System.Drawing.Brushes]::Black
  $displayText = if ($barcodeType -eq 'code39') { $text.ToUpper() } else { $text }
  $textSize = $graphics.MeasureString($displayText, $font)
  $textX = ($imgWidth - $textSize.Width) / 2
  $textY = $margin + $height + 5
  $graphics.DrawString($displayText, $font, $textBrush, $textX, $textY)
  
  $font.Dispose()
  $graphics.Dispose()
  $bitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
  
  Write-XYProgress 0.95 'Finalizing...'
  
  Write-XY @{ files = @($svgFilename, $pngFilename) }
  Write-XY @{ table = @{ title='Barcode Generated'; header=@('Property','Value'); rows=@(@('Type', $barcodeType.ToUpper()), @('Text', $text), @('SVG File', $svgFilename), @('PNG File', $pngFilename)); caption='Barcode generated as SVG and PNG' } }
  [pscustomobject]@{ tool='Barcode Generator'; type=$barcodeType; text=$text; svgFile=$svgFilename; pngFile=$pngFilename; files=@($svgFilename, $pngFilename) }
}

# ------------------------- Fake Data Generator -------------------------
function Invoke-FakeDataGenerator {
  param($Params)
  Write-XYProgress 0.1 'Validating parameters...'
  
  $dataType = ($Params.fakeDataType ?? 'person')
  $country = ($Params.fakeCountry ?? 'us')
  $count = [int]($Params.fakeCount ?? 1)
  $count = [Math]::Max(1, [Math]::Min($count, 100))
  
  Write-XYProgress 0.2 'Loading country data...'
  
  # Country-specific data pools
  $countryData = @{
    'us' = @{
      countryName = 'United States'
      countryCode = 'US'
      firstNames = @('James','Mary','John','Patricia','Robert','Jennifer','Michael','Linda','David','Elizabeth','William','Barbara','Richard','Susan','Joseph','Jessica','Thomas','Sarah','Christopher','Karen','Charles','Lisa','Daniel','Nancy','Matthew','Betty','Anthony','Margaret','Mark','Sandra')
      lastNames = @('Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez','Wilson','Anderson','Thomas','Taylor','Moore','Jackson','Martin','Lee','Thompson','White','Harris','Clark','Lewis','Robinson','Walker','Young','Allen','King','Wright','Scott')
      streets = @('Main St','Oak Ave','Maple Dr','Cedar Ln','Pine Rd','Elm St','Park Ave','Lake Dr','Hill Rd','River Rd','Forest Ave','Valley Dr','Sunset Blvd','Ocean Ave','Mountain Rd')
      cities = @('New York','Los Angeles','Chicago','Houston','Phoenix','Philadelphia','San Antonio','San Diego','Dallas','Austin','Seattle','Denver','Boston','Miami','Atlanta')
      regions = @('NY','CA','IL','TX','AZ','PA','FL','OH','NC','WA','CO','MA','GA','MI','NJ')
      regionLabel = 'State'
      postalFormat = { '{0:D5}' -f ((Get-Random -Maximum 90000) + 10000) }
      phoneFormat = { '+1 ({0:D3}) {1:D3}-{2:D4}' -f ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 9000)+1000) }
      mobileFormat = { '+1 ({0:D3}) {1:D3}-{2:D4}' -f ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 9000)+1000) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$num $street, $city, $region $postal" }
      companies = @('Acme Corp','Global Tech','Innovative Solutions','Digital Dynamics','Future Systems','Prime Industries','Elite Services','Apex Group','Pinnacle Inc','Quantum Labs')
    }
    'uk' = @{
      countryName = 'United Kingdom'
      countryCode = 'GB'
      firstNames = @('Oliver','Olivia','George','Amelia','Harry','Isla','Noah','Ava','Jack','Emily','Leo','Mia','Charlie','Grace','Oscar','Lily','Henry','Sophie','William','Ella','Thomas','Freya','James','Charlotte','Jacob','Ivy','Arthur','Daisy','Alfie','Poppy')
      lastNames = @('Smith','Jones','Williams','Taylor','Brown','Davies','Evans','Wilson','Thomas','Roberts','Johnson','Lewis','Walker','Robinson','Wood','Thompson','White','Watson','Jackson','Wright','Green','Harris','Cooper','King','Lee','Martin','Clarke','James','Morgan','Hughes')
      streets = @('High Street','Church Lane','Station Road','Mill Lane','The Green','Park Road','Victoria Road','Manor Road','Queens Road','Kings Road','London Road','Bridge Street','Market Street','Chapel Lane','School Lane')
      cities = @('London','Birmingham','Manchester','Leeds','Liverpool','Sheffield','Bristol','Newcastle','Nottingham','Southampton','Edinburgh','Glasgow','Cardiff','Belfast','Cambridge','Oxford','Brighton','Bath')
      regions = @('Greater London','West Midlands','Greater Manchester','West Yorkshire','Merseyside','South Yorkshire','Avon','Tyne and Wear','Nottinghamshire','Hampshire','Lothian','Strathclyde','South Glamorgan','Antrim','Cambridgeshire')
      regionLabel = 'County'
      postalFormat = { $letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; "$($letters[(Get-Random -Maximum 26)])$($letters[(Get-Random -Maximum 26)])$((Get-Random -Maximum 9)+1) $((Get-Random -Maximum 9)+1)$($letters[(Get-Random -Maximum 26)])$($letters[(Get-Random -Maximum 26)])" }
      phoneFormat = { '+44 {0:D4} {1:D6}' -f ((Get-Random -Maximum 9000)+1000), ((Get-Random -Maximum 900000)+100000) }
      mobileFormat = { '+44 7{0:D3} {1:D6}' -f ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 900000)+100000) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$num $street`n$city`n$postal" }
      companies = @('British Solutions Ltd','Crown Industries','Royal Tech','Empire Group','Commonwealth Corp','Sterling Services','Albion Partners','Thames Digital','Windsor Holdings','Cambridge Innovations')
    }
    'de' = @{
      countryName = 'Germany'
      countryCode = 'DE'
      firstNames = @('Lukas','Emma','Leon','Mia','Paul','Hannah','Felix','Sophia','Maximilian','Marie','Jonas','Emilia','Ben','Lina','Elias','Anna','Noah','Lea','Luis','Clara','Tim','Laura','Finn','Lena','Julian','Sarah','Niklas','Julia','Moritz','Amelie')
      lastNames = @('Mueller','Schmidt','Schneider','Fischer','Weber','Meyer','Wagner','Becker','Schulz','Hoffmann','Schaefer','Koch','Bauer','Richter','Klein','Wolf','Schroeder','Neumann','Schwarz','Zimmermann','Braun','Krueger','Hofmann','Hartmann','Lange','Schmitt','Werner','Krause','Meier','Lehmann')
      streets = @('Hauptstrasse','Bahnhofstrasse','Schulstrasse','Gartenstrasse','Dorfstrasse','Bergstrasse','Kirchstrasse','Waldstrasse','Ringstrasse','Muehlenweg','Lindenstrasse','Rosenweg','Birkenweg','Ahornweg','Eichenstrasse')
      cities = @('Berlin','Hamburg','Munich','Cologne','Frankfurt','Stuttgart','Dusseldorf','Leipzig','Dortmund','Essen','Bremen','Dresden','Hanover','Nuremberg','Duisburg')
      regions = @('Berlin','Hamburg','Bavaria','North Rhine-Westphalia','Hesse','Baden-Wuerttemberg','Lower Saxony','Saxony','Rhineland-Palatinate','Schleswig-Holstein','Brandenburg','Saxony-Anhalt','Thuringia','Mecklenburg-Vorpommern','Saarland')
      regionLabel = 'Bundesland'
      postalFormat = { '{0:D5}' -f ((Get-Random -Maximum 90000) + 10000) }
      phoneFormat = { '+49 {0:D3} {1:D7}' -f ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 9000000)+1000000) }
      mobileFormat = { $prefix = @('151','152','157','160','170','171','172','173','174','175','176','177','178','179')[(Get-Random -Maximum 14)]; '+49 {0} {1:D7}' -f $prefix, ((Get-Random -Maximum 9000000)+1000000) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$street $num`n$postal $city" }
      companies = @('Deutsche Technik GmbH','Berliner Solutions','Rhein Industries AG','Alpen Group','Schwarzwald Digital','Bayern Systems','Hamburg Innovations','Muenchen Partners','Dresden Tech','Leipzig Consulting')
    }
    'fr' = @{
      countryName = 'France'
      countryCode = 'FR'
      firstNames = @('Gabriel','Emma','Louis','Jade','Raphael','Louise','Leo','Alice','Adam','Chloe','Lucas','Lina','Hugo','Rose','Jules','Lea','Arthur','Anna','Nathan','Mila','Liam','Amelia','Ethan','Manon','Paul','Juliette','Noah','Camille','Tom','Ines')
      lastNames = @('Martin','Bernard','Dubois','Thomas','Robert','Richard','Petit','Durand','Leroy','Moreau','Simon','Laurent','Lefebvre','Michel','Garcia','David','Bertrand','Roux','Vincent','Fournier','Morel','Girard','Andre','Lefevre','Mercier','Dupont','Lambert','Bonnet','Francois','Martinez')
      streets = @('Rue de la Paix','Avenue des Champs','Boulevard Saint-Michel','Rue du Commerce','Place de la Republique','Rue Victor Hugo','Avenue de la Gare','Rue Pasteur','Boulevard Voltaire','Rue Jean Jaures','Rue de la Liberte','Avenue Gambetta','Rue du Moulin','Place du Marche','Rue des Fleurs')
      cities = @('Paris','Marseille','Lyon','Toulouse','Nice','Nantes','Strasbourg','Montpellier','Bordeaux','Lille','Rennes','Reims','Toulon','Grenoble','Dijon')
      regions = @('Ile-de-France','Provence-Alpes-Cote d Azur','Auvergne-Rhone-Alpes','Occitanie','Hauts-de-France','Nouvelle-Aquitaine','Grand Est','Pays de la Loire','Bretagne','Normandie','Bourgogne-Franche-Comte','Centre-Val de Loire','Corse')
      regionLabel = 'Region'
      postalFormat = { '{0:D5}' -f ((Get-Random -Maximum 90000) + 10000) }
      phoneFormat = { '+33 {0:D1} {1:D2} {2:D2} {3:D2} {4:D2}' -f ((Get-Random -Maximum 4)+1), (Get-Random -Maximum 100), (Get-Random -Maximum 100), (Get-Random -Maximum 100), (Get-Random -Maximum 100) }
      mobileFormat = { $prefix = @(6,7)[(Get-Random -Maximum 2)]; '+33 {0} {1:D2} {2:D2} {3:D2} {4:D2}' -f $prefix, (Get-Random -Maximum 100), (Get-Random -Maximum 100), (Get-Random -Maximum 100), (Get-Random -Maximum 100) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$num $street`n$postal $city" }
      companies = @('Solutions Francaises SA','Paris Tech','Groupe Lyonnais','Bordeaux Industries','Marseille Digital','Toulouse Innovations','Nice Services','Nantes Partners','Strasbourg Consulting','Lyon Systems')
    }
    'nl' = @{
      countryName = 'Netherlands'
      countryCode = 'NL'
      firstNames = @('Daan','Emma','Sem','Julia','Lucas','Tess','Levi','Sophie','Finn','Evi','Noah','Anna','Luuk','Saar','Milan','Lotte','Jesse','Noor','Bram','Fleur','Jayden','Mila','Tim','Sara','Lars','Isa','Thijs','Zoey','Ruben','Lieke')
      lastNames = @('De Jong','Jansen','De Vries','Van den Berg','Van Dijk','Bakker','Janssen','Visser','Smit','Meijer','De Boer','Mulder','De Groot','Bos','Vos','Peters','Hendriks','Van Leeuwen','Dekker','Brouwer','De Wit','Dijkstra','Smits','De Graaf','Van der Meer')
      streets = @('Hoofdstraat','Kerkstraat','Dorpsstraat','Stationsweg','Molenweg','Schoolstraat','Julianastraat','Beatrixstraat','Marktplein','Nieuwstraat','Oranjestraat','Wilhelminastraat','Raadhuisstraat','Gravenstraat','Havenstraat')
      cities = @('Amsterdam','Rotterdam','The Hague','Utrecht','Eindhoven','Groningen','Tilburg','Almere','Breda','Nijmegen','Apeldoorn','Haarlem','Arnhem','Enschede','Amersfoort')
      regions = @('North Holland','South Holland','Utrecht','North Brabant','Gelderland','Overijssel','Limburg','Friesland','Groningen','Drenthe','Flevoland','Zeeland')
      regionLabel = 'Province'
      postalFormat = { $letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; '{0:D4} {1}{2}' -f ((Get-Random -Maximum 9000)+1000), $letters[(Get-Random -Maximum 26)], $letters[(Get-Random -Maximum 26)] }
      phoneFormat = { '+31 {0:D2} {1:D3} {2:D4}' -f ((Get-Random -Maximum 90)+10), ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 9000)+1000) }
      mobileFormat = { '+31 6 {0:D8}' -f ((Get-Random -Maximum 90000000)+10000000) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$street $num`n$postal $city" }
      companies = @('Dutch Solutions BV','Amsterdam Tech','Rotterdam Industries','Utrecht Digital','Eindhoven Innovations','Holland Group','Nederlandse Partners','Tulip Systems','Oranje Consulting','Windmill Corp')
    }
    'be' = @{
      countryName = 'Belgium'
      countryCode = 'BE'
      firstNames = @('Noah','Emma','Liam','Louise','Lucas','Marie','Louis','Olivia','Adam','Elise','Arthur','Anna','Jules','Charlotte','Victor','Juliette','Nathan','Camille','Mathis','Lea','Rayan','Lina','Mohamed','Elena','Aaron','Noor','Maxime','Julie','Tom','Laura')
      lastNames = @('Peeters','Janssens','Maes','Jacobs','Mertens','Willems','Claes','Goossens','Wouters','De Smedt','Dubois','Lambert','Martin','Dupont','Simon','Laurent','Leroy','Claessens','Hermans','Van den Berg','Michiels','Leclercq','Desmet','De Backer','Hendrickx')
      streets = @('Kerkstraat','Stationsstraat','Schoolstraat','Nieuwstraat','Molenstraat','Hoogstraat','Dorpsstraat','Groenstraat','Kapelstraat','Beekstraat','Rue de la Station','Rue du Moulin','Grand Place','Rue Haute','Chaussee de Bruxelles')
      cities = @('Brussels','Antwerp','Ghent','Charleroi','Liege','Bruges','Namur','Leuven','Mons','Mechelen','Aalst','La Louviere','Kortrijk','Hasselt','Ostend')
      regions = @('Brussels Capital','Antwerp','East Flanders','Hainaut','Liege','West Flanders','Namur','Flemish Brabant','Limbourg','Walloon Brabant','Luxembourg')
      regionLabel = 'Province'
      postalFormat = { '{0:D4}' -f ((Get-Random -Maximum 9000) + 1000) }
      phoneFormat = { '+32 {0:D1} {1:D3} {2:D2} {3:D2}' -f ((Get-Random -Maximum 8)+2), ((Get-Random -Maximum 900)+100), (Get-Random -Maximum 100), (Get-Random -Maximum 100) }
      mobileFormat = { $prefix = @('470','471','472','473','474','475','476','477','478','479','484','485','486','487','488','489','490','491','492','493','494','495','496','497','498','499')[(Get-Random -Maximum 26)]; '+32 {0} {1:D2} {2:D2} {3:D2}' -f $prefix, (Get-Random -Maximum 100), (Get-Random -Maximum 100), (Get-Random -Maximum 100) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$street $num`n$postal $city" }
      companies = @('Belgian Solutions NV','Brussels Tech','Antwerp Industries','Ghent Digital','Flemish Group','Wallonia Partners','Benelux Corp','Leuven Innovations','Bruges Consulting','Liege Systems')
    }
    'es' = @{
      countryName = 'Spain'
      countryCode = 'ES'
      firstNames = @('Hugo','Lucia','Martin','Sofia','Lucas','Maria','Mateo','Martina','Leo','Paula','Daniel','Valeria','Pablo','Emma','Alejandro','Julia','Manuel','Daniela','Adrian','Alba','Alvaro','Carla','David','Sara','Diego','Noa','Mario','Carmen','Iker','Elena')
      lastNames = @('Garcia','Rodriguez','Martinez','Lopez','Gonzalez','Hernandez','Perez','Sanchez','Ramirez','Torres','Flores','Rivera','Gomez','Diaz','Reyes','Morales','Jimenez','Ruiz','Alvarez','Romero','Navarro','Dominguez','Vazquez','Ramos','Gil','Serrano','Blanco','Molina','Moreno','Ortiz')
      streets = @('Calle Mayor','Avenida de la Constitucion','Paseo del Prado','Calle Real','Plaza Mayor','Calle del Sol','Avenida de la Libertad','Calle de la Paz','Rambla de Catalunya','Gran Via','Calle Nueva','Paseo Maritimo','Calle del Carmen','Avenida del Mar','Calle San Antonio')
      cities = @('Madrid','Barcelona','Valencia','Seville','Zaragoza','Malaga','Murcia','Palma','Las Palmas','Bilbao','Alicante','Cordoba','Valladolid','Vigo','Gijon')
      regions = @('Community of Madrid','Catalonia','Valencian Community','Andalusia','Aragon','Balearic Islands','Canary Islands','Basque Country','Galicia','Castile and Leon','Castile-La Mancha','Region of Murcia','Navarre','Asturias','Cantabria')
      regionLabel = 'Autonomous Community'
      postalFormat = { '{0:D5}' -f ((Get-Random -Maximum 53000) + 1000) }
      phoneFormat = { '+34 9{0:D2} {1:D3} {2:D3}' -f ((Get-Random -Maximum 90)+10), ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 900)+100) }
      mobileFormat = { $prefix = @(6,7)[(Get-Random -Maximum 2)]; '+34 {0}{1:D2} {2:D3} {3:D3}' -f $prefix, ((Get-Random -Maximum 90)+10), ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 900)+100) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$street, $num`n$postal $city" }
      companies = @('Soluciones Espanolas SL','Madrid Tech','Barcelona Industries','Valencia Digital','Iberia Group','Costa Partners','Hispania Corp','Sevilla Innovations','Mediterraneo Consulting','Pirineos Systems')
    }
    'it' = @{
      countryName = 'Italy'
      countryCode = 'IT'
      firstNames = @('Leonardo','Sofia','Francesco','Aurora','Alessandro','Giulia','Lorenzo','Ginevra','Mattia','Alice','Andrea','Emma','Gabriele','Giorgia','Riccardo','Beatrice','Tommaso','Chiara','Edoardo','Anna','Federico','Sara','Luca','Greta','Marco','Martina','Davide','Ludovica','Giuseppe','Francesca')
      lastNames = @('Rossi','Russo','Ferrari','Esposito','Bianchi','Romano','Colombo','Ricci','Marino','Greco','Bruno','Gallo','Conti','De Luca','Costa','Giordano','Mancini','Rizzo','Lombardi','Moretti','Barbieri','Fontana','Santoro','Mariani','Rinaldi','Caruso','Ferrara','Galli','Martini','Leone')
      streets = @('Via Roma','Corso Italia','Via Garibaldi','Via Dante','Piazza del Duomo','Via Mazzini','Via Vittorio Emanuele','Via Nazionale','Via della Repubblica','Via Verdi','Corso Vittorio Emanuele','Via Cavour','Via XX Settembre','Via dei Mille','Piazza della Liberta')
      cities = @('Rome','Milan','Naples','Turin','Palermo','Genoa','Bologna','Florence','Bari','Catania','Venice','Verona','Messina','Padua','Trieste')
      regions = @('Lazio','Lombardy','Campania','Piedmont','Sicily','Liguria','Emilia-Romagna','Tuscany','Apulia','Veneto','Friuli Venezia Giulia','Sardinia','Calabria','Marche','Abruzzo')
      regionLabel = 'Region'
      postalFormat = { '{0:D5}' -f ((Get-Random -Maximum 99000) + 1000) }
      phoneFormat = { '+39 0{0:D1} {1:D4} {2:D4}' -f ((Get-Random -Maximum 9)+1), ((Get-Random -Maximum 9000)+1000), ((Get-Random -Maximum 9000)+1000) }
      mobileFormat = { $prefix = @('320','321','322','323','324','325','326','327','328','329','330','331','333','334','335','336','337','338','339','340','341','342','343','344','345','346','347','348','349','350','351','360','361','362','363','364','365','366','368','370','371','373','377','388','389','390','391','392','393')[(Get-Random -Maximum 49)]; '+39 {0} {1:D3} {2:D4}' -f $prefix, ((Get-Random -Maximum 900)+100), ((Get-Random -Maximum 9000)+1000) }
      addressFormat = { param($num,$street,$city,$region,$postal) "$street, $num`n$postal $city" }
      companies = @('Soluzioni Italiane SRL','Roma Tech','Milano Industries','Firenze Digital','Italia Group','Venezia Partners','Napoli Corp','Torino Innovations','Sicilia Consulting','Lombarda Systems')
    }
  }
  
  # Get country-specific data or default to US
  $cd = $countryData[$country] ?? $countryData['us']
  
  # Common data
  $domains = @('gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','mail.com','proton.me')
  $jobTitles = @('Software Engineer','Product Manager','Data Analyst','Marketing Director','Sales Representative','HR Manager','Financial Analyst','Operations Manager','Project Coordinator','UX Designer')
  
  Write-XYProgress 0.3 "Generating $($cd.countryName) data..."
  
  $results = [System.Collections.Generic.List[object]]::new()
  $rows = [System.Collections.Generic.List[object]]::new()
  
  for ($i = 0; $i -lt $count; $i++) {
    Write-XYProgress (0.3 + 0.6 * ($i / $count)) "Generating record $($i + 1) of $count..."
    
    $firstName = $cd.firstNames[(Get-Random -Maximum $cd.firstNames.Count)]
    $lastName = $cd.lastNames[(Get-Random -Maximum $cd.lastNames.Count)]
    $fullName = "$firstName $lastName"
    $email = "$($firstName.ToLower()).$($lastName.ToLower().Replace(' ',''))@$($domains[(Get-Random -Maximum $domains.Count)])"
    $phone = & $cd.phoneFormat
    $streetNum = (Get-Random -Maximum 299) + 1
    $street = $cd.streets[(Get-Random -Maximum $cd.streets.Count)]
    $city = $cd.cities[(Get-Random -Maximum $cd.cities.Count)]
    $region = $cd.regions[(Get-Random -Maximum $cd.regions.Count)]
    $postal = & $cd.postalFormat
    $address = & $cd.addressFormat $streetNum $street $city $region $postal
    $company = $cd.companies[(Get-Random -Maximum $cd.companies.Count)]
    $jobTitle = $jobTitles[(Get-Random -Maximum $jobTitles.Count)]
    [int]$birthYear = 1958 + (Get-Random -Maximum 51)
    [int]$birthMonth = 1 + (Get-Random -Maximum 12)
    [int]$birthDay = 1 + (Get-Random -Maximum 28)
    $dob = '{0:D4}-{1:D2}-{2:D2}' -f $birthYear, $birthMonth, $birthDay
    
    # Generate additional data for identity type
    $mobile = & $cd.mobileFormat
    $workPhone = & $cd.phoneFormat
    $personalEmail = "$($firstName.ToLower()).$($lastName.ToLower().Replace(' ',''))@$($domains[(Get-Random -Maximum $domains.Count)])"
    $companyDomain = ($company.ToLower() -replace '[^a-z0-9]','') + '.com'
    $workEmail = "$($firstName.ToLower()).$($lastName.ToLower().Replace(' ',''))@$companyDomain"
    $workStreetNum = (Get-Random -Maximum 299) + 1
    $workStreet = $cd.streets[(Get-Random -Maximum $cd.streets.Count)]
    $workCity = $cd.cities[(Get-Random -Maximum $cd.cities.Count)]
    $workRegion = $cd.regions[(Get-Random -Maximum $cd.regions.Count)]
    $workPostal = & $cd.postalFormat
    $workAddress = & $cd.addressFormat $workStreetNum $workStreet $workCity $workRegion $workPostal
    
    $record = switch ($dataType) {
      'person' { [pscustomobject]@{ name=$fullName; email=$email; phone=$phone; address=$address; dob=$dob; country=$cd.countryCode } }
      'contact' { [pscustomobject]@{ firstName=$firstName; lastName=$lastName; email=$email; phone=$phone; country=$cd.countryCode } }
      'address' { [pscustomobject]@{ street="$street $streetNum"; city=$city; region=$region; postalCode=$postal; country=$cd.countryName; countryCode=$cd.countryCode } }
      'company' { [pscustomobject]@{ company=$company; contact=$fullName; email=$email; phone=$phone; country=$cd.countryCode } }
      'employee' { [pscustomobject]@{ name=$fullName; email=$email; jobTitle=$jobTitle; company=$company; phone=$phone; country=$cd.countryCode } }
      'identity' { 
        [pscustomobject]@{ 
          firstName = $firstName
          lastName = $lastName
          fullName = $fullName
          dateOfBirth = $dob
          personalEmail = $personalEmail
          mobile = $mobile
          phone = $phone
          address = $address
          street = "$street $streetNum"
          city = $city
          region = $region
          postalCode = $postal
          country = $cd.countryName
          countryCode = $cd.countryCode
          company = $company
          jobTitle = $jobTitle
          workEmail = $workEmail
          workPhone = $workPhone
          workAddress = $workAddress
          workStreet = "$workStreet $workStreetNum"
          workCity = $workCity
          workRegion = $workRegion
          workPostalCode = $workPostal
        } 
      }
    }
    $results.Add($record)
    
    if ($count -le 10) {
      $rowData = switch ($dataType) {
        'person' { @(($i+1), $fullName, $email, $phone) }
        'contact' { @(($i+1), $firstName, $lastName, $email) }
        'address' { @(($i+1), "$street $streetNum", $city, $postal) }
        'company' { @(($i+1), $company, $fullName, $email) }
        'employee' { @(($i+1), $fullName, $jobTitle, $company) }
        'identity' { @(($i+1), $fullName, $personalEmail, $company) }
      }
      $rows.Add($rowData)
    }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  $headers = switch ($dataType) {
    'person' { @('#','Name','Email','Phone') }
    'contact' { @('#','First Name','Last Name','Email') }
    'address' { @('#','Street','City','Postal Code') }
    'company' { @('#','Company','Contact','Email') }
    'employee' { @('#','Name','Job Title','Company') }
    'identity' { @('#','Name','Personal Email','Company') }
  }
  $typeNames = @{ person='Person'; contact='Contact'; address='Address'; company='Company'; employee='Employee'; identity='Full Identity' }
  
  if ($count -le 10) {
    Write-XY @{ table = @{ title="Fake $($typeNames[$dataType]) Data ($($cd.countryName))"; header=$headers; rows=$rows.ToArray(); caption="Generated $count record(s)" } }
  } else {
    Write-XY @{ table = @{ title="Fake $($typeNames[$dataType]) Data ($($cd.countryName))"; header=@('Property','Value'); rows=@(@('Type', $typeNames[$dataType]), @('Country', $cd.countryName), @('Count', $count), @('Sample', $results[0].name ?? $results[0].company ?? $results[0].street)); caption="Generated $count records (data in output)" } }
  }
  [pscustomobject]@{ tool='Fake Data Generator'; type=$dataType; country=$cd.countryCode; countryName=$cd.countryName; count=$count; data=$results.ToArray() }
}

# ------------------------- Syntax Validator
function Invoke-SyntaxValidator {
  param($Params, $JobInput, [string]$Cwd)
  Write-XYProgress 0.05 'Validating parameters...'
  
  $format = Get-Param $Params 'syntaxFormat' 'json'
  $source = Get-Param $Params 'syntaxSource' 'field'
  $saveFormatted = if ($Params.PSObject.Properties.Name -contains 'syntaxSaveFormatted') { [bool]$Params.syntaxSaveFormatted } else { $false }
  $content = ''
  $fileName = ''
  
  # Get input content
  switch ($source) {
    'field' { $content = Get-Param $Params 'syntaxInput' '' }
    'file' {
      $filePath = Get-Param $Params 'syntaxFilePath' ''
      if (-not $filePath) { throw 'File path is required when source is file' }
      $fullPath = if ([System.IO.Path]::IsPathRooted($filePath)) { $filePath } else { Join-Path $Cwd $filePath }
      if (-not (Test-Path $fullPath)) { throw "File not found: $fullPath" }
      $content = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
      $fileName = [System.IO.Path]::GetFileName($fullPath)
    }
    'input' {
      $inputData = $JobInput.data
      if (-not $inputData) { throw 'No input data available from previous job' }
      $path = Get-Param $Params 'syntaxDataPath' ''
      $val = Get-NestedValue $inputData $path
      if ($null -eq $val) { throw "Data path '$path' not found in input data" }
      $content = if ($val -is [string]) { $val } else { ($val | ConvertTo-Json -Compress -Depth 20) }
    }
  }
  
  if (-not $content.Trim()) { throw 'No content provided for validation' }
  
  Write-XYProgress 0.2 "Validating $($format.ToUpper())..."
  
  $valid = $true
  $errors = [System.Collections.Generic.List[string]]::new()
  $warnings = [System.Collections.Generic.List[string]]::new()
  $formatted = ''
  $stats = @{}
  
  switch ($format) {
    # -------------------- JSON --------------------
    'json' {
      try {
        $parsed = $content | ConvertFrom-Json -ErrorAction Stop
        $formatted = $parsed | ConvertTo-Json -Depth 50
        $stats['type'] = if ($content.Trim().StartsWith('[')) { 'Array' } else { 'Object' }
        $stats['depth'] = 0
        # Calculate depth
        $depthCount = 0; $maxDepth = 0
        foreach ($c in $content.ToCharArray()) {
          if ($c -eq '{' -or $c -eq '[') { $depthCount++; if ($depthCount -gt $maxDepth) { $maxDepth = $depthCount } }
          elseif ($c -eq '}' -or $c -eq ']') { $depthCount-- }
        }
        $stats['depth'] = $maxDepth
        $stats['keys'] = if ($parsed -is [array]) { $parsed.Count } else { ($parsed.PSObject.Properties | Measure-Object).Count }
      } catch {
        $valid = $false
        $errors.Add("JSON Parse Error: $($_.Exception.Message)")
      }
    }
    
    # -------------------- XML --------------------
    'xml' {
      try {
        $xmlDoc = [xml]$content
        # Pretty print XML
        $sw = [System.IO.StringWriter]::new()
        $xws = [System.Xml.XmlWriterSettings]::new()
        $xws.Indent = $true
        $xws.IndentChars = '  '
        $xws.OmitXmlDeclaration = $false
        $xw = [System.Xml.XmlWriter]::Create($sw, $xws)
        $xmlDoc.WriteTo($xw)
        $xw.Flush()
        $formatted = $sw.ToString()
        $stats['rootElement'] = $xmlDoc.DocumentElement.Name
        $stats['elements'] = ($xmlDoc.SelectNodes('//*') | Measure-Object).Count
        $stats['attributes'] = ($xmlDoc.SelectNodes('//@*') | Measure-Object).Count
        # Lint checks
        if (-not $content.Trim().StartsWith('<?xml')) { $warnings.Add('Missing XML declaration (<?xml version="1.0"?>)') }
        if ($xmlDoc.DocumentElement.NamespaceURI -and -not $xmlDoc.DocumentElement.Prefix) { $warnings.Add('Default namespace used without prefix - may cause XPath issues') }
      } catch {
        $valid = $false
        $errors.Add("XML Parse Error: $($_.Exception.Message)")
      }
    }
    
    # -------------------- YAML --------------------
    'yaml' {
      # Basic YAML validation (PowerShell doesn't have built-in YAML)
      $lines = $content -split "`n"
      $indentStack = [System.Collections.Generic.Stack[int]]::new()
      $indentStack.Push(0)
      $lineNum = 0
      $keyCount = 0
      $listItems = 0
      
      foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.TrimEnd()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        
        # Check for tabs
        if ($trimmed -match '^\t') { $errors.Add("Line ${lineNum}: Tabs are not allowed in YAML, use spaces"); $valid = $false }
        
        # Calculate indent
        $indent = 0
        foreach ($c in $line.ToCharArray()) { if ($c -eq ' ') { $indent++ } else { break } }
        
        # Validate indent consistency
        if ($indent % 2 -ne 0 -and $indent -gt 0) { $warnings.Add("Line ${lineNum}: Inconsistent indentation ($indent spaces), recommend 2-space increments") }
        
        # Check for key-value pairs
        if ($trimmed -match '^[\w][\w\s-]*:') { $keyCount++ }
        if ($trimmed.StartsWith('- ')) { $listItems++ }
        
        # Check for common errors
        if ($trimmed -match ':\s*\|\s*$' -or $trimmed -match ':\s*>\s*$') { } # Multiline OK
        elseif ($trimmed -match ':.*:' -and -not ($trimmed -match '".*:.*"' -or $trimmed -match "'.*:.*'")) {
          $warnings.Add("Line ${lineNum}: Multiple colons - ensure values with colons are quoted")
        }
        
        # Check unquoted special values
        if ($trimmed -match ':\s*(yes|no|on|off|true|false)\s*$' -and -not ($trimmed -match '"' -or $trimmed -match "'")) {
          $warnings.Add("Line ${lineNum}: Boolean-like value should be quoted to avoid ambiguity")
        }
      }
      
      if ($keyCount -eq 0 -and $listItems -eq 0) { $errors.Add('No valid YAML structure detected'); $valid = $false }
      
      $stats['keys'] = $keyCount
      $stats['listItems'] = $listItems
      $stats['lines'] = $lineNum
      
      # Format output (basic indentation cleanup)
      $formatted = ($lines | ForEach-Object { $_.TrimEnd() }) -join "`n"
    }
    
    # -------------------- Markdown --------------------
    'markdown' {
      $lines = $content -split "`n"
      $lineNum = 0
      $headings = [System.Collections.Generic.List[object]]::new()
      $links = 0; $images = 0; $codeBlocks = 0; $inCodeBlock = $false
      $lastHeadingLevel = 0
      
      foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.TrimEnd()
        
        # Code blocks
        if ($trimmed -match '^```') {
          $inCodeBlock = -not $inCodeBlock
          $codeBlocks++
          continue
        }
        if ($inCodeBlock) { continue }
        
        # Headings
        if ($trimmed -match '^(#{1,6})\s+(.+)$') {
          $level = $Matches[1].Length
          $text = $Matches[2]
          $headings.Add([pscustomobject]@{ level=$level; text=$text; line=$lineNum })
          
          # Lint: heading hierarchy
          if ($level -gt $lastHeadingLevel + 1 -and $lastHeadingLevel -gt 0) {
            $warnings.Add("Line ${lineNum}: Heading level skipped (H$lastHeadingLevel to H$level)")
          }
          $lastHeadingLevel = $level
          
          # Lint: no space after #
          if ($line -match '^#+[^\s#]') { $warnings.Add("Line ${lineNum}: Missing space after heading marker") }
        }
        
        # Links
        $linkMatches = [regex]::Matches($trimmed, '\[([^\]]+)\]\(([^)]+)\)')
        $links += $linkMatches.Count
        foreach ($m in $linkMatches) {
          $url = $m.Groups[2].Value
          if ($url -notmatch '^(https?://|mailto:|#|/)' -and $url -notmatch '\.\w+$') {
            $warnings.Add("Line ${lineNum}: Potentially invalid link: $url")
          }
        }
        
        # Images
        $images += ([regex]::Matches($trimmed, '!\[([^\]]*)\]\(([^)]+)\)')).Count
        
        # Lint: trailing whitespace
        if ($line -match '\s{3,}$') { $warnings.Add("Line ${lineNum}: Excessive trailing whitespace") }
        
        # Lint: hard tabs
        if ($line -match '\t' -and -not $inCodeBlock) { $warnings.Add("Line ${lineNum}: Tab character found, prefer spaces") }
        
        # Lint: multiple blank lines
        if ($lineNum -gt 1 -and -not $trimmed -and -not $lines[$lineNum - 2].Trim()) {
          # Skip duplicate warnings
        }
      }
      
      if ($inCodeBlock) { $errors.Add('Unclosed code block (missing closing ```)'); $valid = $false }
      if ($headings.Count -eq 0) { $warnings.Add('No headings found in document') }
      if ($headings.Count -gt 0 -and $headings[0].level -ne 1) { $warnings.Add('Document should start with H1 heading') }
      
      $stats['headings'] = $headings.Count
      $stats['links'] = $links
      $stats['images'] = $images
      $stats['codeBlocks'] = [Math]::Floor($codeBlocks / 2)
      $stats['lines'] = $lineNum
      
      $formatted = $content
    }
    
    # -------------------- CSV --------------------
    'csv' {
      $lines = @($content -split "`n" | Where-Object { $_.Trim() })
      if ($lines.Count -eq 0) { $errors.Add('Empty CSV content'); $valid = $false }
      else {
        # Detect delimiter
        $firstLine = $lines[0]
        $delimiterCandidates = @(',', ';', "`t", '|')
        $delimiterCounts = @{}
        foreach ($d in $delimiterCandidates) { $delimiterCounts[$d] = @($firstLine.ToCharArray() | Where-Object { $_ -eq $d }).Count }
        $delimiter = ($delimiterCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
        if ($delimiterCounts[$delimiter] -eq 0) { $delimiter = ',' }
        
        # Parse and validate
        $headerCols = ($firstLine -split [regex]::Escape($delimiter)).Count
        $rowNum = 0
        $maxCols = $headerCols
        $minCols = $headerCols
        
        foreach ($line in $lines) {
          $rowNum++
          $cols = ($line -split [regex]::Escape($delimiter)).Count
          if ($cols -ne $headerCols) {
            $errors.Add("Row ${rowNum}: Column count mismatch (expected $headerCols, got $cols)")
            $valid = $false
          }
          if ($cols -gt $maxCols) { $maxCols = $cols }
          if ($cols -lt $minCols) { $minCols = $cols }
          
          # Check for unescaped quotes
          $quoteCount = @($line.ToCharArray() | Where-Object { $_ -eq '"' }).Count
          if ($quoteCount % 2 -ne 0) { $warnings.Add("Row ${rowNum}: Unbalanced quotes") }
        }
        
        $stats['rows'] = $rowNum
        $stats['columns'] = $headerCols
        $stats['delimiter'] = switch ($delimiter) { ',' { 'Comma' }; ';' { 'Semicolon' }; "`t" { 'Tab' }; '|' { 'Pipe' }; default { $delimiter } }
        
        # Format CSV (align columns for display)
        try {
          $csvData = $content | ConvertFrom-Csv -Delimiter $delimiter -ErrorAction Stop
          $formatted = ($csvData | ConvertTo-Csv -Delimiter $delimiter -NoTypeInformation) -join "`n"
        } catch {
          $formatted = $content
          $warnings.Add("Could not parse CSV for formatting: $($_.Exception.Message)")
        }
      }
    }
    
    # -------------------- TOML --------------------
    'toml' {
      $lines = $content -split "`n"
      $lineNum = 0
      $sections = [System.Collections.Generic.List[string]]::new()
      $keyCount = 0
      $currentSection = 'root'
      
      foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        
        # Section headers
        if ($trimmed -match '^\[\[?([^\]]+)\]\]?$') {
          $currentSection = $Matches[1]
          $sections.Add($currentSection)
          continue
        }
        
        # Key-value pairs
        if ($trimmed -match '^([\w.-]+)\s*=\s*(.+)$') {
          $key = $Matches[1]
          $value = $Matches[2]
          $keyCount++
          
          # Validate value types
          if ($value -match '^".*[^\\]"$' -or $value -match "^'.*'$") { } # String OK
          elseif ($value -match '^-?\d+$') { } # Integer OK
          elseif ($value -match '^-?\d+\.\d+$') { } # Float OK
          elseif ($value -match '^(true|false)$') { } # Boolean OK
          elseif ($value -match '^\d{4}-\d{2}-\d{2}') { } # Date OK
          elseif ($value -match '^\[') { } # Array OK
          elseif ($value -match '^\{') { } # Inline table OK
          else { $warnings.Add("Line ${lineNum}: Unquoted string value for key '$key'") }
        }
        elseif (-not $trimmed.StartsWith('[')) {
          $errors.Add("Line ${lineNum}: Invalid TOML syntax")
          $valid = $false
        }
      }
      
      $stats['sections'] = $sections.Count
      $stats['keys'] = $keyCount
      $stats['lines'] = $lineNum
      $formatted = $content
    }
    
    # -------------------- HTML --------------------
    'html' {
      # Basic HTML validation
      $tagStack = [System.Collections.Generic.Stack[string]]::new()
      $selfClosing = @('area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr')
      
      # Find all tags
      $tagMatches = [regex]::Matches($content, '<(/?)([\w-]+)([^>]*?)(/?)>')
      $tagCount = 0
      
      foreach ($m in $tagMatches) {
        $isClose = $m.Groups[1].Value -eq '/'
        $tagName = $m.Groups[2].Value.ToLower()
        $isSelfClose = $m.Groups[4].Value -eq '/' -or $selfClosing -contains $tagName
        $tagCount++
        
        if ($isClose) {
          if ($tagStack.Count -eq 0) {
            $errors.Add("Unexpected closing tag: </$tagName>")
            $valid = $false
          }
          elseif ($tagStack.Peek() -ne $tagName) {
            $errors.Add("Mismatched tag: expected </$($tagStack.Peek())>, found </$tagName>")
            $valid = $false
            $tagStack.Pop() | Out-Null
          }
          else {
            $tagStack.Pop() | Out-Null
          }
        }
        elseif (-not $isSelfClose) {
          $tagStack.Push($tagName)
        }
      }
      
      while ($tagStack.Count -gt 0) {
        $unclosed = $tagStack.Pop()
        $errors.Add("Unclosed tag: <$unclosed>")
        $valid = $false
      }
      
      # Lint checks
      if ($content -notmatch '<!DOCTYPE\s+html' -and $content -match '<html') {
        $warnings.Add('Missing DOCTYPE declaration')
      }
      if ($content -match '<html' -and $content -notmatch '<html[^>]*lang=') {
        $warnings.Add('Missing lang attribute on <html> tag')
      }
      if ($content -match '<img' -and $content -notmatch '<img[^>]*alt=') {
        $warnings.Add('Image tag(s) missing alt attribute')
      }
      if ($content -match '<head' -and $content -notmatch '<meta[^>]*charset') {
        $warnings.Add('Missing charset meta tag')
      }
      
      $stats['tags'] = $tagCount
      $stats['hasDoctype'] = $content -match '<!DOCTYPE'
      $stats['hasHead'] = $content -match '<head'
      $stats['hasBody'] = $content -match '<body'
      
      # Basic formatting (indent)
      $formatted = $content -replace '>\s*<', ">\n<"
    }
    
    # -------------------- INI --------------------
    'ini' {
      $lines = $content -split "`n"
      $lineNum = 0
      $sections = [System.Collections.Generic.List[string]]::new()
      $keyCount = 0
      $currentSection = 'global'
      
      foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#')) { continue }
        
        # Section
        if ($trimmed -match '^\[([^\]]+)\]$') {
          $currentSection = $Matches[1]
          $sections.Add($currentSection)
          continue
        }
        
        # Key=Value
        if ($trimmed -match '^([^=]+)=(.*)$') {
          $keyCount++
        }
        else {
          $errors.Add("Line ${lineNum}: Invalid INI syntax")
          $valid = $false
        }
      }
      
      $stats['sections'] = $sections.Count
      $stats['keys'] = $keyCount
      $stats['lines'] = $lineNum
      $formatted = $content
    }
    
    # -------------------- Properties --------------------
    'properties' {
      $lines = $content -split "`n"
      $lineNum = 0
      $keyCount = 0
      $continuations = 0
      
      foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.TrimStart()
        if (-not $trimmed -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('!')) { continue }
        
        # Check for continuation
        if ($line.EndsWith('\')) { $continuations++; continue }
        
        # Key=Value or Key:Value or Key Value
        if ($trimmed -match '^([^=:\s]+)\s*[=:]\s*(.*)$' -or $trimmed -match '^([^\s]+)\s+(.+)$') {
          $keyCount++
          $key = $Matches[1]
          
          # Lint: check for special characters in key
          if ($key -match '[^\w.-]') { $warnings.Add("Line ${lineNum}: Key '$key' contains special characters") }
        }
        elseif ($trimmed) {
          $warnings.Add("Line ${lineNum}: Ambiguous syntax - could not parse key-value pair")
        }
      }
      
      $stats['keys'] = $keyCount
      $stats['continuations'] = $continuations
      $stats['lines'] = $lineNum
      $formatted = $content
    }
  }
  
  Write-XYProgress 0.8 'Generating output...'
  
  # Build summary rows
  $summaryRows = @(
    @('Format', $format.ToUpper()),
    @('Valid', $(if ($valid) { 'Yes' } else { 'No' })),
    @('Errors', $errors.Count),
    @('Warnings', $warnings.Count),
    @('Size', "$($content.Length) chars")
  )
  $statsKeyNames = @{
    'type'='Type'; 'depth'='Nesting Depth'; 'keys'='Keys/Properties'
    'rootElement'='Root Element'; 'elements'='Elements'; 'attributes'='Attributes'
    'listItems'='List Items'; 'lines'='Lines'; 'headings'='Headings'
    'links'='Links'; 'images'='Images'; 'codeBlocks'='Code Blocks'
    'rows'='Rows'; 'columns'='Columns'; 'delimiter'='Delimiter'
    'sections'='Sections'; 'tags'='HTML Tags'; 'continuations'='Line Continuations'
    'hasDoctype'='Has DOCTYPE'; 'hasHead'='Has <head>'; 'hasBody'='Has <body>'
  }
  $statsEntries = @($stats.GetEnumerator())
  foreach ($entry in $statsEntries) {
    $statKey = $entry.Key
    $statVal = $entry.Value
    $displayKey = if ($statsKeyNames.ContainsKey($statKey)) { $statsKeyNames[$statKey] } else { [string]$statKey }
    $displayVal = if ($statVal -is [bool]) { if ($statVal) { 'Yes' } else { 'No' } } else { $statVal }
    $summaryRows += ,@($displayKey, $displayVal)
  }
  
  Write-XY @{ table = @{ title="$($format.ToUpper()) Validation Results"; header=@('Property','Value'); rows=$summaryRows; caption=$(if ($valid) { 'Validation passed' } else { 'Validation failed' }) } }
  
  if ($errors.Count -gt 0) {
    $errorRows = for ($i = 0; $i -lt [Math]::Min($errors.Count, 20); $i++) { ,@(($i + 1), $errors[$i]) }
    Write-XY @{ table = @{ title='Errors'; header=@('#','Error'); rows=$errorRows; caption=$(if ($errors.Count -gt 20) { "Showing 20 of $($errors.Count) errors" } else { '' }) } }
  }
  
  if ($warnings.Count -gt 0) {
    $warnRows = for ($i = 0; $i -lt [Math]::Min($warnings.Count, 20); $i++) { ,@(($i + 1), $warnings[$i]) }
    Write-XY @{ table = @{ title='Warnings (Lint)'; header=@('#','Warning'); rows=$warnRows; caption=$(if ($warnings.Count -gt 20) { "Showing 20 of $($warnings.Count) warnings" } else { '' }) } }
  }
  
  # Show formatted preview
  if ($valid -and $formatted) {
    $preview = if ($formatted.Length -gt 2000) { $formatted.Substring(0, 2000) + "`n... (truncated)" } else { $formatted }
    Write-XY @{ text = @{ title='Formatted Output'; content=$preview; caption='' } }
  }
  
  # Save formatted file
  $outputFiles = @()
  if ($saveFormatted -and $valid -and $formatted) {
    $ext = switch ($format) {
      'json' { 'json' }; 'xml' { 'xml' }; 'yaml' { 'yaml' }; 'markdown' { 'md' }
      'csv' { 'csv' }; 'toml' { 'toml' }; 'html' { 'html' }; 'ini' { 'ini' }
      'properties' { 'properties' }; default { 'txt' }
    }
    $outName = if ($fileName) { [System.IO.Path]::GetFileNameWithoutExtension($fileName) + ".formatted.$ext" } else { "formatted.$ext" }
    $outPath = Join-Path $Cwd $outName
    [System.IO.File]::WriteAllText($outPath, $formatted, [System.Text.Encoding]::UTF8)
    $outputFiles += $outName
    Write-XY @{ files = $outputFiles }
  }
  
  Write-XYProgress 0.95 'Finalizing...'
  
  [pscustomobject]@{
    tool = 'Syntax Validator'
    format = $format
    valid = $valid
    errors = $errors.ToArray()
    warnings = $warnings.ToArray()
    errorCount = $errors.Count
    warningCount = $warnings.Count
    stats = $stats
    inputSize = $content.Length
    formattedOutput = $(if ($saveFormatted -and $valid) { $formatted } else { $null })
    outputFiles = $outputFiles
  }
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
    'loremIpsum'     { $result = Invoke-LoremIpsum -Params $params -Cwd $cwd }
    'base64'         { $result = Invoke-Base64 -Params $params -JobInput $jobInput }
    'urlEncode'      { $result = Invoke-UrlEncode -Params $params -JobInput $jobInput }
    'timestamp'      { $result = Invoke-TimestampConverter -Params $params -JobInput $jobInput }
    'jsonFormatter'  { $result = Invoke-JsonFormatter -Params $params -JobInput $jobInput }
    'caseConverter'  { $result = Invoke-CaseConverter -Params $params -JobInput $jobInput }
    'colorConverter' { $result = Invoke-ColorConverter -Params $params -JobInput $jobInput -Cwd $cwd }
    'imageConverter' { $result = Invoke-ImageConverter -Params $params -JobInput $jobInput -Cwd $cwd }
    'slugGenerator'  { $result = Invoke-SlugGenerator -Params $params -JobInput $jobInput }
    'textStatistics' { $result = Invoke-TextStatistics -Params $params -JobInput $jobInput }
    'creditCardValidator' { $result = Invoke-CreditCardValidator -Params $params -JobInput $jobInput }
    'emailValidator' { $result = Invoke-EmailValidator -Params $params -JobInput $jobInput }
    'barcodeGenerator' { $result = Invoke-BarcodeGenerator -Params $params -JobInput $jobInput -Cwd $cwd }
    'fakeDataGenerator' { $result = Invoke-FakeDataGenerator -Params $params }
    'syntaxValidator' { $result = Invoke-SyntaxValidator -Params $params -JobInput $jobInput -Cwd $cwd }
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
