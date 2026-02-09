#!/usr/bin/env node

/**
 * xkOps Toolbox Event Plugin (c) 2026 Tim Alderweireldt
 * 
 * A collection of utility tools for xyOps including:
 * - Token Generator: Generate random strings with customizable character sets
 * - UUID Generator: Generate UUIDs in various versions (v1, v4, v6, v7, nil, max)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const figlet = require('figlet');

// ============================================
// STDIN READER
// ============================================

async function readStdin() {
	const chunks = [];
	for await (const chunk of process.stdin) {
		chunks.push(chunk);
	}
	return JSON.parse(chunks.join(''));
}

// ============================================
// OUTPUT HELPERS
// ============================================

function output(obj) {
	console.log(JSON.stringify({ xy: 1, ...obj }));
}

function progress(value, status) {
	const obj = { progress: value };
	if (status) obj.status = status;
	output(obj);
}

function success(data, description) {
	const obj = { code: 0, data };
	if (description) obj.description = description;
	output(obj);
}

function error(code, description) {
	output({ code, description });
}

// ============================================
// TOKEN GENERATOR
// ============================================

const CHAR_SETS = {
	uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	lowercase: 'abcdefghijklmnopqrstuvwxyz',
	numbers: '0123456789',
	symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

function generateToken(length, options) {
	let chars = '';
	
	if (options.includeUppercase) chars += CHAR_SETS.uppercase;
	if (options.includeLowercase) chars += CHAR_SETS.lowercase;
	if (options.includeNumbers) chars += CHAR_SETS.numbers;
	if (options.includeSymbols) chars += CHAR_SETS.symbols;
	
	if (chars.length === 0) {
		throw new Error('At least one character set must be selected');
	}
	
	let token = '';
	const randomBytes = crypto.randomBytes(length);
	for (let i = 0; i < length; i++) {
		token += chars.charAt(randomBytes[i] % chars.length);
	}
	
	return token;
}

function runTokenGenerator(params) {
	progress(0.1, 'Validating parameters...');
	
	const length = Math.min(1024, Math.max(1, parseInt(params.tokenLength) || 64));
	const count = Math.min(100, Math.max(1, parseInt(params.tokenCount) || 1));
	
	const options = {
		includeUppercase: params.includeUppercase !== false,
		includeLowercase: params.includeLowercase !== false,
		includeNumbers: params.includeNumbers !== false,
		includeSymbols: params.includeSymbols === true
	};
	
	// Check if at least one option is selected
	if (!options.includeUppercase && !options.includeLowercase && 
		!options.includeNumbers && !options.includeSymbols) {
		throw new Error('At least one character set must be selected');
	}
	
	progress(0.3, `Generating ${count} token(s)...`);
	
	const tokens = [];
	for (let i = 0; i < count; i++) {
		tokens.push(generateToken(length, options));
		if (count > 1) {
			progress(0.3 + (0.6 * (i + 1) / count), `Generated ${i + 1} of ${count} tokens...`);
		}
	}
	
	progress(0.95, 'Finalizing...');
	
	// Build character set description
	const charSets = [];
	if (options.includeUppercase) charSets.push('uppercase');
	if (options.includeLowercase) charSets.push('lowercase');
	if (options.includeNumbers) charSets.push('numbers');
	if (options.includeSymbols) charSets.push('symbols');
	
	const result = {
		tool: 'Token Generator',
		tokens: tokens,
		count: count,
		length: length,
		characterSets: charSets
	};
	
	// Output table for UI
	output({
		table: {
			title: 'Generated Tokens',
			header: ['#', 'Token'],
			rows: tokens.map((token, i) => [i + 1, token]),
			caption: `Generated ${count} token(s) with length ${length} using: ${charSets.join(', ')}`
		}
	});
	
	return result;
}

// ============================================
// UUID GENERATOR
// ============================================

/**
 * Generate UUID v1 (time-based)
 * Format: time_low-time_mid-time_hi_and_version-clock_seq-node
 */
function generateUUIDv1() {
	// Get current timestamp in 100-nanosecond intervals since Oct 15, 1582
	const now = Date.now();
	const gregOffset = 122192928000000000n; // Offset from Unix epoch to Gregorian calendar
	const timestamp = BigInt(now) * 10000n + gregOffset;
	
	const timeLow = Number(timestamp & 0xffffffffn);
	const timeMid = Number((timestamp >> 32n) & 0xffffn);
	const timeHiAndVersion = Number((timestamp >> 48n) & 0x0fffn) | 0x1000;
	
	// Clock sequence (random)
	const clockSeq = crypto.randomInt(0x3fff) | 0x8000;
	
	// Node (random, with multicast bit set)
	const node = crypto.randomBytes(6);
	node[0] = node[0] | 0x01; // Set multicast bit
	
	return formatUUIDComponents(timeLow, timeMid, timeHiAndVersion, clockSeq, node);
}

/**
 * Generate UUID v4 (random)
 */
function generateUUIDv4() {
	const bytes = crypto.randomBytes(16);
	
	// Set version (4) and variant (RFC 4122)
	bytes[6] = (bytes[6] & 0x0f) | 0x40;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	
	return bytesToUUID(bytes);
}

/**
 * Generate UUID v6 (reordered time-based, draft RFC)
 */
function generateUUIDv6() {
	const now = Date.now();
	const gregOffset = 122192928000000000n;
	const timestamp = BigInt(now) * 10000n + gregOffset;
	
	// Reorder timestamp for better sorting
	const timeHigh = Number((timestamp >> 28n) & 0xffffffffn);
	const timeMid = Number((timestamp >> 12n) & 0xffffn);
	const timeLowAndVersion = Number(timestamp & 0x0fffn) | 0x6000;
	
	const clockSeq = crypto.randomInt(0x3fff) | 0x8000;
	const node = crypto.randomBytes(6);
	node[0] = node[0] | 0x01;
	
	return formatUUIDComponents(timeHigh, timeMid, timeLowAndVersion, clockSeq, node);
}

/**
 * Generate UUID v7 (Unix Epoch time-based, draft RFC)
 */
function generateUUIDv7() {
	const now = Date.now();
	const bytes = Buffer.alloc(16);
	
	// First 48 bits: Unix timestamp in milliseconds
	bytes[0] = (now / 0x10000000000) & 0xff;
	bytes[1] = (now / 0x100000000) & 0xff;
	bytes[2] = (now / 0x1000000) & 0xff;
	bytes[3] = (now / 0x10000) & 0xff;
	bytes[4] = (now / 0x100) & 0xff;
	bytes[5] = now & 0xff;
	
	// Random data for remaining bits
	const random = crypto.randomBytes(10);
	random.copy(bytes, 6);
	
	// Set version (7) and variant (RFC 4122)
	bytes[6] = (bytes[6] & 0x0f) | 0x70;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	
	return bytesToUUID(bytes);
}

/**
 * Generate Nil UUID (all zeros)
 */
function generateNilUUID() {
	return '00000000-0000-0000-0000-000000000000';
}

/**
 * Generate Max UUID (all ones)
 */
function generateMaxUUID() {
	return 'ffffffff-ffff-ffff-ffff-ffffffffffff';
}

function formatUUIDComponents(timeLow, timeMid, timeHiAndVersion, clockSeq, node) {
	const hex = (n, len) => n.toString(16).padStart(len, '0');
	const nodeHex = Buffer.from(node).toString('hex');
	
	return `${hex(timeLow, 8)}-${hex(timeMid, 4)}-${hex(timeHiAndVersion, 4)}-${hex(clockSeq, 4)}-${nodeHex}`;
}

function bytesToUUID(bytes) {
	const hex = bytes.toString('hex');
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function formatUUID(uuid, format) {
	switch (format) {
		case 'uppercase':
			return uuid.toUpperCase();
		case 'nodashes':
			return uuid.replace(/-/g, '');
		case 'urn':
			return `urn:uuid:${uuid}`;
		case 'standard':
		default:
			return uuid.toLowerCase();
	}
}

function runUUIDGenerator(params) {
	progress(0.1, 'Validating parameters...');
	
	const version = params.uuidVersion || 'v4';
	const format = params.uuidFormat || 'standard';
	const count = Math.min(100, Math.max(1, parseInt(params.uuidCount) || 1));
	
	const generators = {
		v1: generateUUIDv1,
		v4: generateUUIDv4,
		v6: generateUUIDv6,
		v7: generateUUIDv7,
		nil: generateNilUUID,
		max: generateMaxUUID
	};
	
	const generator = generators[version];
	if (!generator) {
		throw new Error(`Unknown UUID version: ${version}`);
	}
	
	progress(0.3, `Generating ${count} UUID(s) (${version})...`);
	
	const uuids = [];
	for (let i = 0; i < count; i++) {
		const uuid = formatUUID(generator(), format);
		uuids.push(uuid);
		if (count > 1) {
			progress(0.3 + (0.6 * (i + 1) / count), `Generated ${i + 1} of ${count} UUIDs...`);
		}
	}
	
	progress(0.95, 'Finalizing...');
	
	const versionNames = {
		v1: 'v1 (Time-based)',
		v4: 'v4 (Random)',
		v6: 'v6 (Reordered Time-based)',
		v7: 'v7 (Unix Epoch Time-based)',
		nil: 'Nil (All zeros)',
		max: 'Max (All ones)'
	};
	
	const formatNames = {
		standard: 'Standard (lowercase)',
		uppercase: 'Uppercase',
		nodashes: 'No dashes',
		urn: 'URN format'
	};
	
	const result = {
		tool: 'UUID Generator',
		uuids: uuids,
		count: count,
		version: version,
		versionName: versionNames[version],
		format: format,
		formatName: formatNames[format]
	};
	
	// Output table for UI
	output({
		table: {
			title: 'Generated UUIDs',
			header: ['#', 'UUID'],
			rows: uuids.map((uuid, i) => [i + 1, uuid]),
			caption: `Generated ${count} ${versionNames[version]} UUID(s) in ${formatNames[format]} format`
		}
	});
	
	return result;
}

// ============================================
// HASH TEXT
// ============================================

const HASH_ALGORITHMS = [
	{ id: 'md5', name: 'MD5', algorithm: 'md5' },
	{ id: 'sha1', name: 'SHA1', algorithm: 'sha1' },
	{ id: 'sha256', name: 'SHA256', algorithm: 'sha256' },
	{ id: 'sha224', name: 'SHA224', algorithm: 'sha224' },
	{ id: 'sha512', name: 'SHA512', algorithm: 'sha512' },
	{ id: 'sha384', name: 'SHA384', algorithm: 'sha384' },
	{ id: 'sha3', name: 'SHA3', algorithm: 'sha3-256' },
	{ id: 'ripemd160', name: 'RIPEMD160', algorithm: 'ripemd160' }
];

function computeHash(text, algorithm, encoding) {
	try {
		return crypto.createHash(algorithm).update(text, 'utf8').digest(encoding);
	} catch (err) {
		return `[Not supported: ${err.message}]`;
	}
}

function getNestedValue(obj, path) {
	if (!path || path.trim() === '') return obj;
	const parts = path.split('.');
	let current = obj;
	for (const part of parts) {
		if (current === null || current === undefined) return undefined;
		current = current[part];
	}
	return current;
}

function runHashText(params, jobInput) {
	progress(0.1, 'Validating parameters...');
	
	const source = params.hashSource || 'field';
	const encoding = params.hashEncoding || 'hex';
	let text = '';
	
	if (source === 'input') {
		// Get text from job input data
		const inputData = jobInput?.data;
		if (!inputData) {
			throw new Error('No input data available from previous job');
		}
		const dataPath = params.hashDataPath || '';
		const value = getNestedValue(inputData, dataPath);
		if (value === undefined) {
			throw new Error(`Data path '${dataPath}' not found in input data`);
		}
		// Convert to string if needed
		text = typeof value === 'string' ? value : JSON.stringify(value);
	} else {
		// Get text from parameter field
		text = params.hashInput || '';
	}
	
	progress(0.2, 'Computing hashes...');
	
	const hashes = {};
	const rows = [];
	
	for (let i = 0; i < HASH_ALGORITHMS.length; i++) {
		const algo = HASH_ALGORITHMS[i];
		const hash = computeHash(text, algo.algorithm, encoding);
		hashes[algo.id] = hash;
		rows.push([algo.name, hash]);
		progress(0.2 + (0.7 * (i + 1) / HASH_ALGORITHMS.length), `Computed ${algo.name}...`);
	}
	
	progress(0.95, 'Finalizing...');
	
	const encodingNames = {
		hex: 'Hexadecimal (base 16)',
		base64: 'Base64',
		binary: 'Binary (raw)'
	};
	
	const result = {
		tool: 'Hash Text',
		inputLength: text.length,
		encoding: encoding,
		encodingName: encodingNames[encoding],
		hashes: hashes
	};
	
	// Output table for UI
	output({
		table: {
			title: 'Hash Results',
			header: ['Algorithm', 'Hash'],
			rows: rows,
			caption: `Hashed ${text.length} character(s) using ${encodingNames[encoding]} encoding`
		}
	});
	
	return result;
}

// ============================================
// QR CODE GENERATOR
// ============================================

async function runQRCode(params, jobInput, cwd) {
	progress(0.1, 'Validating parameters...');
	
	const source = params.qrSource || 'field';
	let text = '';
	
	if (source === 'input') {
		const inputData = jobInput?.data;
		if (!inputData) {
			throw new Error('No input data available from previous job');
		}
		const dataPath = params.qrDataPath || '';
		const value = getNestedValue(inputData, dataPath);
		if (value === undefined) {
			throw new Error(`Data path '${dataPath}' not found in input data`);
		}
		text = typeof value === 'string' ? value : JSON.stringify(value);
	} else {
		text = params.qrText || '';
	}
	
	if (!text) {
		throw new Error('No text or URL provided for QR code');
	}
	
	const foreground = params.qrForeground || '#000000';
	const background = params.qrBackground || '#ffffff';
	const errorLevel = params.qrErrorLevel || 'M';
	const size = Math.min(1024, Math.max(64, parseInt(params.qrSize) || 256));
	const filename = params.qrFilename || 'qrcode.png';
	
	progress(0.3, 'Generating QR code...');
	
	const options = {
		errorCorrectionLevel: errorLevel,
		width: size,
		margin: 2,
		color: {
			dark: foreground,
			light: background
		}
	};
	
	// Generate QR code as PNG file
	const filePath = path.join(cwd, filename);
	await QRCode.toFile(filePath, text, options);
	
	progress(0.8, 'QR code generated...');
	
	// Get file stats
	const stats = fs.statSync(filePath);
	
	progress(0.95, 'Finalizing...');
	
	const errorLevelNames = {
		L: 'Low (~7%)',
		M: 'Medium (~15%)',
		Q: 'Quartile (~25%)',
		H: 'High (~30%)'
	};
	
	const result = {
		tool: 'QR Code Generator',
		text: text,
		textLength: text.length,
		filename: filename,
		fileSize: stats.size,
		size: size,
		errorLevel: errorLevel,
		errorLevelName: errorLevelNames[errorLevel],
		foregroundColor: foreground,
		backgroundColor: background
	};
	
	// Output file for xyOps (array of filenames in cwd)
	output({
		files: [filename]
	});
	
	// Output table for UI
	output({
		table: {
			title: 'QR Code Generated',
			header: ['Property', 'Value'],
			rows: [
				['Content', text.length > 50 ? text.substring(0, 50) + '...' : text],
				['Image Size', `${size}x${size} pixels`],
				['Error Correction', errorLevelNames[errorLevel]],
				['Foreground', foreground],
				['Background', background],
				['File', filename],
				['File Size', `${stats.size} bytes`]
			],
			caption: `QR code saved as ${filename}`
		}
	});
	
	return result;
}

// ============================================
// IBAN VALIDATOR
// ============================================

// IBAN country codes and their expected lengths
const IBAN_LENGTHS = {
	AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20, BR: 29,
	BG: 22, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28, TL: 23, EE: 20,
	EG: 29, SV: 28, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22, GI: 23, GR: 27,
	GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22, IL: 23, IT: 27, JO: 30,
	KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LY: 25, LI: 21, LT: 20, LU: 20,
	MK: 19, MT: 31, MR: 27, MU: 30, MC: 27, MD: 24, ME: 22, NL: 18, NO: 15,
	PK: 24, PS: 29, PL: 28, PT: 25, QA: 29, RO: 24, LC: 32, SM: 27, ST: 25,
	SA: 24, RS: 22, SC: 31, SK: 24, SI: 19, ES: 24, SD: 18, SE: 24, CH: 21,
	TN: 24, TR: 26, UA: 29, AE: 23, GB: 22, VA: 22, VG: 24
};

const COUNTRY_NAMES = {
	AL: 'Albania', AD: 'Andorra', AT: 'Austria', AZ: 'Azerbaijan', BH: 'Bahrain',
	BY: 'Belarus', BE: 'Belgium', BA: 'Bosnia and Herzegovina', BR: 'Brazil',
	BG: 'Bulgaria', CR: 'Costa Rica', HR: 'Croatia', CY: 'Cyprus', CZ: 'Czech Republic',
	DK: 'Denmark', DO: 'Dominican Republic', TL: 'East Timor', EE: 'Estonia',
	EG: 'Egypt', SV: 'El Salvador', FO: 'Faroe Islands', FI: 'Finland', FR: 'France',
	GE: 'Georgia', DE: 'Germany', GI: 'Gibraltar', GR: 'Greece', GL: 'Greenland',
	GT: 'Guatemala', HU: 'Hungary', IS: 'Iceland', IQ: 'Iraq', IE: 'Ireland',
	IL: 'Israel', IT: 'Italy', JO: 'Jordan', KZ: 'Kazakhstan', XK: 'Kosovo',
	KW: 'Kuwait', LV: 'Latvia', LB: 'Lebanon', LY: 'Libya', LI: 'Liechtenstein',
	LT: 'Lithuania', LU: 'Luxembourg', MK: 'North Macedonia', MT: 'Malta',
	MR: 'Mauritania', MU: 'Mauritius', MC: 'Monaco', MD: 'Moldova', ME: 'Montenegro',
	NL: 'Netherlands', NO: 'Norway', PK: 'Pakistan', PS: 'Palestine', PL: 'Poland',
	PT: 'Portugal', QA: 'Qatar', RO: 'Romania', LC: 'Saint Lucia', SM: 'San Marino',
	ST: 'Sao Tome and Principe', SA: 'Saudi Arabia', RS: 'Serbia', SC: 'Seychelles',
	SK: 'Slovakia', SI: 'Slovenia', ES: 'Spain', SD: 'Sudan', SE: 'Sweden',
	CH: 'Switzerland', TN: 'Tunisia', TR: 'Turkey', UA: 'Ukraine',
	AE: 'United Arab Emirates', GB: 'United Kingdom', VA: 'Vatican City',
	VG: 'British Virgin Islands'
};

function validateIBAN(iban) {
	// Remove spaces and convert to uppercase
	const cleanIban = iban.replace(/\s/g, '').toUpperCase();
	
	// Check basic format (letters and digits only)
	if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(cleanIban)) {
		return { valid: false, error: 'Invalid IBAN format. Must start with 2 letters, 2 digits, then alphanumeric characters.' };
	}
	
	const countryCode = cleanIban.substring(0, 2);
	const checkDigits = cleanIban.substring(2, 4);
	const bban = cleanIban.substring(4);
	
	// Check country code
	if (!IBAN_LENGTHS[countryCode]) {
		return { valid: false, error: `Unknown country code: ${countryCode}` };
	}
	
	// Check length
	const expectedLength = IBAN_LENGTHS[countryCode];
	if (cleanIban.length !== expectedLength) {
		return { 
			valid: false, 
			error: `Invalid length for ${countryCode}. Expected ${expectedLength} characters, got ${cleanIban.length}.` 
		};
	}
	
	// Validate check digits using MOD-97 algorithm
	// Move first 4 chars to end, replace letters with numbers (A=10, B=11, etc.)
	const rearranged = cleanIban.substring(4) + cleanIban.substring(0, 4);
	let numericString = '';
	for (const char of rearranged) {
		if (/[0-9]/.test(char)) {
			numericString += char;
		} else {
			numericString += (char.charCodeAt(0) - 55).toString(); // A=10, B=11, etc.
		}
	}
	
	// Calculate MOD 97 using string-based division (for large numbers)
	let remainder = 0;
	for (const digit of numericString) {
		remainder = (remainder * 10 + parseInt(digit)) % 97;
	}
	
	if (remainder !== 1) {
		return { valid: false, error: 'Invalid check digits. The IBAN checksum verification failed.' };
	}
	
	// Format IBAN with spaces (groups of 4)
	const formatted = cleanIban.match(/.{1,4}/g).join(' ');
	
	return {
		valid: true,
		iban: cleanIban,
		formatted: formatted,
		countryCode: countryCode,
		countryName: COUNTRY_NAMES[countryCode] || countryCode,
		checkDigits: checkDigits,
		bban: bban,
		length: cleanIban.length
	};
}

function runIbanValidator(params, jobInput) {
	progress(0.1, 'Validating parameters...');
	
	const source = params.ibanSource || 'field';
	let iban = '';
	
	if (source === 'input') {
		const inputData = jobInput?.data;
		if (!inputData) {
			throw new Error('No input data available from previous job');
		}
		const dataPath = params.ibanDataPath || '';
		const value = getNestedValue(inputData, dataPath);
		if (value === undefined) {
			throw new Error(`Data path '${dataPath}' not found in input data`);
		}
		iban = String(value);
	} else {
		iban = params.ibanInput || '';
	}
	
	if (!iban) {
		throw new Error('No IBAN provided');
	}
	
	progress(0.5, 'Validating IBAN...');
	
	const validation = validateIBAN(iban);
	
	progress(0.95, 'Finalizing...');
	
	const result = {
		tool: 'IBAN Validator',
		input: iban,
		...validation
	};
	
	if (validation.valid) {
		output({
			table: {
				title: 'IBAN Validation Result',
				header: ['Property', 'Value'],
				rows: [
					['Status', '✓ Valid IBAN'],
					['Formatted', validation.formatted],
					['Country', `${validation.countryName} (${validation.countryCode})`],
					['Check Digits', validation.checkDigits],
					['BBAN', validation.bban],
					['Length', `${validation.length} characters`]
				],
				caption: 'IBAN is valid and passes MOD-97 checksum verification'
			}
		});
	} else {
		output({
			table: {
				title: 'IBAN Validation Result',
				header: ['Property', 'Value'],
				rows: [
					['Status', '✗ Invalid IBAN'],
					['Input', iban],
					['Error', validation.error]
				],
				caption: 'IBAN validation failed'
			}
		});
	}
	
	return result;
}

// ============================================
// ASCII ART GENERATOR
// ============================================

function runAsciiArt(params, jobInput, cwd) {
	return new Promise((resolve, reject) => {
		progress(0.1, 'Validating parameters...');
		
		const source = params.asciiSource || 'field';
		let text = '';
		
		if (source === 'input') {
			const inputData = jobInput?.data;
			if (!inputData) {
				return reject(new Error('No input data available from previous job'));
			}
			const dataPath = params.asciiDataPath || '';
			const value = getNestedValue(inputData, dataPath);
			if (value === undefined) {
				return reject(new Error(`Data path '${dataPath}' not found in input data`));
			}
			text = typeof value === 'string' ? value : JSON.stringify(value);
		} else {
			text = params.asciiText || '';
		}
		
		if (!text) {
			return reject(new Error('No text provided for ASCII art'));
		}
		
		const font = params.asciiFont || 'Standard';
		const horizontalLayout = params.asciiHorizontalLayout || 'default';
		const verticalLayout = params.asciiVerticalLayout || 'default';
		const width = Math.min(200, Math.max(40, parseInt(params.asciiWidth) || 80));
		
		progress(0.3, `Generating ASCII art with ${font} font...`);
		
		const options = {
			font: font,
			horizontalLayout: horizontalLayout,
			verticalLayout: verticalLayout,
			width: width
		};
		
		figlet.text(text, options, (err, asciiResult) => {
			if (err) {
				return reject(new Error(`Failed to generate ASCII art: ${err.message}`));
			}
			
			progress(0.95, 'Finalizing...');
			
			const lines = asciiResult.split('\n');
			const result = {
				tool: 'ASCII Art Generator',
				text: text,
				font: font,
				horizontalLayout: horizontalLayout,
				verticalLayout: verticalLayout,
				width: width,
				asciiArt: asciiResult,
				lines: lines.length
			};
			
			// Save to file
			const filename = 'ascii-art.txt';
			const filePath = path.join(cwd, filename);
			fs.writeFileSync(filePath, asciiResult, 'utf8');
			
			result.filename = filename;
			
			// Output file for xyOps
			output({
				files: [filename]
			});
			
			// Output as preformatted text
			output({
				text: {
					title: 'ASCII Art',
					content: asciiResult,
					caption: `Generated with ${font} font (${lines.length} lines) - saved as ${filename}`
				}
			});
			
			resolve(result);
		});
	});
}

// ============================================
// MAIN
// ============================================

async function main() {
	try {
		const job = await readStdin();
		const params = job.params || {};
		const tool = params.tool || 'tokenGenerator';
		const cwd = job.cwd || process.cwd();
		
		let result;
		
		switch (tool) {
			case 'tokenGenerator':
				result = runTokenGenerator(params);
				break;
			case 'uuidGenerator':
				result = runUUIDGenerator(params);
				break;
			case 'hashText':
				result = await runHashText(params, job.input);
				break;
			case 'qrCode':
				result = await runQRCode(params, job.input, cwd);
				break;
		case 'asciiArt':
				result = await runAsciiArt(params, job.input, cwd);
				break;
			case 'ibanValidator':
				result = runIbanValidator(params, job.input);
				break;
			default:
				throw new Error(`Unknown tool: ${tool}`);
		}
		
		success(result, `${result.tool} completed successfully`);
		
	} catch (err) {
		error(1, err.message || String(err));
		process.exit(1);
	}
}

main();
