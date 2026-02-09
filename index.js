#!/usr/bin/env node

/**
 * xkOps Toolbox Event Plugin (c) 2026 Tim Alderweireldt
 * 
 * A collection of utility tools for xyOps including:
 * - Token Generator: Generate random strings with customizable character sets
 * - UUID Generator: Generate UUIDs in various versions (v1, v4, v6, v7, nil, max)
 */

const crypto = require('crypto');

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

function runHashText(params) {
	progress(0.1, 'Validating parameters...');
	
	const text = params.hashInput || '';
	const encoding = params.hashEncoding || 'hex';
	
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
// MAIN
// ============================================

async function main() {
	try {
		const job = await readStdin();
		const params = job.params || {};
		const tool = params.tool || 'tokenGenerator';
		
		let result;
		
		switch (tool) {
			case 'tokenGenerator':
				result = runTokenGenerator(params);
				break;
			case 'uuidGenerator':
				result = runUUIDGenerator(params);
				break;
			case 'hashText':
				result = runHashText(params);
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
