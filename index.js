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
// PASSPHRASE GENERATOR
// ============================================

// Extended English wordlist for passphrase generation (2048 words, EFF-inspired)
const WORDLIST = [
	'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
	'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
	'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
	'adult','advance','advice','aerobic','affair','afford','afraid','again','age','agent',
	'agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert',
	'alien','all','alley','allow','almost','alone','alpha','already','also','alter',
	'always','amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger',
	'angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique',
	'anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic',
	'area','arena','argue','arm','armed','armor','army','around','arrange','arrest',
	'arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset',
	'assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction',
	'audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake',
	'aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge',
	'bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain',
	'barrel','base','basic','basket','battle','beach','bean','beauty','because','become',
	'beef','before','begin','behave','behind','believe','below','belt','bench','benefit',
	'best','betray','better','between','beyond','bicycle','bid','bike','bind','biology',
	'bird','birth','bitter','black','blade','blame','blanket','blast','bleak','bless',
	'blind','blood','blossom','blouse','blue','blur','blush','board','boat','body',
	'boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss',
	'bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread',
	'breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze',
	'broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb',
	'bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy',
	'butter','buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call',
	'calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas',
	'canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry',
	'cart','case','cash','casino','castle','casual','cat','catalog','catch','category',
	'cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century',
	'cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase',
	'chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child',
	'chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle',
	'citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk',
	'clever','click','client','cliff','climb','clinic','clip','clock','clog','close',
	'cloth','cloud','clown','club','clump','cluster','clutch','coach','coast','coconut',
	'code','coffee','coil','coin','collect','color','column','combine','come','comfort',
	'comic','common','company','concert','conduct','confirm','congress','connect','consider','control',
	'convince','cook','cool','copper','copy','coral','core','corn','correct','cost',
	'cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle',
	'craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek',
	'crew','cricket','crime','crisp','critic','crop','cross','crouch','crowd','crucial',
	'cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup',
	'cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad',
	'damage','damp','dance','danger','daring','dash','daughter','dawn','day','deal',
	'debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense',
	'define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny',
	'depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk',
	'despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond',
	'diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur',
	'direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance',
	'divert','divide','divorce','dizzy','doctor','document','dog','doll','dolphin','domain',
	'donate','donkey','donor','door','dose','double','dove','draft','dragon','drama',
	'drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop',
	'drum','dry','duck','dumb','dune','during','dust','dutch','duty','dwarf',
	'dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo',
	'ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow',
	'elder','electric','elegant','element','elephant','elevator','elite','else','embark','embody',
	'embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless',
	'endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough',
	'enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip',
	'era','erase','erode','erosion','error','erupt','escape','essay','essence','estate',
	'eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange',
	'excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit',
	'exotic','expand','expect','expire','explain','expose','express','extend','extra','eye',
	'eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame',
	'family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father',
	'fatigue','fault','favorite','feature','february','federal','fee','feed','feel','female',
	'fence','festival','fetch','fever','few','fiber','fiction','field','figure','file',
	'film','filter','final','find','fine','finger','finish','fire','firm','first',
	'fiscal','fish','fit','fitness','fix','flag','flame','flash','flat','flavor',
	'flee','flight','flip','float','flock','floor','flower','fluid','flush','fly',
	'foam','focus','fog','foil','fold','follow','food','foot','force','forest',
	'forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile',
	'frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen',
	'fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy',
	'gallery','game','gap','garage','garbage','garden','garlic','garment','gas','gasp',
	'gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture',
	'ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance',
	'glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue',
	'goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown',
	'grab','grace','grain','grant','grape','grass','gravity','great','green','grid',
	'grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt',
	'guitar','gun','gym','habit','hair','half','hammer','hamster','hand','happy',
	'harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health',
	'heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden',
	'high','hill','hint','hip','hire','history','hobby','hockey','hold','hole',
	'holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital',
	'host','hotel','hour','hover','hub','huge','human','humble','humor','hundred',
	'hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice','icon','idea',
	'identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune',
	'impact','impose','improve','impulse','inch','include','income','increase','index','indicate',
	'indoor','industry','infant','inflict','inform','inhale','inherit','initial','inject','injury',
	'inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install',
	'intact','interest','into','invest','invite','involve','iron','island','isolate','issue',
	'item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel',
	'job','join','joke','journey','joy','judge','juice','jump','jungle','junior',
	'junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney',
	'kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife',
	'knock','know','lab','label','labor','ladder','lady','lake','lamp','language',
	'laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit',
	'layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal',
	'legend','leisure','lemon','lend','length','lens','leopard','lesson','letter','level',
	'lever','liberty','library','license','life','lift','light','like','limb','limit',
	'link','lion','liquid','list','little','live','lizard','load','loan','lobster',
	'local','lock','logic','lonely','long','loop','lottery','loud','lounge','love',
	'loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad',
	'magic','magnet','maid','mail','main','major','make','mammal','man','manage',
	'mandate','mango','mansion','manual','maple','marble','march','margin','marine','market',
	'marriage','mask','mass','master','match','material','math','matrix','matter','maximum',
	'maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt',
	'member','memory','mention','menu','mercy','merge','merit','merry','mesh','message',
	'metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor',
	'minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile',
	'model','modify','mom','moment','monitor','monkey','monster','month','moon','moral',
	'more','morning','mosquito','mother','motion','motor','mountain','mouse','move','movie',
	'much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual',
	'myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature',
	'near','neck','need','negative','neglect','neither','nephew','nerve','nest','net',
	'network','neutral','never','news','next','nice','night','noble','noise','nominee',
	'noodle','normal','north','nose','notable','note','nothing','notice','novel','november',
	'now','nuclear','number','nurse','nut','oak','obey','object','oblige','obscure',
	'observe','obtain','obvious','occur','ocean','october','odor','off','offer','office',
	'often','oil','okay','old','olive','olympic','omit','once','one','onion',
	'online','only','open','opera','opinion','oppose','option','orange','orbit','orchard',
	'order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer',
	'output','outside','oval','oven','over','own','owner','oxygen','oyster','ozone',
	'pact','paddle','page','pair','palace','palm','panda','panel','panic','panther',
	'paper','parade','parent','park','parrot','party','pass','patch','path','patient',
	'patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican',
	'pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phone',
	'photo','phrase','physical','piano','picnic','picture','piece','pig','pigeon','pill',
	'pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic',
	'plate','play','please','pledge','pluck','plug','plunge','poem','poet','point',
	'polar','pole','police','pond','pony','pool','popular','portion','position','possible',
	'post','potato','pottery','poverty','powder','power','practice','praise','predict','prefer',
	'prepare','present','pretty','prevent','price','pride','primary','print','priority','prison',
	'private','prize','problem','process','produce','profit','program','project','promote','proof',
	'property','prosper','protect','proud','provide','public','pudding','pull','pulp','pulse',
	'pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push','put',
	'puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz','quote',
	'rabbit','raccoon','race','rack','radar','radio','rail','rain','raise','rally',
	'ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw',
	'razor','reach','react','read','ready','real','reason','rebel','rebuild','recall',
	'receive','recipe','record','recycle','reduce','reflect','reform','refuse','region','regret',
	'regular','reject','relax','release','relief','rely','remain','remember','remind','remove',
	'render','renew','rent','reopen','repair','repeat','replace','report','require','rescue',
	'resemble','resist','resource','response','result','retire','retreat','return','reunion','reveal',
	'review','reward','rhythm','rib','ribbon','rice','rich','ride','ridge','rifle',
	'right','rigid','ring','riot','ripple','risk','ritual','rival','river','road',
	'roast','robot','robust','rocket','romance','roof','rookie','room','rose','rotate',
	'rough','round','route','royal','rubber','rude','rug','rule','run','runway',
	'rural','sad','saddle','sadness','safe','sail','salad','salmon','salon','salt',
	'salute','same','sample','sand','satisfy','satoshi','sauce','sausage','save','say',
	'scale','scan','scare','scatter','scene','scheme','school','science','scissors','scorpion',
	'scout','scrap','screen','script','scrub','sea','search','season','seat','second',
	'secret','section','security','seed','seek','segment','select','sell','seminar','senior',
	'sense','sentence','series','service','session','settle','setup','seven','shadow','shaft',
	'shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shiver',
	'shock','shoe','shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle',
	'shy','sibling','sick','side','siege','sight','sign','silent','silk','silly',
	'silver','similar','simple','since','sing','siren','sister','situate','six','size',
	'skate','sketch','ski','skill','skin','skirt','skull','slab','slam','sleep',
	'slender','slice','slide','slight','slim','slogan','slot','slow','slush','small',
	'smart','smile','smoke','smooth','snack','snake','snap','sniff','snow','soap',
	'soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve',
	'someone','song','soon','sorry','sort','soul','sound','soup','source','south',
	'space','spare','spatial','spawn','speak','special','speed','spell','spend','sphere',
	'spice','spider','spike','spin','spirit','split','spoil','sponsor','spoon','sport',
	'spot','spray','spread','spring','spy','square','squeeze','squirrel','stable','stadium',
	'staff','stage','stairs','stamp','stand','start','state','stay','steak','steel',
	'stem','step','stereo','stick','still','sting','stock','stomach','stone','stool',
	'story','stove','strategy','street','strike','strong','struggle','student','stuff','stumble',
	'style','subject','submit','subway','success','such','sudden','suffer','sugar','suggest',
	'suit','summer','sun','sunny','sunset','super','supply','supreme','sure','surface',
	'surge','surprise','surround','survey','suspect','sustain','swallow','swamp','swap','swarm',
	'swear','sweet','swift','swim','swing','switch','sword','symbol','symptom','syrup',
	'system','table','tackle','tag','tail','talent','talk','tank','tape','target',
	'task','taste','tattoo','taxi','teach','team','tell','ten','tenant','tennis',
	'tent','term','test','text','thank','that','theme','then','theory','there',
	'they','thing','this','thought','three','thrive','throw','thumb','thunder','ticket',
	'tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title',
	'toast','tobacco','today','toddler','toe','together','toilet','token','tomato','tomorrow',
	'tone','tongue','tonight','tool','tooth','top','topic','topple','torch','tornado',
	'tortoise','toss','total','tourist','toward','tower','town','toy','track','trade',
	'traffic','tragic','train','transfer','trap','trash','travel','tray','treat','tree',
	'trend','trial','tribe','trick','trigger','trim','trip','trophy','trouble','truck',
	'true','truly','trumpet','trust','truth','try','tube','tuition','tumble','tuna',
	'tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two',
	'type','typical','ugly','umbrella','unable','unaware','uncle','uncover','under','undo',
	'unfair','unfold','unhappy','uniform','unique','unit','universe','unknown','unlock','until',
	'unusual','unveil','update','upgrade','uphold','upon','upper','upset','urban','urge',
	'usage','use','used','useful','useless','usual','utility','vacant','vacuum','vague',
	'valid','valley','valve','van','vanish','vapor','various','vast','vault','vehicle',
	'velvet','vendor','venture','venue','verb','verify','version','very','vessel','veteran',
	'viable','vibrant','vicious','victory','video','view','village','vintage','violin','virtual',
	'virus','visa','visit','visual','vital','vivid','vocal','voice','void','volcano',
	'volume','vote','voyage','wage','wagon','wait','walk','wall','walnut','want',
	'warfare','warm','warrior','wash','wasp','waste','water','wave','way','wealth',
	'weapon','wear','weasel','weather','web','wedding','weekend','weird','welcome','west',
	'wet','whale','what','wheat','wheel','when','where','whip','whisper','wide',
	'width','wife','wild','will','win','window','wine','wing','wink','winner',
	'winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood',
	'wool','word','work','world','worry','worth','wrap','wreck','wrestle','wrist',
	'write','wrong','yard','year','yellow','you','young','youth','zebra','zero',
	'zone','zoo','accent','accept','accident','accurate','achieve','acid','acquire','adapt',
	'adequate','adjust','admit','adopt','advance','adverse','advice','advocate','aerial','affair',
	'affect','afford','agency','agenda','agent','agree','ahead','aircraft','airline','airport',
	'aisle','alarm','album','alert','alien','align','alike','alive','alley','allocate',
	'allow','almost','alone','along','alpha','alpine','already','alter','always','amateur',
	'ambition','ambulance','amend','among','amount','ample','analyse','ancient','angel','angle',
	'animal','ankle','annual','another','answer','anxiety','apart','apology','appeal','appear',
	'appetite','apple','apply','appoint','approach','approve','april','arbitrary','arena','argue',
	'arise','arithmetic','arm','armour','army','around','arrange','array','arrest','arrival',
	'arrive','arrow','article','artist','ascend','aside','aspect','assault','assert','assess',
	'asset','assign','assist','assume','assure','astonish','athlete','attach','attain','attempt',
	'attend','attitude','attract','audience','august','author','autumn','avenue','average','avoid',
	'await','awake','award','aware','awful','axis','badge','badly','bag','bake',
	'balance','balloon','ballot','bamboo','band','bank','banner','barely','bargain','barn',
	'barrel','barrier','basement','basic','basin','basket','batch','battery','battle','beach',
	'beam','bean','bear','beard','beast','beat','beautiful','beauty','become','bedroom',
	'begin','behalf','behave','belief','bell','belong','beloved','below','bench','bend',
	'beneath','benefit','bent','berry','beside','best','betray','better','between','beyond',
	'billion','binary','biology','birth','bishop','bite','bitter','blade','blanket','blast',
	'blend','bless','blessing','blind','block','blond','bloom','blossom','blow','blues',
	'blunt','board','boast','boat','bold','bolt','bomb','bond','bonus','border',
	'bore','borrow','boston','bottle','bottom','bought','bounce','boundary','bow','bowl',
	'boxing','brain','branch','brass','breach','bread','break','breast','breath','breed',
	'breeze','bridge','brief','bright','brilliant','bring','britain','broad','broadcast','broken',
	'bronze','brother','brow','browser','brush','brutal','bucket','buddy','budget','buffalo',
	'bug','building','bulk','bullet','bunch','bundle','burden','bureau','burn','burst',
	'bury','bush','business','butter','button','buyer','cabinet','cable','calculate','calendar',
	'calm','camera','campaign','campus','canada','canal','cancel','cancer','candidate','candle',
	'canvas','capable','capacity','capital','captain','capture','carbon','career','careful','cargo',
	'carriage','carrier','carrot','cartoon','carve','casual','catalog','category','cattle','causal',
	'ceiling','celebrate','cell','central','century','ceremony','certain','chain','chairman','challenge',
	'chamber','champion','channel','chapter','character','charity','chart','charter','cheap','cheat',
	'cheek','cheer','chemical','chest','chicken','chief','childhood','chin','chip','chocolate',
	'choice','choose','christmas','chronic','chunk','cinema','circuit','circular','citizen','civil',
	'civilian','clap','clarity','clash','classic','classroom','clause','climate','climb','clinic',
	'clinical','clock','clone','closet','cloth','clothing','cluster','coach','coalition','coastal',
	'cocktail','cognitive','collapse','collar','colleague','collect','colonial','colony','combat','combination',
	'comedy','comfort','commander','commerce','commission','commit','commodity','commonwealth','commune','communicate',
	'communist','companion','comparable','comparative','compare','comparison','compel','compensate','compete','competent',
	'compile','complain','complement','complex','compliance','complicated','component','compose','compound','comprehensive',
	'comprise','compromise','compute','concede','conceive','concentrate','conception','concern','conclude','concrete',
	'condemn','condition','conduct','confer','confess','confidence','confident','configuration','confine','confirmation',
	'conflict','conform','confront','confusion','congress','conjunction','consciousness','consensus','consent','consequence',
	'conservative','considerable','consideration','consist','consistent','consolidate','conspiracy','constant','constituency','constitute',
	'constraint','construct','consult','consume','consumer','consumption','contact','contain','contemporary','content',
	'contest','context','continent','continual','continuity','contract','contrary','contrast','contribute','controversial',
	'controversy','convenient','convention','conventional','conversation','conversion','convert','convey','conviction','convince',
	'cooperate','cooperation','coordinate','cope','copyright','coral','corner','corporate','correct','correlate',
	'correspond','corridor','corrupt','costume','cottage','council','counsel','counter','countryside','courage',
	'coverage','coward','crack','cradle','craft','crash','crawl','crazy','creation','creative',
	'creature','credential','credible','creek','cricket','criminal','crisis','criterion','critical','criticism',
	'criticize','crop','crossing','crucial','crude','cruel','crush','crystal','cultural','cumulative',
	'curious','currency','curriculum','curtain','custody','custom','cutting','dairy','damage','damp',
	'dancer','dare','database','dawn','deadline','deadly','dealer','dean','dear','debate',
	'debris','decent','decisive','declaration','declare','decline','decorate','decrease','decree','dedicate',
	'deem','deeply','default','defeat','defect','defendant','defensive','deficiency','deficit','define',
	'definite','definition','delegate','deliberate','delicate','delight','demon','demonstrate','denial','dense',
	'dental','department','departure','deploy','deposit','depress','deprive','depth','derive','descend',
	'descent','deserve','desktop','desperate','despite','destination','destruction','detailed','detect','detection',
	'determination','determine','devastating','developer','development','devote','dialogue','diameter','dictate','dictionary'
];

const PP_SYMBOLS = '!@#$%^&*';

function generatePassphrase(options) {
	const { wordCount, maxWordLength, separator, capitalize, includeNumber, includeSymbol } = options;
	
	// Filter words by max length (minimum 3 chars)
	const filteredWords = WORDLIST.filter(w => w.length >= 3 && w.length <= maxWordLength);
	
	if (filteredWords.length < 100) {
		throw new Error(`Not enough words with max length ${maxWordLength}. Try increasing max word length.`);
	}
	
	// Select random words
	const words = [];
	for (let i = 0; i < wordCount; i++) {
		const randomIndex = crypto.randomInt(filteredWords.length);
		let word = filteredWords[randomIndex];
		if (capitalize) {
			word = word.charAt(0).toUpperCase() + word.slice(1);
		}
		words.push(word);
	}
	
	// Get separator character
	const separators = {
		hyphen: '-',
		space: ' ',
		dot: '.',
		underscore: '_',
		none: ''
	};
	const sep = separators[separator] || '-';
	
	// Build passphrase
	let passphrase = words.join(sep);
	
	// Add number at random position
	if (includeNumber) {
		const num = crypto.randomInt(100).toString();
		const parts = sep ? passphrase.split(sep) : words.slice();
		const pos = crypto.randomInt(parts.length + 1);
		parts.splice(pos, 0, num);
		passphrase = parts.join(sep);
	}
	
	// Add symbol at random position
	if (includeSymbol) {
		const sym = PP_SYMBOLS.charAt(crypto.randomInt(PP_SYMBOLS.length));
		const pos = crypto.randomInt(passphrase.length + 1);
		passphrase = passphrase.slice(0, pos) + sym + passphrase.slice(pos);
	}
	
	return passphrase;
}

function calculateEntropy(wordCount, poolSize, includeNumber, includeSymbol) {
	// Base entropy from words
	let entropy = wordCount * Math.log2(poolSize);
	
	// Add entropy for number (0-99 = ~6.6 bits) and position
	if (includeNumber) {
		entropy += Math.log2(100) + Math.log2(wordCount + 1);
	}
	
	// Add entropy for symbol (8 symbols) and position
	if (includeSymbol) {
		entropy += Math.log2(PP_SYMBOLS.length) + Math.log2(50); // approximate position entropy
	}
	
	return Math.round(entropy);
}

function getStrengthRating(entropy) {
	if (entropy < 40) return { rating: 'Weak', symbol: '⚠️' };
	if (entropy < 60) return { rating: 'Fair', symbol: '🔶' };
	if (entropy < 80) return { rating: 'Strong', symbol: '🔷' };
	if (entropy < 100) return { rating: 'Very Strong', symbol: '✅' };
	return { rating: 'Excellent', symbol: '🛡️' };
}

function runPassphraseGenerator(params) {
	progress(0.1, 'Validating parameters...');
	
	const wordCount = Math.min(10, Math.max(3, parseInt(params.ppWordCount) || 4));
	const maxWordLength = Math.min(15, Math.max(3, parseInt(params.ppMaxWordLength) || 8));
	const separator = params.ppSeparator || 'hyphen';
	const capitalize = params.ppCapitalize !== false;
	const includeNumber = params.ppIncludeNumber !== false;
	const includeSymbol = params.ppIncludeSymbol === true;
	const count = Math.min(20, Math.max(1, parseInt(params.ppCount) || 1));
	
	// Filter words for pool size calculation
	const filteredWords = WORDLIST.filter(w => w.length >= 3 && w.length <= maxWordLength);
	const poolSize = filteredWords.length;
	
	if (poolSize < 100) {
		throw new Error(`Not enough words with max length ${maxWordLength}. Try increasing max word length.`);
	}
	
	progress(0.3, `Generating ${count} passphrase(s)...`);
	
	const options = { wordCount, maxWordLength, separator, capitalize, includeNumber, includeSymbol };
	const passphrases = [];
	
	for (let i = 0; i < count; i++) {
		passphrases.push(generatePassphrase(options));
		if (count > 1) {
			progress(0.3 + (0.6 * (i + 1) / count), `Generated ${i + 1} of ${count}...`);
		}
	}
	
	progress(0.95, 'Finalizing...');
	
	// Calculate entropy
	const entropy = calculateEntropy(wordCount, poolSize, includeNumber, includeSymbol);
	const strength = getStrengthRating(entropy);
	
	const separatorNames = {
		hyphen: 'Hyphen (-)',
		space: 'Space',
		dot: 'Dot (.)',
		underscore: 'Underscore (_)',
		none: 'None'
	};
	
	const result = {
		tool: 'Passphrase Generator',
		passphrases: passphrases,
		count: count,
		wordCount: wordCount,
		maxWordLength: maxWordLength,
		separator: separator,
		capitalize: capitalize,
		includeNumber: includeNumber,
		includeSymbol: includeSymbol,
		wordPoolSize: poolSize,
		entropy: entropy,
		strength: strength.rating
	};
	
	// Output table for UI
	const rows = passphrases.map((pp, i) => [i + 1, pp, pp.length]);
	
	output({
		table: {
			title: 'Generated Passphrases',
			header: ['#', 'Passphrase', 'Length'],
			rows: rows,
			caption: `${strength.symbol} ${strength.rating} | ${wordCount} words | ~${entropy} bits entropy | Word pool: ${poolSize}`
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
// LOREM IPSUM GENERATOR
// ============================================

const LOREM_WORDS = [
	'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit',
	'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore',
	'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud',
	'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo',
	'consequat', 'duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate',
	'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint',
	'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia',
	'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum', 'ac', 'accumsan',
	'aliquet', 'aliquam', 'ante', 'aptent', 'arcu', 'at', 'auctor', 'augue',
	'bibendum', 'blandit', 'condimentum', 'congue', 'cras', 'curabitur', 'cursus',
	'dapibus', 'diam', 'dictum', 'dictumst', 'dignissim', 'dis', 'donec', 'egestas',
	'eget', 'eleifend', 'elementum', 'eros', 'etiam', 'eu', 'euismod', 'facilisi',
	'facilisis', 'fames', 'faucibus', 'felis', 'fermentum', 'feugiat', 'fringilla',
	'fusce', 'gravida', 'habitant', 'habitasse', 'hac', 'hendrerit', 'himenaeos',
	'iaculis', 'imperdiet', 'inceptos', 'integer', 'interdum', 'justo', 'lacinia',
	'lacus', 'laoreet', 'lectus', 'leo', 'libero', 'ligula', 'litora', 'lobortis',
	'luctus', 'maecenas', 'massa', 'mattis', 'mauris', 'metus', 'mi', 'morbi',
	'nam', 'nascetur', 'natoque', 'nec', 'neque', 'nibh', 'nisl', 'nullam', 'nunc',
	'odio', 'orci', 'ornare', 'parturient', 'pellentesque', 'penatibus', 'per',
	'pharetra', 'phasellus', 'placerat', 'platea', 'porta', 'porttitor', 'posuere',
	'potenti', 'praesent', 'pretium', 'primis', 'proin', 'pulvinar', 'purus',
	'quam', 'quisque', 'rhoncus', 'ridiculus', 'risus', 'rutrum', 'sagittis',
	'sapien', 'scelerisque', 'semper', 'senectus', 'sociosqu', 'sodales', 'sollicitudin',
	'suscipit', 'suspendisse', 'taciti', 'tellus', 'tempus', 'tincidunt', 'torquent',
	'tortor', 'tristique', 'turpis', 'ultrices', 'ultricies', 'urna', 'varius',
	'vehicula', 'vel', 'venenatis', 'vestibulum', 'vitae', 'vivamus', 'viverra', 'volutpat', 'vulputate'
];

function generateLoremSentence(wordsPerSentence, startWithLorem, isFirstSentence) {
	const words = [];
	const wordCount = Math.max(3, Math.min(50, wordsPerSentence));
	
	for (let i = 0; i < wordCount; i++) {
		if (startWithLorem && isFirstSentence && i < 2) {
			words.push(i === 0 ? 'Lorem' : 'ipsum');
		} else {
			const randomIndex = crypto.randomInt(LOREM_WORDS.length);
			let word = LOREM_WORDS[randomIndex];
			// Capitalize first word of sentence
			if (i === 0) {
				word = word.charAt(0).toUpperCase() + word.slice(1);
			}
			words.push(word);
		}
	}
	
	return words.join(' ') + '.';
}

function generateLoremParagraph(sentencesPerParagraph, wordsPerSentence, startWithLorem, isFirstParagraph) {
	const sentences = [];
	const sentenceCount = Math.max(1, Math.min(20, sentencesPerParagraph));
	
	for (let i = 0; i < sentenceCount; i++) {
		const isFirstSentence = isFirstParagraph && i === 0;
		sentences.push(generateLoremSentence(wordsPerSentence, startWithLorem, isFirstSentence));
	}
	
	return sentences.join(' ');
}

function runLoremIpsum(params) {
	progress(0.1, 'Validating parameters...');
	
	const paragraphs = Math.min(50, Math.max(1, parseInt(params.loremParagraphs) || 3));
	const sentencesPerParagraph = Math.min(20, Math.max(1, parseInt(params.loremSentences) || 4));
	const wordsPerSentence = Math.min(50, Math.max(3, parseInt(params.loremWords) || 10));
	const startWithLorem = params.loremStartWithLorem !== false;
	const asHtml = params.loremAsHtml === true;
	
	progress(0.3, `Generating ${paragraphs} paragraph(s)...`);
	
	const paragraphTexts = [];
	for (let i = 0; i < paragraphs; i++) {
		paragraphTexts.push(generateLoremParagraph(sentencesPerParagraph, wordsPerSentence, startWithLorem, i === 0));
		progress(0.3 + (0.6 * (i + 1) / paragraphs), `Generated ${i + 1} of ${paragraphs} paragraphs...`);
	}
	
	progress(0.95, 'Finalizing...');
	
	let text;
	if (asHtml) {
		text = paragraphTexts.map(p => `<p>${p}</p>`).join('\n');
	} else {
		text = paragraphTexts.join('\n\n');
	}
	
	// Count statistics
	const totalWords = paragraphTexts.reduce((sum, p) => sum + p.split(/\s+/).length, 0);
	const totalSentences = paragraphTexts.reduce((sum, p) => sum + (p.match(/\./g) || []).length, 0);
	const totalChars = text.length;
	
	const result = {
		tool: 'Lorem Ipsum Generator',
		text: text,
		paragraphs: paragraphs,
		sentencesPerParagraph: sentencesPerParagraph,
		wordsPerSentence: wordsPerSentence,
		startWithLorem: startWithLorem,
		asHtml: asHtml,
		totalWords: totalWords,
		totalSentences: totalSentences,
		totalCharacters: totalChars
	};
	
	// Output text for UI
	output({
		text: {
			title: 'Generated Lorem Ipsum',
			content: text,
			caption: `${paragraphs} paragraph(s) | ${totalSentences} sentences | ${totalWords} words | ${totalChars} characters${asHtml ? ' (HTML)' : ''}`
		}
	});
	
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
		case 'passphrase':
				result = runPassphraseGenerator(params);
				break;
			case 'loremIpsum':
				result = runLoremIpsum(params);
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
