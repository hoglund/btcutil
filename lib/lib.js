import crypto from 'crypto';
import elliptic from 'elliptic';
import bs58check from 'bs58check';

const { ec: EC } = elliptic;
const ec = new EC('secp256k1');

// Helper function to encode a number into Bitcoin varint format
const encodeVarint = (number) => {
	if (number < 0xfd) {
		return Buffer.from([number]);
	} else if (number <= 0xffff) {
		const buf = Buffer.alloc(3);
		buf[0] = 0xfd;
		buf.writeUInt16LE(number, 1);
		return buf;
	} else if (number <= 0xffffffff) {
		const buf = Buffer.alloc(5);
		buf[0] = 0xfe;
		buf.writeUInt32LE(number, 1);
		return buf;
	} else {
		const buf = Buffer.alloc(9);
		buf[0] = 0xff;
		buf.writeBigUInt64LE(BigInt(number), 1);
		return buf;
	}
};

// Function to hash the message according to Bitcoin's protocol
const hashMessage = (message) => {
	const prefix = 'Bitcoin Signed Message:\n';
	const prefixBuffer = Buffer.from(prefix, 'utf8');
	const messageBuffer = Buffer.from(message, 'utf8');

	const prefixLengthVarint = encodeVarint(prefixBuffer.length);
	const messageLengthVarint = encodeVarint(messageBuffer.length);

	const dataToHash = Buffer.concat([
		prefixLengthVarint,
		prefixBuffer,
		messageLengthVarint,
		messageBuffer,
	]);

	// Double SHA256 hash
	const hash1 = crypto.createHash('sha256').update(dataToHash).digest();
	const messageHash = crypto.createHash('sha256').update(hash1).digest();

	return messageHash;
};

// Function to decode the base64 signature and extract components
const decodeSignature = (signature) => {
	// Decode the base64 signature
	const signatureBuffer = Buffer.from(signature, 'base64');

	// Check signature length
	if (signatureBuffer.length !== 65) {
		throw new Error('Invalid signature length. Expected 65 bytes.');
	}

	// Extract the header byte
	const headerByte = signatureBuffer[0];

	// Interpret the header byte
	const recoveryId = (headerByte - 27) & 0x03; // Recovery ID (0-3)
	const isCompressed = ((headerByte - 27) & 0x04) !== 0; // Compression flag

	// Extract r and s components
	const r = signatureBuffer.slice(1, 33);  // Bytes 1-32
	const s = signatureBuffer.slice(33, 65); // Bytes 33-64

	// Create the signature object
	const sig = {
		r: r.toString('hex'),
		s: s.toString('hex'),
	};

	return { sig, recoveryId, isCompressed };
};

// Function to verify the signature using the public key and message hash
const verifySignature = (messageHash, pubkey, sig) => {
	// Create a public key object from the compressed public key
	const key = ec.keyFromPublic(pubkey, 'hex');

	// Perform the verification
	const isValid = key.verify(messageHash, sig);

	return isValid;
};

// Main verifyMessage function
const verifyMessage = (message, pubkey, signature) => {
	try {
		// Decode the signature and extract components
		const { sig } = decodeSignature(signature);

		// Hash the message according to Bitcoin's protocol
		const messageHash = hashMessage(message);

		// Verify the signature
		const isValid = verifySignature(messageHash, pubkey, sig);

		return isValid;
	} catch (error) {
		console.error('An error occurred during verification:', error.message);
		return false;
	}
};

const p2wpkhScriptPubKey = (publicKeyHex) => {
    // Convert the public key hex to a Buffer
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');

    // Step 1: Hash the public key with SHA256
    const sha256Hash = crypto.createHash('sha256').update(publicKeyBuffer).digest();

    // Step 2: Hash the SHA256 result with RIPEMD160 to get the public key hash (PKH)
    const pkh = crypto.createHash('ripemd160').update(sha256Hash).digest();

    // Step 3: Create the scriptPubKey: OP_0 [length of PKH] [PKH]
    const scriptPubKey = Buffer.concat([
        Buffer.from([0x00]),        // OP_0 (SegWit marker)
        Buffer.from([0x14]),        // Length of PKH (20 bytes)
        pkh                        // Public key hash (20 bytes)
    ]);

    return scriptPubKey.toString('hex');
};

// Function to parse the witness script and generate the scriptPubKey
const p2wshScriptPubKey = (witnessScriptHex) => {
	// Split the input by whitespace and remove empty strings
	const scriptParts = witnessScriptHex.trim().split(/\s+/);

	// Convert hex parts to bytes and concatenate
	const scriptBuffer = Buffer.concat(
		scriptParts.map((hex) => Buffer.from(hex, 'hex'))
	);

	// Hash the witness script using SHA256 (for P2WSH)
	const witnessScriptHash = crypto.createHash('sha256').update(scriptBuffer).digest();

	// Create the scriptPubKey: OP_0 [32-byte witness script hash]
	const scriptPubKey = Buffer.concat([
		Buffer.from([0x00, 0x20]), // OP_0 followed by push 32 bytes (0x20)
		witnessScriptHash,
	]);

	return scriptPubKey.toString('hex');
};

//Computes a P2PKH address from a compressed public key in hex format.
const pubKeyToP2PKHAddress = (pubKeyHex) => {
    // Step 1: Convert hex public key to Buffer
    const pubKeyBuffer = Buffer.from(pubKeyHex, 'hex');

    // Step 2: Perform SHA-256 hashing on the public key
    const sha256Hash = crypto.createHash('sha256').update(pubKeyBuffer).digest();

    // Step 3: Perform RIPEMD-160 hashing on the SHA-256 hash
    const ripemd160Hash = crypto.createHash('ripemd160').update(sha256Hash).digest();

    // Step 4: Add network version byte
    const versionByte = 0x00; // 0x00 for mainnet
    const extendedRipemd160 = Buffer.allocUnsafe(21);
    extendedRipemd160.writeUInt8(versionByte, 0);
    ripemd160Hash.copy(extendedRipemd160, 1); // Copy RIPEMD-160 hash after version byte

    // Step 5 & 6: Base58Check encode the extended RIPEMD-160 hash
    const address = bs58check.encode(extendedRipemd160);

    return address;
}

export {pubKeyToP2PKHAddress, p2wshScriptPubKey, p2wpkhScriptPubKey, verifyMessage}
