#!/usr/bin/env node
import { Command } from 'commander';
import crypto from 'crypto';
import elliptic from 'elliptic';
import chalk from 'chalk';

const { ec: EC } = elliptic;
const ec = new EC('secp256k1');

const program = new Command();

program
	.name('btcUtil.js')
	.description('CLI tool for Bitcoin message signing and verification')
	.version('1.0.0');

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
export const verifyMessage = (message, pubkey, signature) => {
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

// Function to parse the witness script and generate the scriptPubKey
const createScriptPubKey = (witnessScriptHex) => {
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

// Add the createScriptPubKey command
program
	.command('scriptPubKey')
	.description('Create a scriptPubKey from a witness script in hex format')
	.requiredOption('-w, --witness-script <witnessScriptHex>', 'Witness script in hex format with whitespace between parts')
	.action((options) => {
		const { witnessScript } = options;

		try {
			const scriptPubKeyHex = createScriptPubKey(witnessScript);
			console.log('scriptPubKey:', scriptPubKeyHex);
		} catch (error) {
			console.error('An error occurred:', error.message);
			process.exit(1);
		}
	});

program
	.command('verifyMessage')
	.description('Verify a Bitcoin-style message signature')
	.requiredOption('-m, --message <message>', 'Message text')
	.requiredOption('-k, --pubkey <compressed_pubkey>', 'Compressed public key in hex format')
	.requiredOption('-s, --signature <base64_signature>', 'Base64-encoded signature')
	.action((options) => {
		const { message, pubkey, signature } = options;

		const isValid = verifyMessage(message, pubkey, signature);

		if (isValid) {
			console.log(chalk.bold.green('Signature is valid.'));
		} else {
			console.log(chalk.bold.red('Signature is invalid.'));
		}
	});

program.parse(process.argv);
