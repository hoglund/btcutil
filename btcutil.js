#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';

import { pubKeyToP2PKHAddress, createScriptPubKey, verifyMessage } from './lib/lib.js';
import { getRandomAmount } from './lib/random.js';

const program = new Command();

program
	.name('btcutil.js')
	.description('CLI tool for Bitcoin message signing and verification')
	.version('1.0.0');


program
	.command('pubKeyToP2PKHAddress')
	.description('Compute a P2PKH address from a compressed public key in hex format.')
	.requiredOption('-k, --key <hex>', 'Compressed public key in hex format')
	.action((options) => {
		const { key } = options;
		console.log(pubKeyToP2PKHAddress(key));
	});

program
	.command('scriptPubKey')
	.description('Create a scriptPubKey from a witness script in hex format')
	.requiredOption('-w, --witnessScript <witnessScript>', 'Witness script in hex format with whitespace between parts')
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

program
    .command('getRandomAmount')
    .description('Generate random amount')
    .requiredOption('-m, --mean <mean>', 'mean')
    .action(async (options) => {
        const {mean} = options;
        console.log(await getRandomAmount(mean));
    });

program.parse(process.argv);
