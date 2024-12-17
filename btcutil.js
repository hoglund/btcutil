#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';

import { pubKeyToP2PKHAddress, p2wshScriptPubKey, p2wpkhScriptPubKey, verifyMessage } from './lib/lib.js';
import { getRandomAmount, getRandomNumber } from './lib/random.js';

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
	.description('Create a scriptPubKey in hex format')
	.option('-s, --p2wsh <hex>', 'Witness script in hex format with whitespace between parts')
	.option('-p, --p2wpkh <hex>', 'Witness script from public key')
	.action((options) => {
		const { p2wsh, p2wpkh } = options;

		// Ensure that only one option is provided
        if (!p2wsh && !p2wpkh) {
            console.error('You must provide either a witness script (--p2wsh) or a public key (--p2pkh).');
            process.exit(1);
        }

        try {
			if (p2wsh) {
                const scriptPubKeyHex = p2wshScriptPubKey(p2wsh);
                console.log('scriptPubKey:', scriptPubKeyHex);
			} else if (p2wpkh) {
				console.log(p2wpkh);
                const scriptPubKeyHex = p2wpkhScriptPubKey(p2wpkh);
                console.log('scriptPubKey:', scriptPubKeyHex);
			}
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
    .action((options) => {
        const {mean} = options;
        console.log(getRandomAmount(mean));
    });

program
    .command('getRandomNumber')
    .description('Generate random number')
    .action(() => {
        console.log(getRandomNumber());
    });

program.parse(process.argv);
