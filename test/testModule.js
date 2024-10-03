import { expect } from 'chai';
import { pubKeyToP2PKHAddress, createScriptPubKey, verifyMessage } from '../lib/lib.js';

describe('Module Function Tests', () => {
	describe('pubKeyToP2PKHAddress', () => {
		it('should convert public key to correct P2PKH address', () => {
			const pubkey = '03e32974215bf4ece01344a6dff8a46a55b1da519e6c85e4e405e4a4f7c0fa08c8';
			const expectedAddress = '1qfRbKvzV7DCfaEb7eXPuLAHDEe64UQGS';
			const generatedAddress = pubKeyToP2PKHAddress(pubkey);
			expect(generatedAddress).to.equal(expectedAddress);
		});
	});

	describe('verifyMessage', () => {
		it('should verify a valid Bitcoin message signature', () => {
			const pubkey = '03e32974215bf4ece01344a6dff8a46a55b1da519e6c85e4e405e4a4f7c0fa08c8';
			const signature =
				  'H4UODztnq2K+kjuYLDrNRh/FavOGS71l/wV819Gqd1kXZqj6s4nyiaGXmMW6+YYp+ZhmTf2MQlXonqaNIDeXaMY=';
			const message = 'This is a test message for Bitcoin signature.';

			const isValid = verifyMessage(message, pubkey, signature);

			expect(isValid).to.be.true;
		});
	});

	describe('createScriptPubKey', () => {
		it('should create the correct scriptPubKey from witnessScript', () => {
			const witnessScript =
				  '52 21 03e32974215bf4ece01344a6dff8a46a55b1da519e6c85e4e405e4a4f7c0fa08c8 21 03d84b3722bc385179c5b' +
				  'd8b9c7d65fff80887b3915abf2ebd3dec3f3339fc04a9 21 0399c2bc00e0ac8c0a658e65717a11776c902bcd6388d0f2070a2719cf62e8c787 53 ae';
			const scriptPubKey = '0020dd4ea72860d320e26e0f029b52e0e0559e03c880293f843f6ba9bce84360517d';

			const generatedScriptPubKey = createScriptPubKey(witnessScript);

			expect(generatedScriptPubKey).to.equal(scriptPubKey);
		});
	});
});
