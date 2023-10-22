import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import * as utils from '@noble/curves/abstract/utils';
import { randomBytes } from '@noble/hashes/utils';
import { secretbox } from '@noble/ciphers/salsa';
import { base64 } from '@scure/base';

const getNormalizedX = (key: Uint8Array): Uint8Array => {
	return key.slice(1, 33);
};
export const addX = (pubkey: Uint8Array) => utils.concatBytes(new Uint8Array([0x02]), pubkey);

const utf8Decoder = new TextDecoder('utf-8');
const utf8Encoder = new TextEncoder();
export const stringToBytes = (str = '') => utf8Encoder.encode(str);
export const stringToBase64 = (str: string) => base64.encode(stringToBytes(str));
export const base64ToString = (str: string) => utf8Decoder.decode(base64.decode(str));
// export const isValidPrivateKey = utils.isValidPrivateKey;
export const bytesToHex = utils.bytesToHex;
export const hexToBytes = utils.hexToBytes;

export const getPubKeyFromPrivateKey = (privateKey: Uint8Array) =>
	getNormalizedX(schnorr.getPublicKey(privateKey));

export const generatePrivateKey = secp256k1.utils.randomPrivateKey;

export const generateNonce = (bytes = 16) => bytesToHex(randomBytes(bytes));

export const lockBox = (key: Uint8Array, plainText: Uint8Array) => {
	const nonce = randomBytes(24);
	const box = secretbox(key, nonce);
	const ciphertext = box.seal(plainText);
	return utils.concatBytes(nonce, ciphertext);
	// const plaintext = box.open(ciphertext);
};

export const unlockBox = (key: Uint8Array, encryptedData: Uint8Array) => {
	const nonce = encryptedData.slice(0, 24);
	const ciphertext = encryptedData.slice(24);
	const box = secretbox(key, nonce);
	return box.open(ciphertext);
};

export async function encrypt(
	ourPrivateKeyU8: Uint8Array,
	pubkey: Uint8Array,
	text: string
): Promise<Uint8Array> {
	const key = secp256k1.getSharedSecret(ourPrivateKeyU8, addX(pubkey), true);
	const normalizedKey = getNormalizedX(key);

	const iv = randomBytes(16);
	const encodedText = utf8Encoder.encode(text);
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		normalizedKey,
		{ name: 'AES-CBC' },
		false,
		['encrypt']
	);
	const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, encodedText);
	return utils.concatBytes(iv, new Uint8Array(ciphertext));
}

export async function decrypt(
	ourPrivateKeyU8: Uint8Array,
	pubkey: Uint8Array,
	data: Uint8Array
): Promise<string> {
	try {
		const key = secp256k1.getSharedSecret(ourPrivateKeyU8, addX(pubkey));
		const normalizedKey = getNormalizedX(key);

		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			normalizedKey,
			{ name: 'AES-CBC' },
			false,
			['decrypt']
		);

		const ciphertext = data.slice(16);
		const iv = data.slice(0, 16);
		const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, ciphertext);

		const text = utf8Decoder.decode(plaintext);
		return text;
	} catch (err) {
		console.error(err);
		return '';
	}
}

export const sign = (messageBytes: Uint8Array, privateKeyU8: Uint8Array) => {
	const sig = schnorr.sign(messageBytes, privateKeyU8);
	return sig;
};

export const verify = (sig: Uint8Array, message: Uint8Array, pubkey: Uint8Array): boolean => {
	const validSig = schnorr.verify(sig, message, pubkey);
	return validSig;
};
