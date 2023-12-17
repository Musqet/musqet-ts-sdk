import {
	generatePrivateKey,
	getPubKeyFromPrivateKey,
	bytesToHex,
	hexToBytes,
	lockBox,
	unlockBox
} from '../../src/cryptography';
test('crypto', async () => {
	const alicePrivateKey = generatePrivateKey();
	const alicePublicKey = getPubKeyFromPrivateKey(alicePrivateKey);
	const hexPubkey = bytesToHex(alicePublicKey);
	// swap to hex and back
	expect(alicePublicKey).toEqual(hexToBytes(hexPubkey));
	const message = 'hello world, a test';
	const plainText = new TextEncoder().encode(message);
	// encrypt and decrypt for self (bytes)
	const encrypted = lockBox(alicePrivateKey, plainText);
	const decrypted = unlockBox(alicePrivateKey, encrypted);
	const decryptedText = new TextDecoder().decode(decrypted);
	expect(message).toEqual(decryptedText);
	// todo encrypt and decrypt need fixing but aren't used yet
	// // encrypt and decrypt for two people
	// // Alice encrypts for Bob
	// const bobPrivateKey = generatePrivateKey();
	// const bobPublicKey = getPubKeyFromPrivateKey(bobPrivateKey);
	// const encrypted2 = await encrypt(alicePrivateKey, bobPublicKey, message);
	// // Bob decrypts
	// const decrypted2 = await decrypt(bobPrivateKey, alicePublicKey, encrypted2);
	// expect(message).toEqual(decrypted2);
	// pause for 20ms
	await new Promise((resolve) => setTimeout(resolve, 20));
});
