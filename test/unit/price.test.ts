import { MusqetUser } from '../../src/musqetClass';
import { generateNonce } from '../../src/cryptography';

test('MusqetUser', async () => {
	const passphrase = generateNonce(12);
	const name = `TestUser${generateNonce(4)}`;
	const email = `${name}@example.com`;
	console.log('name, passphrase, email :>> ', name, passphrase, email);
	// ! New User
	const newUser = new MusqetUser('dev');
	newUser.subscribe((status: string) => {
		console.log(status);
	});
	expect(newUser.isInitiated()).toBe(false);
	const isInit = await newUser.signup(name, email, passphrase);
	expect(isInit).toBe(true);
	newUser.getPrice('GBP').then((price) => {
		console.log('price :>> ', price);
		expect(price.symbol).toBe('£');
		expect(Number(price.price)).toBeGreaterThan(0);
	});
}, 10000);
