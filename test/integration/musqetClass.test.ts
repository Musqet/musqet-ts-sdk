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
	const isBackedUp = await newUser.backup();
	expect(newUser.isInitiated()).toBe(true);
	expect(newUser.hasNode()).toBe(false);
	// ! restore the user
	const oldUser = new MusqetUser();
	oldUser.subscribe((status: string) => {
		console.log(status);
	});
	const isRestored = await oldUser.login(email, passphrase);
	expect(isRestored).toBe(true);
	expect(oldUser.isInitiated()).toBe(true);
	expect(oldUser.hasNode()).toBe(false);
	// ! Prices
	// const price = await oldUser.getPrice('GBP');
	// expect(price.symbol).toBe('£');
	// expect(Number(price.price)).toBeGreaterThan(0);
	// ! register a new business
	const businessForm = {
		name,
		address: '1 Test Street, London, SW1 1AA, UK',
		businessName: 'Test Business for ' + name,
		phone: '0123456789',
		email: 'alice@example.com',
		annualRevenue: 183000000,
		website: 'https://example.com',
		channelSize: 500000,
		activationCode: 'TEST_ACTIVATION_CODE'
	};
	// todo check if saving the user is necessary
	const saved = await oldUser.backup();
	const isRegistered = await oldUser.registerBusiness(businessForm);
	expect(isRegistered).toBe(true);
	// ! Wait for the business to be approved
	let bizApproved = false;
	while (!bizApproved) {
		// pause for 3 seconds
		await new Promise((resolve) => setTimeout(resolve, 3000));
		const node = await oldUser.getNodeStatus();
		bizApproved = node.status === 'waiting_init';
		console.log('bizApproved :>> ', bizApproved);
	}
	// ! Initiate the node
	const isNodeInit = await oldUser.initNode();
	expect(isNodeInit).toBe(true);
	// ! Get the node status
	expect(oldUser.hasNode()).toBe(true);
	const node = await oldUser.getNodeStatus();
	console.log(node);
	// ! New nodes don't start sync so need a restart
	const isNodeRestart = await oldUser.stopNode();
	expect(isNodeRestart).toBe(true);
	// ! Wait for the node to be ready
	let nodeReadyAgain = false;
	while (!nodeReadyAgain) {
		// pause for 3 seconds
		await new Promise((resolve) => setTimeout(resolve, 3000));
		const node = await oldUser.getNodeStatus();
		console.log('node.status :>> ', node.status);
		nodeReadyAgain = node.status === 'stopped' || node.status === 'running';
	}
	// ! Start the node
	// this should be done automatically by the server
	// const isNodeStart = await oldUser.startNode();
	// if (!isNodeStart) console.log(oldUser.errors);
	// expect(isNodeStart).toBe(true);
	// ! Wait for the node to be ready
	let nodeReadyAgainAgain = false;
	while (!nodeReadyAgainAgain) {
		// pause for 3 seconds
		await new Promise((resolve) => setTimeout(resolve, 3000));
		const node = await oldUser.getNodeStatus();
		console.log('node.status :>> ', node.status);
		nodeReadyAgainAgain = node.status === 'running';
	}
	// ! Wait for node sync
	let nodeSyncing = false;
	let syncCount = 0;
	while (!nodeSyncing) {
		// pause for 3 seconds
		await new Promise((resolve) => setTimeout(resolve, 3000));
		syncCount++;
		const node = await oldUser.getNodeStatus();
		console.log(
			'node.synced :>> ',
			node.blockTip ? Math.round((node.blockHeight * 100) / node.blockTip) + '%' : node
		);
		nodeSyncing =
			node.blockTip !== undefined && node.blockTip > 0 && node.blockTip === node.blockHeight;
		if (syncCount > 10) {
			console.log('Syncing taking too long');
			break;
		}
	}
	// ! Finally, delete the user
	const isDeleted = await oldUser.deleteUser();
	expect(isDeleted).toBe(true);
}, 600000);
