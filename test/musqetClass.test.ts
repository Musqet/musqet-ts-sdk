import { MusqetUser } from '../src/musqetClass';

const config = {
	newUser: true,
	prices: false,
	newBiz: true,
	newNode: true,
	restartNode: true
};

test('MusqetUser', async () => {
	const passphrase = 'secret password';
	const name = 'Test User';
	const email = 'mail@example.com';
	// ! New User
	if (config.newUser) {
		const newUser = new MusqetUser('dev');
		newUser.subscribe((status: string) => {
			console.log(status);
			if (status === 'Error') {
				console.log(newUser.errors);
			}
		});
		expect(newUser.initiated).toBe(false);
		const isInit = await newUser.signup(name, email, passphrase);
		if (!isInit) console.log(newUser.errors);
		expect(isInit).toBe(true);
		const isBackedUp = await newUser.backup();
		if (!isBackedUp) console.log(newUser.errors);
		expect(newUser.initiated).toBe(true);
		expect(newUser.hasNode()).toBe(false);
	}
	// ! restore the user
	const oldUser = new MusqetUser();
	oldUser.subscribe((status: string) => {
		console.log(status);
		if (status === 'Error') {
			console.log(oldUser.errors);
		}
	});
	const isRestored = await oldUser.login(email, passphrase);
	if (!isRestored) console.log(oldUser.errors);
	expect(isRestored).toBe(true);
	expect(oldUser.initiated).toBe(true);
	// expect(oldUser.hasNode()).toBe(false);
	// ! Prices
	if (config.prices) {
		const price = await oldUser.getPrice('GBP');
		expect(price.symbol).toBe('£');
		console.log('price :>> ', price);
		expect(Number(price.price)).toBeGreaterThan(0);
	}
	// ! register a new business
	if (config.newBiz) {
		const businessForm = {
			name: 'Alice',
			address: '1 Test Street, London, SW1 1AA, UK',
			businessName: 'Test Business Name',
			phone: '0123456789',
			email: 'alice@example.com',
			annualRevenue: 183000000,
			website: 'https://example.com',
			channelSize: 500000,
			activationCode: 'ACTIVATION_CODE'
		};
		const saved = await oldUser.backup();
		if (!saved) console.log('Not saved!', oldUser.errors);
		const isRegistered = await oldUser.registerBusiness(businessForm);
		if (!isRegistered) console.log(oldUser.errors);
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
	}
	if (config.newNode) {
		// ! Initiate the node
		const isNodeInit = await oldUser.initNode();
		if (!isNodeInit) console.log(oldUser.errors);
		expect(isNodeInit).toBe(true);
		// ! Get the node status
		expect(oldUser.hasNode()).toBe(true);
		const node = await oldUser.getNodeStatus();
		console.log(node);
	}
	if (config.restartNode) {
		// ! New nodes don't start sync so need a restart
		const isNodeRestart = await oldUser.stopNode();
		if (!isNodeRestart) console.log(oldUser.errors);
		expect(isNodeRestart).toBe(true);
		// ! Wait for the node to be ready
		let nodeReadyAgain = false;
		while (!nodeReadyAgain) {
			// pause for 3 seconds
			await new Promise((resolve) => setTimeout(resolve, 3000));
			const node = await oldUser.getNodeStatus();
			console.log('node.status :>> ', node.status);
			nodeReadyAgain = node.status === 'stopped';
		}
		// ! Start the node
		const isNodeStart = await oldUser.startNode();
		if (!isNodeStart) console.log(oldUser.errors);
		expect(isNodeStart).toBe(true);
		// ! Wait for the node to be ready
		let nodeReadyAgainAgain = false;
		while (!nodeReadyAgainAgain) {
			// pause for 3 seconds
			await new Promise((resolve) => setTimeout(resolve, 3000));
			const node = await oldUser.getNodeStatus();
			console.log('node.status :>> ', node.status);
			nodeReadyAgainAgain = node.status === 'running';
		}
	}
	// ! Wait for node sync
	let nodeSynced = false;
	while (!nodeSynced) {
		// pause for 3 seconds
		await new Promise((resolve) => setTimeout(resolve, 3000));
		const node = await oldUser.getNodeStatus();
		console.log(
			'node.synced :>> ',
			node.blockTip ? Math.round((node.blockHeight * 100) / node.blockTip) + '%' : node
		);
		nodeSynced = node.synced;
	}
	// ! Finally, delete the user
	// const isDeleted = await oldUser.deleteUser();
	// expect(isDeleted).toBe(true);
	// ! DANGER! This will delete all nodes that are not named 'musqet'
	// await oldUser.delNodes();
	expect(true).toBe(true);
});
