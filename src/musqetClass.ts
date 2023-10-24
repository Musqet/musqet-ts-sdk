import { schnorr } from '@noble/curves/secp256k1';
import { eskdf } from '@noble/hashes/eskdf';
import { randomBytes } from '@noble/hashes/utils';
import { base64url, base64 } from '@scure/base';
import { isAPIError } from './helpers';
import { lockBox, unlockBox, bytesToHex, hexToBytes } from './cryptography';
import {
	APIChallengePostResponse,
	APIChallengeResponse,
	APIError,
	APINewBusinessResponse,
	APINodeStatus,
	APIPriceResponse,
	APIUserResponse,
	Environment,
	NewBusinessForm,
	NodeStatusResponse,
	SettingsObject,
	SettingsValue
} from './types';
import { NODE_STATUS, PREFIX, STATUS } from './const/strings';
import { KDF_MODULUS, ONE_MINUTE_MILLIS } from './const/numbers';
import { ENVIRONMENT } from './const/envs';

export class MusqetUser {
	// init properties
	private initiated = false;
	private publicKeyBase64URL = '';
	private subscribeStatus = (status: string) => {};
	private status = STATUS.READY;
	private registered = false;
	private settings: SettingsObject = {
		pub: new Uint8Array(0),
		priv: new Uint8Array(0),
		totp: new Uint8Array(0),
		name: '',
		email: '',
		challengeExpires: 0,
		bearerToken: '',
		musqetPub: '',
		business: '',
		businessPub: '',
		role: null,
		macaroon: '',
		nodeId: '',
		nodeUrl: '',
		mnemonic: '',
		encipheredSeed: '',
		nodePassword: ''
	};
	errors: Error[] = [];
	// TODO: update with API URL
	private API = 'http://localhost:3000/api/v1/';

	constructor(env: Environment = 'dev') {
		switch (env) {
			case ENVIRONMENT.LOCAL:
				this.API = 'http://localhost:3000/api/v1/';
				break;
			case ENVIRONMENT.DEV:
				this.API = 'https://testnet.musqet.tech/api/v1/';
				break;
			case ENVIRONMENT.PROD:
				this.API = 'https://app.musqet.tech/api/v1/';
				break;
			default:
				this.API = 'https://testnet.musqet.tech/api/v1/';
				break;
		}
	}

	// getters

	/**
	 *
	 * @returns {string} the current status
	 */
	getStatus() {
		return this.status;
	}

	/**
	 *
	 * @returns {string} the current status
	 */
	getpublicKeyBase64URL() {
		return this.publicKeyBase64URL;
	}

	/**
	 *
	 * @returns {boolean} true if the musqetUser is registered
	 */
	isRegistered() {
		return this.registered;
	}

	/**
	 *
	 * @returns {boolean} true if the musqetUser is initialized
	 */
	isInitiated() {
		return this.initiated;
	}

	// Public methods

	/**
	 * Subscribe to status updates
	 * @param {function} callback - callback function to receive status updates
	 * @returns {void}
	 * @example
	 * const musqetUser = new MusqetUser();
	 * musqetUser.subscribe((status) => {
	 *  console.log(status);
	 * });
	 */
	subscribe(callback: (status: string) => void): void {
		this.subscribeStatus = callback;
	}

	/**
	 * Initialize a new user from their name, email address and passphrase
	 * @param {string} name - user's name
	 * @param {string} email - user's email address
	 * @param {string} passphrase - user's passphrase
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.signup("name", "email", "passphrase");
	 * console.log(success);
	 */
	async signup(name: string, email: string, passphrase: string): Promise<boolean> {
		try {
			this.updateStatus(STATUS.STARTING);
			if (!name || typeof name !== 'string') {
				this.addError('Name is required');
				return false;
			}
			if (!email || typeof email !== 'string') {
				this.addError('Email is required');
				return false;
			}
			if (!passphrase || typeof passphrase !== 'string') {
				this.addError('Passphrase is required');
				return false;
			}
			this.settings.name = name;
			this.settings.email = email;
			const isInit = await this.initFromPassphrase(email, passphrase);
			if (!isInit) {
				return false;
			}
			// Register the user
			const isRegistered = await this.register();
			if (!isRegistered) {
				return false;
			}
			// complete a challenge
			if (!this.checkChallengeExpiry()) {
				const challengeCompleted = await this.completeChallenge();
				if (!challengeCompleted) {
					this.addError('Challenge not completed');
					return false;
				}
			}
			// backup the user's settings
			this.updateStatus(STATUS.USER_CREATED);
			this.updateStatus(STATUS.READY);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Method to initialize an existing user by generating their private key
	 * @param {string} email - user's email address
	 * @param {string} passphrase - user's passphrase
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.initFromPassphrase("email", "passphrase");
	 * console.log(success);
	 * // true
	 */
	async login(email: string, passphrase: string): Promise<boolean> {
		this.updateStatus(STATUS.LOGIN);
		try {
			if (!email) {
				this.addError('Email is required');
				return false;
			}
			if (!passphrase) {
				this.addError('Passphrase is required');
				return false;
			}
			const isInit = await this.initFromPassphrase(email, passphrase);
			if (!isInit) {
				return false;
			}

			// complete a challenge
			const challengeCompleted = await this.completeChallenge();
			if (!challengeCompleted) {
				return false;
			}
			// fetch user's settings from server
			const response = await fetch(`${this.API}u/${this.publicKeyBase64URL}`, {
				headers: {
					Authorization: `Bearer ${this.settings.bearerToken}`
				}
			});
			const json: APIError | APIUserResponse = await response.json();
			if (isAPIError(json)) {
				this.addError(json.message);
				return false;
			}
			const { backup } = json.data;
			const decryptedSettings = this.decryptSettings(this.settings.priv, backup);
			this.settings = {
				...decryptedSettings,
				challengeExpires: this.settings.challengeExpires,
				bearerToken: this.settings.bearerToken
			};
			this.updateStatus(STATUS.LOGGED_IN);
			this.updateStatus(STATUS.READY);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Automatically log in the user from their private key stored in secure storage
	 */
	// async autoLogin(): Promise<boolean> {
	// 	try {
	// 		// TODO - this will depend on the secure storage implementation
	// 		// for now, just return false
	// 		return false;
	// 		return true;
	// 	} catch (err) {
	// 		this.addError(`${err}`);
	// 		return false;
	// 	}
	// }

	/**
	 * Delete the user from the server
	 * Used for testing only and tidying up test users
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.deleteUser();
	 * console.log(success);
	 * // true
	 */
	async deleteUser(): Promise<boolean> {
		// todo delete any businesses that the user is the only merchant of
		const response = await fetch(`${this.API}u/${this.publicKeyBase64URL}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${this.settings.bearerToken}`
			}
		});
		const json: APIError | { ok: true } = await response.json();
		if (isAPIError(json)) {
			this.addError(json.message);
			return false;
		}
		return true;
	}

	/**
	 * Backup the user's settings to the server
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.backup();
	 * console.log(success);
	 * // true
	 */
	async backup(): Promise<boolean> {
		if (!this.initiated) {
			this.addError('User is not initialized');
			return false;
		}
		if (!this.settings.priv.length) {
			this.addError('Private key is required');
			return false;
		}
		this.updateStatus(STATUS.BACKING_UP);
		try {
			if (!this.checkChallengeExpiry()) {
				const challengeCompleted = await this.completeChallenge();
				if (!challengeCompleted) {
					throw 'Challenge not completed';
				}
			}
			const payload = {
				name: this.settings.name,
				backup: this.settingsToEncryptedHex(this.settings.priv)
			};
			const response = await fetch(`${this.API}u/${this.publicKeyBase64URL}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.settings.bearerToken}`
				},
				body: JSON.stringify(payload)
			});
			const json: APIError | APIUserResponse = await response.json();
			if (isAPIError(json)) {
				throw json.message;
			}
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	hasNode() {
		return !!this.settings.nodeId;
	}

	/**
	 * Fetch the current BTC price from the server for fiat conversion on the client
	 * @param {string} currency - currency ticker, eg USD or EUR or GBP
	 * @returns {Promise<{price: string, symbol: string}>} - price (eg 58000.00) and symbol (eg $)
	 */
	async getPrice(currency: string): Promise<{ price: string; symbol: string }> {
		if (!this.checkChallengeExpiry()) {
			const challengeCompleted = await this.completeChallenge();
			if (!challengeCompleted) {
				throw 'Challenge not completed';
			}
		}
		this.updateStatus(STATUS.FETCH_PRICE);
		if (!currency || typeof currency !== 'string') {
			throw 'Currency is required';
		}
		const response = await fetch(`${this.API}price?currency=${currency}`, {
			headers: {
				Authorization: `Bearer ${this.settings.bearerToken}`
			}
		});
		const json: APIError | APIPriceResponse = await response.json();
		if (isAPIError(json)) {
			throw json.message;
		}
		const { price, symbol } = json.data;
		this.updateStatus(STATUS.FETCH_PRICE);
		this.updateStatus(STATUS.PRICE_FETCHED);
		return { price, symbol };
	}

	/**
	 * Register a new business
	 * @param {NewBusinessForm} businessFormData - form data for the new business
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.registerBusiness({
	 * name: 'Alice',
	 * address: '1 Test Street, London, SW1 1AA, UK',
	 * businessName: 'Test Business Name',
	 * phone: '0123456789',
	 * email: 'alice@example.com',
	 * annualRevenue: 1000000000,
	 * website: 'https://example.com',
	 * channelSize: 1000000,
	 * });
	 * console.log(success);
	 * // true
	 */
	async registerBusiness(businessFormData: NewBusinessForm): Promise<boolean> {
		try {
			if (!this.checkChallengeExpiry()) {
				const challengeCompleted = await this.completeChallenge();
				if (!challengeCompleted) {
					throw 'Challenge not completed';
				}
			}
			this.updateStatus(STATUS.REGISTER_BUSINESS);
			const response = await fetch(`${this.API}b/new`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.settings.bearerToken}`
				},
				body: JSON.stringify(businessFormData)
			});
			const json: APIError | APINewBusinessResponse = await response.json();
			if (isAPIError(json)) {
				throw json.message;
			}
			const { businessId } = json.data;
			this.settings.business = businessId;
			this.updateStatus(STATUS.BUSINESS_REGISTERED);
			this.updateStatus(STATUS.READY);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Fetch the current status of a business's lightning node
	 * @returns {Promise<NodeStatusResponse>} - node status
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const status = await musqetUser.getNodeStatus();
	 * console.log(status);
	 * // {
	 * //   nodeId: 'nodeId',
	 * //   nodeUrl: 'nodeUrl',
	 * //   status: 'starting',
	 * //   update: false,
	 * //   synced: false,
	 * //   blockHeight: 0,
	 * //   blockTip: 8000,
	 * // }
	 */
	async getNodeStatus(): Promise<NodeStatusResponse> {
		try {
			if (!this.settings.business) throw 'Business is required: cannot get node status';
			if (!this.checkChallengeExpiry()) {
				const challengeCompleted = await this.completeChallenge();
				if (!challengeCompleted) {
					throw 'Challenge not completed';
				}
			}
			const r = await fetch(`${this.API}b/${this.settings.business}/ln/status`, {
				headers: {
					Authorization: `Bearer ${this.settings.bearerToken}`
				}
			});
			const json: APIError | APINodeStatus = await r.json();
			if (isAPIError(json)) {
				throw json.message;
			}
			// set a flag to backup if settings are changed
			let settingsChanged = false;
			if (!this.settings.nodeUrl) {
				this.settings.nodeUrl = json.data.nodeUrl;
				settingsChanged = true;
			}
			if (!this.settings.nodeId) {
				this.settings.nodeId = json.data.nodeId;
				settingsChanged = true;
			}
			// if the node is waiting unlock, unlock it
			if (json.data.status === NODE_STATUS.WAITING_UNLOCK) {
				const unlockResponse = await fetch(
					`https://${this.settings.nodeUrl}:8080/v1/unlockwallet`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							wallet_password: this.settings.nodePassword,
							stateless_init: true
						})
					}
				);
				if (!unlockResponse.ok) {
					throw 'Node unlock failed';
				}
			}
			if (settingsChanged) await this.backup();
			return json.data;
		} catch (err) {
			this.addError(`${err}`);
			return {
				nodeId: '',
				nodeUrl: '',
				status: NODE_STATUS.STOPPED,
				update: false,
				synced: false,
				blockHeight: 0,
				blockTip: 0
			};
		}
	}

	/**
	 * Initialize a new lightning node for a business
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.initNode();
	 * console.log(success);
	 * // true
	 */
	async initNode(): Promise<boolean> {
		try {
			// check there is a node
			if (!this.settings.nodeId || !this.settings.nodeUrl) {
				throw 'No node found to initialize';
			}
			this.updateStatus(STATUS.INIT_NODE);
			const response4 = await fetch(`https://${this.settings.nodeUrl}:8080/v1/genseed`);
			const json4: {
				cipher_seed_mnemonic: string[];
				enciphered_seed: string;
			} = await response4.json();
			this.settings.mnemonic = json4.cipher_seed_mnemonic.join(' ');
			this.settings.encipheredSeed = json4.enciphered_seed;
			this.settings.nodePassword = base64.encode(randomBytes(32));
			const response5 = await fetch(`https://${this.settings.nodeUrl}:8080/v1/initwallet`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					wallet_password: this.settings.nodePassword,
					cipher_seed_mnemonic: json4.cipher_seed_mnemonic,
					stateless_init: true
				})
			});
			const json5: { admin_macaroon: string } = await response5.json();
			this.settings.macaroon = bytesToHex(base64.decode(json5.admin_macaroon));
			this.updateStatus(STATUS.NODE_INITIALIZED);
			this.updateStatus(STATUS.SAVING);
			const saved = await this.backup();
			if (!saved) throw 'Settings not saved';
			this.updateStatus(STATUS.SAVED);
			// bake a macaroon for musqet
			this.updateStatus(STATUS.BAKING);
			const invoicePermissions = {
				permissions: [
					{
						entity: 'invoices',
						action: 'read'
					},
					{
						entity: 'invoices',
						action: 'write'
					},
					{
						entity: 'info',
						action: 'read'
					},
					{
						entity: 'info',
						action: 'write'
					},
					{
						entity: 'address',
						action: 'read'
					},
					{
						entity: 'address',
						action: 'write'
					},
					{
						entity: 'onchain',
						action: 'read'
					}
				]
			};
			let macaroon = '',
				counter = 0;
			while (!macaroon) {
				counter++;
				// pause
				await new Promise((resolve) => setTimeout(resolve, 1000));
				const response6 = await fetch(`https://${this.settings.nodeUrl}:8080/v1/macaroon`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Grpc-Metadata-Macaroon': this.settings.macaroon
					},
					body: JSON.stringify(invoicePermissions)
				});
				const json6: { macaroon: string } = await response6.json();
				macaroon = json6.macaroon ?? '';
				if (counter > 15 && !macaroon) {
					throw 'Macaroon not baked';
				}
			}
			// post the macaroon to the server
			const postMacaroon = await fetch(`${this.API}b/${this.settings.business}/ln/macaroon`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.settings.bearerToken}`
				},
				body: JSON.stringify({
					macaroon
				})
			});
			const postMacaroonResponse:
				| APIError
				| {
						ok: true;
						data: {
							pubkey: string;
							host: string;
						};
				  } = await postMacaroon.json();
			if (isAPIError(postMacaroonResponse)) {
				throw postMacaroonResponse.message;
			}
			this.updateStatus(STATUS.BAKED);
			await this.backup();
			// connect the node to Musqet node
			// const { pubkey, host } = postMacaroonResponse.data;
			// if (!pubkey || !host) {
			// 	throw 'Musqet node not found: cannot connect as peer';
			// }
			// const peerConnected = await this.connectPeer(pubkey, host);
			// if (!peerConnected) {
			// 	throw 'Peer not connected';
			// }
			// this.updateStatus(STATUS.PEER_CONNECTED);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Stop the lightning node
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.stopNode();
	 * console.log(success);
	 * // true
	 */
	async stopNode(): Promise<boolean> {
		try {
			// check there is a node
			if (!this.settings.nodeId || !this.settings.nodeUrl) {
				throw 'No node found to stop';
			}
			this.updateStatus(STATUS.STOPPING_NODE);
			const response = await fetch(`${this.API}b/${this.settings.business}/ln/stopNode`, {
				method: 'GET',
				headers: {
					Authorization: `Bearer ${this.settings.bearerToken}`
				}
			});
			const json: APIError | { ok: true } = await response.json();
			if (isAPIError(json)) {
				throw json.message;
			}
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Start the lightning node
	 * @returns {Promise<boolean>} - true if successful
	 * @example
	 * const musqetUser = new MusqetUser();
	 * const success = await musqetUser.startNode();
	 * console.log(success);
	 * // true
	 */
	async startNode(): Promise<boolean> {
		try {
			// check there is a node
			if (!this.settings.nodeId || !this.settings.nodeUrl) {
				throw 'No node found to start';
			}
			this.updateStatus(STATUS.STARTING_NODE);
			const response = await fetch(`${this.API}b/${this.settings.business}/ln/startNode`, {
				method: 'GET',
				headers: {
					Authorization: `Bearer ${this.settings.bearerToken}`
				}
			});
			const json: APIError | { ok: true } = await response.json();
			if (isAPIError(json)) {
				throw json.message;
			}
			this.updateStatus(STATUS.NODE_STARTED);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	//

	// Start day
	async startDay(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// End day
	async endDay(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Start shift
	async startShift(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// End shift
	async endShift(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Emergency rebalance
	async emergencyRebalance(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Approve a manager
	async approveManager(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Remove a manager
	async removeManager(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Approve a cashier
	async approveCashier(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Remove a cashier
	async removeCashier(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Approve a terminal
	async addTerminal(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Remove a terminal
	async removeTerminal(): Promise<boolean> {
		// TODO: implement
		return Promise.resolve(false);
	}

	// Get sales data
	async getSalesData(): Promise<unknown> {
		// TODO: implement
		// Not sure what this will look like yet
		return Promise.resolve({
			sales: [],
			total: 0,
			currency: 'BTC'
		});
	}

	// Private methods

	/**
	 * Register a new user on the server after initializing a new user
	 *
	 */
	private async register(): Promise<boolean> {
		try {
			if (!this.initiated) {
				throw 'User is not initialized';
			}
			if (!this.settings.email) {
				throw 'Email is required';
			}
			if (!this.settings.pub.length || !this.publicKeyBase64URL) {
				throw 'Public key is required';
			}
			if (!this.settings.name) {
				throw 'Name is required';
			}
			this.updateStatus(STATUS.REGISTER_USER);
			const response = await fetch(`${this.API}u/new`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					pubkey: this.publicKeyBase64URL,
					email: this.settings.email,
					name: this.settings.name
				})
			});
			const json = await response.json();
			if (!json.ok) {
				throw json.message;
			}
			this.registered = true;
			this.updateStatus(STATUS.USER_REGISTERED);
			this.updateStatus(STATUS.READY);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	/**
	 * Initialize a new user from an email address and passphrase
	 * @param {string} identifier - email
	 * @param {string} passphrase - passphrase
	 * @returns {Promise<boolean>} - true if successful
	 * @private
	 */
	private async initFromPassphrase(identifier: string, passphrase: string): Promise<boolean> {
		try {
			if (!passphrase) {
				throw 'Passphrase is required';
			}
			if (!identifier) {
				throw 'Identifier is required';
			}
			// TODO: require a minimum length for passphrase
			this.settings.email = identifier;
			this.updateStatus(STATUS.GENERATING_KEYS);
			const kdf = await eskdf(`${PREFIX.MUSQET}_${identifier}`, `${PREFIX.MUSQET}_${passphrase}`);
			this.settings.priv = kdf.deriveChildKey('ecc', 0, {
				modulus: KDF_MODULUS
			});
			this.settings.totp = kdf.deriveChildKey('ecc', 1, {
				modulus: KDF_MODULUS
			});
			this.settings.pub = schnorr.getPublicKey(this.settings.priv);
			this.publicKeyBase64URL = base64url.encode(this.settings.pub);
			this.initiated = true;
			this.updateStatus(STATUS.READY);
		} catch (err) {
			this.addError(`${err}`);
		}
		return this.initiated;
	}

	/**
	 * Check if the user has a valid challenge
	 * @returns {boolean} - true if the user has a valid challenge
	 */
	private checkChallengeExpiry(): boolean {
		this.updateStatus(STATUS.CHECK_EXPIRY);
		if (!this.settings.challengeExpires) return false;
		const now = Date.now();
		this.updateStatus(STATUS.READY);
		return now < this.settings.challengeExpires;
	}

	/**
	 * Encrypt the user's settings using an encryption key
	 * @param {Uint8Array} encryptionKey - key to encrypt the settings
	 * @returns {string} - encrypted settings in hex
	 */
	private settingsToEncryptedHex(encryptionKey: Uint8Array): string {
		this.updateStatus(STATUS.ENCRYPTING);
		try {
			const settingsString = JSON.stringify(this.settings, (_key: string, value: SettingsValue) => {
				if (value instanceof Uint8Array) {
					return `<U8>${value.toString()}`;
				}
				if (typeof value === 'number') {
					return `${value}`;
				}
				return value;
			});
			const settingsBytes = new TextEncoder().encode(settingsString);
			const encryptedBytes = lockBox(encryptionKey, settingsBytes);
			const encryptedHex = bytesToHex(encryptedBytes);
			this.updateStatus(STATUS.ENCRYPTED);
			this.updateStatus(STATUS.READY);
			return encryptedHex;
		} catch (err) {
			this.addError(`${err}`);
			throw err;
		}
	}

	/**
	 * Decrypt the user's settings using an encryption key
	 * @param {Uint8Array} key - a key to decrypt the settings
	 * @param {string} musqetEncryptedStorage - encrypted settings in hex string
	 * @returns {SettingsObject}
	 * @private
	 */
	private decryptSettings(key: Uint8Array, musqetEncryptedStorage: string): SettingsObject {
		this.updateStatus(STATUS.DECRYPTING);
		try {
			if (this.settings.priv.length === 0) throw 'Private key is required';
			if (!musqetEncryptedStorage || typeof musqetEncryptedStorage !== 'string')
				throw 'Encrypted settings are required';
			const encryptedBytes = hexToBytes(musqetEncryptedStorage);
			const settingsBytes = unlockBox(key, encryptedBytes);
			const settingsString = new TextDecoder().decode(settingsBytes);
			const settings: SettingsObject = JSON.parse(settingsString, (key: string, value: string) => {
				if (key && typeof value === 'string' && value.startsWith('<U8>')) {
					const arr: number[] = value
						.replace('<U8>', '')
						.split(',')
						.map((s) => parseInt(s));
					return new Uint8Array(arr);
				}
				if (key && key === 'challengeExpires') {
					return parseInt(value);
				}
				return value;
			});
			this.updateStatus(STATUS.DECRYPTED);
			this.updateStatus(STATUS.READY);
			return settings;
		} catch (err) {
			this.addError(`${err}`);
			throw err;
		}
	}

	/**
	 * Add an error to the settings object
	 * @param {string} error - error message
	 * @returns {void}
	 * @private
	 */
	private addError(error: string): void {
		const e = new Error(`${new Date().toISOString()}: ${error}`);
		this.errors.push(e);
		if (this.errors.length > 10) {
			this.errors.shift();
		}
		this.updateStatus(STATUS.ERROR);
	}

	/**
	 * fetch a nonce from the server, sign it, and send it back to the server
	 * the server will assign a cookie to authorize the user for 1 hour.
	 * Incorrect challenges will incur an exponential back off and the server will
	 * return a 429 error.
	 * @returns {Promise<boolean>} - true if successful
	 * @private
	 */
	private async completeChallenge(): Promise<boolean> {
		// if (!this.registered) return false;
		if (!this.settings.email) {
			this.addError('Email is required');
			return false;
		}
		if (!this.settings.pub.length) {
			this.addError('Public key is required');
			return false;
		}
		try {
			this.updateStatus(STATUS.START_CHALLENGE);
			const response1 = await fetch(
				`${this.API}challenge?email=${
					this.settings.email
				}&pubkey=${this.publicKeyBase64URL.replaceAll('=', '~')}`
			);
			const json1: APIError | APIChallengeResponse = await response1.json();
			if (isAPIError(json1)) {
				this.addError(json1.message);
				return false;
			}
			if (!json1.data.nonce) {
				this.addError('Nonce not received');
				return false;
			}
			const nonce = json1.data.nonce;
			if (!nonce) {
				this.addError('Nonce not received');
				return false;
			}
			this.updateStatus(STATUS.SIGN_CHALLENGE);
			const nonceU8 = base64url.decode(nonce);
			const signatureU8 = schnorr.sign(nonceU8, this.settings.priv);
			const signature = base64url.encode(signatureU8);
			this.updateStatus(STATUS.SEND_CHALLENGE);
			const response2 = await fetch(`${this.API}challenge`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					pubkey: this.publicKeyBase64URL,
					signature,
					nonce
				})
			});
			const json2: APIError | APIChallengePostResponse = await response2.json();
			if (isAPIError(json2)) {
				this.addError(json2.message);
				return false;
			}
			this.settings.challengeExpires = new Date(json2.data.expires).getTime() - ONE_MINUTE_MILLIS;
			this.settings.bearerToken = json2.data.token;
			this.updateStatus(STATUS.CHALLENGE_COMPLETE);
			this.updateStatus(STATUS.READY);
			return true;
		} catch (err) {
			this.addError(`${err}`);
			return false;
		}
	}

	private updateStatus(status: string) {
		this.status = status;
		this.subscribeStatus(status);
	}

	private async connectPeer(pubkey: string, host: string): Promise<boolean> {
		try {
			const peerConnectRequest = await fetch(`https://${this.settings.nodeUrl}:8080/v1/peers`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Grpc-Metadata-Macaroon': this.settings.macaroon
				},
				body: JSON.stringify({
					addr: {
						pubkey,
						host
					},
					perm: true
				})
			});
			if (!peerConnectRequest.ok) {
				throw 'Peer connection failed';
			}
			return true;
		} catch (error) {
			this.addError(`${error}`);
			return false;
		}
	}
}
