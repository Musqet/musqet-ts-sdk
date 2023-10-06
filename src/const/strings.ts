import { NodeStatus } from '../types';

export const ROLE = {
	MERCHANT: 'merchant',
	MANAGER: 'manager',
	CASHIER: 'cashier'
};

export const STATUS = {
	STARTING: 'Starting signup',
	SIGNUP: 'Starting signup',
	USER_CREATED: 'New user created',
	READY: 'Ready',
	LOGIN: 'Starting login',
	LOGGED_IN: 'User logged in',
	BACKING_UP: 'Backing up',
	FETCH_PRICE: 'Fetching price',
	PRICE_FETCHED: 'Price fetched',
	REGISTER_BUSINESS: 'Registering business',
	BUSINESS_REGISTERED: 'Business registered',
	REGISTER_USER: 'Registering New User',
	USER_REGISTERED: 'User registered',
	STARTING_NODE: 'Starting lightning node',
	NODE_STARTED: 'Lightning node started',
	INIT_NODE: 'Initializing lightning node',
	NODE_INITIALIZED: 'Lightning node initialized',
	STOPPING_NODE: 'Stopping lightning node',
	NODE_STOPPED: 'Lightning node stopped',
	SAVING: 'Saving settings',
	SAVED: 'Settings saved',
	BAKING: 'Baking macaroon',
	BAKED: 'Macaroon baked',
	GENERATING_KEYS: 'Generating Keys',
	CHECK_EXPIRY: 'Checking challenge expiry',
	ENCRYPTING: 'Encrypting settings',
	ENCRYPTED: 'Settings encrypted',
	DECRYPTING: 'Decrypting settings',
	DECRYPTED: 'Decrypted settings',
	START_CHALLENGE: 'Starting challenge',
	SIGN_CHALLENGE: 'Signing challenge',
	SEND_CHALLENGE: 'Sending challenge',
	CHALLENGE_COMPLETE: 'Challenge completed',
	ERROR: 'Error'
};

export const NODE_STATUS: { [k: string]: NodeStatus } = {
	STARTING: 'starting',
	RUNNING: 'running',
	STOPPING: 'stopping',
	STOPPED: 'stopped',
	PROVISIONING: 'provisioning',
	WAITING_INIT: 'waiting_init',
	WAITING_UNLOCK: 'waiting_unlock',
	WAITING_START: 'waiting_start'
};

export const PREFIX = {
	MUSQET: 'MUSQET'
};
