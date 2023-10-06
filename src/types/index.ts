export type APIError = {
	ok: false;
	message: string;
};
export type NodeStatus =
	| 'starting'
	| 'running'
	| 'stopping'
	| 'stopped'
	| 'provisioning'
	| 'waiting_init'
	| 'waiting_unlock'
	| 'waiting_start';
export type NodeStatusResponse = {
	nodeId: string;
	nodeUrl: string;
	status: NodeStatus;
	update: boolean;
	synced: boolean;
	blockHeight: number;
	blockTip: number;
};
export type APINodeStatus = {
	ok: true;
	data: NodeStatusResponse;
};
export type APIChallengeResponse = {
	ok: true;
	data: {
		nonce: string;
	};
};
export type APIChallengePostResponse = {
	ok: true;
	data: {
		nonce: string;
		token: string;
		expires: string;
	};
};

export type APIResponse = {
	ok: true;
};

export type APIPriceResponse = APIResponse & {
	data: {
		price: string;
		symbol: string;
	};
};
export type APIUserResponse = APIResponse & {
	data: {
		name: string;
		businesses: { [key: string]: string };
		backup: string;
	};
};
export type APINewBusinessResponse = APIResponse & {
	data: {
		businessId: string;
	};
};
export type APINewNodeResponse = APIResponse & {
	data: {
		nodeId: string;
	};
};
export type APINodeStatusResponse = APIResponse & {
	data: {
		nodeId: string;
		nodeUrl: string;
		status: NodeStatus;
		update: boolean;
		synced: boolean;
	};
};
export type NewBusinessForm = {
	name: string;
	address: string;
	businessName: string;
	phone: string;
	email: string;
	annualRevenue: number;
	website: string;
	channelSize: number;
	activationCode: string;
};

export type StorageObject = {
	priv: number[];
	pub: number[];
	passphrase: string;
	musqetPub: string;
	macaroon: string;
	nodeId: string;
	nodeUrl: string;
};

export type SettingsObject = {
	priv: Uint8Array; // User's private key
	pub: Uint8Array; // User's public key
	totp: Uint8Array; // User's TOTP key
	name: string; // User's name
	email: string; // User's email
	challengeExpires: number; // Challenge expiration timestamp
	bearerToken: string; // Bearer token for API calls
	musqetPub: string; // Musqet public key
	business: string; // Business name
	businessPub: string; // Business public key
	role: Role | null; // User's role
	macaroon: string; // User's macaroon - only available to manager & merchant roles. Cashiers will be empty string
	nodeId: string; // Business node ID
	nodeUrl: string; // Business node URL
	mnemonic: string; // Mnemonic seed phrase
	encipheredSeed: string; // Enciphered seed
	nodePassword: string; // Node password
};

export type SettingsValue = string | Uint8Array | number;

export type Role = 'merchant' | 'manager' | 'cashier';
