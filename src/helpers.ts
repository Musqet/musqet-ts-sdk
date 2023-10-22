import { APIError } from './types';

export const isAPIError = (obj: { ok: boolean; message?: string | undefined }): obj is APIError => {
	return obj.ok === false && obj.message !== undefined;
};
