import { APIError } from "./types";

export const isAPIError = (obj: any): obj is APIError => {
	return obj.ok === false && obj.message !== undefined;
};
