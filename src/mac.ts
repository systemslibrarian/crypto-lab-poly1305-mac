import { poly1305 } from '@noble/ciphers/_poly1305.js';

const POLY1305_KEY_LENGTH = 32;
const POLY1305_TAG_LENGTH = 16;

export interface MACResult {
	tag: Uint8Array;
	tagHex: string;
	message: string;
	messageBytes: Uint8Array;
}

function assertKeyLength(key: Uint8Array): void {
	if (key.length !== POLY1305_KEY_LENGTH) {
		throw new Error(`Poly1305 requires a ${POLY1305_KEY_LENGTH}-byte one-time key.`);
	}
}

function encodeMessage(message: string): Uint8Array {
	return new TextEncoder().encode(message);
}

export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
}

export function generateKey(): Uint8Array {
	const key = new Uint8Array(POLY1305_KEY_LENGTH);
	// Poly1305 is a one-time MAC: the 32-byte key must never be reused across messages.
	crypto.getRandomValues(key);
	return key;
}

export function computeMAC(message: string, key: Uint8Array): Uint8Array {
	assertKeyLength(key);
	return poly1305(encodeMessage(message), key);
}

export function computeMACResult(message: string, key: Uint8Array): MACResult {
	const messageBytes = encodeMessage(message);
	const tag = computeMAC(message, key);

	return {
		tag,
		tagHex: bytesToHex(tag),
		message,
		messageBytes,
	};
}

export function verifyMAC(message: string, tag: Uint8Array, key: Uint8Array): boolean {
	assertKeyLength(key);

	if (tag.length !== POLY1305_TAG_LENGTH) {
		return false;
	}

	const recomputedTag = computeMAC(message, key);
	let diff = 0;

	for (let index = 0; index < POLY1305_TAG_LENGTH; index += 1) {
		diff |= recomputedTag[index] ^ tag[index];
	}

	return diff === 0;
}

export function tamperMessage(message: string): string {
	return `${message} `;
}

export function tamperTag(tag: Uint8Array): Uint8Array {
	const tamperedTag = new Uint8Array(tag);
	tamperedTag[8] ^= 0x01;
	return tamperedTag;
}