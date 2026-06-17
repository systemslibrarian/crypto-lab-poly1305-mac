import { describe, expect, it } from 'vitest';
import {
	bytesToHex,
	computeMAC,
	computeMACResult,
	generateKey,
	tamperMessage,
	tamperTag,
	verifyMAC,
} from './mac.ts';
import { clampR } from './poly-math.ts';

function hexToBytes(hex: string): Uint8Array {
	const clean = hex.replace(/\s+/g, '');
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

// Canonical test vector from RFC 8439 §2.5.2 "Poly1305 Example and Test Vector".
const RFC_KEY = hexToBytes(
	'85d6be7857556d337f4452fe42d506a8' + '0103808afb0db2fd4abff6af4149f51b',
);
const RFC_MESSAGE = 'Cryptographic Forum Research Group';
const RFC_TAG_HEX = 'A8061DC1305136C6C22B8BAF0C0127A9';
// Clamped r from the same worked example (interpreted as a little-endian integer).
const RFC_CLAMPED_R = BigInt('0x0806d5400e52447c036d555408bed685');

describe('Poly1305 against the RFC 8439 test vector', () => {
	it('computes the documented tag', () => {
		expect(bytesToHex(computeMAC(RFC_MESSAGE, RFC_KEY))).toBe(RFC_TAG_HEX);
	});

	it('clamps r to the documented value', () => {
		expect(clampR(RFC_KEY.subarray(0, 16))).toBe(RFC_CLAMPED_R);
	});

	it('verifies the genuine (message, tag) pair', () => {
		const tag = computeMAC(RFC_MESSAGE, RFC_KEY);
		expect(verifyMAC(RFC_MESSAGE, tag, RFC_KEY)).toBe(true);
	});
});

describe('verifyMAC rejects tampering', () => {
	it('fails when the message changes by a single trailing space', () => {
		const tag = computeMAC(RFC_MESSAGE, RFC_KEY);
		expect(verifyMAC(tamperMessage(RFC_MESSAGE), tag, RFC_KEY)).toBe(false);
	});

	it('fails when one tag byte is flipped', () => {
		const tag = computeMAC(RFC_MESSAGE, RFC_KEY);
		expect(verifyMAC(RFC_MESSAGE, tamperTag(tag), RFC_KEY)).toBe(false);
	});

	it('fails on a wrong-length tag', () => {
		expect(verifyMAC(RFC_MESSAGE, new Uint8Array(15), RFC_KEY)).toBe(false);
	});
});

describe('key handling', () => {
	it('generates a fresh 32-byte key', () => {
		const a = generateKey();
		const b = generateKey();
		expect(a).toHaveLength(32);
		// Two independent draws must not collide (a 2^-256 event otherwise).
		expect(bytesToHex(a)).not.toBe(bytesToHex(b));
	});

	it('rejects keys that are not 32 bytes', () => {
		expect(() => computeMAC('x', new Uint8Array(16))).toThrow();
	});
});

describe('computeMACResult shape', () => {
	it('returns the tag, its hex, the message, and its bytes', () => {
		const result = computeMACResult(RFC_MESSAGE, RFC_KEY);
		expect(result.tagHex).toBe(RFC_TAG_HEX);
		expect(result.message).toBe(RFC_MESSAGE);
		expect(result.tag).toHaveLength(16);
		expect(result.messageBytes).toHaveLength(RFC_MESSAGE.length);
	});
});
