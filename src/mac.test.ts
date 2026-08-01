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
import {
	clampR,
	forgeTag,
	recoverKeyCandidates,
	recoverKeyFromTagPairs,
	singleBlockInteger,
	tagBytesToInteger,
} from './poly-math.ts';

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

describe('key-reuse forgery from two single-block pairs', () => {
	// The whole point of the "one-time" rule: two genuine (message, tag) pairs
	// under ONE key let an attacker recover (r, s) and forge a valid tag for a
	// message the sender never signed — verified live against the real key.
	const MSG_A = 'Pay Alice $10';
	const MSG_B = 'Pay Bob $20';
	const FORGED = 'Pay Mallory $99';

	function attack(key: Uint8Array) {
		const tagA = computeMAC(MSG_A, key);
		const tagB = computeMAC(MSG_B, key);
		const recovered = recoverKeyFromTagPairs(
			singleBlockInteger(MSG_A),
			tagBytesToInteger(tagA),
			singleBlockInteger(MSG_B),
			tagBytesToInteger(tagB),
		);
		return recovered;
	}

	it('recovers the real r from the RFC test key', () => {
		const recovered = attack(RFC_KEY);
		expect(recovered).not.toBeNull();
		expect(recovered!.r).toBe(RFC_CLAMPED_R);
	});

	it('forges a tag the genuine key accepts', () => {
		const recovered = attack(RFC_KEY);
		expect(recovered).not.toBeNull();
		const forged = forgeTag(recovered!, FORGED);
		// The forged tag must verify against the SAME key under real Poly1305.
		expect(verifyMAC(FORGED, forged, RFC_KEY)).toBe(true);
		expect(bytesToHex(forged)).toBe(bytesToHex(computeMAC(FORGED, RFC_KEY)));
	});

	it('works for many independent random keys', () => {
		for (let trial = 0; trial < 50; trial += 1) {
			const key = generateKey();
			const recovered = attack(key);
			expect(recovered).not.toBeNull();
			const forged = forgeTag(recovered!, FORGED);
			expect(verifyMAC(FORGED, forged, key)).toBe(true);
		}
	});

	it('returns null when the two messages are identical (no independent equation)', () => {
		const key = generateKey();
		const tag = computeMAC(MSG_A, key);
		const c = singleBlockInteger(MSG_A);
		const t = tagBytesToInteger(tag);
		expect(recoverKeyCandidates(c, t, c, t)).toHaveLength(0);
		expect(recoverKeyFromTagPairs(c, t, c, t)).toBeNull();
	});

	function candidatesFor(key: Uint8Array, one: string, two: string) {
		return recoverKeyCandidates(
			singleBlockInteger(one),
			tagBytesToInteger(computeMAC(one, key)),
			singleBlockInteger(two),
			tagBytesToInteger(computeMAC(two, key)),
		);
	}

	it('never returns a key that is not a valid clamped r', () => {
		// Candidates come back reduced mod 2^130-5, so they can be wider than the
		// 16-byte key half. r + k*2^128 has the same low 16 bytes as the real r and
		// used to pass a mask-only clamp test, yielding a wrong key and a forged tag
		// the genuine key rejected. Every survivor must be a real clamped r.
		for (const [one, two] of [
			['A', 'B'],
			['8', ':'],
			['ab', 'ac'],
			['hi', 'ho'],
		]) {
			for (let trial = 0; trial < 40; trial += 1) {
				const key = generateKey();
				for (const candidate of candidatesFor(key, one, two)) {
					expect(candidate.r).toBeLessThan(2n ** 124n);
					expect(candidate.s).toBeLessThan(2n ** 128n);
				}
			}
		}
	});

	it('when it claims a unique key, that key is the real r', () => {
		// The honesty property: a non-null recovery must never be a lucky alias.
		// Includes message pairs one byte apart, which is where the alias appeared.
		for (const [one, two] of [
			[MSG_A, MSG_B],
			['A', 'B'],
			['ab', 'ac'],
			['hi', 'ho'],
			['abc', 'abd'],
		]) {
			for (let trial = 0; trial < 40; trial += 1) {
				const key = generateKey();
				const recovered = recoverKeyFromTagPairs(
					singleBlockInteger(one),
					tagBytesToInteger(computeMAC(one, key)),
					singleBlockInteger(two),
					tagBytesToInteger(computeMAC(two, key)),
				);
				if (recovered === null) continue; // ambiguous — reported honestly, not forged from
				expect(recovered.r).toBe(clampR(key.subarray(0, 16)));
				expect(verifyMAC(FORGED, forgeTag(recovered, FORGED), key)).toBe(true);
			}
		}
	});

	it('reports ambiguity instead of guessing when two pairs underdetermine the key', () => {
		// "ab"/"ac" differ only in byte 1, so neighbouring wrap terms produce
		// candidate r values a single step apart in r's top byte. Several of those
		// are valid clamped keys reproducing both tags; none can be singled out.
		let sawAmbiguous = false;
		for (let trial = 0; trial < 60 && !sawAmbiguous; trial += 1) {
			const key = generateKey();
			const candidates = candidatesFor(key, 'ab', 'ac');
			// Whatever the count, the sender's real key is always among them.
			expect(candidates.map((c) => c.r)).toContain(clampR(key.subarray(0, 16)));
			if (candidates.length > 1) {
				sawAmbiguous = true;
				expect(
					recoverKeyFromTagPairs(
						singleBlockInteger('ab'),
						tagBytesToInteger(computeMAC('ab', key)),
						singleBlockInteger('ac'),
						tagBytesToInteger(computeMAC('ac', key)),
					),
				).toBeNull();
			}
		}
		// ~98% of keys are ambiguous for this pair, so 60 trials missing it would
		// itself be a signal that the candidate enumeration stopped working.
		expect(sawAmbiguous).toBe(true);
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
