const BLOCK_SIZE = 16;
const MAX_BLOCKS = 4;
const POLY1305_PRIME = (2n ** 130n) - 5n;
const TWO_POW_128 = 2n ** 128n;

export interface PolyStep {
	blockIndex: number;
	blockHex: string;
	blockValue: string;
	accumulatorBefore: string;
	// (accumulator + block) — the addition the old table hid.
	sumBeforeMultiply: string;
	// ((accumulator + block) * r) — before reduction mod p.
	productBeforeReduce: string;
	accumulatorAfter: string;
	rClamped: string;
}

function utf8Bytes(message: string): Uint8Array {
	return new TextEncoder().encode(message);
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
}

function littleEndianBytesToBigInt(bytes: Uint8Array): bigint {
	let value = 0n;

	for (let index = bytes.length - 1; index >= 0; index -= 1) {
		value = (value << 8n) | BigInt(bytes[index]);
	}

	return value;
}

function getPaddedBlockBytes(messageBytes: Uint8Array, blockIndex: number): Uint8Array {
	const start = blockIndex * BLOCK_SIZE;
	const chunk = messageBytes.slice(start, start + BLOCK_SIZE);
	return chunk;
}

function getPoly1305BlockValue(chunk: Uint8Array): bigint {
	const blockWithOne = new Uint8Array(chunk.length + 1);
	blockWithOne.set(chunk);
	blockWithOne[chunk.length] = 0x01;
	return littleEndianBytesToBigInt(blockWithOne);
}

export function clampR(r: Uint8Array): bigint {
	if (r.length < BLOCK_SIZE) {
		throw new Error('Poly1305 r requires at least 16 bytes.');
	}

	const clamped = new Uint8Array(r.slice(0, BLOCK_SIZE));
	clamped[3] &= 0x0f;
	clamped[7] &= 0x0f;
	clamped[11] &= 0x0f;
	clamped[15] &= 0x0f;
	clamped[4] &= 0xfc;
	clamped[8] &= 0xfc;
	clamped[12] &= 0xfc;

	return littleEndianBytesToBigInt(clamped);
}

export function computeSteps(message: string, key: Uint8Array): PolyStep[] {
	if (key.length < 32) {
		throw new Error('Poly1305 visualization requires a 32-byte key.');
	}

	const messageBytes = utf8Bytes(message);
	const availableBlocks = Math.ceil(messageBytes.length / BLOCK_SIZE);
	const totalBlocks = Math.min(MAX_BLOCKS, availableBlocks);
	const rClamped = clampR(key.subarray(0, BLOCK_SIZE));
	const steps: PolyStep[] = [];
	let accumulator = 0n;

	for (let blockIndex = 0; blockIndex < totalBlocks; blockIndex += 1) {
		const blockBytes = getPaddedBlockBytes(messageBytes, blockIndex);
		const blockValue = getPoly1305BlockValue(blockBytes);
		const accumulatorBefore = accumulator;

		// The real recurrence, exposed as its three stages so the table can show
		// each one: add the block, multiply by the fixed r, then reduce mod p.
		const sumBeforeMultiply = accumulatorBefore + blockValue;
		const productBeforeReduce = sumBeforeMultiply * rClamped;
		accumulator = productBeforeReduce % POLY1305_PRIME;

		steps.push({
			blockIndex,
			blockHex: bytesToHex(blockBytes),
			blockValue: blockValue.toString(),
			accumulatorBefore: accumulatorBefore.toString(),
			sumBeforeMultiply: sumBeforeMultiply.toString(),
			productBeforeReduce: productBeforeReduce.toString(),
			accumulatorAfter: accumulator.toString(),
			rClamped: rClamped.toString(),
		});
	}

	return steps;
}

// ---------------------------------------------------------------------------
// Key-reuse forgery
//
// Poly1305 splits a message into 16-byte blocks. A message that fits in a
// SINGLE block (<= 16 bytes) has the simplest possible tag equation:
//
//     tag = ((c * r) mod p + s) mod 2^128
//
// where c is the padded little-endian block integer (public, derived from the
// message), r and s are the two secret halves of the key, and p = 2^130 - 5.
//
// Given two genuine (message, tag) pairs (c1, t1) and (c2, t2) under the SAME
// key, s cancels when the two equations are subtracted:
//
//     (c1 - c2) * r  ≡  (t1 - t2) + Δ·2^128   (mod p)
//
// The only unknown left besides r is a tiny integer wrap term Δ (the number of
// 2^128 truncations that separated the two tags), which lies in a small range.
// We try each Δ, solve for a candidate r modulo p, keep only candidates whose
// low bytes satisfy Poly1305's clamp mask, recover the matching s, and verify
// the candidate against BOTH known tags. The candidate that reproduces both is
// the real (r, s) — no brute force over the key, just algebra an attacker can
// do on paper. Once r and s are known, ANY new single-block message can be
// tagged. This is the whole reason a Poly1305 key must never be reused.
// ---------------------------------------------------------------------------

const CLAMP_HIGH_NIBBLE_INDICES = [3, 7, 11, 15];
const CLAMP_LOW_BITS_INDICES = [4, 8, 12];

export const SINGLE_BLOCK_MAX_BYTES = BLOCK_SIZE;

export interface RecoveredKey {
	r: bigint;
	s: bigint;
}

export interface ForgeryResult {
	recovered: RecoveredKey | null;
	forgedTag: Uint8Array | null;
	forgedTagHex: string | null;
}

export function utf8ByteLength(message: string): number {
	return utf8Bytes(message).length;
}

/** The integer value a 16-byte Poly1305 tag encodes (little-endian). */
export function tagBytesToInteger(tag: Uint8Array): bigint {
	return littleEndianBytesToBigInt(tag.slice(0, BLOCK_SIZE));
}

/** Padded little-endian block integer for a message that fits in one block. */
export function singleBlockInteger(message: string): bigint {
	const bytes = utf8Bytes(message);
	if (bytes.length > BLOCK_SIZE) {
		throw new Error('singleBlockInteger requires a message of at most 16 bytes.');
	}
	return getPoly1305BlockValue(bytes);
}

function modularInverse(value: bigint, modulus: bigint): bigint {
	let a = ((value % modulus) + modulus) % modulus;
	let [oldR, r] = [a, modulus];
	let [oldS, s] = [1n, 0n];

	while (r !== 0n) {
		const quotient = oldR / r;
		[oldR, r] = [r, oldR - quotient * r];
		[oldS, s] = [s, oldS - quotient * s];
	}

	return ((oldS % modulus) + modulus) % modulus;
}

/** True iff r's little-endian bytes satisfy the Poly1305 clamp mask. */
function satisfiesClamp(r: bigint): boolean {
	const bytes: number[] = [];
	let value = r;
	for (let index = 0; index < BLOCK_SIZE; index += 1) {
		bytes.push(Number(value & 0xffn));
		value >>= 8n;
	}
	for (const index of CLAMP_HIGH_NIBBLE_INDICES) {
		if ((bytes[index] & 0xf0) !== 0) return false;
	}
	for (const index of CLAMP_LOW_BITS_INDICES) {
		if ((bytes[index] & 0x03) !== 0) return false;
	}
	return true;
}

function bigIntToLittleEndian16(value: bigint): Uint8Array {
	const bytes = new Uint8Array(BLOCK_SIZE);
	let v = value;
	for (let index = 0; index < BLOCK_SIZE; index += 1) {
		bytes[index] = Number(v & 0xffn);
		v >>= 8n;
	}
	return bytes;
}

/**
 * Recover the secret (r, s) from two genuine single-block (message, tag) pairs
 * computed under the same key. Returns null if no candidate reproduces both
 * tags (e.g. the two messages are identical, giving no independent equation).
 */
export function recoverKeyFromTagPairs(
	c1: bigint,
	t1: bigint,
	c2: bigint,
	t2: bigint,
): RecoveredKey | null {
	const cDiff = (((c1 - c2) % POLY1305_PRIME) + POLY1305_PRIME) % POLY1305_PRIME;
	if (cDiff === 0n) {
		return null;
	}
	const cDiffInverse = modularInverse(cDiff, POLY1305_PRIME);
	const tDiff = t1 - t2;

	for (let delta = -4n; delta <= 4n; delta += 1n) {
		const rhs = (((tDiff + delta * TWO_POW_128) % POLY1305_PRIME) + POLY1305_PRIME) % POLY1305_PRIME;
		const r = (rhs * cDiffInverse) % POLY1305_PRIME;
		if (!satisfiesClamp(r)) {
			continue;
		}
		const s = ((((t1 - ((c1 * r) % POLY1305_PRIME)) % TWO_POW_128) + TWO_POW_128) % TWO_POW_128);
		const check1 = (((c1 * r) % POLY1305_PRIME) + s) % TWO_POW_128;
		const check2 = (((c2 * r) % POLY1305_PRIME) + s) % TWO_POW_128;
		if (check1 === t1 && check2 === t2) {
			return { r, s };
		}
	}

	return null;
}

/** Forge a tag for a new single-block message from recovered (r, s). */
export function forgeTag(recovered: RecoveredKey, message: string): Uint8Array {
	const c = singleBlockInteger(message);
	const tagValue = (((c * recovered.r) % POLY1305_PRIME) + recovered.s) % TWO_POW_128;
	return bigIntToLittleEndian16(tagValue);
}