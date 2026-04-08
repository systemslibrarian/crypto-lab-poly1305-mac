const BLOCK_SIZE = 16;
const MAX_BLOCKS = 4;
const POLY1305_PRIME = (2n ** 130n) - 5n;

export interface PolyStep {
	blockIndex: number;
	blockHex: string;
	blockValue: string;
	accumulatorBefore: string;
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
	const padded = new Uint8Array(BLOCK_SIZE);
	padded.set(chunk);
	return padded;
}

function getPoly1305BlockValue(blockBytes: Uint8Array): bigint {
	const blockWithOne = new Uint8Array(BLOCK_SIZE + 1);
	blockWithOne.set(blockBytes);
	blockWithOne[BLOCK_SIZE] = 0x01;
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

		accumulator = ((accumulator + blockValue) * rClamped) % POLY1305_PRIME;

		steps.push({
			blockIndex,
			blockHex: bytesToHex(blockBytes),
			blockValue: blockValue.toString(),
			accumulatorBefore: accumulatorBefore.toString(),
			accumulatorAfter: accumulator.toString(),
			rClamped: rClamped.toString(),
		});
	}

	return steps;
}