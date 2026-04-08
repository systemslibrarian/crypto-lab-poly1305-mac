import { poly1305 } from '@noble/ciphers/_poly1305.js';
import './style.css';
import {
	bytesToHex,
	computeMAC,
	computeMACResult,
	generateKey,
	tamperMessage,
	tamperTag,
	verifyMAC,
} from './mac.ts';
import { clampR, computeSteps } from './poly-math.ts';
import { mountApp } from './ui.ts';

void poly1305;

const demoMessage = 'Authenticate me.';
const demoKey = generateKey();
const demoTag = computeMAC(demoMessage, demoKey);
const demoResult = computeMACResult(demoMessage, demoKey);
const tamperedMessage = tamperMessage(demoMessage);
const tamperedTag = tamperTag(demoTag);
const demoStepsMessage = 'Hello, Poly1305 MAC demo!';
const demoSteps = computeSteps(demoStepsMessage, demoKey);

console.group('Phase 2: Poly1305 MAC self-test');
console.log('Key (hex):', bytesToHex(demoKey));
console.log('Message:', demoMessage);
console.log('Tag (hex):', bytesToHex(demoTag));
console.log('Message bytes:', demoResult.messageBytes);
console.log('Verify original:', verifyMAC(demoMessage, demoTag, demoKey));
console.log('Tampered message:', JSON.stringify(tamperedMessage));
console.log('Verify tampered message:', verifyMAC(tamperedMessage, demoTag, demoKey));
console.log('Tampered tag (hex):', bytesToHex(tamperedTag));
console.log('Verify tampered tag:', verifyMAC(demoMessage, tamperedTag, demoKey));
console.groupEnd();

console.group('Phase 3: Poly1305 polynomial steps');
console.log('Visualization message:', demoStepsMessage);
console.log('Clamped r (decimal):', clampR(demoKey.subarray(0, 16)).toString());
console.table(demoSteps);
console.groupEnd();

mountApp(document.querySelector<HTMLDivElement>('#app')!);
