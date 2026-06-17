// @vitest-environment jsdom
import { webcrypto } from 'node:crypto';
import axe from 'axe-core';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mountApp } from './ui.ts';

beforeAll(() => {
	// generateKey() needs Web Crypto; jsdom does not always expose getRandomValues, so borrow Node's.
	if (!globalThis.crypto?.getRandomValues) {
		Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
	}
});

function mountFresh(): HTMLDivElement {
	// Reset the document so repeated mounts cannot create duplicate IDs.
	document.body.innerHTML = '';
	const root = document.createElement('div');
	document.body.appendChild(root);
	mountApp(root);
	return root;
}

beforeEach(() => {
	document.body.innerHTML = '';
});

describe('rendered app accessibility', () => {
	it('has no axe-core violations', async () => {
		mountFresh();

		const results = await axe.run(document.body, {
			// jsdom has no layout engine, so contrast is verified separately with math.
			rules: { 'color-contrast': { enabled: false } },
		});

		const summary = results.violations.map(
			(v) => `${v.id}: ${v.help} -> ${v.nodes.map((n) => n.html).join(' | ')}`,
		);
		expect(summary).toEqual([]);
	});

	it('exposes a single h1 and live verification regions', () => {
		const root = mountFresh();

		expect(root.querySelectorAll('h1')).toHaveLength(1);
		expect(root.querySelector('main')).not.toBeNull();
		// Every verify status is a polite live region so results are announced.
		const statuses = root.querySelectorAll('.scenario-status[aria-live="polite"]');
		expect(statuses).toHaveLength(3);
	});
});
