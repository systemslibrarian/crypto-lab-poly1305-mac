import { expect, test, type Page } from '@playwright/test';

/**
 * Functional regression gate for the Poly1305 MAC demo.
 *
 * The a11y spec proves the page is reachable and scannable; this one proves the
 * page is *right*. Every assertion here is checked against a value the page
 * itself rendered — the 32-byte key in #key-display drives the expected r, s,
 * genuine tags and forged tag, so a wrong verdict cannot be papered over with a
 * hardcoded string. The three claims the README makes are pinned end to end:
 *
 *   1. Verification: original VALID, tampered message INVALID, tampered tag
 *      INVALID — with the tamper itself (trailing space / one flipped bit)
 *      asserted, so the failure names its cause.
 *   2. The Polynomial Stepper's arithmetic is internally consistent: each row's
 *      three stages compose into the next accumulator, the rows chain, and the
 *      final accumulator plus s reproduces the tag the page displayed.
 *   3. The key-reuse forgery is real: the recovered r/s equal the real key's,
 *      the forged tag equals the tag equation, and the "key broken" banner
 *      appears — plus every way the forgery can fail (identical messages,
 *      ambiguous candidates, over-length input).
 */

const PRIME = 2n ** 130n - 5n;
const TWO_POW_128 = 2n ** 128n;

const CLAMP_HIGH_NIBBLE = [3, 7, 11, 15];
const CLAMP_LOW_BITS = [4, 8, 12];

function hexToBytes(hex: string): number[] {
  const clean = hex.trim();
  expect(clean).toMatch(/^[0-9A-F]*$/);
  expect(clean.length % 2).toBe(0);
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function littleEndian(bytes: number[]): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function clampBytes(first16: number[]): number[] {
  const out = first16.slice();
  for (const i of CLAMP_HIGH_NIBBLE) out[i] &= 0x0f;
  for (const i of CLAMP_LOW_BITS) out[i] &= 0xfc;
  return out;
}

/** The (r, s) an honest observer derives from the key the page is displaying. */
function keyHalves(keyHex: string): { r: bigint; s: bigint; clampedHex: string } {
  const bytes = hexToBytes(keyHex);
  expect(bytes).toHaveLength(32);
  const clamped = clampBytes(bytes.slice(0, 16));
  return {
    r: littleEndian(clamped),
    s: littleEndian(bytes.slice(16)),
    clampedHex: clamped.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(''),
  };
}

/** Padded little-endian block integer for a message of at most 16 bytes. */
function singleBlockInteger(message: string): bigint {
  const bytes = Array.from(new TextEncoder().encode(message));
  expect(bytes.length).toBeLessThanOrEqual(16);
  return littleEndian([...bytes, 0x01]);
}

/** tag = ((c * r) mod p + s) mod 2^128, as 16 little-endian bytes in hex. */
function expectedTagHex(message: string, r: bigint, s: bigint): string {
  let value = (((singleBlockInteger(message) * r) % PRIME) + s) % TWO_POW_128;
  const bytes: string[] = [];
  for (let i = 0; i < 16; i += 1) {
    bytes.push(Number(value & 0xffn).toString(16).padStart(2, '0').toUpperCase());
    value >>= 8n;
  }
  return bytes.join('');
}

/** The page shortens 32-hex secrets to `first14…last8`; match either form. */
function expectShortHexOf(displayed: string, full: string): void {
  const compact = displayed.trim();
  if (compact.includes('…')) {
    expect(full.startsWith(compact.split('…')[0])).toBe(true);
    expect(full.endsWith(compact.split('…')[1])).toBe(true);
  } else {
    expect(compact).toBe(full);
  }
}

async function text(page: Page, selector: string): Promise<string> {
  return ((await page.locator(selector).textContent()) ?? '').trim();
}

async function keyOf(page: Page) {
  return keyHalves(await text(page, '#key-display'));
}

// Uncaught page exceptions fail the test that provoked them. Reset per test;
// a worker only ever runs one test at a time, so this stays test-scoped.
let pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto('.');
  await expect(page.locator('#compute-mac-button')).toBeVisible();
});

test.afterEach(() => {
  expect(pageErrors).toEqual([]);
});

test('the key, its clamped r, and the clamp comparison agree', async ({ page }) => {
  const keyHex = await text(page, '#key-display');
  const { clampedHex } = keyHalves(keyHex);

  // The "Clamped r" panel is populated at mount from the real key, not a stub.
  expect(await text(page, '#r-hex-display')).toBe(clampedHex);

  const lines = page.locator('#clamp-compare .clamp-line');
  await expect(lines).toHaveCount(2);
  const before = await lines.nth(0).locator('.clamp-byte').allTextContents();
  const after = await lines.nth(1).locator('.clamp-byte').allTextContents();
  expect(before.join('')).toBe(keyHex.slice(0, 32));
  expect(after.join('')).toBe(clampedHex);

  // Every byte the "after" line marks as changed really did change, and every
  // byte it leaves alone really is unchanged.
  const changed = await lines.nth(1).locator('.clamp-byte--changed').allTextContents();
  const reallyChanged = before.filter((b, i) => b !== after[i]);
  expect(changed).toEqual(after.filter((b, i) => b !== before[i]));
  expect(changed).toHaveLength(reallyChanged.length);
});

test('computing a MAC fills the tag grid and hex with the same 16 bytes', async ({ page }) => {
  await expect(page.locator('#tag-hex-display')).toHaveText('0'.repeat(32));
  await page.locator('#compute-mac-button').click();

  const tagHex = await text(page, '#tag-hex-display');
  expect(tagHex).toMatch(/^[0-9A-F]{32}$/);
  expect(tagHex).not.toBe('0'.repeat(32));

  const cells = await page.locator('#tag-display .tag-cell').allTextContents();
  expect(cells).toHaveLength(16);
  expect(cells.join('')).toBe(tagHex);

  // Every cell's accessible name states the byte value it renders, so the color
  // channel is never the only carrier (README: "hue encodes its value").
  for (let i = 0; i < 16; i += 1) {
    await expect(page.locator('#tag-display .tag-cell').nth(i)).toHaveAttribute(
      'aria-label',
      `Byte ${i + 1} of 16: 0x${cells[i]}`,
    );
  }
});

test('scenario 1 verifies the untampered message as VALID', async ({ page }) => {
  await page.locator('#compute-mac-button').click();
  await page.locator('#verify-original-button').click();

  await expect(page.locator('#verify-original-status')).toHaveText('VALID');
  await expect(page.locator('#verify-original-status')).toHaveClass(/scenario-status--valid/);
  // The other two scenarios have not been run: no verdict leaks across cards.
  await expect(page.locator('#verify-message-status')).toHaveText('Ready to verify');
  await expect(page.locator('#verify-tag-status')).toHaveText('Ready to verify');
});

test('scenario 2 rejects the tampered message and shows the tamper', async ({ page }) => {
  const message = 'Authenticate this message.';
  await page.locator('#message-input').fill(message);
  await page.locator('#compute-mac-button').click();

  // The cause is named on screen: the same message plus one trailing space.
  const preview = (await page.locator('#tampered-message-display').textContent()) ?? '';
  expect(preview).toBe(`${message} `);

  await page.locator('#verify-message-button').click();
  await expect(page.locator('#verify-message-status')).toHaveText('INVALID');
  await expect(page.locator('#verify-message-status')).toHaveClass(/scenario-status--invalid/);
});

test('scenario 3 rejects a one-bit tag flip and shows exactly that bit', async ({ page }) => {
  await page.locator('#compute-mac-button').click();
  const original = await page.locator('#tag-display .tag-cell').allTextContents();

  await page.locator('#verify-tag-button').click();
  await expect(page.locator('#verify-tag-status')).toHaveText('INVALID');
  await expect(page.locator('#verify-tag-status')).toHaveClass(/scenario-status--invalid/);

  const tampered = await page.locator('#tampered-tag-display .tag-cell').allTextContents();
  expect(tampered).toHaveLength(16);
  // The README promises "a single bit of a single tag byte": exactly one byte
  // differs, it is byte index 8, and the two values differ by exactly one bit.
  const differing = tampered.map((b, i) => (b === original[i] ? -1 : i)).filter((i) => i >= 0);
  expect(differing).toEqual([8]);
  expect(parseInt(tampered[8], 16) ^ parseInt(original[8], 16)).toBe(1);

  // The flipped cell is the one flagged, in markup and in its accessible name.
  const flagged = page.locator('#tampered-tag-display .tag-cell--tampered');
  await expect(flagged).toHaveCount(1);
  await expect(flagged).toHaveAttribute('aria-label', `Byte 9 of 16: 0x${tampered[8]}, flipped by the tamper`);
});

test('editing the message retracts the tag and every verdict', async ({ page }) => {
  await page.locator('#compute-mac-button').click();
  await page.locator('#verify-original-button').click();
  await expect(page.locator('#verify-original-status')).toHaveText('VALID');
  const firstTag = await text(page, '#tag-hex-display');

  await page.locator('#message-input').fill('A different message entirely.');

  // No stale VALID over a message that was never MACed.
  for (const id of ['#verify-original-status', '#verify-message-status', '#verify-tag-status']) {
    await expect(page.locator(id)).toHaveText('Awaiting MAC');
  }
  await expect(page.locator('#tag-hex-display')).toHaveText('0'.repeat(32));
  await expect(page.locator('#verify-original-button')).toBeDisabled();

  await page.locator('#compute-mac-button').click();
  expect(await text(page, '#tag-hex-display')).not.toBe(firstTag);
});

test('the polynomial stepper is arithmetically self-consistent and reproduces the tag', async ({ page }) => {
  const message = 'Authenticate this message.'; // 26 bytes -> exactly 2 blocks
  const messageBytes = new TextEncoder().encode(message);
  await page.locator('#message-input').fill(message);
  await page.locator('#compute-mac-button').click();
  const tagHex = await text(page, '#tag-hex-display');

  await page.locator('#show-math-button').click();
  const rows = page.locator('#math-steps-body .math-row');
  await expect(rows).toHaveCount(Math.min(4, Math.ceil(messageBytes.length / 16)));

  const { r, s } = await keyOf(page);
  // The displayed clamped r is the r the table multiplies by.
  expect(littleEndian(hexToBytes(await text(page, '#r-hex-display')))).toBe(r);
  expect(BigInt(await text(page, '#r-decimal-display'))).toBe(r);

  const count = await rows.count();
  let expectedAccBefore = 0n;
  let lastAccAfter = 0n;

  for (let i = 0; i < count; i += 1) {
    const cells = await rows.nth(i).locator('td').allTextContents();
    expect(cells).toHaveLength(7);
    const [index, blockHex, blockValue, accBefore, sum, product, accAfter] = cells.map((c) => c.trim());

    expect(index).toBe(String(i + 1));
    // Block bytes are this slice of the message, and the block value is that
    // slice with a 0x01 padding byte appended, read little-endian.
    const slice = Array.from(messageBytes.slice(i * 16, i * 16 + 16));
    expect(hexToBytes(blockHex)).toEqual(slice);
    expect(BigInt(blockValue)).toBe(littleEndian([...slice, 0x01]));

    // The three stages compose into the recurrence, and rows chain.
    expect(BigInt(accBefore)).toBe(expectedAccBefore);
    expect(BigInt(sum)).toBe(BigInt(accBefore) + BigInt(blockValue));
    expect(BigInt(product)).toBe(BigInt(sum) * r);
    expect(BigInt(accAfter)).toBe(BigInt(product) % PRIME);

    expectedAccBefore = BigInt(accAfter);
    lastAccAfter = BigInt(accAfter);
  }

  // The whole point: the accumulator the table built, plus s, IS the tag the
  // page displayed in Section A.
  expect((lastAccAfter + s) % TWO_POW_128).toBe(littleEndian(hexToBytes(tagHex)));
});

test('the stepper says so when a message has no blocks at all', async ({ page }) => {
  await page.locator('#message-input').fill('');
  await page.locator('#show-math-button').click();
  await expect(page.locator('#math-steps-body .math-empty')).toHaveText(/no bytes.*no Poly1305 blocks/);
  await expect(page.locator('#math-steps-body .math-row')).toHaveCount(0);
});

test('key reuse forges a tag the real key accepts', async ({ page }) => {
  const messageOne = 'Pay Alice $10';
  const messageTwo = 'Pay Bob $20';
  const forged = 'Pay Mallory $99';
  const { r, s } = await keyOf(page);

  await page.locator('#compute-reuse-button').click();

  // Both genuine tags are real Poly1305 tags under the displayed key.
  expect(await text(page, '#reuse-tag-one')).toBe(expectedTagHex(messageOne, r, s));
  expect(await text(page, '#reuse-tag-two')).toBe(expectedTagHex(messageTwo, r, s));

  // The byte-length note's three numbers are the real UTF-8 lengths.
  const note = await text(page, '#reuse-length-note');
  const lengths = [...note.matchAll(/(\d+) B/g)].map((m) => Number(m[1]));
  expect(lengths).toEqual(
    [messageOne, messageTwo, forged].map((m) => new TextEncoder().encode(m).length),
  );
  await expect(page.locator('#reuse-length-note')).not.toHaveClass(/reuse-length-note--over/);

  await page.locator('#forge-button').click();

  await expect(page.locator('#forge-status')).toHaveText(/^VALID/);
  await expect(page.locator('#forge-status')).toHaveClass(/scenario-status--valid/);
  await expect(page.locator('#reuse-warning-banner')).toBeVisible();
  await expect(page.locator('#reuse-warning-banner')).toContainText('Key broken');

  // The attacker's algebra recovered the SENDER'S key, not merely some key:
  // both halves match what the displayed 32-byte key implies.
  const secrets = page.locator('#forge-recovered .attack-solve-val');
  await expect(secrets).toHaveCount(2);
  expectShortHexOf(await secrets.nth(0).innerText(), r.toString(16).toUpperCase().padStart(32, '0'));
  expectShortHexOf(await secrets.nth(1).innerText(), s.toString(16).toUpperCase().padStart(32, '0'));

  // And the forged tag is the tag equation evaluated on a message the sender
  // never signed — distinct from both captured tags.
  const forgedHex = await text(page, '#forge-tag-hex');
  expect(forgedHex).toBe(expectedTagHex(forged, r, s));
  expect(forgedHex).not.toBe(expectedTagHex(messageOne, r, s));
  expect(forgedHex).not.toBe(expectedTagHex(messageTwo, r, s));
  expect((await page.locator('#forge-tag-display .tag-cell').allTextContents()).join('')).toBe(forgedHex);
});

test('a forged message the user types stays forgeable (and clears the old verdict)', async ({ page }) => {
  const { r, s } = await keyOf(page);
  await page.locator('#compute-reuse-button').click();
  await page.locator('#forge-button').click();
  await expect(page.locator('#reuse-warning-banner')).toBeVisible();

  // Regression: editing the forged message used to disable Forge for good (the
  // gate read state.recoveredKey, which is only set *after* a forgery) and left
  // the "key broken" alert standing over a cleared, all-zero tag.
  await page.locator('#forge-message-input').fill('Pay Mallory $7');
  await expect(page.locator('#forge-tag-hex')).toHaveText('0'.repeat(32));
  await expect(page.locator('#reuse-warning-banner')).toBeHidden();
  await expect(page.locator('#forge-status')).toHaveText('Ready — click Forge Tag');
  await expect(page.locator('#forge-button')).toBeEnabled();

  await page.locator('#forge-button').click();
  await expect(page.locator('#forge-status')).toHaveText(/^VALID/);
  expect(await text(page, '#forge-tag-hex')).toBe(expectedTagHex('Pay Mallory $7', r, s));
});

test('two identical messages cannot recover the key, and the page says why', async ({ page }) => {
  await page.locator('#reuse-message-two').fill('Pay Alice $10');
  await page.locator('#compute-reuse-button').click();
  // The same message under the same key gives the same tag — one equation twice.
  expect(await text(page, '#reuse-tag-one')).toBe(await text(page, '#reuse-tag-two'));

  await page.locator('#forge-button').click();
  await expect(page.locator('#forge-status')).toHaveText('Need two different messages');
  await expect(page.locator('#forge-status')).toHaveClass(/scenario-status--invalid/);
  await expect(page.locator('#forge-recovered')).toContainText('same equation');
  await expect(page.locator('#reuse-warning-banner')).toBeHidden();
  await expect(page.locator('#forge-tag-hex')).toHaveText('0'.repeat(32));
});

test('messages over one block are refused, naming which ones', async ({ page }) => {
  await page.locator('#reuse-message-one').fill('This message is far longer than one block');
  await page.locator('#compute-reuse-button').click();

  await expect(page.locator('#reuse-length-note')).toHaveClass(/reuse-length-note--over/);
  await expect(page.locator('#reuse-length-note')).toContainText('Message 1 exceed 16 bytes');
  await expect(page.locator('#reuse-length-note')).not.toContainText('Message 2 ');
  await expect(page.locator('#forge-button')).toBeDisabled();
  await expect(page.locator('#reuse-warning-banner')).toBeHidden();

  // An over-length forge target is refused too, without losing the pairs.
  await page.locator('#reuse-message-one').fill('Pay Alice $10');
  await page.locator('#compute-reuse-button').click();
  await expect(page.locator('#forge-button')).toBeEnabled();
  await page.locator('#forge-message-input').fill('This forged message is much too long');
  await expect(page.locator('#reuse-length-note')).toContainText('the forged message exceed 16 bytes');
  await expect(page.locator('#forge-button')).toBeDisabled();
});

test('an underdetermined pair is reported as ambiguous rather than forged from', async ({ page }) => {
  // "ab"/"ac" differ in one byte, so several candidate keys reproduce both tags
  // for ~98% of keys. Regenerate until we hit one; failing every attempt would
  // itself mean the candidate enumeration stopped working.
  await page.locator('#reuse-message-one').fill('ab');
  await page.locator('#reuse-message-two').fill('ac');

  let statusText = '';
  for (let attempt = 0; attempt < 12; attempt += 1) {
    if (attempt > 0) {
      await page.locator('#generate-key-button').click();
      await page.locator('#reuse-message-one').fill('ab');
      await page.locator('#reuse-message-two').fill('ac');
    }
    await page.locator('#compute-reuse-button').click();
    await page.locator('#forge-button').click();
    statusText = await text(page, '#forge-status');
    if (/candidates fit/.test(statusText)) break;
  }

  expect(statusText).toMatch(/^Key not pinned down — \d+ candidates fit$/);
  await expect(page.locator('#forge-status')).toHaveClass(/scenario-status--invalid/);

  // The count in the verdict and the count in the explanation are the same
  // number, and it really is more than one.
  const claimed = Number(/(\d+) candidates fit/.exec(statusText)![1]);
  expect(claimed).toBeGreaterThan(1);
  expect(Number(await text(page, '#forge-recovered strong'))).toBe(claimed);

  // Nothing was forged from the guess.
  await expect(page.locator('#forge-tag-hex')).toHaveText('0'.repeat(32));
  await expect(page.locator('#reuse-warning-banner')).toBeHidden();
});
