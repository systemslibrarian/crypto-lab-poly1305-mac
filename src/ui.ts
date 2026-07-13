import {
  bytesToHex,
  computeMACResult,
  generateKey,
  tamperMessage,
  tamperTag,
  verifyMAC,
  type MACResult,
} from './mac.ts';
import {
  clampR,
  computeSteps,
  forgeTag,
  recoverKeyFromTagPairs,
  singleBlockInteger,
  tagBytesToInteger,
  utf8ByteLength,
  SINGLE_BLOCK_MAX_BYTES,
  type PolyStep,
  type RecoveredKey,
} from './poly-math.ts';

const DEFAULT_MESSAGE = 'Authenticate this message.';
// Key-reuse forgery uses single-block (<=16-byte) messages so two (message,
// tag) pairs uniquely determine (r, s). Defaults are chosen to fit one block.
const DEFAULT_REUSE_MESSAGE_ONE = 'Pay Alice $10';
const DEFAULT_REUSE_MESSAGE_TWO = 'Pay Bob $20';
const DEFAULT_FORGE_MESSAGE = 'Pay Mallory $99';
const ZERO_TAG = new Uint8Array(16);

type StatusTone = 'pending' | 'valid' | 'invalid';
type TabKey = 'what' | 'math' | 'constant-time';

interface ReusePair {
  message: string;
  blockInteger: bigint;
  tagInteger: bigint;
}

interface AppState {
  key: Uint8Array;
  macResult: MACResult | null;
  // The two genuine single-block pairs the sender signed under one key, and the
  // key (r, s) an attacker recovers from them. Populated by "Sign Both Messages".
  reusePairOne: ReusePair | null;
  reusePairTwo: ReusePair | null;
  recoveredKey: RecoveredKey | null;
}

interface UIElements {
  keyDisplay: HTMLDivElement;
  messageInput: HTMLTextAreaElement;
  tagDisplay: HTMLDivElement;
  tagHexDisplay: HTMLDivElement;
  tamperedMessageDisplay: HTMLDivElement;
  tamperedTagDisplay: HTMLDivElement;
  verifyOriginalButton: HTMLButtonElement;
  verifyMessageButton: HTMLButtonElement;
  verifyTagButton: HTMLButtonElement;
  verifyOriginalStatus: HTMLParagraphElement;
  verifyMessageStatus: HTMLParagraphElement;
  verifyTagStatus: HTMLParagraphElement;
  rHexDisplay: HTMLDivElement;
  rDecimalDisplay: HTMLParagraphElement;
  clampCompare: HTMLDivElement;
  mathStepsBody: HTMLTableSectionElement;
  reuseMessageOne: HTMLTextAreaElement;
  reuseMessageTwo: HTMLTextAreaElement;
  reuseTagOne: HTMLDivElement;
  reuseTagTwo: HTMLDivElement;
  reuseWarningBanner: HTMLDivElement;
  forgeMessageInput: HTMLTextAreaElement;
  forgeButton: HTMLButtonElement;
  forgeStep: HTMLParagraphElement;
  forgeRecovered: HTMLDivElement;
  forgeTagDisplay: HTMLDivElement;
  forgeTagHex: HTMLDivElement;
  forgeStatus: HTMLParagraphElement;
  reuseLengthNote: HTMLParagraphElement;
  generateKeyButton: HTMLButtonElement;
  copyKeyButton: HTMLButtonElement;
  computeMacButton: HTMLButtonElement;
  copyTagButton: HTMLButtonElement;
  showMathButton: HTMLButtonElement;
  computeReuseButton: HTMLButtonElement;
  tabButtons: HTMLButtonElement[];
  tabPanels: HTMLElement[];
  copyAnnouncer: HTMLDivElement;
}

function createTemplate(): string {
  return `
    <main class="page-shell" id="main-content" tabindex="-1">
      <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch to light mode" title="Switch to light mode">🌙</button>
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">Poly1305</h1>
          <p class="cl-hero-sub">One-Time MAC · GF(2^130-5)</p>
          <p class="cl-hero-desc">
            Compute and verify a Poly1305 tag, watch the message evaluate as a polynomial over the field GF(2^130-5),
            and see how reusing one key across two messages leaks it.
          </p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">
            An authentication tag is often the only thing standing between a genuine message and a forged one.
            Poly1305 is provably strong per key, but it is a one-time MAC: reuse the key and an attacker can solve
            for it and forge at will.
          </p>
        </aside>
      </header>

      <section class="lab-section" aria-labelledby="playground-heading">
        <div class="section-heading-row">
          <div>
            <p class="section-kicker">Section A</p>
            <h2 id="playground-heading">MAC Playground</h2>
          </div>
          <button class="action-button" type="button" id="generate-key-button">Generate New Key</button>
        </div>

        <div class="playground-grid">
          <article class="panel-card">
            <div class="panel-header">
              <h3>Key</h3>
              <button class="ghost-button" type="button" id="copy-key-button" aria-label="Copy key">Copy</button>
            </div>
            <p class="panel-copy">Shared 32-byte key for the playground and the key-reuse warning below.</p>
            <div class="mono-block mono-hex key-display" id="key-display"></div>
          </article>

          <article class="panel-card panel-card--wide">
            <div class="panel-header">
              <h3>Message</h3>
              <button class="action-button" type="button" id="compute-mac-button">Compute MAC</button>
            </div>
            <textarea id="message-input" class="message-input" rows="4" aria-label="Message to authenticate">${DEFAULT_MESSAGE}</textarea>
          </article>

          <article class="panel-card panel-card--wide">
            <div class="panel-header">
              <div>
                <h3>Authentication Tag</h3>
                <p class="panel-copy">128-bit tag (16 bytes)</p>
              </div>
              <button class="ghost-button" type="button" id="copy-tag-button" aria-label="Copy tag">Copy</button>
            </div>
            <div class="tag-grid" id="tag-display" aria-hidden="true"></div>
            <p class="tag-legend">
              Each square is one of the 16 tag bytes. <strong>Color = byte value:</strong>
              <span class="tag-legend-scale" aria-hidden="true"></span>
              <span class="tag-legend-ends"><span>0x00</span><span>0xFF</span></span>
              Hover a square for its exact value.
            </p>
            <div class="mono-inline mono-hex" id="tag-hex-display"></div>
          </article>
        </div>

        <div class="scenario-grid">
          <article class="scenario-card">
            <h3>Scenario 1 — Verify Original</h3>
            <p class="scenario-copy">Run verification against the unchanged message and tag.</p>
            <button class="action-button" type="button" id="verify-original-button" disabled>Verify Original</button>
            <p class="scenario-status" id="verify-original-status" role="status" aria-live="polite" aria-atomic="true">Awaiting MAC</p>
          </article>

          <article class="scenario-card">
            <h3>Scenario 2 — Tamper Message</h3>
            <p class="scenario-copy">Modified message shown below: original plus a single trailing space.</p>
            <div class="preview-block" id="tampered-message-display"></div>
            <button class="action-button" type="button" id="verify-message-button" disabled>Verify Tampered Message</button>
            <p class="scenario-status" id="verify-message-status" role="status" aria-live="polite" aria-atomic="true">Awaiting MAC</p>
          </article>

          <article class="scenario-card">
            <h3>Scenario 3 — Tamper Tag</h3>
            <p class="scenario-copy">The original message is preserved, but byte 8 of the tag is flipped.</p>
            <div class="tag-grid tag-grid--compact" id="tampered-tag-display" aria-hidden="true"></div>
            <button class="action-button" type="button" id="verify-tag-button" disabled>Verify Tampered Tag</button>
            <p class="scenario-status" id="verify-tag-status" role="status" aria-live="polite" aria-atomic="true">Awaiting MAC</p>
          </article>
        </div>
      </section>

      <section class="lab-section" aria-labelledby="stepper-heading">
        <div class="section-heading-row">
          <div>
            <p class="section-kicker">Section B</p>
            <h2 id="stepper-heading">Polynomial Stepper</h2>
          </div>
          <button class="action-button" type="button" id="show-math-button">Show Math</button>
        </div>

        <p class="stepper-intro">
          Poly1305 does its arithmetic in a <strong>finite field</strong> — a number system with a fixed set of
          values where add and multiply always “wrap around” a chosen prime, here <code>p = 2¹³⁰ − 5</code> (written
          <strong>GF(2¹³⁰−5)</strong>). Working in this field is what gives the tag its provable forgery bound. Two
          values come from the key: <strong>r</strong>, the fixed multiplier used every step, and <strong>s</strong>,
          added once at the very end.
        </p>

        <div class="math-summary-grid">
          <article class="panel-card">
            <div class="panel-header">
              <h3>Clamped r</h3>
            </div>
            <div class="mono-block mono-hex" id="r-hex-display"></div>
            <p class="math-decimal" id="r-decimal-display"></p>
            <details class="inline-glossary">
              <summary>What is clamping?</summary>
              <p class="inline-glossary-copy">
                Before use, 22 specific bits of the key's first 16 bytes are forced to <code>0</code>. This
                <strong>clamping</strong> keeps <code>r</code> in a range that makes the field multiplication fast and
                blocks classes of polynomial forgery. Highlighted nibbles below are the bits clamping zeroes:
              </p>
              <div class="clamp-compare" id="clamp-compare" role="region" aria-label="Key bytes before and after clamping" tabindex="0"></div>
            </details>
          </article>
          <article class="panel-card">
            <div class="panel-header">
              <h3>Prime Field</h3>
            </div>
            <div class="mono-block">p = 2^130 - 5</div>
            <p class="math-decimal">1361129467683753853853498429727072845819</p>
            <p class="panel-copy">The field size. Every add and multiply in the stepper is taken mod this prime.</p>
          </article>
        </div>

        <p class="stepper-recurrence">
          Each block updates a running accumulator with the same recurrence:
          <code>acc ← ((acc + block) × r) mod p</code>. The table breaks that into its three stages so you can
          follow how <strong>Acc After</strong> is built — the block is <em>added</em> first (this is what makes the
          message blocks the coefficients of a polynomial in <code>r</code>), then multiplied by the fixed
          <code>r</code>, then reduced mod <code>p</code>.
        </p>

        <p class="table-hint">Scroll the table sideways to see every column.</p>
        <div class="table-shell" tabindex="0" role="region" aria-label="Poly1305 accumulator steps, scroll horizontally to see all columns">
          <table class="math-table">
            <caption class="sr-only">
              First four Poly1305 blocks. Each row shows the block value, then the three stages of the recurrence:
              accumulator plus block, that sum times the fixed r, and the result reduced mod p to give the next accumulator.
            </caption>
            <thead>
              <tr>
                <th scope="col">Block #</th>
                <th scope="col">Block (hex)</th>
                <th scope="col">Block Value</th>
                <th scope="col">Acc Before</th>
                <th scope="col">Acc + Block</th>
                <th scope="col">(Acc + Block) × r</th>
                <th scope="col">mod p → Acc After</th>
              </tr>
            </thead>
            <tbody id="math-steps-body"></tbody>
          </table>
        </div>

        <p class="section-footnote">
          <strong>r</strong> is the fixed multiplier derived from the first half of the key (shown above as “Clamped r”); it is the same in every row.
          Showing first 4 blocks only for clarity. Real Poly1305 processes all message blocks sequentially.
        </p>
      </section>

      <section class="lab-section" aria-labelledby="reuse-heading">
        <div class="section-heading-row">
          <div>
            <p class="section-kicker">Section C</p>
            <h2 id="reuse-heading">Forge a Tag by Reusing One Key</h2>
          </div>
          <button class="action-button action-button--danger" type="button" id="compute-reuse-button">Step 1 · Sign Both Messages (Same Key)</button>
        </div>

        <p class="reuse-intro">
          Poly1305 is a <strong>one-time</strong> MAC: safe for exactly one message per key.
          Below, the sender breaks that rule and signs <em>two</em> short messages with the same key.
          You then play the attacker — who never sees the key — and forge a valid tag for a
          <em>third</em> message the sender never signed. If the forgery verifies, the key is broken.
        </p>

        <div class="attack-lane">
          <div class="attack-step">
            <p class="attack-step-label"><span class="attack-step-num">1</span> Two genuine (message, tag) pairs under one key</p>
            <div class="reuse-grid">
              <article class="panel-card">
                <h3>Message 1 (signed by sender)</h3>
                <textarea id="reuse-message-one" class="message-input" rows="2" aria-label="Key reuse message 1">${DEFAULT_REUSE_MESSAGE_ONE}</textarea>
                <div class="mono-inline mono-hex" id="reuse-tag-one"></div>
              </article>
              <article class="panel-card">
                <h3>Message 2 (signed by sender)</h3>
                <textarea id="reuse-message-two" class="message-input" rows="2" aria-label="Key reuse message 2">${DEFAULT_REUSE_MESSAGE_TWO}</textarea>
                <div class="mono-inline mono-hex" id="reuse-tag-two"></div>
              </article>
            </div>
            <p class="reuse-length-note" id="reuse-length-note"></p>
          </div>

          <div class="attack-step">
            <p class="attack-step-label"><span class="attack-step-num">2</span> Attacker solves the two tag equations for the secret r and s</p>
            <div class="attack-solve" id="forge-recovered" role="region" aria-label="Recovered secret key values" tabindex="0">
              <p class="attack-solve-empty">Run step 1, type a forged message, then forge to reveal the recovered r and s here.</p>
            </div>
          </div>

          <div class="attack-step">
            <p class="attack-step-label"><span class="attack-step-num">3</span> Forge a tag for a message the sender never signed</p>
            <article class="panel-card">
              <div class="panel-header">
                <div>
                  <h3>Forged message (you choose)</h3>
                  <p class="panel-copy">Up to 16 bytes (one Poly1305 block).</p>
                </div>
                <button class="action-button action-button--danger" type="button" id="forge-button" disabled>Forge Tag</button>
              </div>
              <textarea id="forge-message-input" class="message-input" rows="2" aria-label="Message to forge a tag for">${DEFAULT_FORGE_MESSAGE}</textarea>
              <p class="panel-copy" id="forge-step">Forged tag (computed from the stolen r and s):</p>
              <div class="tag-grid tag-grid--compact" id="forge-tag-display" aria-hidden="true"></div>
              <div class="mono-inline mono-hex" id="forge-tag-hex"></div>
              <p class="scenario-status" id="forge-status" role="status" aria-live="polite" aria-atomic="true">Awaiting forgery</p>
            </article>
          </div>
        </div>

        <div class="warning-banner" id="reuse-warning-banner" role="alert" hidden>
          <strong>⚠ Key broken.</strong>
          <span>A message the sender never signed just verified as VALID under their key. That is why a Poly1305 key must authenticate only ONE message.</span>
        </div>

        <details class="explanation-details">
          <summary>How the forgery works (the algebra)</summary>
          <p>
            A single-block message has the tag equation <code>tag = ((c · r) mod p + s) mod 2¹²⁸</code>,
            where <code>c</code> is the message's padded block integer (public) and <code>(r, s)</code> is the
            secret key. Two pairs under the same key give two equations. Subtracting them cancels <code>s</code>,
            leaving <code>(c₁ − c₂)·r ≡ (t₁ − t₂) + Δ·2¹²⁸ (mod p)</code> with only a tiny integer wrap term
            <code>Δ</code> unknown. Trying the few possible <code>Δ</code> values, keeping the candidate whose bits
            satisfy Poly1305's clamp mask, and checking it against both known tags recovers the real <code>r</code>
            (and then <code>s</code>) — no brute force. With <code>(r, s)</code> in hand, any new message is trivially
            forgeable. In ChaCha20-Poly1305 this never happens: a fresh Poly1305 key is derived per nonce, so no two
            messages ever share one.
          </p>
        </details>
      </section>

      <section class="lab-section" aria-labelledby="info-heading">
        <div class="section-heading-row">
          <div>
            <p class="section-kicker">Reference</p>
            <h2 id="info-heading">Poly1305 Notes</h2>
          </div>
        </div>

        <div class="info-tabs" role="tablist" aria-label="Poly1305 reference tabs">
          <button class="tab-button is-active" id="tab-what" data-tab="what" type="button" role="tab" aria-selected="true" aria-controls="panel-what">What Poly1305 Is</button>
          <button class="tab-button" id="tab-math" data-tab="math" type="button" role="tab" aria-selected="false" aria-controls="panel-math">The Math</button>
          <button class="tab-button" id="tab-constant-time" data-tab="constant-time" type="button" role="tab" aria-selected="false" aria-controls="panel-constant-time">Constant-Time Verification</button>
        </div>

        <div class="info-panels">
          <div class="info-panel is-active" id="panel-what" data-panel="what" role="tabpanel" aria-labelledby="tab-what" tabindex="0">
            <p>
              Poly1305 is a one-time MAC. Reusing its 32-byte key destroys the security model, so the same key must never
              authenticate two different messages. When used correctly, its 128-bit tag gives an attacker about a 2^-128
              forgery chance per attempt.
            </p>
            <p>
              It was designed by Daniel J. Bernstein and evaluates a polynomial over GF(2^130-5). Verification must also
              be constant time: comparing tags with early exits creates a timing side channel.
            </p>
            <p>
              In ChaCha20-Poly1305, ChaCha20 derives a fresh one-time Poly1305 key from each unique nonce. That is what
              makes the construction safe in normal protocol use. Standalone Poly1305 is only appropriate when one-time
              key usage can be guaranteed externally.
            </p>
          </div>

          <div class="info-panel" id="panel-math" data-panel="math" role="tabpanel" aria-labelledby="tab-math" tabindex="0" hidden>
            <p>
              The message is split into 16-byte blocks. Each block is interpreted as a little-endian integer after a
              single 0x01 byte is appended, and the accumulator evolves as accumulator = (accumulator + block) * r mod p.
            </p>
            <p>
              The first 16 bytes of the key become r after clamping, while the last 16 bytes become s. After all blocks
              are processed, the final tag is (accumulator + s) mod 2^128.
            </p>
            <p>
              Clamping r forces a restricted bit pattern that blocks classes of polynomial forgery attacks. The prime
              p = 2^130 - 5 is chosen because it supports efficient reduction while remaining large enough for the padded
              16-byte blocks Poly1305 consumes.
            </p>
          </div>

          <div class="info-panel" id="panel-constant-time" data-panel="constant-time" role="tabpanel" aria-labelledby="tab-constant-time" tabindex="0" hidden>
            <p>
              Safe verification recomputes the expected tag and compares every byte, even when the first byte already
              differs. Returning early leaks how much of the candidate tag was correct, and that timing signal can help
              attackers refine forgeries.
            </p>
            <p>
              This demo uses a constant-time XOR accumulation: diff starts at zero, every byte contributes with XOR, and
              verification succeeds only if diff is still zero after all 16 bytes have been processed.
            </p>
          </div>
        </div>
      </section>

      <div class="sr-only" id="copy-announcer" role="status" aria-live="polite"></div>
    </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-mac-race/" style="color:#35d6bb">mac-race</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-chacha20-stream/" style="color:#35d6bb">chacha20-stream</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" style="color:#35d6bb">aes-modes</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/" style="color:#35d6bb">nonce-guard</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" style="color:#35d6bb">babel-hash</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-poly1305-mac" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
  `;
}

function requireElement<T extends Element>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);

  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }

  return element;
}

function collectElements(root: HTMLDivElement): UIElements {
  return {
    keyDisplay: requireElement(root, '#key-display'),
    messageInput: requireElement(root, '#message-input'),
    tagDisplay: requireElement(root, '#tag-display'),
    tagHexDisplay: requireElement(root, '#tag-hex-display'),
    tamperedMessageDisplay: requireElement(root, '#tampered-message-display'),
    tamperedTagDisplay: requireElement(root, '#tampered-tag-display'),
    verifyOriginalButton: requireElement(root, '#verify-original-button'),
    verifyMessageButton: requireElement(root, '#verify-message-button'),
    verifyTagButton: requireElement(root, '#verify-tag-button'),
    verifyOriginalStatus: requireElement(root, '#verify-original-status'),
    verifyMessageStatus: requireElement(root, '#verify-message-status'),
    verifyTagStatus: requireElement(root, '#verify-tag-status'),
    rHexDisplay: requireElement(root, '#r-hex-display'),
    rDecimalDisplay: requireElement(root, '#r-decimal-display'),
    clampCompare: requireElement(root, '#clamp-compare'),
    mathStepsBody: requireElement(root, '#math-steps-body'),
    reuseMessageOne: requireElement(root, '#reuse-message-one'),
    reuseMessageTwo: requireElement(root, '#reuse-message-two'),
    reuseTagOne: requireElement(root, '#reuse-tag-one'),
    reuseTagTwo: requireElement(root, '#reuse-tag-two'),
    reuseWarningBanner: requireElement(root, '#reuse-warning-banner'),
    forgeMessageInput: requireElement(root, '#forge-message-input'),
    forgeButton: requireElement(root, '#forge-button'),
    forgeStep: requireElement(root, '#forge-step'),
    forgeRecovered: requireElement(root, '#forge-recovered'),
    forgeTagDisplay: requireElement(root, '#forge-tag-display'),
    forgeTagHex: requireElement(root, '#forge-tag-hex'),
    forgeStatus: requireElement(root, '#forge-status'),
    reuseLengthNote: requireElement(root, '#reuse-length-note'),
    generateKeyButton: requireElement(root, '#generate-key-button'),
    copyKeyButton: requireElement(root, '#copy-key-button'),
    computeMacButton: requireElement(root, '#compute-mac-button'),
    copyTagButton: requireElement(root, '#copy-tag-button'),
    showMathButton: requireElement(root, '#show-math-button'),
    computeReuseButton: requireElement(root, '#compute-reuse-button'),
    tabButtons: Array.from(root.querySelectorAll<HTMLButtonElement>('[data-tab]')),
    tabPanels: Array.from(root.querySelectorAll<HTMLElement>('[data-panel]')),
    copyAnnouncer: requireElement(root, '#copy-announcer'),
  };
}

// Map a byte 0x00..0xFF to a hue: 0x00 -> blue (220deg), 0xFF -> red (0deg).
// The color is a readable fingerprint of the byte's value, not decoration.
function byteHue(byte: number): number {
  return 220 - Math.round((byte / 255) * 220);
}

function renderTagCells(bytes: Uint8Array, tamperedIndex?: number, animateFlip = false): string {
  return Array.from({ length: 16 }, (_, index) => {
    const byte = bytes[index] ?? 0;
    const hue = byteHue(byte);
    const hex = byte.toString(16).padStart(2, '0').toUpperCase();
    const isTampered = tamperedIndex === index;
    const modifier =
      (isTampered ? ' tag-cell--tampered' : '') + (isTampered && animateFlip ? ' tag-cell--flipping' : '');
    // title = hover tooltip; aria-label carries the value + tamper note so the
    // meaning survives for screen readers (color is never the only channel).
    const label = `Byte ${index + 1} of 16: 0x${hex}${isTampered ? ', flipped by the tamper' : ''}`;

    return `
      <span
        class="tag-cell${modifier}"
        style="--tag-color: hsl(${hue}deg 74% 58%);"
        title="Byte ${index + 1}: 0x${hex} — cell color encodes this value (0x00 blue → 0xFF red)"
        aria-label="${label}"
      >${hex}</span>
    `;
  }).join('');
}

function clampRBytes(key: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(key.slice(0, 16));
  clamped[3] &= 0x0f;
  clamped[7] &= 0x0f;
  clamped[11] &= 0x0f;
  clamped[15] &= 0x0f;
  clamped[4] &= 0xfc;
  clamped[8] &= 0xfc;
  clamped[12] &= 0xfc;
  return clamped;
}

// Indices whose HIGH nibble (top 4 bits) is zeroed by clamping, and those whose
// low 2 bits are zeroed. Used to highlight exactly which bits clamping touches.
const CLAMP_HIGH_NIBBLE = new Set([3, 7, 11, 15]);
const CLAMP_LOW_BITS = new Set([4, 8, 12]);

// Render the first 16 key bytes before and after clamping, highlighting each
// byte that changes. Purely illustrative — the real clampR drives the math.
function renderClampCompare(elements: UIElements, key: Uint8Array): void {
  const before = key.slice(0, 16);
  const after = clampRBytes(key);
  const cell = (label: string, bytes: Uint8Array, showMask: boolean): string => {
    const cells = Array.from({ length: 16 }, (_, i) => {
      const hex = bytes[i].toString(16).padStart(2, '0').toUpperCase();
      const clampedHere = CLAMP_HIGH_NIBBLE.has(i) || CLAMP_LOW_BITS.has(i);
      const changed = before[i] !== after[i];
      const cls =
        'clamp-byte' +
        (showMask && clampedHere ? ' clamp-byte--masked' : '') +
        (!showMask && changed ? ' clamp-byte--changed' : '');
      return `<span class="${cls}">${hex}</span>`;
    }).join('');
    return `<div class="clamp-line"><span class="clamp-line-label">${label}</span><span class="clamp-bytes">${cells}</span></div>`;
  };
  elements.clampCompare.innerHTML =
    cell('Key bytes 0–15 (before)', before, true) + cell('Clamped r (after)', after, false);
}

function setStatus(element: HTMLParagraphElement, text: string, tone: StatusTone): void {
  // Avoid re-writing identical text so the aria-live region does not re-announce
  // unchanged states (e.g. "Awaiting MAC" on every keystroke).
  if (element.textContent !== text) {
    element.textContent = text;
  }
  element.className = `scenario-status scenario-status--${tone}`;
}

function setVerificationEnabled(elements: UIElements, enabled: boolean): void {
  elements.verifyOriginalButton.disabled = !enabled;
  elements.verifyMessageButton.disabled = !enabled;
  elements.verifyTagButton.disabled = !enabled;
}

function renderPlaceholderMathRow(elements: UIElements): void {
  elements.mathStepsBody.innerHTML = `
    <tr>
      <td colspan="7" class="math-empty">Compute a MAC, then click Show Math to inspect the first four Poly1305 blocks.</td>
    </tr>
  `;
}

function resetMathPanel(elements: UIElements, key: Uint8Array): void {
  elements.rHexDisplay.textContent = bytesToHex(clampRBytes(key));
  elements.rDecimalDisplay.textContent = 'Run Show Math to compute the accumulator steps for the current message.';
  renderClampCompare(elements, key);
  renderPlaceholderMathRow(elements);
}

function renderMathRows(elements: UIElements, steps: PolyStep[], key: Uint8Array): void {
  const clampedRHex = bytesToHex(clampRBytes(key));
  const clampedRDecimal = clampR(key.subarray(0, 16)).toString();

  elements.rHexDisplay.textContent = clampedRHex;
  elements.rDecimalDisplay.textContent = clampedRDecimal;
  renderClampCompare(elements, key);

  if (steps.length === 0) {
    elements.mathStepsBody.innerHTML = `
      <tr>
        <td colspan="7" class="math-empty">This message has no bytes, so there are no Poly1305 blocks to visualize.</td>
      </tr>
    `;
    return;
  }

  const rowsHtml = steps
    .map(
      (step, index) => `
        <tr class="math-row" style="animation-delay: ${index * 120}ms;">
          <td>${step.blockIndex + 1}</td>
          <td class="mono-cell mono-cell--hex">${step.blockHex}</td>
          <td class="mono-cell">${step.blockValue}</td>
          <td class="mono-cell">${step.accumulatorBefore}</td>
          <td class="mono-cell math-cell--add" style="animation-delay: ${index * 120 + 40}ms;">${step.sumBeforeMultiply}</td>
          <td class="mono-cell math-cell--mul" style="animation-delay: ${index * 120 + 80}ms;">${step.productBeforeReduce}</td>
          <td class="mono-cell math-cell--acc" style="animation-delay: ${index * 120 + 120}ms;">${step.accumulatorAfter}</td>
        </tr>
      `,
    )
    .join('');

  // Annotate the very first row so the huge "Block Value" numbers stop looking
  // arbitrary: they are the block's bytes with a 0x01 appended, read little-endian.
  const firstBlockBytes = steps[0].blockHex.match(/.{1,2}/g)?.join(' ') ?? steps[0].blockHex;
  const annotation = `
    <tr class="math-annotation-row">
      <td colspan="7">
        <p class="math-annotation">
          <strong>Reading block 1:</strong> take the block's bytes
          <code>${firstBlockBytes}</code>, append a single <code>01</code> padding byte, and read the result
          <em>little-endian</em> (least-significant byte first) as an integer — that is the
          <strong>${steps[0].blockValue}</strong> in the Block Value column. The <code>01</code> marks where this
          block ends so different-length messages can't collide.
        </p>
      </td>
    </tr>
  `;

  elements.mathStepsBody.innerHTML = annotation + rowsHtml;
}

function renderKey(elements: UIElements, key: Uint8Array): void {
  elements.keyDisplay.textContent = bytesToHex(key);
}

function renderTagDisplays(elements: UIElements, tag: Uint8Array | null): void {
  const activeTag = tag ?? ZERO_TAG;
  elements.tagDisplay.innerHTML = renderTagCells(activeTag);
  elements.tagHexDisplay.textContent = bytesToHex(activeTag);
  elements.tamperedTagDisplay.innerHTML = tag ? renderTagCells(tamperTag(tag), 8) : renderTagCells(ZERO_TAG);
}

function updateTamperedMessagePreview(elements: UIElements): void {
  elements.tamperedMessageDisplay.textContent = tamperMessage(elements.messageInput.value);
}

function shortHex(hex: string): string {
  return hex.length <= 24 ? hex : `${hex.slice(0, 14)}…${hex.slice(-8)}`;
}

// Live byte-length note so the learner sees why a message is (or isn't) a single
// block. Returns true when the message fits one Poly1305 block (<= 16 bytes).
function updateReuseLengthNote(elements: UIElements): boolean {
  const lenOne = utf8ByteLength(elements.reuseMessageOne.value);
  const lenTwo = utf8ByteLength(elements.reuseMessageTwo.value);
  const lenForge = utf8ByteLength(elements.forgeMessageInput.value);
  const allFit =
    lenOne <= SINGLE_BLOCK_MAX_BYTES && lenTwo <= SINGLE_BLOCK_MAX_BYTES && lenForge <= SINGLE_BLOCK_MAX_BYTES;
  const over: string[] = [];
  if (lenOne > SINGLE_BLOCK_MAX_BYTES) over.push('Message 1');
  if (lenTwo > SINGLE_BLOCK_MAX_BYTES) over.push('Message 2');
  if (lenForge > SINGLE_BLOCK_MAX_BYTES) over.push('the forged message');

  if (allFit) {
    elements.reuseLengthNote.textContent = `Message 1: ${lenOne} B · Message 2: ${lenTwo} B · Forge: ${lenForge} B — all within one 16-byte block, so two pairs pin down (r, s) exactly.`;
    elements.reuseLengthNote.classList.remove('reuse-length-note--over');
  } else {
    elements.reuseLengthNote.textContent = `${over.join(' and ')} exceed 16 bytes. This two-pair forgery is exact only for single-block messages; shorten to demonstrate it. (Longer messages need more pairs — the attack still exists, it just needs more captured tags.)`;
    elements.reuseLengthNote.classList.add('reuse-length-note--over');
  }
  return allFit;
}

function renderForgeEmpty(elements: UIElements): void {
  elements.forgeRecovered.innerHTML =
    '<p class="attack-solve-empty">Run step 1, type a forged message, then forge to reveal the recovered r and s here.</p>';
  elements.forgeTagDisplay.innerHTML = renderTagCells(ZERO_TAG);
  elements.forgeTagHex.textContent = bytesToHex(ZERO_TAG);
  setStatus(elements.forgeStatus, 'Awaiting forgery', 'pending');
}

function resetReuseSection(elements: UIElements): void {
  elements.reuseTagOne.textContent = bytesToHex(ZERO_TAG);
  elements.reuseTagTwo.textContent = bytesToHex(ZERO_TAG);
  elements.reuseWarningBanner.hidden = true;
  elements.forgeButton.disabled = true;
  renderForgeEmpty(elements);
  updateReuseLengthNote(elements);
}

function clearComputedOutputs(elements: UIElements, state: AppState): void {
  state.macResult = null;
  renderTagDisplays(elements, null);
  setVerificationEnabled(elements, false);
  setStatus(elements.verifyOriginalStatus, 'Awaiting MAC', 'pending');
  setStatus(elements.verifyMessageStatus, 'Awaiting MAC', 'pending');
  setStatus(elements.verifyTagStatus, 'Awaiting MAC', 'pending');
  updateTamperedMessagePreview(elements);
  resetMathPanel(elements, state.key);
}

async function copyText(
  button: HTMLButtonElement,
  text: string,
  announcer: HTMLDivElement,
  label: string,
): Promise<void> {
  const originalLabel = button.textContent ?? 'Copy';
  let message: string;

  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
    message = `${label} copied to clipboard.`;
  } catch {
    button.textContent = 'Copy Failed';
    message = `Could not copy ${label.toLowerCase()} to clipboard.`;
  }

  announcer.textContent = message;

  window.setTimeout(() => {
    button.textContent = originalLabel;
  }, 1200);
}

function activateTab(elements: UIElements, activeTab: TabKey): void {
  for (const button of elements.tabButtons) {
    const isActive = button.dataset.tab === activeTab;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-selected', String(isActive));
    button.tabIndex = isActive ? 0 : -1;
  }

  for (const panel of elements.tabPanels) {
    const isActive = panel.dataset.panel === activeTab;
    panel.classList.toggle('is-active', isActive);
    panel.hidden = !isActive;
  }
}

function wireTabs(elements: UIElements): void {
  for (const button of elements.tabButtons) {
    button.addEventListener('click', () => {
      activateTab(elements, button.dataset.tab as TabKey);
      button.focus();
    });
  }

  const tablist = elements.tabButtons[0]?.parentElement;
  if (tablist) {
    tablist.addEventListener('keydown', (event: KeyboardEvent) => {
      const current = elements.tabButtons.findIndex((b) => b === document.activeElement);
      if (current === -1) return;

      let next = current;
      if (event.key === 'ArrowRight') next = (current + 1) % elements.tabButtons.length;
      else if (event.key === 'ArrowLeft') next = (current - 1 + elements.tabButtons.length) % elements.tabButtons.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = elements.tabButtons.length - 1;
      else return;

      event.preventDefault();
      const target = elements.tabButtons[next];
      activateTab(elements, target.dataset.tab as TabKey);
      target.focus();
    });
  }
}

function computeAndRenderMAC(elements: UIElements, state: AppState): void {
  const result = computeMACResult(elements.messageInput.value, state.key);
  state.macResult = result;
  renderTagDisplays(elements, result.tag);
  setVerificationEnabled(elements, true);
  setStatus(elements.verifyOriginalStatus, 'Ready to verify', 'pending');
  setStatus(elements.verifyMessageStatus, 'Ready to verify', 'pending');
  setStatus(elements.verifyTagStatus, 'Ready to verify', 'pending');
  updateTamperedMessagePreview(elements);
}

function wireInteractions(elements: UIElements, state: AppState): void {
  elements.generateKeyButton.addEventListener('click', () => {
    state.key = generateKey();
    state.reusePairOne = null;
    state.reusePairTwo = null;
    state.recoveredKey = null;
    renderKey(elements, state.key);
    clearComputedOutputs(elements, state);
    resetReuseSection(elements);
  });

  elements.copyKeyButton.addEventListener('click', async () => {
    await copyText(elements.copyKeyButton, bytesToHex(state.key), elements.copyAnnouncer, 'Key');
  });

  elements.copyTagButton.addEventListener('click', async () => {
    const text = state.macResult ? state.macResult.tagHex : bytesToHex(ZERO_TAG);
    await copyText(elements.copyTagButton, text, elements.copyAnnouncer, 'Tag');
  });

  elements.messageInput.addEventListener('input', () => {
    clearComputedOutputs(elements, state);
  });

  elements.computeMacButton.addEventListener('click', () => {
    computeAndRenderMAC(elements, state);
  });

  elements.verifyOriginalButton.addEventListener('click', () => {
    if (!state.macResult) {
      return;
    }

    const isValid = verifyMAC(state.macResult.message, state.macResult.tag, state.key);
    setStatus(elements.verifyOriginalStatus, isValid ? 'VALID' : 'INVALID', isValid ? 'valid' : 'invalid');
  });

  elements.verifyMessageButton.addEventListener('click', () => {
    if (!state.macResult) {
      return;
    }

    const tampered = tamperMessage(state.macResult.message);
    const isValid = verifyMAC(tampered, state.macResult.tag, state.key);
    setStatus(elements.verifyMessageStatus, isValid ? 'VALID' : 'INVALID', isValid ? 'valid' : 'invalid');
  });

  elements.verifyTagButton.addEventListener('click', () => {
    if (!state.macResult) {
      return;
    }

    const alteredTag = tamperTag(state.macResult.tag);
    const isValid = verifyMAC(state.macResult.message, alteredTag, state.key);
    // Re-render the tampered tag with byte 8 animating its recolor as it flips,
    // so the color channel (not just the outline) shows the change landing.
    elements.tamperedTagDisplay.innerHTML = renderTagCells(alteredTag, 8, true);
    setStatus(elements.verifyTagStatus, isValid ? 'VALID' : 'INVALID', isValid ? 'valid' : 'invalid');
  });

  elements.showMathButton.addEventListener('click', () => {
    const steps = computeSteps(elements.messageInput.value, state.key);
    renderMathRows(elements, steps, state.key);
  });

  // Editing any reuse/forge message invalidates a prior forgery and refreshes
  // the length note. The learner must re-run step 1 after changing the signed pair.
  const onReuseInputChanged = () => {
    state.reusePairOne = null;
    state.reusePairTwo = null;
    state.recoveredKey = null;
    elements.forgeButton.disabled = true;
    elements.reuseWarningBanner.hidden = true;
    elements.reuseTagOne.textContent = bytesToHex(ZERO_TAG);
    elements.reuseTagTwo.textContent = bytesToHex(ZERO_TAG);
    renderForgeEmpty(elements);
    updateReuseLengthNote(elements);
  };
  elements.reuseMessageOne.addEventListener('input', onReuseInputChanged);
  elements.reuseMessageTwo.addEventListener('input', onReuseInputChanged);
  elements.forgeMessageInput.addEventListener('input', () => {
    // Changing only the forged message doesn't invalidate the recovered key.
    elements.forgeButton.disabled = state.recoveredKey === null || !updateReuseLengthNote(elements);
    if (state.recoveredKey) {
      renderForgeEmpty(elements);
      setStatus(elements.forgeStatus, 'Ready — click Forge Tag', 'pending');
    } else {
      updateReuseLengthNote(elements);
    }
  });

  // STEP 1: the sender signs both messages under ONE key. Store the public
  // (block integer, tag integer) pairs the attacker will work from.
  elements.computeReuseButton.addEventListener('click', () => {
    const messageOne = elements.reuseMessageOne.value;
    const messageTwo = elements.reuseMessageTwo.value;
    const resultOne = computeMACResult(messageOne, state.key);
    const resultTwo = computeMACResult(messageTwo, state.key);

    elements.reuseTagOne.textContent = resultOne.tagHex;
    elements.reuseTagTwo.textContent = resultTwo.tagHex;

    const allSingleBlock = updateReuseLengthNote(elements);
    state.reusePairOne = null;
    state.reusePairTwo = null;
    state.recoveredKey = null;
    renderForgeEmpty(elements);
    elements.reuseWarningBanner.hidden = true;

    if (!allSingleBlock) {
      elements.forgeButton.disabled = true;
      return;
    }

    state.reusePairOne = {
      message: messageOne,
      blockInteger: singleBlockInteger(messageOne),
      tagInteger: tagBytesToInteger(resultOne.tag),
    };
    state.reusePairTwo = {
      message: messageTwo,
      blockInteger: singleBlockInteger(messageTwo),
      tagInteger: tagBytesToInteger(resultTwo.tag),
    };
    // Ready to forge once the learner has a forge message (also single-block).
    elements.forgeButton.disabled = utf8ByteLength(elements.forgeMessageInput.value) > SINGLE_BLOCK_MAX_BYTES;
    setStatus(elements.forgeStatus, 'Sender signed both. Now forge a third.', 'pending');
  });

  // STEP 2 + 3: attacker recovers (r, s) from the two pairs and forges a tag
  // for a NEW message, then we verify that forged tag against the real key.
  elements.forgeButton.addEventListener('click', () => {
    if (!state.reusePairOne || !state.reusePairTwo) {
      return;
    }
    const forgeMessage = elements.forgeMessageInput.value;
    if (utf8ByteLength(forgeMessage) > SINGLE_BLOCK_MAX_BYTES) {
      return;
    }

    const recovered = recoverKeyFromTagPairs(
      state.reusePairOne.blockInteger,
      state.reusePairOne.tagInteger,
      state.reusePairTwo.blockInteger,
      state.reusePairTwo.tagInteger,
    );
    state.recoveredKey = recovered;

    if (!recovered) {
      elements.forgeRecovered.innerHTML =
        '<p class="attack-solve-empty">The two messages are identical, so they give the same equation — pick two different messages to recover the key.</p>';
      renderForgeEmpty(elements);
      setStatus(elements.forgeStatus, 'Need two different messages', 'invalid');
      elements.reuseWarningBanner.hidden = true;
      return;
    }

    // Show the stolen secrets (shortened) so the recovery is visible, not asserted.
    const rHex = recovered.r.toString(16).toUpperCase().padStart(32, '0');
    const sHex = recovered.s.toString(16).toUpperCase().padStart(32, '0');
    elements.forgeRecovered.innerHTML = `
      <p class="attack-solve-line"><span class="attack-solve-key">r</span> <span class="mono-inline mono-hex attack-solve-val">${shortHex(rHex)}</span></p>
      <p class="attack-solve-line"><span class="attack-solve-key">s</span> <span class="mono-inline mono-hex attack-solve-val">${shortHex(sHex)}</span></p>
      <p class="attack-solve-caption">Recovered from the two tags by algebra — the attacker never saw the key.</p>
    `;

    const forgedTag = forgeTag(recovered, forgeMessage);
    // The moment of truth: does the REAL key accept this forged tag?
    const accepted = verifyMAC(forgeMessage, forgedTag, state.key);
    elements.forgeTagDisplay.innerHTML = renderTagCells(forgedTag);
    elements.forgeTagHex.textContent = bytesToHex(forgedTag);

    if (accepted) {
      setStatus(elements.forgeStatus, 'VALID — forged tag accepted by the real key', 'valid');
      elements.reuseWarningBanner.hidden = false;
    } else {
      // Should never happen for single-block inputs; fail honestly if it does.
      setStatus(elements.forgeStatus, 'Forgery did not verify', 'invalid');
      elements.reuseWarningBanner.hidden = true;
    }
  });

  wireTabs(elements);
  activateTab(elements, 'what');
}

export function mountApp(target: HTMLDivElement): void {
  target.innerHTML = createTemplate();

  const elements = collectElements(target);
  const state: AppState = {
    key: generateKey(),
    macResult: null,
    reusePairOne: null,
    reusePairTwo: null,
    recoveredKey: null,
  };

  elements.messageInput.value = DEFAULT_MESSAGE;
  elements.reuseMessageOne.value = DEFAULT_REUSE_MESSAGE_ONE;
  elements.reuseMessageTwo.value = DEFAULT_REUSE_MESSAGE_TWO;
  elements.forgeMessageInput.value = DEFAULT_FORGE_MESSAGE;

  renderKey(elements, state.key);
  clearComputedOutputs(elements, state);
  resetReuseSection(elements);
  wireInteractions(elements, state);
}