import {
  bytesToHex,
  computeMACResult,
  generateKey,
  tamperMessage,
  tamperTag,
  verifyMAC,
  type MACResult,
} from './mac.ts';
import { clampR, computeSteps, type PolyStep } from './poly-math.ts';

const DEFAULT_MESSAGE = 'Authenticate this message.';
const DEFAULT_REUSE_MESSAGE_ONE = 'Transfer $100';
const DEFAULT_REUSE_MESSAGE_TWO = 'Transfer $999';
const ZERO_TAG = new Uint8Array(16);

type StatusTone = 'pending' | 'valid' | 'invalid';
type TabKey = 'what' | 'math' | 'constant-time';

interface AppState {
  key: Uint8Array;
  macResult: MACResult | null;
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
  mathStepsBody: HTMLTableSectionElement;
  reuseMessageOne: HTMLTextAreaElement;
  reuseMessageTwo: HTMLTextAreaElement;
  reuseTagOne: HTMLDivElement;
  reuseTagTwo: HTMLDivElement;
  reuseWarningBanner: HTMLDivElement;
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
      <header class="hero-panel">
        <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch to light mode" title="Switch to light mode">🌙</button>
        <div class="hero-copy">
          <a class="portfolio-badge" href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">
            systemslibrarian.github.io/crypto-lab/ <span class="sr-only">(opens in new tab)</span>
          </a>
          <p class="eyebrow">Crypto Lab Portfolio</p>
          <h1>Poly1305 MAC</h1>
          <p class="hero-text">
            Explore how a one-time message authentication code works, why reusing a key breaks its security,
            and how Poly1305 turns message blocks into a polynomial over a finite field.
          </p>
          <details class="why-details">
            <summary>Why this matters</summary>
            <p>
              Authentication tags are often the only barrier between a legitimate message and a forged one.
              Poly1305 is extremely strong when used correctly, but it fails hard under key reuse. This demo is
              built to make that boundary visible.
            </p>
          </details>
        </div>
        <div class="hero-metric-card">
          <p class="hero-metric-label">Verified Import</p>
          <p class="hero-metric-value">@noble/ciphers/_poly1305.js</p>
          <p class="hero-metric-note">Sub-import confirmed from package exports after npm show @noble/ciphers verification.</p>
        </div>
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

        <div class="math-summary-grid">
          <article class="panel-card">
            <h3>Clamped r</h3>
            <div class="mono-block mono-hex" id="r-hex-display"></div>
            <p class="math-decimal" id="r-decimal-display"></p>
          </article>
          <article class="panel-card">
            <h3>Prime Field</h3>
            <div class="mono-block">p = 2^130 - 5</div>
            <p class="math-decimal">1361129467683753853853498429727072845819</p>
          </article>
        </div>

        <p class="table-hint">Scroll the table sideways to see every column.</p>
        <div class="table-shell" tabindex="0" role="region" aria-label="Poly1305 accumulator steps, scroll horizontally to see all columns">
          <table class="math-table">
            <caption class="sr-only">
              First four Poly1305 blocks, showing each block value and the accumulator before and after the
              (accumulator + block) × r mod p step.
            </caption>
            <thead>
              <tr>
                <th scope="col">Block #</th>
                <th scope="col">Block (hex)</th>
                <th scope="col">Block Value</th>
                <th scope="col">Acc Before</th>
                <th scope="col">× r mod p</th>
                <th scope="col">Acc After</th>
              </tr>
            </thead>
            <tbody id="math-steps-body"></tbody>
          </table>
        </div>

        <p class="section-footnote">
          Showing first 4 blocks only for clarity. Real Poly1305 processes all message blocks sequentially.
        </p>
      </section>

      <section class="lab-section" aria-labelledby="reuse-heading">
        <div class="section-heading-row">
          <div>
            <p class="section-kicker">Section C</p>
            <h2 id="reuse-heading">Key Reuse Warning</h2>
          </div>
          <button class="action-button action-button--danger" type="button" id="compute-reuse-button">Compute Both MACs (Same Key)</button>
        </div>

        <div class="reuse-grid">
          <article class="panel-card">
            <h3>Message 1</h3>
            <textarea id="reuse-message-one" class="message-input" rows="3" aria-label="Key reuse message 1">${DEFAULT_REUSE_MESSAGE_ONE}</textarea>
            <div class="mono-inline mono-hex" id="reuse-tag-one"></div>
          </article>

          <article class="panel-card">
            <h3>Message 2</h3>
            <textarea id="reuse-message-two" class="message-input" rows="3" aria-label="Key reuse message 2">${DEFAULT_REUSE_MESSAGE_TWO}</textarea>
            <div class="mono-inline mono-hex" id="reuse-tag-two"></div>
          </article>
        </div>

        <div class="warning-banner" id="reuse-warning-banner" role="alert" hidden>
          <strong>⚠ Poly1305 keys must NEVER be reused.</strong>
          <span>Two MACs under the same key can be combined to forge a third.</span>
        </div>

        <details class="explanation-details">
          <summary>Why reuse breaks Poly1305</summary>
          <p>
            When an attacker sees two valid (message, tag) pairs under the same key, they can solve for the key's
            r and s values algebraically. With r and s known, they can forge a valid tag for any message. In
            ChaCha20-Poly1305, this is prevented automatically: the cipher generates a fresh Poly1305 key from each
            unique nonce.
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
    mathStepsBody: requireElement(root, '#math-steps-body'),
    reuseMessageOne: requireElement(root, '#reuse-message-one'),
    reuseMessageTwo: requireElement(root, '#reuse-message-two'),
    reuseTagOne: requireElement(root, '#reuse-tag-one'),
    reuseTagTwo: requireElement(root, '#reuse-tag-two'),
    reuseWarningBanner: requireElement(root, '#reuse-warning-banner'),
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

function renderTagCells(bytes: Uint8Array, tamperedIndex?: number): string {
  return Array.from({ length: 16 }, (_, index) => {
    const byte = bytes[index] ?? 0;
    const hue = 220 - Math.round((byte / 255) * 220);
    const modifier = tamperedIndex === index ? ' tag-cell--tampered' : '';

    return `
      <span
        class="tag-cell${modifier}"
        style="--tag-color: hsl(${hue}deg 74% 58%);"
        aria-label="Tag byte ${index + 1}"
      >${byte.toString(16).padStart(2, '0').toUpperCase()}</span>
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

function shortenHex(hex: string): string {
  if (hex.length <= 18) {
    return hex;
  }

  return `${hex.slice(0, 10)}...${hex.slice(-6)}`;
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
      <td colspan="6" class="math-empty">Compute a MAC, then click Show Math to inspect the first four Poly1305 blocks.</td>
    </tr>
  `;
}

function resetMathPanel(elements: UIElements, key: Uint8Array): void {
  elements.rHexDisplay.textContent = bytesToHex(clampRBytes(key));
  elements.rDecimalDisplay.textContent = 'Run Show Math to compute the accumulator steps for the current message.';
  renderPlaceholderMathRow(elements);
}

function renderMathRows(elements: UIElements, steps: PolyStep[], key: Uint8Array): void {
  const clampedRHex = bytesToHex(clampRBytes(key));
  const clampedRDecimal = clampR(key.subarray(0, 16)).toString();

  elements.rHexDisplay.textContent = clampedRHex;
  elements.rDecimalDisplay.textContent = clampedRDecimal;

  if (steps.length === 0) {
    elements.mathStepsBody.innerHTML = `
      <tr>
        <td colspan="6" class="math-empty">This message has no bytes, so there are no Poly1305 blocks to visualize.</td>
      </tr>
    `;
    return;
  }

  const shortR = shortenHex(clampedRHex);

  elements.mathStepsBody.innerHTML = steps
    .map(
      (step, index) => `
        <tr class="math-row" style="animation-delay: ${index * 100}ms;">
          <td>${step.blockIndex + 1}</td>
          <td class="mono-cell mono-cell--hex">${step.blockHex}</td>
          <td class="mono-cell">${step.blockValue}</td>
          <td class="mono-cell">${step.accumulatorBefore}</td>
          <td class="mono-cell mono-cell--hex">${shortR}</td>
          <td class="mono-cell">${step.accumulatorAfter}</td>
        </tr>
      `,
    )
    .join('');
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

function resetReuseSection(elements: UIElements): void {
  elements.reuseTagOne.textContent = bytesToHex(ZERO_TAG);
  elements.reuseTagTwo.textContent = bytesToHex(ZERO_TAG);
  elements.reuseWarningBanner.hidden = true;
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
    renderTagDisplays(elements, state.macResult.tag);
    setStatus(elements.verifyTagStatus, isValid ? 'VALID' : 'INVALID', isValid ? 'valid' : 'invalid');
  });

  elements.showMathButton.addEventListener('click', () => {
    const steps = computeSteps(elements.messageInput.value, state.key);
    renderMathRows(elements, steps, state.key);
  });

  elements.computeReuseButton.addEventListener('click', () => {
    const messageOne = elements.reuseMessageOne.value;
    const messageTwo = elements.reuseMessageTwo.value;
    const tagOne = computeMACResult(messageOne, state.key).tagHex;
    const tagTwo = computeMACResult(messageTwo, state.key).tagHex;

    elements.reuseTagOne.textContent = tagOne;
    elements.reuseTagTwo.textContent = tagTwo;
    elements.reuseWarningBanner.hidden = false;
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
  };

  elements.messageInput.value = DEFAULT_MESSAGE;
  elements.reuseMessageOne.value = DEFAULT_REUSE_MESSAGE_ONE;
  elements.reuseMessageTwo.value = DEFAULT_REUSE_MESSAGE_TWO;

  renderKey(elements, state.key);
  clearComputedOutputs(elements, state);
  resetReuseSection(elements);
  wireInteractions(elements, state);
}