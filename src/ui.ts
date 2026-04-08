function renderTagCells(tamperedIndex?: number): string {
  return Array.from({ length: 16 }, (_, index) => {
    const hue = 210 - Math.round((index / 15) * 210);
    const modifier = tamperedIndex === index ? ' tag-cell--tampered' : '';

    return `
      <span
        class="tag-cell${modifier}"
        style="--tag-color: hsl(${hue}deg 74% 58%);"
        aria-label="Tag byte ${index + 1}"
      >00</span>
    `;
  }).join('');
}

export function mountApp(target: HTMLDivElement): void {
  target.innerHTML = `
    <main class="page-shell">
      <header class="hero-panel">
        <div class="hero-copy">
          <a class="portfolio-badge" href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">
            systemslibrarian.github.io/crypto-lab/
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
              <button class="ghost-button" type="button" id="copy-key-button">Copy</button>
            </div>
            <p class="panel-copy">Shared 32-byte key for the playground and the key-reuse warning below.</p>
            <div class="mono-block key-display" id="key-display">0000000000000000000000000000000000000000000000000000000000000000</div>
          </article>

          <article class="panel-card panel-card--wide">
            <div class="panel-header">
              <h3>Message</h3>
              <button class="action-button" type="button" id="compute-mac-button">Compute MAC</button>
            </div>
            <textarea id="message-input" class="message-input" rows="4">Authenticate this message.</textarea>
          </article>

          <article class="panel-card panel-card--wide">
            <div class="panel-header">
              <div>
                <h3>Authentication Tag</h3>
                <p class="panel-copy">128-bit tag (16 bytes)</p>
              </div>
              <button class="ghost-button" type="button" id="copy-tag-button">Copy</button>
            </div>
            <div class="tag-grid" id="tag-display">${renderTagCells()}</div>
            <div class="mono-inline" id="tag-hex-display">00000000000000000000000000000000</div>
          </article>
        </div>

        <div class="scenario-grid">
          <article class="scenario-card">
            <h3>Scenario 1 — Verify Original</h3>
            <p class="scenario-copy">Run verification against the unchanged message and tag.</p>
            <button class="action-button" type="button" id="verify-original-button">Verify Original</button>
            <p class="scenario-status" id="verify-original-status">Awaiting MAC</p>
          </article>

          <article class="scenario-card">
            <h3>Scenario 2 — Tamper Message</h3>
            <p class="scenario-copy">Modified message shown below: original plus a single trailing space.</p>
            <div class="mono-block" id="tampered-message-display">Authenticate this message. </div>
            <button class="action-button" type="button" id="verify-message-button">Verify Tampered Message</button>
            <p class="scenario-status" id="verify-message-status">Awaiting MAC</p>
          </article>

          <article class="scenario-card">
            <h3>Scenario 3 — Tamper Tag</h3>
            <p class="scenario-copy">The original message is preserved, but byte 8 of the tag is flipped.</p>
            <div class="tag-grid tag-grid--compact" id="tampered-tag-display">${renderTagCells(8)}</div>
            <button class="action-button" type="button" id="verify-tag-button">Verify Tampered Tag</button>
            <p class="scenario-status" id="verify-tag-status">Awaiting MAC</p>
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
            <div class="mono-block" id="r-hex-display">00000000000000000000000000000000</div>
            <p class="math-decimal" id="r-decimal-display">0</p>
          </article>
          <article class="panel-card">
            <h3>Prime Field</h3>
            <div class="mono-block">p = 2^130 - 5</div>
            <p class="math-decimal">1361129467683753853853498429727072845819</p>
          </article>
        </div>

        <div class="table-shell">
          <table class="math-table">
            <thead>
              <tr>
                <th>Block #</th>
                <th>Block (hex)</th>
                <th>Block Value</th>
                <th>Acc Before</th>
                <th>× r mod p</th>
                <th>Acc After</th>
              </tr>
            </thead>
            <tbody id="math-steps-body">
              <tr>
                <td>0</td>
                <td class="mono-cell">00000000000000000000000000000000</td>
                <td class="mono-cell">0</td>
                <td class="mono-cell">0</td>
                <td class="mono-cell">r</td>
                <td class="mono-cell">0</td>
              </tr>
            </tbody>
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
            <textarea id="reuse-message-one" class="message-input" rows="3">Transfer $100</textarea>
            <div class="mono-inline" id="reuse-tag-one">00000000000000000000000000000000</div>
          </article>

          <article class="panel-card">
            <h3>Message 2</h3>
            <textarea id="reuse-message-two" class="message-input" rows="3">Transfer $999</textarea>
            <div class="mono-inline" id="reuse-tag-two">00000000000000000000000000000000</div>
          </article>
        </div>

        <div class="warning-banner" id="reuse-warning-banner">
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
          <button class="tab-button is-active" id="tab-what" type="button" role="tab" aria-selected="true">What Poly1305 Is</button>
          <button class="tab-button" id="tab-math" type="button" role="tab" aria-selected="false">The Math</button>
          <button class="tab-button" id="tab-constant-time" type="button" role="tab" aria-selected="false">Constant-Time Verification</button>
        </div>

        <div class="info-panels">
          <article class="info-panel is-active" id="panel-what" role="tabpanel" aria-labelledby="tab-what">
            <p>
              Poly1305 is a one-time message authentication code. It outputs a 128-bit tag, giving a forgery chance of
              about 2^-128 per attempt when used correctly. It was designed by Daniel J. Bernstein and evaluates a
              polynomial over GF(2^130-5).
            </p>
            <p>
              In ChaCha20-Poly1305, ChaCha20 derives a fresh one-time Poly1305 key from each nonce, which solves the
              key-reuse problem automatically. Standalone Poly1305 should only be used when one-time key usage is
              guaranteed.
            </p>
          </article>

          <article class="info-panel" id="panel-math" role="tabpanel" aria-labelledby="tab-math" hidden>
            <p>
              The message is split into 16-byte blocks. Each block is read as a little-endian integer after appending
              a 0x01 byte, then the accumulator updates as accumulator = (accumulator + block) * r mod p.
            </p>
            <p>
              The first half of the key becomes the clamped value r, and the second half becomes s. After processing
              every block, the final tag is (accumulator + s) mod 2^128.
            </p>
          </article>

          <article class="info-panel" id="panel-constant-time" role="tabpanel" aria-labelledby="tab-constant-time" hidden>
            <p>
              Verification must compare tags in constant time. Returning early on the first mismatched byte leaks how
              much of the tag was correct, which can become an oracle for an attacker. A fixed-length XOR accumulation
              avoids that timing leak.
            </p>
          </article>
        </div>
      </section>
    </main>
  `;
}