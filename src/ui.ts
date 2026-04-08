export function mountApp(target: HTMLDivElement): void {
  target.innerHTML = `
    <main class="shell">
      <section class="hero">
        <p class="eyebrow">Crypto Lab Portfolio</p>
        <h1>Poly1305 Message Authentication Code</h1>
        <p>
          Vite and TypeScript scaffold is live. The noble Poly1305 sub-import resolves,
          and the interactive MAC playground, polynomial stepper, and key-reuse demo
          will be layered onto this shell next.
        </p>
        <div class="status-strip">
          <span class="status-pill">Dependency: <strong>@noble/ciphers/_poly1305.js</strong></span>
          <span class="status-pill">Status: Phase 1 verification in progress</span>
        </div>
      </section>
    </main>
  `;
}