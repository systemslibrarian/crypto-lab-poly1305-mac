# crypto-lab-poly1305-mac

## What It Is

Poly1305 is a one-time message authentication code (MAC) designed by Daniel J. Bernstein. It takes a 32-byte key and a variable-length message and produces a 128-bit authentication tag by evaluating a polynomial over the prime field GF(2^130 − 5). The security model is information-theoretic: as long as each key is used only once, no amount of computation gives an attacker better than a 2^−128 chance of forging a valid tag. This demo uses the standalone `poly1305` export from `@noble/ciphers/_poly1305.js` to compute and verify tags entirely in the browser.

## When to Use It

- **Authenticating a single message under a fresh key** — Poly1305's one-time guarantee makes it ideal when a higher-level protocol (such as ChaCha20-Poly1305) derives a unique key per message.
- **High-throughput MAC in AEAD constructions** — Poly1305's arithmetic is simple enough for constant-time implementations on commodity hardware, making it a common choice inside TLS 1.3 and WireGuard.
- **Replacing HMAC when polynomial MAC performance matters** — On platforms without AES-NI, Poly1305 can be faster than HMAC-SHA-256 while offering a strong forgery bound.
- **When you need a MAC with a provable security bound** — Poly1305's forgery probability is at most the number of message blocks divided by the field size, a concrete bound absent from many hash-based MACs.
- **Do NOT use standalone Poly1305 when you cannot guarantee one-time key usage** — reusing a key across two messages lets an attacker recover the secret r value and forge tags for any future message. This is a teaching demo, not a production MAC implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/)**

Generate a random 32-byte key, type any message, and compute its Poly1305 authentication tag. Three verification scenarios let you confirm the original tag, tamper the message (a trailing space), or flip a single tag byte — all with constant-time comparison. The Polynomial Stepper section visualises the first four blocks as `(accumulator + block) × r mod p`, and the Key Reuse Warning computes two MACs under the same key to demonstrate why reuse is fatal.

## What Can Go Wrong

- **Key reuse** — Poly1305 is a one-time MAC. Authenticating two different messages under the same 32-byte key lets an attacker solve for the secret r and s values algebraically and forge tags for any message.
- **Non-constant-time tag comparison** — Comparing tags with an early-exit `===` loop leaks how many leading bytes matched, giving an attacker a timing oracle to iteratively guess a valid tag.
- **Unclamped r value** — The first 16 bytes of the key must have specific bits zeroed (clamping). Skipping this step permits classes of polynomial forgery that the clamping mask is designed to block.
- **Using Poly1305 without an AEAD wrapper** — Standalone Poly1305 authenticates but does not encrypt. Sending a cleartext message with only a Poly1305 tag gives integrity without confidentiality, which is rarely the correct security goal.
- **Nonce misuse in ChaCha20-Poly1305** — In the AEAD construction, repeating a nonce under the same encryption key re-derives the same Poly1305 sub-key, collapsing back to the key-reuse failure above.

## Real-World Usage

- **TLS 1.3** — The `TLS_CHACHA20_POLY1305_SHA256` cipher suite uses Poly1305 as the MAC inside its AEAD, protecting every record on connections that negotiate this suite.
- **WireGuard** — All tunnel packets are authenticated with ChaCha20-Poly1305, relying on Poly1305 for per-packet integrity and authenticity.
- **OpenSSH** — The `chacha20-poly1305@openssh.com` cipher uses Poly1305 to authenticate both the packet length and payload, replacing the older HMAC-based transport MACs.
- **NaCl / libsodium `crypto_secretbox`** — The widely deployed `secretbox` construction pairs XSalsa20 encryption with Poly1305 authentication, used in applications from Signal to Keybase.
- **IETF RFC 8439** — The canonical specification for ChaCha20-Poly1305, referenced by QUIC (RFC 9001), Noise Protocol Framework, and other modern protocols.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-poly1305-mac
cd crypto-lab-poly1305-mac
npm install
npm run dev
```

## Related Demos
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — head-to-head comparison of HMAC, CMAC, Poly1305, and GHASH.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the ChaCha20 keystream that pairs with Poly1305 in the AEAD construction.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM and other authenticated-encryption modes for comparison.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — what nonce reuse does to AEAD constructions, the failure mode behind ChaCha20-Poly1305 misuse.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — SHA-256, BLAKE3, and HMAC, the hash-based MAC alternative to polynomial MACs.

## Tests

The test suite verifies correctness against the canonical **RFC 8439 §2.5.2** Poly1305 test vector (key, message, clamped `r`, and tag), checks that tampering with either the message or the tag fails verification, and runs an automated [axe-core](https://github.com/dequelabs/axe-core) accessibility audit over the rendered UI. Color contrast for both themes meets WCAG 2.1 AA (≥ 4.5:1 for text).

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
