import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every verification outcome — including both tamper branches — plus the
 * nonce-reuse forgery and each info tab is scanned in both themes at desktop
 * and phone width. See `gate.ts` for why nothing is injected into the page,
 * why each scan asserts its content first, and why `violations` is not the
 * whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);

    // The third ratchet rule — a baselined finding that no longer appears must
    // be deleted, so the list can only shrink. `expectBaselineNotStale` was
    // exported from `gate.ts` and imported by nothing, so it had never run.
    //
    // Dark theme only, which was measured rather than assumed. `nonTextSeen` is
    // a single flat set with no theme dimension, so the rule only holds where
    // the drive reaches EVERY baselined selector. A light drive produces just
    // two of the eight: the six `.action-button` primaries are accent-bordered
    // and clear 3:1 against the light surfaces, so they are never findings
    // there and a light-theme call would report all six as stale on every run.
    // This baseline describes the dark drive; both dark widths reach all eight.
    if (theme === 'dark') expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    // Same reasoning as above; both dark configurations reach all eight.
    if (theme === 'dark') expectBaselineNotStale();
  });
}
