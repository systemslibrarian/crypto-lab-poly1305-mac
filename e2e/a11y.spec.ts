import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the Poly1305 MAC demo.
 *
 * Scans the full page in BOTH themes (dark default + light) with every
 * <details> expanded, every reference tab revealed, and every live demo DRIVEN
 * so the dynamically-injected regions (key, tag grid, verification verdicts,
 * polynomial-stepper table, key-reuse tags + warning banner) are in the DOM
 * when axe runs.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (the math-row
// enter animation) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Open every <details>, reveal all tab panels (drop [hidden]), and un-hide any
// class-toggled panels so their content is scannable.
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>('.info-panel[hidden]')) {
      el.removeAttribute('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('.warning-banner[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

// Drive every live demo so injected output regions exist during the scan.
async function driveDemos(page: Page): Promise<void> {
  // Section A — compute MAC then run all three verification scenarios.
  await page.locator('#compute-mac-button').click();
  await expect(page.locator('#verify-original-button')).toBeEnabled();
  await page.locator('#verify-original-button').click();
  await page.locator('#verify-message-button').click();
  await page.locator('#verify-tag-button').click();

  // Section B — polynomial stepper (injects the math table rows).
  await page.locator('#show-math-button').click();
  await expect(page.locator('#math-steps-body .math-row').first()).toBeVisible();

  // Section C — key reuse (injects both tags + reveals the warning banner).
  await page.locator('#compute-reuse-button').click();
  await expect(page.locator('#reuse-warning-banner')).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#compute-mac-button')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
