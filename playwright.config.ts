import { defineConfig } from '@playwright/test';

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    command: 'npm run preview -- --port 4280 --strictPort',
    url: 'http://localhost:4280/crypto-lab-poly1305-mac/',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4280/crypto-lab-poly1305-mac/',
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { channel: undefined, browserName: 'chromium' },
    },
  ],
});
