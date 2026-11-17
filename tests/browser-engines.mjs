import { chromium, webkit } from 'playwright';
// Headless Chromium is muted by Playwright. WebKit on macOS can play synthetic
// call tones through the user's speakers, so it requires an explicit opt-in.
export const testBrowsers = process.platform === 'darwin' && process.env.PVP_TEST_WEBKIT !== '1'
  ? { chromium }
  : { chromium, webkit };
