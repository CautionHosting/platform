// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//
// Full resident-passkey register + discoverable-login round-trip, driven through
// the real Vue frontend and a Chrome DevTools Protocol (CDP) virtual authenticator.
//
// The CDP `WebAuthn` domain lets us attach a fake, in-process ctap2 authenticator
// to the page that can mint *resident* (discoverable) credentials — something the
// Rust `soft-authenticator` (webauthn-authenticator-rs SoftPasskey) cannot do. That
// makes this the only test that exercises the branch's actual feature: username-less,
// discoverable login resolved server-side by `userHandle`, with an empty
// `allowCredentials` and `mediation: 'conditional'` in `/auth/login/begin`.
//
// Env:
//   BASE_URL   - gateway origin (default http://localhost:8000)
//   ALPHA_CODE - unredeemed beta code to register with (required)
//   USERNAME   - username to register (default "cdpuser")

import puppeteer from 'puppeteer';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8000';
const USERNAME = process.env.USERNAME || 'cdpuser';
const ALPHA_CODE = process.env.ALPHA_CODE;

if (!ALPHA_CODE) {
  throw new Error('ALPHA_CODE env var is required');
}

// allowCredentials may be omitted entirely or sent as an empty array — both mean
// "no hinted credentials", i.e. the discoverable path.
function isEmptyAllowCredentials(publicKey) {
  const allow = publicKey?.allowCredentials;
  return allow === undefined || allow === null || allow.length === 0;
}

async function attachVirtualAuthenticator(page) {
  const client = await page.createCDPSession();
  await client.send('Network.enable');
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId };
}

async function registerResidentCredential(page, client, authenticatorId) {
  await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('[data-testid="register-username"]');

  await page.type('[data-testid="register-username"]', USERNAME);
  await page.type('[data-testid="register-code"]', ALPHA_CODE);

  const finishResp = page.waitForResponse((r) => r.url().includes('/auth/register/finish'));
  await page.click('[data-testid="register-submit"]');

  const resp = await finishResp;
  if (resp.status() !== 200) {
    const body = await resp.text();
    throw new Error(`register/finish returned ${resp.status()}: ${body}`);
  }

  // Confirm the authenticator actually minted a resident (discoverable) credential —
  // this is the property that makes username-less login possible.
  const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
  if (credentials.length !== 1) {
    throw new Error(`expected exactly 1 credential on the virtual authenticator, got ${credentials.length}`);
  }
  if (credentials[0].isResidentCredential !== true) {
    throw new Error('registered credential is not resident (isResidentCredential !== true)');
  }

  console.log('✓ registered resident credential (isResidentCredential=true, attestation verified)');
}

async function logOut(client) {
  // Drop the session cookie so the next page load is unauthenticated. The virtual
  // authenticator (and its resident credential) stays attached to the browser.
  await client.send('Network.clearBrowserCookies');
}

async function loginDiscoverable(page) {
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('[data-testid="login-username"]');

  // The frontend only calls /auth/login/begin when the login button is clicked
  // (button-driven, not on page load), so both response waiters must be armed
  // before the click, not before goto.
  const beginResp = page.waitForResponse((r) => r.url().includes('/auth/login/begin'));
  const loginFinish = page.waitForResponse((r) => r.url().includes('/auth/login/finish'));

  // Leave the username field empty — this is the discoverable/username-less path.
  await page.click('[data-testid="login-submit"]');

  const begin = await beginResp;
  const beginBody = await begin.json();
  if (!isEmptyAllowCredentials(beginBody.publicKey) || beginBody.mediation !== 'conditional') {
    throw new Error(
      `login/begin was not discoverable: ${JSON.stringify(beginBody)}`
    );
  }
  console.log('✓ login/begin was discoverable (empty allowCredentials, mediation=conditional)');

  const finish = await loginFinish;
  if (finish.status() !== 200) {
    const body = await finish.text();
    throw new Error(`login/finish returned ${finish.status()}: ${body}`);
  }
  console.log('✓ discoverable login assertion verified (resolved by userHandle)');
}

async function main() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
    // AuthLayout renders a "Desktop required" placeholder (hiding the register/login
    // forms) when innerWidth <= 960, so force a desktop viewport (default is 800x600).
    defaultViewport: { width: 1400, height: 900 },
  });

  try {
    const page = await browser.newPage();
    const { client, authenticatorId } = await attachVirtualAuthenticator(page);

    await registerResidentCredential(page, client, authenticatorId);
    await logOut(client);
    await loginDiscoverable(page);

    console.log('\nPASS: CDP resident-passkey register + discoverable login');
  } finally {
    await browser.close();
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
