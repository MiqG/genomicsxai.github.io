// Vercel serverless function: exchange GitHub OAuth code for access token
import crypto from 'node:crypto';

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(/;\s*/).forEach((pair) => {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1);
  });
  return out;
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export default async function handler(req, res) {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Missing code parameter' });
  }

  // CSRF protection: state must match the cookie set by /api/auth/login.
  const cookies = parseCookies(req.headers.cookie);
  const expected = cookies.oauth_state;
  if (!state || !expected || !timingSafeEqualStr(String(state), expected)) {
    return res.status(400).json({ error: 'Invalid OAuth state' });
  }

  // One-shot cookie: clear it as soon as it has been validated.
  const clearStateCookie = 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0';

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    res.setHeader('Set-Cookie', clearStateCookie);
    return res.status(500).json({ error: 'OAuth app not configured' });
  }

  try {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
      }),
    });

    const data = await response.json();

    if (data.error) {
      res.setHeader('Set-Cookie', clearStateCookie);
      return res.status(400).json({ error: data.error_description || data.error });
    }

    const siteUrl = process.env.SITE_URL || 'https://genomicsxai.github.io';
    res.setHeader('Set-Cookie', clearStateCookie);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'");
    // Safely embed token + redirect target via JSON.stringify to prevent script injection.
    const tokenJs = JSON.stringify(data.access_token || '');
    const redirectJs = JSON.stringify(`${siteUrl}/submission-guidelines/#submit-form`);
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating...</title></head>
<body>
<p>Signing in... you will be redirected shortly.</p>
<script>
  sessionStorage.setItem('gh_token', ${tokenJs});
  window.location.href = ${redirectJs};
</script>
</body></html>`);
  } catch (err) {
    res.setHeader('Set-Cookie', clearStateCookie);
    res.status(500).json({ error: 'Failed to exchange code for token' });
  }
}
