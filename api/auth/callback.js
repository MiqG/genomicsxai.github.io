// Vercel serverless function: exchange GitHub OAuth code for access token,
// then store the token in an HttpOnly cookie scoped to the API origin.
import {
  parseCookies,
  timingSafeEqualStr,
  setSessionCookie,
  clearStateCookieHeader,
} from '../_lib/auth.js';

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

  const clearStateCookie = clearStateCookieHeader();

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
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
    });

    const data = await response.json();

    if (data.error || !data.access_token) {
      res.setHeader('Set-Cookie', clearStateCookie);
      return res.status(400).json({
        error: data.error_description || data.error || 'No access token in response',
      });
    }

    // Store token in an HttpOnly cookie scoped to /api on the auth origin.
    // Cross-origin XHR from the form sends this cookie when credentials: 'include' is set.
    res.setHeader('Set-Cookie', [
      `gh_session=${data.access_token}; HttpOnly; Secure; SameSite=None; Path=/api; Max-Age=28800`,
      clearStateCookie,
    ]);

    const siteUrl = process.env.SITE_URL || 'https://genomicsxai.github.io';
    res.redirect(`${siteUrl}/submission-guidelines/#submit-form`);
  } catch (err) {
    res.setHeader('Set-Cookie', clearStateCookie);
    res.status(500).json({ error: 'Failed to exchange code for token' });
  }
}
