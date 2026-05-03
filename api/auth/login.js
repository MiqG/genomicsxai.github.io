// Vercel serverless function: redirect to GitHub OAuth authorization
import crypto from 'node:crypto';

export default function handler(req, res) {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'GITHUB_CLIENT_ID not configured' });
  }

  const baseUrl = process.env.OAUTH_BASE_URL
    || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? 'https://' + process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.SITE_URL);
  const redirectUri = `${baseUrl}/api/auth/callback`;

  // CSRF protection: cryptographically random state, persisted in a cookie scoped to the auth path.
  const state = crypto.randomBytes(32).toString('hex');
  res.setHeader(
    'Set-Cookie',
    `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=600`
  );

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'public_repo',
    state,
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
}
