// Vercel serverless function: redirect to GitHub OAuth authorization
export default function handler(req, res) {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'GITHUB_CLIENT_ID not configured' });
  }

  const baseUrl = process.env.OAUTH_BASE_URL
    || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? 'https://' + process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.SITE_URL);
  const redirectUri = `${baseUrl}/api/auth/callback`;
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'public_repo',
    state: Math.random().toString(36).slice(2),
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
}
