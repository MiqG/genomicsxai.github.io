// Vercel serverless function: exchange GitHub OAuth code for access token
export default async function handler(req, res) {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Missing code parameter' });
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
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
      return res.status(400).json({ error: data.error_description || data.error });
    }

    // Return a small HTML page that stores the token and redirects back to the form
    const siteUrl = process.env.SITE_URL || 'https://genomicsxai.github.io';
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authenticating...</title></head>
<body>
<p>Signing in... you will be redirected shortly.</p>
<script>
  sessionStorage.setItem('gh_token', '${data.access_token}');
  window.location.href = '${siteUrl}/submission-guidelines/#submit-form';
</script>
</body></html>`);
  } catch (err) {
    res.status(500).json({ error: 'Failed to exchange code for token' });
  }
}
