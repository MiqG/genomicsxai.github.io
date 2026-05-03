// Vercel serverless function: proxy authenticated requests to api.github.com.
// The HttpOnly session cookie is read here and translated into a Bearer-style
// Authorization header before forwarding. The browser never sees the token.
import { setCorsHeaders, originAllowed, getSession } from '../_lib/auth.js';

const ALLOWED_METHODS = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'];

export default async function handler(req, res) {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (!originAllowed(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  if (!ALLOWED_METHODS.includes(req.method)) {
    return res.status(405).json({ error: 'method not allowed' });
  }

  const token = getSession(req);
  if (!token) {
    return res.status(401).json({ error: 'not authenticated' });
  }

  // Reconstruct the GitHub path from the request URL, preserving query string.
  const fullUrl = new URL(req.url, 'http://placeholder');
  const ghPath = fullUrl.pathname.replace(/^\/api\/github/, '') + fullUrl.search;
  if (!ghPath.startsWith('/')) {
    return res.status(400).json({ error: 'invalid path' });
  }

  const opts = {
    method: req.method,
    headers: {
      Authorization: 'token ' + token,
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'genomicsxai-submission-form',
    },
  };

  if (req.method !== 'GET' && req.method !== 'DELETE') {
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(req.body);
    }
  }

  try {
    const ghRes = await fetch('https://api.github.com' + ghPath, opts);

    // Forward rate-limit headers so the form can surface them.
    ['x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-limit'].forEach((h) => {
      const v = ghRes.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    if (ghRes.status === 204) {
      return res.status(204).end();
    }

    const text = await ghRes.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    res.status(ghRes.status).json(data);
  } catch (err) {
    res.status(502).json({ error: 'Upstream GitHub API error', detail: err.message });
  }
}
