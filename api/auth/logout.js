// Vercel serverless function: clear the session cookie.
import { setCorsHeaders, originAllowed, clearSessionCookie } from '../_lib/auth.js';

export default function handler(req, res) {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (!originAllowed(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'method not allowed' });
  }

  clearSessionCookie(res);
  res.status(204).end();
}
