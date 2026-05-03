// Shared auth helpers for Vercel serverless functions.
import crypto from 'node:crypto';

// Origins permitted to call the API. Production site + local Hugo dev.
export const ALLOWED_ORIGINS = [
  'https://genomicsxai.github.io',
  'http://localhost:1313',
];

export function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
}

export function originAllowed(req) {
  return ALLOWED_ORIGINS.includes(req.headers.origin);
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(/;\s*/).forEach((pair) => {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1);
  });
  return out;
}

export function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  return cookies.gh_session || null;
}

export const SESSION_TTL_SECONDS = 28800; // 8h, matches GitHub user-to-server token default

export function setSessionCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `gh_session=${token}; HttpOnly; Secure; SameSite=None; Path=/api; Max-Age=${SESSION_TTL_SECONDS}`
  );
}

export function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'gh_session=; HttpOnly; Secure; SameSite=None; Path=/api; Max-Age=0'
  );
}

export function clearStateCookieHeader() {
  return 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0';
}
