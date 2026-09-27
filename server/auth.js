// JWT and authentication utilities
import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';

// JWT configuration
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

// Sign token
export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue access token
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// Verify access token
export function verifyAccessToken(token, secret) {
  // Check token segments
  if (typeof token !== 'string') throw unauthenticated('malformed token');
  const parts = token.split('.');
  if (parts.length !== 3) throw unauthenticated('malformed token: expected 3 segments');

  const [rawH, rawP, rawSig] = parts;

  // Parse header and payload
  let header, claims;
  try {
    header = JSON.parse(unb64(rawH).toString('utf8'));
  } catch {
    throw unauthenticated('malformed token: invalid header encoding');
  }
  try {
    claims = JSON.parse(unb64(rawP).toString('utf8'));
  } catch {
    throw unauthenticated('malformed token: invalid payload encoding');
  }

  // Validate algorithm and type
  if (header.alg !== ALG) throw unauthenticated('malformed token: algorithm must be HS256');
  if (header.typ !== 'JWT') throw unauthenticated('malformed token: typ must be JWT');

  // Verify signature
  const expectedSig = createHmac('sha256', secret)
    .update(`${rawH}.${rawP}`)
    .digest();
  let actualSig;
  try {
    actualSig = unb64(rawSig);
  } catch {
    throw unauthenticated('malformed token: invalid signature encoding');
  }
  if (
    actualSig.length !== expectedSig.length ||
    !timingSafeEqual(actualSig, expectedSig)
  ) {
    throw unauthenticated('invalid token signature');
  }

  // Validate expiration
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number') throw unauthenticated('token missing exp');
  if (claims.exp <= now) throw unauthenticated('token expired');

  // Validate issuer and audience
  if (claims.iss !== ISS) throw unauthenticated('invalid token issuer');
  if (claims.aud !== AUD) throw unauthenticated('invalid token audience');

  // Validate JTI
  if (!claims.jti || typeof claims.jti !== 'string' || claims.jti.trim() === '') {
    throw unauthenticated('token missing jti');
  }

  return claims;
}

// Token freshness check
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// Refresh and invite token generation
export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

// Token hashing
export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// Password hashing
export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

// Password verification
export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
