// HTTP helpers and error types

// HTTP error response class
export class HttpError extends Error {
  constructor(status, code, message, reason = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

// Common HTTP error factory helpers
export const badRequest = (msg, reason = null) => new HttpError(400, 'VALIDATION', msg, reason);
export const unauthenticated = (msg = 'not authenticated') => new HttpError(401, 'UNAUTHENTICATED', msg);
export const tokenStale = () => new HttpError(401, 'TOKEN_STALE', 'token is stale; refresh and retry');
export const forbidden = (msg = 'forbidden', reason = 'missing_permission') => new HttpError(403, 'FORBIDDEN', msg, reason);
export const selfRoleChange = () => new HttpError(403, 'SELF_ROLE_CHANGE', 'you cannot change your own role');
export const notFound = (msg = 'not found') => new HttpError(404, 'NOT_FOUND', msg);
export const conflict = (msg, code = 'CONFLICT') => new HttpError(409, code, msg);
export const lastOwner = () => new HttpError(409, 'LAST_OWNER', 'the org must always have at least one owner');
export const deviceBusy = (msg = 'device already has an exclusive session') => new HttpError(409, 'DEVICE_BUSY', msg);
export const gone = (msg = 'invite is no longer valid') => new HttpError(410, 'GONE', msg);

// Timestamp normalisation
export function normalizeTs(value, field) {
  if (value === null || value === undefined) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw badRequest(`${field} is not a valid timestamp`);
  return d.toISOString();
}

// Send JSON response
export function send(res, status, body) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

// Send JSON error response
export function sendError(res, err, requestId) {
  const status = err instanceof HttpError ? err.status : 500;
  const code = err instanceof HttpError ? err.code : 'INTERNAL';
  const message = err instanceof HttpError ? err.message : 'internal error';

  if (!(err instanceof HttpError)) {
    console.error(`[${requestId}] unhandled:`, err);
  }

  send(res, status, { error: { code, message, reason: err.reason ?? null, requestId } });
}

const MAX_BODY = 1_000_000;

// Read JSON request body
export function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(badRequest('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (size === 0) return resolve({});
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(badRequest('body must be a JSON object'));
        }
        resolve(parsed);
      } catch {
        reject(badRequest('malformed JSON body'));
      }
    });

    req.on('error', reject);
  });
}
