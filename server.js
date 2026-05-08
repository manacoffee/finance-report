/**
 * Mana Coffee — Xero / Gmail / MCP server
 *
 * v2.1 (08/05/2026) — Chunked upload for large chat-uploaded receipts.
 *   - Adds three MCP tools: `upload_receipt_chunk`, `attach_uploaded_receipt_to_bill`,
 *     `attach_uploaded_receipt_to_spend_money`. Closes the gap where a single
 *     base64 payload over MCP gets truncated by the LLM client (~10KB practical
 *     ceiling) but the underlying receipt is 50KB+. Caller splits the base64
 *     into chunks, server stitches them, then attaches to Xero in one shot.
 *   - In-memory upload state with 1-hour TTL. Lost on Railway redeploy, which
 *     is fine — uploads are seconds-long, not hours.
 *   - The existing `attach_receipt_to_*` tools still work for small receipts.
 *
 * v2 (29/04/2026) — Hardening pass. Major changes vs original:
 *
 *  Security
 *    - Shared-secret bearer auth on /sse, /messages, /api/* (except OAuth flows)
 *    - OAuth `state` is now a single-use random token validated on callback (CSRF fix)
 *    - CORS locked to an explicit allowlist (no more `*`)
 *    - Xero where-clause inputs escape `\` before `"` (prior code only escaped `"`)
 *    - Catch-all `*` route no longer swallows `/api/*` typos
 *
 *  Correctness / robustness
 *    - Bills now created as DRAFT (matches the workflow doc; was AUTHORISED in original)
 *    - Token refresh has a single-flight lock (prevents two parallel refreshes invalidating each other)
 *    - Tokens are persisted to a JSON file (TOKEN_STORE_PATH) on every rotation,
 *      so they survive Railway redeploys IF a volume is mounted at that path.
 *      Falls back to env vars on first boot.
 *    - Idempotency-Key sent to Xero on create_bill / create_spend_money — protects
 *      against retry-induced double-creates
 *    - update_xero_bill: contact change is verified post-write; null `reference` clears the field
 *    - extract_gmail_email_body returns BOTH plain and stripped-HTML, and lets
 *      the caller pick (CCA needs HTML; Stel/most others are fine on plain)
 *    - Gmail message-list fetch uses bounded concurrency + Promise.allSettled
 *      (was unbounded Promise.all, which fails-all on a single 5xx)
 *    - PDF size capped before pdf-parse runs (was unbounded; DOS risk)
 *    - UTF-8-safe truncation for extracted text (was splitting surrogate pairs)
 *    - All axios calls have a 60s timeout (was none — could hang forever)
 *    - JSON body limit dropped from 50mb to 15mb (still fits any real receipt)
 *    - executeTool now calls handler functions directly instead of looping back via localhost HTTP
 *    - mcpSessions Map gets periodic cleanup (was leaking on dropped connections that didn't fire 'close')
 *    - All endpoints redact base64 from console logs
 *
 *  Required env vars (in addition to the original Xero/Gmail/Anthropic ones):
 *    MCP_SHARED_SECRET    - Long random string. Required on Authorization: Bearer <secret>
 *                           for /sse, /messages, /api/*. Set in Claude's connector config.
 *    PUBLIC_BASE_URL      - Optional. Used for log messages. Defaults to http://localhost:PORT.
 *    ALLOWED_ORIGINS      - Optional. Comma-separated CORS origins for the web UI.
 *                           Empty = no CORS (MCP doesn't need it).
 *    TOKEN_STORE_PATH     - Optional. Defaults to /data/tokens.json. Mount a Railway
 *                           volume at /data for cross-redeploy persistence.
 *    MAX_PDF_BYTES        - Optional. Default 25_000_000 (25 MB).
 *    MAX_UPLOAD_CHUNK_CHARS - Optional. Default 200_000. Per-chunk base64 cap.
 *    MAX_UPLOAD_CHUNKS    - Optional. Default 500. Per-upload chunk-count cap.
 */

const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { randomUUID, randomBytes, timingSafeEqual, createHash } = require('crypto');
const pdf = require('pdf-parse');

// ──────────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const MCP_SHARED_SECRET = process.env.MCP_SHARED_SECRET || '';
const TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || '/data/tokens.json';
const MAX_PDF_BYTES = Number(process.env.MAX_PDF_BYTES) || 25_000_000;
const MAX_UPLOAD_CHUNK_CHARS = Number(process.env.MAX_UPLOAD_CHUNK_CHARS) || 200_000;
const MAX_UPLOAD_CHUNKS = Number(process.env.MAX_UPLOAD_CHUNKS) || 500;
const UPLOAD_TTL_MS = 60 * 60_000; // 1 hour
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

if (!MCP_SHARED_SECRET || MCP_SHARED_SECRET.length < 32) {
  console.error('FATAL: MCP_SHARED_SECRET env var is required and must be ≥32 chars.');
  console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// Default 60s timeout on every axios call. Prior code had none — a slow
// Xero/Gmail response would hang the request handler indefinitely.
axios.defaults.timeout = 60_000;

// ──────────────────────────────────────────────────────────────────────────
// Token persistence
// ──────────────────────────────────────────────────────────────────────────
//
// Tokens are written to TOKEN_STORE_PATH on every rotation. On Railway you
// MUST mount a persistent volume at that path's directory (e.g. /data) for
// these to survive redeploys. Without a volume, tokens fall back to env
// vars on each boot, which means the first refresh after a redeploy uses
// the old env-var token — usually fine because Xero doesn't always rotate,
// but unreliable.

function loadTokenStore() {
  try {
    if (fs.existsSync(TOKEN_STORE_PATH)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf8'));
      console.log(`Loaded persisted tokens from ${TOKEN_STORE_PATH}`);
      return {
        xero: data.xero || {},
        gmail: data.gmail || {},
      };
    } else {
      console.log(`No persisted token store at ${TOKEN_STORE_PATH}; falling back to env vars`);
    }
  } catch (e) {
    console.error('Failed to load token store, falling back to env vars:', e.message);
  }
  return {
    xero: {
      refreshToken: process.env.XERO_REFRESH_TOKEN || null,
      tenantId: process.env.XERO_TENANT_ID || null,
    },
    gmail: {
      refreshToken: process.env.GMAIL_REFRESH_TOKEN || null,
    },
  };
}

function saveTokenStore() {
  try {
    const dir = path.dirname(TOKEN_STORE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const payload = JSON.stringify({
      xero: {
        refreshToken: xeroStore.refreshToken,
        tenantId: xeroStore.tenantId,
        // We don't persist accessToken — it's short-lived and re-derived on boot
      },
      gmail: {
        refreshToken: gmailStore.refreshToken,
      },
      savedAt: new Date().toISOString(),
    }, null, 2);
    // Atomic write: write to temp, then rename. Avoids partial-write corruption
    // if the process is killed mid-write.
    const tmpPath = TOKEN_STORE_PATH + '.tmp';
    fs.writeFileSync(tmpPath, payload, { mode: 0o600 });
    fs.renameSync(tmpPath, TOKEN_STORE_PATH);
  } catch (e) {
    // Persistence failure is non-fatal — server continues, tokens just won't
    // survive a restart. Log loudly so it gets noticed.
    console.error('TOKEN PERSISTENCE FAILED:', e.message);
    console.error('Tokens will not survive a restart. Mount a volume at ' + path.dirname(TOKEN_STORE_PATH));
  }
}

const _initialTokens = loadTokenStore();
let xeroStore = {
  accessToken: null,
  refreshToken: _initialTokens.xero.refreshToken,
  tenantId: _initialTokens.xero.tenantId,
  expiresAt: 0,
};
let gmailStore = {
  accessToken: null,
  refreshToken: _initialTokens.gmail.refreshToken,
  expiresAt: 0,
};

// ──────────────────────────────────────────────────────────────────────────
// Auth: shared-secret bearer middleware + OAuth state CSRF
// ──────────────────────────────────────────────────────────────────────────

function timingSafeStringEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function requireBearer(req, res, next) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m || !timingSafeStringEquals(m[1].trim(), MCP_SHARED_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// SSE clients can't always set headers (EventSource API). Allow secret via
// query string as a fallback, but only over HTTPS in production.
function requireBearerOrQuery(req, res, next) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const headerSecret = m ? m[1].trim() : null;
  const querySecret = typeof req.query.auth === 'string' ? req.query.auth : null;
  const candidate = headerSecret || querySecret;
  if (!candidate || !timingSafeStringEquals(candidate, MCP_SHARED_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// OAuth state: single-use random tokens that bind the callback to the
// originating /api/*-auth request. Prevents CSRF-style code injection.
const oauthStates = new Map(); // state -> { provider, expiresAt }

function generateOAuthState(provider) {
  const state = randomBytes(32).toString('hex');
  oauthStates.set(state, { provider, expiresAt: Date.now() + 10 * 60_000 });
  return state;
}

function validateOAuthState(state, expectedProvider) {
  if (typeof state !== 'string' || !state) return false;
  const entry = oauthStates.get(state);
  if (!entry) return false;
  oauthStates.delete(state); // single-use
  if (entry.expiresAt < Date.now()) return false;
  return entry.provider === expectedProvider;
}

// Sweep expired states periodically to bound memory.
setInterval(() => {
  const now = Date.now();
  for (const [state, entry] of oauthStates.entries()) {
    if (entry.expiresAt < now) oauthStates.delete(state);
  }
}, 5 * 60_000).unref();

// ──────────────────────────────────────────────────────────────────────────
// Chunked-upload state (v2.1)
// ──────────────────────────────────────────────────────────────────────────
//
// In-memory only — survives within a Railway process, lost on redeploy.
// That's fine; uploads are seconds-long, not hours. The 1-hour TTL is a
// generous backstop in case Claude abandons an upload mid-flight.

const uploadsInProgress = new Map(); // uploadId -> { chunks: Buffer[], totalBytes, createdAt }

setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of uploadsInProgress.entries()) {
    if (now - entry.createdAt > UPLOAD_TTL_MS) {
      uploadsInProgress.delete(id);
      console.log(`Upload swept: ${id} (${entry.totalBytes} bytes, ${entry.chunks.length} chunks)`);
    }
  }
}, 5 * 60_000).unref();

// ──────────────────────────────────────────────────────────────────────────
// Express app, CORS, body parsing
// ──────────────────────────────────────────────────────────────────────────

const app = express();

// CORS: only set headers if origin is in allowlist. The MCP transport doesn't
// use CORS (Claude calls server-to-server), so an empty allowlist is fine.
// The web UI hosted on the same Railway URL is same-origin and also doesn't
// need CORS.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// 15mb is enough for any legitimate receipt photo (typical ~3MB raw, ~4MB
// base64). The original 50mb was a DOS vector.
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Async route wrapper — pipes thrown errors into the global error handler
// instead of leaving promises unhandled.
const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

function xeroHeaders(token, tenantId, extra = {}) {
  return {
    Authorization: `Bearer ${token}`,
    'xero-tenant-id': tenantId,
    Accept: 'application/json',
    'Content-Type': 'application/json',
    ...extra,
  };
}

function gmailHeaders(token) {
  return { Authorization: `Bearer ${token}`, Accept: 'application/json' };
}

// Decode a base64url string into a Buffer. Gmail returns attachment data
// and raw message bodies in base64url encoding (RFC 4648 §5).
function base64urlDecode(str) {
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

// Escape a value for inclusion inside a Xero where-clause double-quoted
// string. Order matters: backslash first, then quote.
function xeroWhereEscape(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Escape regex metacharacters in user input.
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Truncate a string to roughly `maxChars` UTF-16 code units, but don't split
// a surrogate pair. Appends a [...truncated] marker.
function truncateText(str, maxChars) {
  if (typeof str !== 'string') return '';
  if (str.length <= maxChars) return str;
  let end = maxChars;
  const codeAtEnd = str.charCodeAt(end - 1);
  // High surrogate? Drop it so we don't leave a half-pair.
  if (codeAtEnd >= 0xD800 && codeAtEnd <= 0xDBFF) end--;
  return str.slice(0, end) + '\n[...truncated]';
}

// Bounded-concurrency map. Returns Promise.allSettled-style results: each
// entry is { status: 'fulfilled', value } or { status: 'rejected', reason }.
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= items.length) return;
      try {
        results[i] = { status: 'fulfilled', value: await fn(items[i], i) };
      } catch (err) {
        results[i] = { status: 'rejected', reason: err };
      }
    }
  }
  const workerCount = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

// Idempotency keys derived from logical identity of the create. Xero
// dedupes within a 24-hour window when this header is sent. Protects
// against retry-induced double-creates.
function idempotencyKeyForBill(supplierName, invoiceNumber) {
  const seed = `bill:v1:${supplierName}:${invoiceNumber}`;
  return createHash('sha256').update(seed).digest('hex');
}
function idempotencyKeyForSpend(payeeName, transactionDate, reference, total) {
  const seed = `spend:v1:${payeeName}:${transactionDate}:${reference || ''}:${total || ''}`;
  return createHash('sha256').update(seed).digest('hex');
}

// Headers helper that strips potentially huge fields (base64) before logging.
function redactForLog(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const clone = Array.isArray(obj) ? [...obj] : { ...obj };
  for (const key of Object.keys(clone)) {
    if (/base64|content|chunk/i.test(key) && typeof clone[key] === 'string' && clone[key].length > 200) {
      clone[key] = `[redacted ${clone[key].length} chars]`;
    } else if (typeof clone[key] === 'object' && clone[key] !== null) {
      clone[key] = redactForLog(clone[key]);
    }
  }
  return clone;
}

function logSection(label, body) {
  console.log(`═══ ${label} ═══`);
  if (body !== undefined) console.log(JSON.stringify(redactForLog(body), null, 2));
}
function logError(label, err) {
  console.error(`═══ ${label} ERROR ═══`);
  console.error('Status:', err.response?.status);
  console.error('Data:', JSON.stringify(err.response?.data, null, 2));
  console.error('Message:', err.message);
  console.error('═══════════════════════');
}

// ──────────────────────────────────────────────────────────────────────────
// Token refresh — single-flight locked so parallel callers don't race
// ──────────────────────────────────────────────────────────────────────────

let xeroRefreshInFlight = null;

async function getValidToken() {
  if (xeroStore.accessToken && Date.now() < xeroStore.expiresAt - 60_000) {
    return { token: xeroStore.accessToken, tenantId: xeroStore.tenantId };
  }
  if (!xeroStore.refreshToken) {
    throw new Error('Not connected to Xero — please visit /api/xero-auth to reconnect');
  }
  // If a refresh is already running, await it instead of starting another.
  // Without this lock, two parallel callers each refresh, each gets a new
  // refresh_token, the second overwrites the first, and the first's response
  // ends up holding a token Xero has already invalidated.
  if (xeroRefreshInFlight) return xeroRefreshInFlight;

  xeroRefreshInFlight = (async () => {
    try {
      const r = await axios.post(
        'https://identity.xero.com/connect/token',
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: xeroStore.refreshToken,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(
              `${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`
            ).toString('base64')}`,
          },
        }
      );
      xeroStore.accessToken = r.data.access_token;
      xeroStore.refreshToken = r.data.refresh_token || xeroStore.refreshToken;
      xeroStore.expiresAt = Date.now() + r.data.expires_in * 1_000;
      saveTokenStore();
      return { token: xeroStore.accessToken, tenantId: xeroStore.tenantId };
    } finally {
      xeroRefreshInFlight = null;
    }
  })();

  return xeroRefreshInFlight;
}

let gmailRefreshInFlight = null;

async function getValidGmailToken() {
  if (gmailStore.accessToken && Date.now() < gmailStore.expiresAt - 60_000) {
    return gmailStore.accessToken;
  }
  if (!gmailStore.refreshToken) {
    throw new Error('Not connected to Gmail — please visit /api/gmail-auth to connect');
  }
  if (gmailRefreshInFlight) return gmailRefreshInFlight;

  gmailRefreshInFlight = (async () => {
    try {
      const r = await axios.post(
        'https://oauth2.googleapis.com/token',
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: gmailStore.refreshToken,
          client_id: process.env.GMAIL_CLIENT_ID,
          client_secret: process.env.GMAIL_CLIENT_SECRET,
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      gmailStore.accessToken = r.data.access_token;
      // Google rotates refresh tokens rarely; keep the existing one if not returned.
      if (r.data.refresh_token) gmailStore.refreshToken = r.data.refresh_token;
      gmailStore.expiresAt = Date.now() + r.data.expires_in * 1_000;
      saveTokenStore();
      return gmailStore.accessToken;
    } finally {
      gmailRefreshInFlight = null;
    }
  })();

  return gmailRefreshInFlight;
}

// ──────────────────────────────────────────────────────────────────────────
// OAuth: Xero
// ──────────────────────────────────────────────────────────────────────────

app.get('/api/xero-auth', (req, res) => {
  const state = generateOAuthState('xero');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.XERO_CLIENT_ID,
    redirect_uri: process.env.XERO_REDIRECT_URI,
    scope: 'openid profile email offline_access accounting.invoices accounting.contacts accounting.banktransactions accounting.settings.read accounting.reports.profitandloss.read accounting.attachments',
    state,
  });
  res.redirect(`https://login.xero.com/identity/connect/authorize?${params}`);
});

app.get('/api/xero-callback', asyncRoute(async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code) return res.redirect('/?xero=error&reason=no_code');
  if (!validateOAuthState(state, 'xero')) {
    console.error('Xero callback: invalid or expired state token. Possible CSRF.');
    return res.redirect('/?xero=error&reason=bad_state');
  }
  try {
    const tokenRes = await axios.post(
      'https://identity.xero.com/connect/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.XERO_REDIRECT_URI,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(
            `${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`
          ).toString('base64')}`,
        },
      }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const tenantsRes = await axios.get('https://api.xero.com/connections', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const tenantId = tenantsRes.data[0]?.tenantId;
    if (!tenantId) throw new Error('No Xero organisation found on this account');
    xeroStore = {
      accessToken: access_token,
      refreshToken: refresh_token,
      tenantId,
      expiresAt: Date.now() + expires_in * 1_000,
    };
    saveTokenStore();
    res.redirect('/?xero=connected');
  } catch (err) {
    logError('XERO CALLBACK', err);
    res.redirect('/?xero=error');
  }
}));

// ──────────────────────────────────────────────────────────────────────────
// OAuth: Gmail
// ──────────────────────────────────────────────────────────────────────────

app.get('/api/gmail-auth', (req, res) => {
  if (!process.env.GMAIL_CLIENT_ID || !process.env.GMAIL_REDIRECT_URI) {
    return res.status(500).send('Gmail OAuth not configured — GMAIL_CLIENT_ID / GMAIL_REDIRECT_URI env vars missing.');
  }
  const state = generateOAuthState('gmail');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.GMAIL_CLIENT_ID,
    redirect_uri: process.env.GMAIL_REDIRECT_URI,
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    state,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/gmail-callback', asyncRoute(async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code) return res.redirect('/?gmail=error&reason=no_code');
  if (!validateOAuthState(state, 'gmail')) {
    console.error('Gmail callback: invalid or expired state token. Possible CSRF.');
    return res.redirect('/?gmail=error&reason=bad_state');
  }
  try {
    const tokenRes = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.GMAIL_CLIENT_ID,
        client_secret: process.env.GMAIL_CLIENT_SECRET,
        redirect_uri: process.env.GMAIL_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    if (!refresh_token) {
      console.error('Gmail callback: no refresh_token. Revoke at https://myaccount.google.com/permissions and re-auth.');
      return res.redirect('/?gmail=error&reason=no_refresh_token');
    }
    gmailStore = {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: Date.now() + expires_in * 1_000,
    };
    saveTokenStore();
    res.redirect('/?gmail=connected');
  } catch (err) {
    logError('GMAIL CALLBACK', err);
    res.redirect('/?gmail=error');
  }
}));

// ──────────────────────────────────────────────────────────────────────────
// Xero handler functions — these are called both by Express routes AND by
// executeTool() (no localhost loopback). All error handling is at the
// caller level via asyncRoute.
// ──────────────────────────────────────────────────────────────────────────

async function xeroCheckInvoice(invoiceNumber) {
  if (!invoiceNumber) {
    const err = new Error('invoiceNumber required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();

  // 1. Purchase bills (ACCPAY) — exact match supported
  const billsRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/Invoices?InvoiceNumbers=${encodeURIComponent(invoiceNumber)}&Type=ACCPAY`,
    { headers: xeroHeaders(token, tenantId) }
  );
  const invoices = billsRes.data.Invoices || [];
  const activeBills = invoices.filter(i => i.Status !== 'VOIDED' && i.Status !== 'DELETED');
  const bill = activeBills[0] || null;

  // 2. Spend Money — Xero only supports Contains() in where-clause for Reference,
  //    so we fetch candidates then post-filter with a word-boundary regex to
  //    avoid `INV-1234` matching `INV-12345`.
  const safe = xeroWhereEscape(invoiceNumber);
  const spendWhere = `Type=="SPEND" AND Reference!=null AND Reference.Contains("${safe}")`;
  const spendRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/BankTransactions?where=${encodeURIComponent(spendWhere)}`,
    { headers: xeroHeaders(token, tenantId) }
  );
  const candidates = (spendRes.data.BankTransactions || [])
    .filter(t => t.Status !== 'DELETED' && t.Status !== 'VOIDED');
  // Word-boundary match: invoice number must be bounded by start/end of string
  // or by a non-alphanumeric character. Catches both "INV-1234" and bare "1234"
  // without false-positives on "1234567".
  const boundary = new RegExp(`(^|[^A-Za-z0-9])${escapeRegex(invoiceNumber)}([^A-Za-z0-9]|$)`);
  const spendTxs = candidates.filter(t => boundary.test(t.Reference || ''));
  const spend = spendTxs[0] || null;

  const existsAsBill = !!bill;
  const existsAsSpendMoney = !!spend;

  return {
    exists: existsAsBill || existsAsSpendMoney,
    status: bill?.Status || spend?.Status || null,
    invoiceId: bill?.InvoiceID || null,
    existsAsBill,
    bill: bill ? {
      invoiceId: bill.InvoiceID, status: bill.Status, total: bill.Total,
      date: bill.Date, contact: bill.Contact?.Name,
    } : null,
    existsAsSpendMoney,
    spendMoney: spend ? {
      bankTransactionId: spend.BankTransactionID, status: spend.Status,
      total: spend.Total, date: spend.Date,
      reference: spend.Reference, contact: spend.Contact?.Name,
    } : null,
    spendMoneyMatches: spendTxs.length,
    spendMoneyCandidatesPreFilter: candidates.length,
  };
}

async function xeroSearchSpendMoney(input) {
  const { reference, contactName, amount, fromDate, toDate, bankAccountCode } = input || {};
  if (!reference && !contactName && !amount && !fromDate && !toDate) {
    const err = new Error('At least one of reference, contactName, amount, fromDate, toDate is required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();
  const clauses = ['Type=="SPEND"'];
  if (reference) {
    clauses.push(`Reference!=null AND Reference.Contains("${xeroWhereEscape(reference)}")`);
  }
  if (contactName) {
    clauses.push(`Contact.Name.Contains("${xeroWhereEscape(contactName)}")`);
  }
  if (fromDate) {
    const [y, m, d] = String(fromDate).split('-').map(Number);
    if (y && m && d) clauses.push(`Date>=DateTime(${y},${m},${d})`);
  }
  if (toDate) {
    const [y, m, d] = String(toDate).split('-').map(Number);
    if (y && m && d) clauses.push(`Date<=DateTime(${y},${m},${d})`);
  }
  const where = clauses.join(' AND ');
  const r = await axios.get(
    `https://api.xero.com/api.xro/2.0/BankTransactions?where=${encodeURIComponent(where)}`,
    { headers: xeroHeaders(token, tenantId) }
  );
  let txs = (r.data.BankTransactions || [])
    .filter(t => t.Status !== 'DELETED' && t.Status !== 'VOIDED');

  if (amount !== undefined && amount !== null && amount !== '') {
    const target = Number(amount);
    if (!Number.isNaN(target)) {
      txs = txs.filter(t => Math.abs(Number(t.Total) - target) < 0.02);
    }
  }
  if (bankAccountCode) {
    txs = txs.filter(t => t.BankAccount?.Code === String(bankAccountCode));
  }

  return {
    count: txs.length,
    transactions: txs.map(t => ({
      bankTransactionId: t.BankTransactionID,
      date: t.Date,
      status: t.Status,
      total: t.Total,
      reference: t.Reference,
      contact: t.Contact?.Name,
      bankAccountCode: t.BankAccount?.Code,
      bankAccountName: t.BankAccount?.Name,
    })),
  };
}

async function xeroCreateBill(input) {
  const { supplierName, invoiceNumber, invoiceDate, dueDate, lineItems, status } = input || {};
  if (!supplierName || !invoiceNumber || !invoiceDate || !lineItems?.length) {
    const err = new Error('supplierName, invoiceNumber, invoiceDate, and lineItems are required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();

  // Resolve contact
  const contactRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(supplierName)}`,
    { headers: xeroHeaders(token, tenantId) }
  );
  const contact = contactRes.data.Contacts?.[0];
  if (!contact) {
    const err = new Error(`Supplier "${supplierName}" not found in Xero contacts.`);
    err.status = 404;
    throw err;
  }

  // DRAFT by default — matches the workflow in xero-build-reference. Original
  // code had AUTHORISED hardcoded which contradicted the doc and skipped human
  // review. Caller can still pass status:'AUTHORISED' explicitly if needed.
  const billStatus = (status === 'AUTHORISED' || status === 'SUBMITTED') ? status : 'DRAFT';

  const idemKey = idempotencyKeyForBill(supplierName, invoiceNumber);

  const r = await axios.post(
    'https://api.xero.com/api.xro/2.0/Invoices',
    {
      Invoices: [{
        Type: 'ACCPAY',
        Contact: { ContactID: contact.ContactID },
        InvoiceNumber: invoiceNumber,
        Date: invoiceDate,
        DueDate: dueDate || null,
        Status: billStatus,
        LineAmountTypes: 'Exclusive',
        LineItems: lineItems.map(li => ({
          Description: li.description,
          Quantity: Number(li.quantity) || 1,
          UnitAmount: Number(li.unitAmount),
          AccountCode: String(li.accountCode),
          TaxType: li.taxType || 'INPUT',
        })),
      }],
    },
    { headers: xeroHeaders(token, tenantId, { 'Idempotency-Key': idemKey }) }
  );
  const created = r.data.Invoices?.[0];
  return {
    success: true,
    invoiceId: created?.InvoiceID,
    invoiceNumber: created?.InvoiceNumber,
    status: created?.Status,
    total: created?.Total,
  };
}

async function xeroUpdateBill(input) {
  const { invoiceId, supplierName, invoiceDate, dueDate, reference, status } = input || {};
  if (!invoiceId) {
    const err = new Error('invoiceId required');
    err.status = 400;
    throw err;
  }
  const hasUpdate = supplierName || invoiceDate || dueDate || reference !== undefined || status;
  if (!hasUpdate) {
    const err = new Error('At least one field to update required: supplierName, invoiceDate, dueDate, reference, or status');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();

  const updated = { InvoiceID: invoiceId };
  let intendedContactId = null;

  if (supplierName) {
    const contactRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(supplierName)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const contact = contactRes.data.Contacts?.[0];
    if (!contact) {
      const err = new Error(`Supplier "${supplierName}" not found in Xero contacts.`);
      err.status = 404;
      throw err;
    }
    intendedContactId = contact.ContactID;
    updated.Contact = { ContactID: contact.ContactID };
  }
  if (invoiceDate) updated.Date = invoiceDate;
  if (dueDate) updated.DueDate = dueDate;
  // Allow null or "" to clear the Reference field. Xero accepts empty string.
  if (reference !== undefined) updated.Reference = reference === null ? '' : reference;
  if (status) updated.Status = status;

  const r = await axios.post(
    `https://api.xero.com/api.xro/2.0/Invoices/${invoiceId}`,
    { Invoices: [updated] },
    { headers: xeroHeaders(token, tenantId) }
  );
  const result = r.data.Invoices?.[0];

  // Verify contact change actually took. Xero silently rejects contact changes
  // on AUTHORISED bills in some cases; surface a warning so Claude knows.
  let contactChangeWarning = null;
  if (intendedContactId && result?.Contact?.ContactID !== intendedContactId) {
    contactChangeWarning = `Contact change requested (ContactID=${intendedContactId}) but Xero stored ContactID=${result?.Contact?.ContactID}. Likely cause: the bill is AUTHORISED — change the contact in the Xero UI instead.`;
  }

  return {
    success: !contactChangeWarning,
    contactChangeWarning,
    invoiceId: result?.InvoiceID,
    invoiceNumber: result?.InvoiceNumber,
    status: result?.Status,
    total: result?.Total,
    contact: result?.Contact?.Name,
    contactId: result?.Contact?.ContactID,
    date: result?.Date,
    dueDate: result?.DueDate,
    reference: result?.Reference,
  };
}

async function xeroVoidBill(invoiceId) {
  // Set status to DELETED. Only works on DRAFT or SUBMITTED bills; AUTHORISED
  // must be voided via VOIDED status.
  if (!invoiceId) {
    const err = new Error('invoiceId required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();
  // Try DELETED first (works on DRAFT). If that fails, try VOIDED (AUTHORISED).
  for (const status of ['DELETED', 'VOIDED']) {
    try {
      const r = await axios.post(
        `https://api.xero.com/api.xro/2.0/Invoices/${invoiceId}`,
        { Invoices: [{ InvoiceID: invoiceId, Status: status }] },
        { headers: xeroHeaders(token, tenantId) }
      );
      const result = r.data.Invoices?.[0];
      return { success: true, status: result?.Status, invoiceId: result?.InvoiceID };
    } catch (err) {
      if (status === 'VOIDED') throw err; // last attempt
      // else fall through and try VOIDED
    }
  }
}

async function xeroDeleteSpendMoney(bankTransactionId) {
  if (!bankTransactionId) {
    const err = new Error('bankTransactionId required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();
  const r = await axios.post(
    `https://api.xero.com/api.xro/2.0/BankTransactions/${bankTransactionId}`,
    { BankTransactions: [{ BankTransactionID: bankTransactionId, Status: 'DELETED' }] },
    { headers: xeroHeaders(token, tenantId) }
  );
  const result = r.data.BankTransactions?.[0];
  return { success: true, status: result?.Status, bankTransactionId: result?.BankTransactionID };
}

async function xeroCreateSpendMoney(input) {
  const { payeeName, transactionDate, reference, bankAccountCode, lineItems } = input || {};
  if (!payeeName || !transactionDate || !lineItems?.length) {
    const err = new Error('payeeName, transactionDate, and lineItems are required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();

  // Resolve or create contact
  const contactRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(payeeName)}`,
    { headers: xeroHeaders(token, tenantId) }
  );
  let contact = contactRes.data.Contacts?.[0];
  if (!contact) {
    const newContactRes = await axios.post(
      'https://api.xero.com/api.xro/2.0/Contacts',
      { Contacts: [{ Name: payeeName }] },
      { headers: xeroHeaders(token, tenantId) }
    );
    contact = newContactRes.data.Contacts?.[0];
  }

  const code = String(bankAccountCode || '605');
  const acctRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/Accounts?where=${encodeURIComponent(`Code=="${xeroWhereEscape(code)}"`)}`,
    { headers: xeroHeaders(token, tenantId) }
  );
  const bankAccount = acctRes.data.Accounts?.[0];
  if (!bankAccount) {
    const err = new Error(`Bank account with code ${code} not found`);
    err.status = 404;
    throw err;
  }

  const totalEx = lineItems.reduce(
    (s, li) => s + (Number(li.unitAmount) || 0) * (Number(li.quantity) || 1),
    0
  );
  const idemKey = idempotencyKeyForSpend(payeeName, transactionDate, reference, totalEx.toFixed(2));

  const r = await axios.post(
    'https://api.xero.com/api.xro/2.0/BankTransactions',
    {
      BankTransactions: [{
        Type: 'SPEND',
        Contact: { ContactID: contact.ContactID },
        BankAccount: { AccountID: bankAccount.AccountID },
        Date: transactionDate,
        Reference: reference || null,
        Status: 'AUTHORISED',
        LineAmountTypes: 'Exclusive',
        LineItems: lineItems.map(li => ({
          Description: li.description,
          Quantity: Number(li.quantity) || 1,
          UnitAmount: Number(li.unitAmount),
          AccountCode: String(li.accountCode),
          TaxType: li.taxType || 'INPUT',
        })),
      }],
    },
    { headers: xeroHeaders(token, tenantId, { 'Idempotency-Key': idemKey }) }
  );
  const created = r.data.BankTransactions?.[0];
  return {
    success: true,
    bankTransactionId: created?.BankTransactionID,
    status: created?.Status,
    total: created?.Total,
    contactId: contact.ContactID,
  };
}

async function xeroGetOpenBills({ fromDate, toDate } = {}) {
  const { token, tenantId } = await getValidToken();
  let url = 'https://api.xero.com/api.xro/2.0/Invoices?Type=ACCPAY&Statuses=DRAFT,SUBMITTED,AUTHORISED';
  if (fromDate) url += `&fromDate=${encodeURIComponent(fromDate)}`;
  if (toDate) url += `&toDate=${encodeURIComponent(toDate)}`;
  const r = await axios.get(url, { headers: xeroHeaders(token, tenantId) });
  return { bills: r.data.Invoices || [] };
}

async function xeroAttachToInvoice(billId, filename, buffer, mimeType) {
  if (!billId || !filename || !buffer) {
    const err = new Error('billId, filename, and buffer are required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();
  const r = await axios.post(
    `https://api.xero.com/api.xro/2.0/Invoices/${billId}/Attachments/${encodeURIComponent(filename)}`,
    buffer,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'xero-tenant-id': tenantId,
        'Content-Type': mimeType || 'application/pdf',
        'Content-Length': buffer.length,
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }
  );
  return { success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] };
}

async function xeroAttachToSpendMoney(bankTransactionId, filename, buffer, mimeType) {
  if (!bankTransactionId || !filename || !buffer) {
    const err = new Error('bankTransactionId, filename, and buffer are required');
    err.status = 400;
    throw err;
  }
  const { token, tenantId } = await getValidToken();
  const r = await axios.post(
    `https://api.xero.com/api.xro/2.0/BankTransactions/${bankTransactionId}/Attachments/${encodeURIComponent(filename)}`,
    buffer,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'xero-tenant-id': tenantId,
        'Content-Type': mimeType || 'application/pdf',
        'Content-Length': buffer.length,
      },
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }
  );
  return { success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] };
}

// ──────────────────────────────────────────────────────────────────────────
// Chunked upload handlers (v2.1)
// ──────────────────────────────────────────────────────────────────────────
//
// Pattern:
//   1. Caller splits a large base64 payload into chunks of <= MAX_UPLOAD_CHUNK_CHARS
//   2. First call to appendReceiptChunk omits uploadId; server returns one
//   3. Subsequent calls pass the same uploadId
//   4. After last chunk, caller invokes attachUploadedReceiptTo{Bill,SpendMoney}
//      which assembles and attaches in one Xero call
//
// On attach failure, the upload buffer is preserved so the caller can retry
// without re-uploading. Successful attaches consume (delete) the buffer.

function appendReceiptChunk(uploadId, base64Chunk) {
  if (typeof base64Chunk !== 'string' || !base64Chunk.length) {
    const err = new Error('base64_chunk required (non-empty string)');
    err.status = 400;
    throw err;
  }
  if (base64Chunk.length > MAX_UPLOAD_CHUNK_CHARS) {
    const err = new Error(`Chunk too large: ${base64Chunk.length} chars (max ${MAX_UPLOAD_CHUNK_CHARS}). Split into smaller pieces.`);
    err.status = 413;
    throw err;
  }

  let entry;
  let id = uploadId;
  if (id) {
    entry = uploadsInProgress.get(id);
    if (!entry) {
      const err = new Error(`Upload ${id} not found or expired (TTL is ${Math.round(UPLOAD_TTL_MS / 60000)} min). Start a new upload by omitting upload_id.`);
      err.status = 404;
      throw err;
    }
  } else {
    id = randomUUID();
    entry = { chunks: [], totalBytes: 0, createdAt: Date.now() };
    uploadsInProgress.set(id, entry);
  }

  // Decode immediately — this catches base64 corruption per-chunk rather
  // than at finalize time.
  let buffer;
  try {
    buffer = Buffer.from(base64Chunk, 'base64');
  } catch (e) {
    const err = new Error(`base64 decode failed: ${e.message}`);
    err.status = 400;
    throw err;
  }

  entry.chunks.push(buffer);
  entry.totalBytes += buffer.length;

  if (entry.chunks.length > MAX_UPLOAD_CHUNKS) {
    uploadsInProgress.delete(id);
    const err = new Error(`Too many chunks: ${entry.chunks.length} (max ${MAX_UPLOAD_CHUNKS}). Use larger chunks.`);
    err.status = 413;
    throw err;
  }
  if (entry.totalBytes > MAX_PDF_BYTES) {
    uploadsInProgress.delete(id);
    const err = new Error(`Upload exceeds ${MAX_PDF_BYTES} bytes (got ${entry.totalBytes}).`);
    err.status = 413;
    throw err;
  }

  return {
    upload_id: id,
    chunks_received: entry.chunks.length,
    total_bytes: entry.totalBytes,
    chunk_bytes: buffer.length,
  };
}

function consumeUpload(uploadId, deleteOnSuccess) {
  if (!uploadId) {
    const err = new Error('upload_id required');
    err.status = 400;
    throw err;
  }
  const entry = uploadsInProgress.get(uploadId);
  if (!entry) {
    const err = new Error(`Upload ${uploadId} not found or expired`);
    err.status = 404;
    throw err;
  }
  return {
    buffer: Buffer.concat(entry.chunks, entry.totalBytes),
    cleanup: () => { if (deleteOnSuccess) uploadsInProgress.delete(uploadId); },
  };
}

async function attachUploadedReceiptToSpendMoney(uploadId, bankTransactionId, filename, mimeType) {
  const { buffer, cleanup } = consumeUpload(uploadId, true);
  const result = await xeroAttachToSpendMoney(bankTransactionId, filename, buffer, mimeType || 'application/pdf');
  cleanup(); // only delete on success — failure leaves the upload intact for retry
  return { ...result, upload_id: uploadId, consumed: true };
}

async function attachUploadedReceiptToBill(uploadId, billId, filename, mimeType) {
  const { buffer, cleanup } = consumeUpload(uploadId, true);
  const result = await xeroAttachToInvoice(billId, filename, buffer, mimeType || 'application/pdf');
  cleanup();
  return { ...result, upload_id: uploadId, consumed: true };
}

// ──────────────────────────────────────────────────────────────────────────
// Gmail handler functions
// ──────────────────────────────────────────────────────────────────────────

async function resolveGmailLabelId(labelName) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    'https://gmail.googleapis.com/gmail/v1/users/me/labels',
    { headers: gmailHeaders(token) }
  );
  const match = (r.data.labels || []).find(l => l.name === labelName);
  if (!match) {
    const err = new Error(`Gmail label "${labelName}" not found (case-sensitive)`);
    err.status = 404;
    throw err;
  }
  return match.id;
}

function collectAttachments(payload, out = []) {
  if (!payload) return out;
  if (payload.filename && payload.body && payload.body.attachmentId) {
    out.push({
      filename: payload.filename,
      mimeType: payload.mimeType,
      size: payload.body.size || 0,
      attachmentId: payload.body.attachmentId,
      partId: payload.partId || null,
    });
  }
  if (Array.isArray(payload.parts)) {
    payload.parts.forEach(p => collectAttachments(p, out));
  }
  return out;
}

function pickHeader(headers, name) {
  const h = (headers || []).find(x => (x.name || '').toLowerCase() === name.toLowerCase());
  return h ? h.value : null;
}

async function fetchGmailAttachment(messageId, attachmentId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.data) throw new Error('Gmail attachment returned empty data');
  const buf = base64urlDecode(r.data.data);
  if (buf.length > MAX_PDF_BYTES) {
    const err = new Error(`Attachment is ${buf.length} bytes, exceeds MAX_PDF_BYTES=${MAX_PDF_BYTES}`);
    err.status = 413;
    throw err;
  }
  return buf;
}

async function fetchGmailRawMessage(messageId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.raw) throw new Error('Gmail raw message returned empty data');
  return base64urlDecode(r.data.raw);
}

async function fetchGmailFullMessage(messageId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.payload) throw new Error('Gmail full message returned empty payload');
  return r.data;
}

async function gmailListByLabel({ label, maxResults }) {
  if (!label) {
    const err = new Error('label is required');
    err.status = 400;
    throw err;
  }
  const token = await getValidGmailToken();
  const labelId = await resolveGmailLabelId(label);
  const limit = Math.min(Number(maxResults) || 50, 500);
  const listRes = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=${encodeURIComponent(labelId)}&maxResults=${limit}`,
    { headers: gmailHeaders(token) }
  );
  const ids = (listRes.data.messages || []).map(m => m.id);

  // Bounded concurrency. The original used Promise.all(ids.map()) which
  // (a) flooded Gmail's per-user rate limit, and (b) failed the whole batch
  // on a single message error. allSettled-style results lets us return
  // partials and tell the caller about failures.
  const fetched = await mapWithConcurrency(ids, 5, async (id) => {
    const m = await axios.get(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`,
      { headers: gmailHeaders(token) }
    );
    const p = m.data.payload || {};
    const headers = p.headers || [];
    return {
      messageId: m.data.id,
      threadId: m.data.threadId,
      subject: pickHeader(headers, 'Subject'),
      from: pickHeader(headers, 'From'),
      to: pickHeader(headers, 'To'),
      date: pickHeader(headers, 'Date'),
      internalDate: m.data.internalDate,
      snippet: m.data.snippet,
      attachments: collectAttachments(p),
    };
  });

  const messages = [];
  const failures = [];
  fetched.forEach((entry, i) => {
    if (entry.status === 'fulfilled') messages.push(entry.value);
    else failures.push({ messageId: ids[i], error: entry.reason?.message || String(entry.reason) });
  });

  return { label, count: messages.length, requestedCount: ids.length, failures, messages };
}

// PDF text extraction. Bounded by MAX_PDF_BYTES via fetchGmailAttachment.
async function extractPdfTextFromGmail({ messageId, attachmentId, maxChars = 50000 }) {
  if (!messageId || !attachmentId) {
    const err = new Error('messageId and attachmentId are required');
    err.status = 400;
    throw err;
  }
  const buffer = await fetchGmailAttachment(messageId, attachmentId);
  let parsed;
  try {
    parsed = await pdf(buffer);
  } catch (e) {
    const err = new Error(`pdf-parse failed: ${e.message}. PDF may be image-only or corrupt.`);
    err.status = 422;
    throw err;
  }
  const effectiveMax = Number(maxChars) > 0 ? Number(maxChars) : 50000;
  const text = truncateText(parsed.text || '', effectiveMax);
  return {
    messageId,
    attachmentId,
    pageCount: parsed.numpages,
    bytes: buffer.length,
    charsReturned: text.length,
    text,
    warning: !parsed.text || parsed.text.trim().length === 0
      ? 'No text extracted — PDF is likely image-only/scanned. OCR required.'
      : null,
  };
}

// Minimal HTML→text. Not a general parser — only feed it supplier email bodies.
function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<\/(p|div|li|h[1-6]|tr|table)>/gi, '\n')
    // Cell separators — important for CCA invoices where line-item rows are
    // table rows. Without this, cell contents mash together.
    .replace(/<\/(td|th)>/gi, '\t')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    // Named entities
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&hellip;/gi, '…')
    .replace(/&copy;/gi, '©')
    .replace(/&reg;/gi, '®')
    .replace(/&trade;/gi, '™')
    .replace(/&mdash;/gi, '—')
    .replace(/&ndash;/gi, '–')
    // Numeric entities
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // Whitespace cleanup
    .replace(/[ \t]+/g, ' ')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Email body extraction. Returns BOTH plain and stripped-html when available;
// caller picks via `prefer` parameter ('plain' | 'html' | 'auto').
// 'auto' default: plain if it has reasonable length, else html.
// Fixes the "CCA plain-text drops table rows" failure mode by exposing both
// representations to the caller.
async function extractEmailBodyFromGmail({ messageId, maxChars = 50000, prefer = 'auto' }) {
  if (!messageId) {
    const err = new Error('messageId is required');
    err.status = 400;
    throw err;
  }
  const message = await fetchGmailFullMessage(messageId);

  const collected = { plain: [], html: [] };
  function walk(part) {
    if (!part) return;
    if (part.mimeType === 'text/plain' && part.body?.data) {
      collected.plain.push(base64urlDecode(part.body.data).toString('utf8'));
    } else if (part.mimeType === 'text/html' && part.body?.data) {
      collected.html.push(base64urlDecode(part.body.data).toString('utf8'));
    }
    if (Array.isArray(part.parts)) part.parts.forEach(walk);
  }
  walk(message.payload);

  const plainBody = collected.plain.join('\n\n').trim();
  const htmlBody = collected.html.length ? stripHtml(collected.html.join('\n\n')).trim() : '';

  let chosenSource, chosen;
  if (prefer === 'plain') {
    chosenSource = plainBody ? 'plain' : (htmlBody ? 'html' : null);
    chosen = plainBody || htmlBody;
  } else if (prefer === 'html') {
    chosenSource = htmlBody ? 'html' : (plainBody ? 'plain' : null);
    chosen = htmlBody || plainBody;
  } else {
    // auto: prefer HTML if it's >= 1.2x the plain length (suggests plain is dropping content)
    if (htmlBody && (!plainBody || htmlBody.length >= plainBody.length * 1.2)) {
      chosenSource = 'html';
      chosen = htmlBody;
    } else {
      chosenSource = plainBody ? 'plain' : (htmlBody ? 'html' : null);
      chosen = plainBody || htmlBody;
    }
  }
  chosen = chosen || '';

  const headers = message.payload?.headers || [];

  return {
    messageId,
    subject: pickHeader(headers, 'Subject'),
    from: pickHeader(headers, 'From'),
    date: pickHeader(headers, 'Date'),
    bodySource: chosenSource,
    hasPlain: plainBody.length > 0,
    hasHtml: htmlBody.length > 0,
    plainCharCount: plainBody.length,
    htmlCharCount: htmlBody.length,
    charsReturned: Math.min(chosen.length, Number(maxChars) > 0 ? Number(maxChars) : 50000),
    text: truncateText(chosen, Number(maxChars) > 0 ? Number(maxChars) : 50000),
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Atomic create-and-attach (Gmail-pipeline path) — addresses the orphan
// problem where create succeeds but attach fails. If attach fails, the
// just-created Xero record is voided/deleted, returning the caller to the
// pre-create state.
// ──────────────────────────────────────────────────────────────────────────

async function createBillWithGmailAttachment(input) {
  const created = await xeroCreateBill(input.bill);
  try {
    const buffer = input.useEml
      ? await fetchGmailRawMessage(input.gmailMessageId)
      : await fetchGmailAttachment(input.gmailMessageId, input.gmailAttachmentId);
    const filename = input.filename || (input.useEml
      ? `email-${input.gmailMessageId}.eml`
      : `attachment-${input.gmailAttachmentId}.pdf`);
    const mimeType = input.useEml ? 'message/rfc822' : (input.mimeType || 'application/pdf');
    const attached = await xeroAttachToInvoice(created.invoiceId, filename, buffer, mimeType);
    return { ...created, attachment: attached };
  } catch (attachErr) {
    // Roll back the bill so we don't leave an unattached orphan.
    let rollback;
    try { rollback = await xeroVoidBill(created.invoiceId); }
    catch (rollbackErr) { rollback = { error: rollbackErr.message }; }
    const err = new Error(`Bill created (${created.invoiceId}) but attach failed: ${attachErr.message}. Rollback: ${JSON.stringify(rollback)}`);
    err.status = 502;
    err.createdInvoiceId = created.invoiceId;
    err.rollback = rollback;
    throw err;
  }
}

async function createSpendMoneyWithGmailAttachment(input) {
  const created = await xeroCreateSpendMoney(input.spend);
  try {
    const buffer = input.useEml
      ? await fetchGmailRawMessage(input.gmailMessageId)
      : await fetchGmailAttachment(input.gmailMessageId, input.gmailAttachmentId);
    const filename = input.filename || (input.useEml
      ? `email-${input.gmailMessageId}.eml`
      : `attachment-${input.gmailAttachmentId}.pdf`);
    const mimeType = input.useEml ? 'message/rfc822' : (input.mimeType || 'application/pdf');
    const attached = await xeroAttachToSpendMoney(created.bankTransactionId, filename, buffer, mimeType);
    return { ...created, attachment: attached };
  } catch (attachErr) {
    let rollback;
    try { rollback = await xeroDeleteSpendMoney(created.bankTransactionId); }
    catch (rollbackErr) { rollback = { error: rollbackErr.message }; }
    const err = new Error(`Spend Money created (${created.bankTransactionId}) but attach failed: ${attachErr.message}. Rollback: ${JSON.stringify(rollback)}`);
    err.status = 502;
    err.createdBankTransactionId = created.bankTransactionId;
    err.rollback = rollback;
    throw err;
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Express routes — thin wrappers around the handler functions
// ──────────────────────────────────────────────────────────────────────────

// /api/debug — reveals enough about the configuration to be useful for
// debugging but is auth-protected. Was previously open.
app.get('/api/debug', requireBearer, (req, res) => {
  res.json({
    clientIdLength: (process.env.XERO_CLIENT_ID || '').length,
    clientIdStart: (process.env.XERO_CLIENT_ID || '').slice(0, 4),
    redirectUri: process.env.XERO_REDIRECT_URI,
    hasSecret: !!process.env.XERO_CLIENT_SECRET,
    hasStoredRefreshToken: !!xeroStore.refreshToken,
    tenantId: xeroStore.tenantId,
    tokenStorePath: TOKEN_STORE_PATH,
    tokenStoreExists: fs.existsSync(TOKEN_STORE_PATH),
    gmail: {
      clientIdConfigured: !!process.env.GMAIL_CLIENT_ID,
      clientSecretConfigured: !!process.env.GMAIL_CLIENT_SECRET,
      redirectUri: process.env.GMAIL_REDIRECT_URI || null,
      hasStoredRefreshToken: !!gmailStore.refreshToken,
    },
    activeMcpSessions: mcpSessions.size,
    activeUploads: uploadsInProgress.size,
    uploadLimits: {
      maxChunkChars: MAX_UPLOAD_CHUNK_CHARS,
      maxChunks: MAX_UPLOAD_CHUNKS,
      maxTotalBytes: MAX_PDF_BYTES,
      ttlMinutes: Math.round(UPLOAD_TTL_MS / 60000),
    },
  });
});

// Health check — public, no auth, returns minimal info.
app.get('/healthz', (req, res) => res.json({ ok: true, time: Date.now() }));

// Web app route — kept for backwards compat with the React dashboard.
// Now requires the same shared secret as the MCP routes.
app.get('/api/xero-labour', requireBearer, asyncRoute(async (req, res) => {
  const { fromDate, toDate } = req.query;
  if (!fromDate || !toDate) {
    return res.status(400).json({ error: 'fromDate and toDate required' });
  }
  const { token, tenantId } = await getValidToken();
  const LABOUR_KEYWORDS = ['wage', 'labour', 'labor', 'payroll', 'salary', 'salaries', 'superannuation', 'super'];
  const plRes = await axios.get(
    `https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss?fromDate=${encodeURIComponent(fromDate)}&toDate=${encodeURIComponent(toDate)}&standardLayout=true`,
    { headers: xeroHeaders(token, tenantId) }
  );
  const rows = plRes.data?.Reports?.[0]?.Rows || [];
  let labourExGST = 0;
  const walk = rows => {
    for (const row of rows) {
      if (row.Rows) walk(row.Rows);
      if (row.Cells) {
        const name = (row.Cells[0]?.Value || '').toLowerCase();
        const amt = parseFloat(row.Cells[1]?.Value) || 0;
        if (LABOUR_KEYWORDS.some(k => name.includes(k))) labourExGST += Math.abs(amt);
      }
    }
  };
  walk(rows);
  res.json({ labourExGST: parseFloat(labourExGST.toFixed(2)) });
}));

app.post('/api/parse-invoice', requireBearer, asyncRoute(async (req, res) => {
  const { base64, filename } = req.body;
  if (!base64) return res.status(400).json({ error: 'No file data' });

  // Supplier→category lookup. Keys are lowercased substrings of the supplier
  // name as returned by the parser. Original code had "big michaels" (no
  // apostrophe) which never matched "Big Michael's Fruit and Vegetables".
  const SUPPLIER_CATS = [
    [/stel/, 'coffee'],
    [/norkatu/, 'coffee'],
    [/moco/, 'food'],
    [/fresho/, 'food'],
    [/big\s*michael/, 'food'],     // matches "Big Michael's"
    [/coca[\s-]*cola|ccep|cca\b/, 'food'],
    [/ordermentum/, 'food'],
    [/carbar/, 'vehicle'],
  ];
  const categFromSupplier = name => {
    const l = (name || '').toLowerCase();
    for (const [re, cat] of SUPPLIER_CATS) if (re.test(l)) return cat;
    return null;
  };

  const response = await axios.post(
    'https://api.anthropic.com/v1/messages',
    {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: [
          { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } },
          { type: 'text', text: 'Extract from this invoice and respond ONLY with valid JSON, no markdown:\n{"supplier":"<name>","invoice_number":"<inv#>","invoice_date":"<date>","total_inc_gst":<number>,"total_ex_gst":<number>,"gst_amount":<number>}\nUse null for missing fields.' },
        ],
      }],
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
    }
  );
  const text = response.data.content?.map(b => b.text || '').join('') || '{}';
  let parsed;
  try { parsed = JSON.parse(text.replace(/```json|```/g, '').trim()); }
  catch (e) { return res.status(502).json({ error: 'Parser returned non-JSON', raw: text }); }
  res.json({ ...parsed, category: categFromSupplier(parsed.supplier), file: filename });
}));

app.post('/api/generate-report', requireBearer, asyncRoute(async (req, res) => {
  const { weekLabel, coffeeEx, foodEx, total, cogsCoEx, cogsFdEx, gp, gpPct, labourEx, labourPct, txns, avg } = req.body;
  const fmt = n => `$${Number(n).toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const pct = (a, b) => b === 0 ? '—' : `${((a / b) * 100).toFixed(1)}%`;
  const prompt = `You are a financial analyst for a café. Generate a concise weekly report.
Week: ${weekLabel || 'This week'}
Turnover Coffee: ${fmt(coffeeEx)}, Food & Bev: ${fmt(foodEx)}, Total: ${fmt(total)}
COGS Coffee: ${fmt(cogsCoEx)} (${pct(cogsCoEx, coffeeEx)}), Food: ${fmt(cogsFdEx)} (${pct(cogsFdEx, foodEx)})
Labour: ${fmt(labourEx)} (${Number(labourPct).toFixed(1)}% of turnover)
Gross Profit: ${fmt(gp)} (${Number(gpPct).toFixed(1)}%), Transactions: ${Number(txns).toLocaleString()}, Avg Spend: ${fmt(avg)}
Provide: 1) 2-sentence executive summary 2) Key highlights 3) Watch points (flag labour >35% or high COGS) 4) 2-3 recommendations. Use **bold** for section labels.`;
  const response = await axios.post(
    'https://api.anthropic.com/v1/messages',
    { model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] },
    {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
    }
  );
  res.json({ report: response.data.content?.map(b => b.text || '').join('') || '' });
}));

app.get('/api/xero-check-invoice', requireBearer, asyncRoute(async (req, res) => {
  logSection('CHECK INVOICE', { invoiceNumber: req.query.invoiceNumber });
  const result = await xeroCheckInvoice(req.query.invoiceNumber);
  res.json(result);
}));

app.get('/api/xero-search-spend-money', requireBearer, asyncRoute(async (req, res) => {
  logSection('SEARCH SPEND MONEY', req.query);
  const result = await xeroSearchSpendMoney({
    reference: req.query.reference,
    contactName: req.query.contactName,
    amount: req.query.amount,
    fromDate: req.query.fromDate,
    toDate: req.query.toDate,
    bankAccountCode: req.query.bankAccountCode,
  });
  res.json(result);
}));

app.post('/api/xero-create-bill', requireBearer, asyncRoute(async (req, res) => {
  logSection('CREATE BILL', req.body);
  const result = await xeroCreateBill(req.body);
  res.json(result);
}));

app.post('/api/xero-update-bill', requireBearer, asyncRoute(async (req, res) => {
  logSection('UPDATE BILL', req.body);
  const result = await xeroUpdateBill(req.body);
  res.json(result);
}));

app.get('/api/xero-open-bills', requireBearer, asyncRoute(async (req, res) => {
  const result = await xeroGetOpenBills(req.query);
  res.json(result);
}));

app.post('/api/xero-create-spend-money', requireBearer, asyncRoute(async (req, res) => {
  logSection('CREATE SPEND MONEY', req.body);
  const result = await xeroCreateSpendMoney(req.body);
  res.json(result);
}));

app.post('/api/xero-attach-receipt', requireBearer, asyncRoute(async (req, res) => {
  const { billId, filename, base64Content, mimeType } = req.body;
  if (!billId || !filename || !base64Content) {
    return res.status(400).json({ error: 'billId, filename, and base64Content are required' });
  }
  const buffer = Buffer.from(base64Content, 'base64');
  if (buffer.length > MAX_PDF_BYTES) {
    return res.status(413).json({ error: `Decoded buffer ${buffer.length} bytes exceeds MAX_PDF_BYTES=${MAX_PDF_BYTES}` });
  }
  const result = await xeroAttachToInvoice(billId, filename, buffer, mimeType);
  res.json(result);
}));

app.post('/api/xero-attach-receipt-spend-money', requireBearer, asyncRoute(async (req, res) => {
  const { bankTransactionId, filename, base64Content, mimeType } = req.body;
  if (!bankTransactionId || !filename || !base64Content) {
    return res.status(400).json({ error: 'bankTransactionId, filename, and base64Content are required' });
  }
  const buffer = Buffer.from(base64Content, 'base64');
  if (buffer.length > MAX_PDF_BYTES) {
    return res.status(413).json({ error: `Decoded buffer ${buffer.length} bytes exceeds MAX_PDF_BYTES=${MAX_PDF_BYTES}` });
  }
  const result = await xeroAttachToSpendMoney(bankTransactionId, filename, buffer, mimeType);
  res.json(result);
}));

// Chunked upload routes (v2.1)
app.post('/api/upload-chunk', requireBearer, asyncRoute(async (req, res) => {
  logSection('UPLOAD CHUNK', { upload_id: req.body.upload_id, chunk_chars: req.body.base64_chunk?.length });
  const result = appendReceiptChunk(req.body.upload_id, req.body.base64_chunk);
  res.json(result);
}));

app.post('/api/attach-uploaded-to-spend-money', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH UPLOADED TO SPEND MONEY', req.body);
  const { upload_id, bank_transaction_id, filename, mime_type } = req.body;
  const result = await attachUploadedReceiptToSpendMoney(upload_id, bank_transaction_id, filename, mime_type);
  res.json(result);
}));

app.post('/api/attach-uploaded-to-bill', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH UPLOADED TO BILL', req.body);
  const { upload_id, bill_id, filename, mime_type } = req.body;
  const result = await attachUploadedReceiptToBill(upload_id, bill_id, filename, mime_type);
  res.json(result);
}));

app.get('/api/gmail-list-by-label', requireBearer, asyncRoute(async (req, res) => {
  const result = await gmailListByLabel({ label: req.query.label, maxResults: req.query.maxResults });
  res.json(result);
}));

app.post('/api/extract-pdf-text', requireBearer, asyncRoute(async (req, res) => {
  const result = await extractPdfTextFromGmail(req.body);
  res.json(result);
}));

app.post('/api/extract-email-body', requireBearer, asyncRoute(async (req, res) => {
  const result = await extractEmailBodyFromGmail(req.body);
  res.json(result);
}));

app.post('/api/xero-attach-gmail-pdf-to-bill', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH GMAIL PDF TO BILL', req.body);
  const { billId, gmailMessageId, gmailAttachmentId, filename, mimeType } = req.body;
  if (!billId || !gmailMessageId || !gmailAttachmentId || !filename) {
    return res.status(400).json({ error: 'billId, gmailMessageId, gmailAttachmentId, filename are required' });
  }
  const buffer = await fetchGmailAttachment(gmailMessageId, gmailAttachmentId);
  const result = await xeroAttachToInvoice(billId, filename, buffer, mimeType);
  res.json(result);
}));

app.post('/api/xero-attach-gmail-pdf-to-spend-money', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH GMAIL PDF TO SPEND MONEY', req.body);
  const { bankTransactionId, gmailMessageId, gmailAttachmentId, filename, mimeType } = req.body;
  if (!bankTransactionId || !gmailMessageId || !gmailAttachmentId || !filename) {
    return res.status(400).json({ error: 'bankTransactionId, gmailMessageId, gmailAttachmentId, filename are required' });
  }
  const buffer = await fetchGmailAttachment(gmailMessageId, gmailAttachmentId);
  const result = await xeroAttachToSpendMoney(bankTransactionId, filename, buffer, mimeType);
  res.json(result);
}));

app.post('/api/xero-attach-gmail-email-to-bill', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH GMAIL EMAIL TO BILL', req.body);
  const { billId, gmailMessageId, filename } = req.body;
  if (!billId || !gmailMessageId) {
    return res.status(400).json({ error: 'billId and gmailMessageId are required' });
  }
  const buffer = await fetchGmailRawMessage(gmailMessageId);
  const name = filename || `email-${gmailMessageId}.eml`;
  const result = await xeroAttachToInvoice(billId, name, buffer, 'message/rfc822');
  res.json(result);
}));

app.post('/api/xero-attach-gmail-email-to-spend-money', requireBearer, asyncRoute(async (req, res) => {
  logSection('ATTACH GMAIL EMAIL TO SPEND MONEY', req.body);
  const { bankTransactionId, gmailMessageId, filename } = req.body;
  if (!bankTransactionId || !gmailMessageId) {
    return res.status(400).json({ error: 'bankTransactionId and gmailMessageId are required' });
  }
  const buffer = await fetchGmailRawMessage(gmailMessageId);
  const name = filename || `email-${gmailMessageId}.eml`;
  const result = await xeroAttachToSpendMoney(bankTransactionId, name, buffer, 'message/rfc822');
  res.json(result);
}));

// ──────────────────────────────────────────────────────────────────────────
// MCP tool definitions
// ──────────────────────────────────────────────────────────────────────────

const MCP_TOOLS = [
  {
    name: 'check_duplicate_invoice',
    description: 'Check if an invoice number already exists in Xero — searches BOTH purchase bills (ACCPAY) AND Spend Money bank transactions. Uses word-boundary matching on the Reference field, so "INV-1234" will not false-match "INV-12345". ALWAYS call this before creating a bill or Spend Money. Returns { existsAsBill, existsAsSpendMoney, bill, spendMoney, ... }.',
    inputSchema: { type: 'object', properties: { invoice_number: { type: 'string' } }, required: ['invoice_number'] },
  },
  {
    name: 'create_xero_bill',
    description: 'Create a purchase bill in Xero. Defaults to DRAFT status (per workflow doc). Pass status:"AUTHORISED" only if you really want to skip the review step. Only call after confirming no duplicate with check_duplicate_invoice. Sends an Idempotency-Key derived from supplier+invoice_number, so retries within 24h won\'t double-create.',
    inputSchema: {
      type: 'object',
      properties: {
        supplier_name: { type: 'string' },
        invoice_number: { type: 'string' },
        invoice_date: { type: 'string', description: 'YYYY-MM-DD' },
        due_date: { type: 'string', description: 'YYYY-MM-DD' },
        status: { type: 'string', description: 'DRAFT (default), SUBMITTED, or AUTHORISED' },
        line_items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              description: { type: 'string' },
              quantity: { type: 'number', default: 1 },
              unit_amount: { type: 'number', description: 'EX-GST amount' },
              account_code: { type: 'string', description: 'Coffee/milk=700, Food&Bev=701, General=429' },
              tax_type: { type: 'string', default: 'INPUT' },
            },
            required: ['description', 'unit_amount', 'account_code'],
          },
        },
      },
      required: ['supplier_name', 'invoice_number', 'invoice_date', 'line_items'],
    },
  },
  {
    name: 'update_xero_bill',
    description: 'Update fields on an existing purchase bill (ACCPAY): contact, dates, reference, status. Does NOT update line items. Returns a contactChangeWarning if Xero silently rejected a contact change (common on AUTHORISED bills). Pass reference:"" or reference:null to clear the field.',
    inputSchema: {
      type: 'object',
      properties: {
        invoice_id: { type: 'string', description: 'The Xero InvoiceID (UUID)' },
        supplier_name: { type: 'string' },
        invoice_date: { type: 'string', description: 'YYYY-MM-DD' },
        due_date: { type: 'string', description: 'YYYY-MM-DD' },
        reference: { type: ['string', 'null'], description: 'Set or clear (pass null or "")' },
        status: { type: 'string', description: 'DRAFT, SUBMITTED, AUTHORISED, DELETED' },
      },
      required: ['invoice_id'],
    },
  },
  {
    name: 'attach_receipt_to_bill',
    description: 'Attach a base64-encoded PDF/image to an existing Xero bill in a single call. Use ONLY for small receipts (under ~10KB base64). For larger files, use upload_receipt_chunk + attach_uploaded_receipt_to_bill instead.',
    inputSchema: {
      type: 'object',
      properties: {
        bill_id: { type: 'string' },
        filename: { type: 'string' },
        base64_content: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bill_id', 'filename', 'base64_content'],
    },
  },
  {
    name: 'get_open_bills',
    description: 'Get DRAFT/SUBMITTED/AUTHORISED bills from Xero for reconciliation matching.',
    inputSchema: { type: 'object', properties: { from_date: { type: 'string' }, to_date: { type: 'string' } } },
  },
  {
    name: 'search_spend_money',
    description: 'Search Spend Money (SPEND) bank transactions by any combination of reference, contact name, amount (±$0.01), date range, and bank account code. Use for legacy entries where the invoice number may not be in the Reference field. At least one filter required.',
    inputSchema: {
      type: 'object',
      properties: {
        reference: { type: 'string' },
        contact_name: { type: 'string' },
        amount: { type: 'number' },
        from_date: { type: 'string' },
        to_date: { type: 'string' },
        bank_account_code: { type: 'string' },
      },
    },
  },
  {
    name: 'create_spend_money',
    description: 'Create an AUTHORISED Spend Money transaction. Defaults to bank account 605 (Business Trans Acct). Sends an Idempotency-Key derived from payee+date+reference+total, so retries won\'t double-create.',
    inputSchema: {
      type: 'object',
      properties: {
        payee_name: { type: 'string', description: 'Auto-created as contact if missing.' },
        transaction_date: { type: 'string', description: 'YYYY-MM-DD' },
        reference: { type: 'string' },
        bank_account_code: { type: 'string', description: 'Default 605. Others: 602 Tyro, 603 Cash Float, 778 Petty Cash.', default: '605' },
        line_items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              description: { type: 'string' },
              quantity: { type: 'number', default: 1 },
              unit_amount: { type: 'number', description: 'EX-GST amount' },
              account_code: { type: 'string' },
              tax_type: { type: 'string', default: 'INPUT' },
            },
            required: ['description', 'unit_amount', 'account_code'],
          },
        },
      },
      required: ['payee_name', 'transaction_date', 'line_items'],
    },
  },
  {
    name: 'attach_receipt_to_spend_money',
    description: 'Attach a base64-encoded PDF/image to an existing Spend Money in a single call. Use ONLY for small receipts (under ~10KB base64). For larger files, use upload_receipt_chunk + attach_uploaded_receipt_to_spend_money instead.',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string' },
        filename: { type: 'string' },
        base64_content: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bank_transaction_id', 'filename', 'base64_content'],
    },
  },
  {
    name: 'upload_receipt_chunk',
    description: 'Upload one chunk of a base64-encoded receipt for later attachment. Use this when a receipt is too large for a single attach_receipt_to_* call (typically >10KB base64). Workflow: split the base64 into chunks (recommended ~6-8KB each, server max 200KB), call this for each chunk in order. First call: omit upload_id; server returns one. Subsequent calls: pass the same upload_id. Server decodes each chunk on receipt so corruption fails fast. After the final chunk, call attach_uploaded_receipt_to_bill or attach_uploaded_receipt_to_spend_money. Uploads expire 60 minutes after the first chunk.',
    inputSchema: {
      type: 'object',
      properties: {
        upload_id: { type: 'string', description: 'Omit on the first chunk to start a new upload. Pass on subsequent chunks.' },
        base64_chunk: { type: 'string', description: 'A contiguous slice of the base64-encoded file. Order matters — server concatenates chunks in call order.' },
      },
      required: ['base64_chunk'],
    },
  },
  {
    name: 'attach_uploaded_receipt_to_spend_money',
    description: 'Attach a previously-uploaded chunked receipt to a Spend Money. Pass the upload_id returned by upload_receipt_chunk. The upload buffer is consumed (deleted) on success. On Xero attach failure, the buffer is preserved so you can retry without re-uploading.',
    inputSchema: {
      type: 'object',
      properties: {
        upload_id: { type: 'string' },
        bank_transaction_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['upload_id', 'bank_transaction_id', 'filename'],
    },
  },
  {
    name: 'attach_uploaded_receipt_to_bill',
    description: 'Attach a previously-uploaded chunked receipt to a Bill. Same pattern as attach_uploaded_receipt_to_spend_money.',
    inputSchema: {
      type: 'object',
      properties: {
        upload_id: { type: 'string' },
        bill_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['upload_id', 'bill_id', 'filename'],
    },
  },
  {
    name: 'list_supplier_invoice_emails',
    description: 'List Gmail messages under a label, with attachment metadata. Designed for the daily sweep workflow. Label is case-sensitive (e.g. "Supplier Invoices" with capital I). Returns messageId + attachmentId for each attachment, plus a `failures` array if any individual messages failed to fetch.',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string' },
        max_results: { type: 'number', description: 'Default 50, max 500.' },
      },
      required: ['label'],
    },
  },
  {
    name: 'attach_gmail_pdf_to_bill',
    description: 'Server-side fetch a PDF from a Gmail message and attach to a Xero bill. No base64 over MCP. Use for Norkatu (PDF-source bills).',
    inputSchema: {
      type: 'object',
      properties: {
        bill_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        gmail_attachment_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bill_id', 'gmail_message_id', 'gmail_attachment_id', 'filename'],
    },
  },
  {
    name: 'attach_gmail_pdf_to_spend_money',
    description: 'Server-side fetch a PDF from a Gmail message and attach to a Spend Money. Use for Moco, Big Michael\'s, Carbar (PDF-source spend money).',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        gmail_attachment_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bank_transaction_id', 'gmail_message_id', 'gmail_attachment_id', 'filename'],
    },
  },
  {
    name: 'attach_gmail_email_to_bill',
    description: 'Attach the raw Gmail message as .eml to a Xero bill. Use for email-only invoices like Stel Coffee (MYOB PayDirect).',
    inputSchema: {
      type: 'object',
      properties: {
        bill_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        filename: { type: 'string' },
      },
      required: ['bill_id', 'gmail_message_id'],
    },
  },
  {
    name: 'attach_gmail_email_to_spend_money',
    description: 'Attach the raw Gmail message as .eml to a Spend Money. Use for CCA (email-body invoice, no PDF).',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        filename: { type: 'string' },
      },
      required: ['bank_transaction_id', 'gmail_message_id'],
    },
  },
  {
    name: 'extract_gmail_pdf_text',
    description: 'Fetch a Gmail PDF attachment server-side, extract text via pdf-parse. Returns warning if PDF appears image-only (OCR needed). Bytes never leave the Railway server. PDFs are size-capped server-side.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string' },
        attachment_id: { type: 'string' },
        max_chars: { type: 'number', description: 'Default 50000.' },
      },
      required: ['message_id', 'attachment_id'],
    },
  },
  {
    name: 'extract_gmail_email_body',
    description: 'Fetch a Gmail message and extract its body text. Returns BOTH plain and HTML-stripped representations. Use prefer="auto" (default) to let the server choose, "plain" for Stel-style invoices, "html" for CCA where the plain-text MIME drops table rows.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string' },
        max_chars: { type: 'number', description: 'Default 50000.' },
        prefer: { type: 'string', description: 'auto | plain | html. Default auto.', default: 'auto' },
      },
      required: ['message_id'],
    },
  },
  {
    name: 'create_bill_with_gmail_attachment',
    description: 'Atomic: create a bill AND attach its source from Gmail in one operation. If the attach step fails, the bill is automatically voided so you don\'t end up with an orphan unattached record. Set use_eml=true for email-body invoices (Stel); leave false for PDF attachments (Norkatu).',
    inputSchema: {
      type: 'object',
      properties: {
        bill: {
          type: 'object',
          description: 'Same shape as create_xero_bill input.',
        },
        gmail_message_id: { type: 'string' },
        gmail_attachment_id: { type: 'string', description: 'Required when use_eml is false.' },
        filename: { type: 'string' },
        mime_type: { type: 'string' },
        use_eml: { type: 'boolean', description: 'If true, attach raw .eml instead of a PDF attachment. Default false.' },
      },
      required: ['bill', 'gmail_message_id'],
    },
  },
  {
    name: 'create_spend_money_with_gmail_attachment',
    description: 'Atomic: create a Spend Money AND attach its Gmail source. Rolls back the Spend Money on attach failure. Set use_eml=true for CCA-style email-body invoices.',
    inputSchema: {
      type: 'object',
      properties: {
        spend: { type: 'object', description: 'Same shape as create_spend_money input.' },
        gmail_message_id: { type: 'string' },
        gmail_attachment_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string' },
        use_eml: { type: 'boolean', default: false },
      },
      required: ['spend', 'gmail_message_id'],
    },
  },
  {
    name: 'void_xero_bill',
    description: 'Void a Xero bill by setting its status to DELETED (if DRAFT/SUBMITTED) or VOIDED (if AUTHORISED). Use for cleanup if a create succeeded but the workflow needs to be reverted.',
    inputSchema: {
      type: 'object',
      properties: { invoice_id: { type: 'string' } },
      required: ['invoice_id'],
    },
  },
  {
    name: 'delete_spend_money',
    description: 'Delete a Spend Money by setting its status to DELETED. Use for cleanup.',
    inputSchema: {
      type: 'object',
      properties: { bank_transaction_id: { type: 'string' } },
      required: ['bank_transaction_id'],
    },
  },
];

// ──────────────────────────────────────────────────────────────────────────
// executeTool — dispatches MCP tool calls to handler functions DIRECTLY,
// without HTTP loopback to Express. The original code did localhost HTTP
// calls which added latency, opened sockets per call, and could fail on
// localhost DNS quirks.
// ──────────────────────────────────────────────────────────────────────────

async function executeTool(name, params) {
  switch (name) {
    case 'check_duplicate_invoice':
      return xeroCheckInvoice(params.invoice_number);

    case 'search_spend_money':
      return xeroSearchSpendMoney({
        reference: params.reference,
        contactName: params.contact_name,
        amount: params.amount,
        fromDate: params.from_date,
        toDate: params.to_date,
        bankAccountCode: params.bank_account_code,
      });

    case 'create_xero_bill':
      return xeroCreateBill({
        supplierName: params.supplier_name,
        invoiceNumber: params.invoice_number,
        invoiceDate: params.invoice_date,
        dueDate: params.due_date,
        status: params.status,
        lineItems: (params.line_items || []).map(li => ({
          description: li.description,
          quantity: li.quantity || 1,
          unitAmount: li.unit_amount,
          accountCode: li.account_code,
          taxType: li.tax_type || 'INPUT',
        })),
      });

    case 'update_xero_bill':
      return xeroUpdateBill({
        invoiceId: params.invoice_id,
        supplierName: params.supplier_name,
        invoiceDate: params.invoice_date,
        dueDate: params.due_date,
        reference: params.reference,
        status: params.status,
      });

    case 'get_open_bills':
      return xeroGetOpenBills({ fromDate: params.from_date, toDate: params.to_date });

    case 'create_spend_money':
      return xeroCreateSpendMoney({
        payeeName: params.payee_name,
        transactionDate: params.transaction_date,
        reference: params.reference,
        bankAccountCode: params.bank_account_code || '605',
        lineItems: (params.line_items || []).map(li => ({
          description: li.description,
          quantity: li.quantity || 1,
          unitAmount: li.unit_amount,
          accountCode: li.account_code,
          taxType: li.tax_type || 'INPUT',
        })),
      });

    case 'attach_receipt_to_bill': {
      if (!params.bill_id || !params.filename || !params.base64_content) {
        throw new Error('bill_id, filename, base64_content are required');
      }
      const buffer = Buffer.from(params.base64_content, 'base64');
      if (buffer.length > MAX_PDF_BYTES) throw new Error(`Buffer too large: ${buffer.length}`);
      return xeroAttachToInvoice(params.bill_id, params.filename, buffer, params.mime_type || 'application/pdf');
    }

    case 'attach_receipt_to_spend_money': {
      if (!params.bank_transaction_id || !params.filename || !params.base64_content) {
        throw new Error('bank_transaction_id, filename, base64_content are required');
      }
      const buffer = Buffer.from(params.base64_content, 'base64');
      if (buffer.length > MAX_PDF_BYTES) throw new Error(`Buffer too large: ${buffer.length}`);
      return xeroAttachToSpendMoney(params.bank_transaction_id, params.filename, buffer, params.mime_type || 'application/pdf');
    }

    case 'upload_receipt_chunk':
      return appendReceiptChunk(params.upload_id, params.base64_chunk);

    case 'attach_uploaded_receipt_to_spend_money':
      return attachUploadedReceiptToSpendMoney(
        params.upload_id,
        params.bank_transaction_id,
        params.filename,
        params.mime_type
      );

    case 'attach_uploaded_receipt_to_bill':
      return attachUploadedReceiptToBill(
        params.upload_id,
        params.bill_id,
        params.filename,
        params.mime_type
      );

    case 'list_supplier_invoice_emails':
      return gmailListByLabel({ label: params.label, maxResults: params.max_results });

    case 'attach_gmail_pdf_to_bill': {
      const buffer = await fetchGmailAttachment(params.gmail_message_id, params.gmail_attachment_id);
      return xeroAttachToInvoice(params.bill_id, params.filename, buffer, params.mime_type || 'application/pdf');
    }

    case 'attach_gmail_pdf_to_spend_money': {
      const buffer = await fetchGmailAttachment(params.gmail_message_id, params.gmail_attachment_id);
      return xeroAttachToSpendMoney(params.bank_transaction_id, params.filename, buffer, params.mime_type || 'application/pdf');
    }

    case 'attach_gmail_email_to_bill': {
      const buffer = await fetchGmailRawMessage(params.gmail_message_id);
      const name = params.filename || `email-${params.gmail_message_id}.eml`;
      return xeroAttachToInvoice(params.bill_id, name, buffer, 'message/rfc822');
    }

    case 'attach_gmail_email_to_spend_money': {
      const buffer = await fetchGmailRawMessage(params.gmail_message_id);
      const name = params.filename || `email-${params.gmail_message_id}.eml`;
      return xeroAttachToSpendMoney(params.bank_transaction_id, name, buffer, 'message/rfc822');
    }

    case 'extract_gmail_pdf_text':
      return extractPdfTextFromGmail({
        messageId: params.message_id,
        attachmentId: params.attachment_id,
        maxChars: params.max_chars,
      });

    case 'extract_gmail_email_body':
      return extractEmailBodyFromGmail({
        messageId: params.message_id,
        maxChars: params.max_chars,
        prefer: params.prefer,
      });

    case 'create_bill_with_gmail_attachment':
      return createBillWithGmailAttachment({
        bill: {
          supplierName: params.bill?.supplier_name,
          invoiceNumber: params.bill?.invoice_number,
          invoiceDate: params.bill?.invoice_date,
          dueDate: params.bill?.due_date,
          status: params.bill?.status,
          lineItems: (params.bill?.line_items || []).map(li => ({
            description: li.description,
            quantity: li.quantity || 1,
            unitAmount: li.unit_amount,
            accountCode: li.account_code,
            taxType: li.tax_type || 'INPUT',
          })),
        },
        gmailMessageId: params.gmail_message_id,
        gmailAttachmentId: params.gmail_attachment_id,
        filename: params.filename,
        mimeType: params.mime_type,
        useEml: !!params.use_eml,
      });

    case 'create_spend_money_with_gmail_attachment':
      return createSpendMoneyWithGmailAttachment({
        spend: {
          payeeName: params.spend?.payee_name,
          transactionDate: params.spend?.transaction_date,
          reference: params.spend?.reference,
          bankAccountCode: params.spend?.bank_account_code || '605',
          lineItems: (params.spend?.line_items || []).map(li => ({
            description: li.description,
            quantity: li.quantity || 1,
            unitAmount: li.unit_amount,
            accountCode: li.account_code,
            taxType: li.tax_type || 'INPUT',
          })),
        },
        gmailMessageId: params.gmail_message_id,
        gmailAttachmentId: params.gmail_attachment_id,
        filename: params.filename,
        mimeType: params.mime_type,
        useEml: !!params.use_eml,
      });

    case 'void_xero_bill':
      return xeroVoidBill(params.invoice_id);

    case 'delete_spend_money':
      return xeroDeleteSpendMoney(params.bank_transaction_id);

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// MCP transport: SSE + JSON-RPC over POST
// ──────────────────────────────────────────────────────────────────────────

const mcpSessions = new Map(); // sessionId -> { res, lastActivity }

function sendToSession(sessionId, data) {
  const session = mcpSessions.get(sessionId);
  if (session && session.res && !session.res.writableEnded) {
    session.res.write(`data: ${JSON.stringify(data)}\n\n`);
    session.lastActivity = Date.now();
  }
}

// Periodic sweep of stale sessions. Without this, sessions where the 'close'
// event never fires (e.g. abrupt network drops) would accumulate forever.
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of mcpSessions.entries()) {
    if (s.res.writableEnded || now - s.lastActivity > 10 * 60_000) {
      try { s.res.end(); } catch (e) { /* ignore */ }
      mcpSessions.delete(sid);
      console.log(`MCP session swept: ${sid}`);
    }
  }
}, 60_000).unref();

app.get('/sse', requireBearerOrQuery, (req, res) => {
  const sessionId = randomUUID();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // CORS deliberately not set here — the bearer check above is the gate.
  res.flushHeaders();
  mcpSessions.set(sessionId, { res, lastActivity: Date.now() });
  console.log(`MCP session opened: ${sessionId}`);
  // Endpoint URI includes the session ID; the auth happens on /messages too.
  // Forward the same auth (header or ?auth=) into the /messages endpoint
  // path. Claude POSTs tool calls to whatever URL we emit here, and we still
  // require auth on /messages — so it has to be in the URL.
  const auth = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  const authParam = auth ? auth[1].trim() : (typeof req.query.auth === 'string' ? req.query.auth : '');
  const messagesPath = `/messages?sessionId=${sessionId}` + (authParam ? `&auth=${encodeURIComponent(authParam)}` : '');
  res.write(`event: endpoint\ndata: ${messagesPath}\n\n`);
  const ping = setInterval(() => {
    if (!res.writableEnded) res.write(': ping\n\n');
    else clearInterval(ping);
  }, 30_000);
  req.on('close', () => {
    mcpSessions.delete(sessionId);
    clearInterval(ping);
    console.log(`MCP session closed: ${sessionId}`);
  });
});

app.post('/messages', requireBearerOrQuery, async (req, res) => {
  const { sessionId } = req.query;
  const message = req.body;
  // Accept the message immediately; respond async over SSE.
  res.status(202).json({ status: 'accepted' });
  try {
    const { method, id, params } = message || {};
    if (method === 'initialize') {
      sendToSession(sessionId, {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mana-coffee-xero', version: '2.1.0' },
        },
      });
    } else if (method === 'notifications/initialized') {
      // JSON-RPC notification — no response by spec.
      return;
    } else if (method === 'tools/list') {
      sendToSession(sessionId, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    } else if (method === 'tools/call') {
      const { name, arguments: args } = params || {};
      console.log(`MCP tool call: ${name}`);
      try {
        const result = await executeTool(name, args || {});
        sendToSession(sessionId, {
          jsonrpc: '2.0', id,
          result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] },
        });
      } catch (toolErr) {
        logError(`MCP TOOL ${name}`, toolErr);
        sendToSession(sessionId, {
          jsonrpc: '2.0', id,
          error: {
            code: -32603,
            message: toolErr.response?.data?.Message
              || toolErr.response?.data?.error?.message
              || toolErr.message,
            data: toolErr.response?.data,
          },
        });
      }
    } else {
      sendToSession(sessionId, {
        jsonrpc: '2.0', id,
        error: { code: -32601, message: `Method not found: ${method}` },
      });
    }
  } catch (err) {
    sendToSession(sessionId, {
      jsonrpc: '2.0', id: req.body?.id,
      error: { code: -32603, message: err.message },
    });
  }
});

app.options('/messages', (req, res) => res.sendStatus(204));

// ──────────────────────────────────────────────────────────────────────────
// Catch-all: serve the SPA only for non-API paths. Original code used a
// bare app.get('*') which served index.html for typo'd /api/* paths,
// causing axios HTML-as-JSON parse errors instead of clean 404s.
// ──────────────────────────────────────────────────────────────────────────

app.use('/api', (req, res) => res.status(404).json({ error: `Unknown route: ${req.method} ${req.path}` }));

// Express 5 requires named wildcard params; '*splat' captures any remaining path.
// Express 4 also accepts this. We use a regex to be transport-agnostic.
app.get(/.*/, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ──────────────────────────────────────────────────────────────────────────
// Global error handler (last middleware)
// ──────────────────────────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (res.headersSent) return; // can't write twice
  logError(`UNHANDLED ${req.method} ${req.path}`, err);
  const status = err.status || err.response?.status || 500;
  res.status(status).json({
    error: err.response?.data?.Message
      || err.response?.data?.error?.message
      || err.message,
    ...(err.response?.data && { xeroResponse: err.response.data }),
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Process-level safety nets
// ──────────────────────────────────────────────────────────────────────────

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  // Don't exit — Railway will restart anyway, and an in-flight tool call
  // failing is preferable to losing all sessions.
});

app.listen(PORT, () => {
  console.log(`Mana Coffee server v2.1 listening on port ${PORT}`);
  console.log(`Public base URL: ${PUBLIC_BASE_URL}`);
  console.log(`Token store: ${TOKEN_STORE_PATH}${fs.existsSync(TOKEN_STORE_PATH) ? ' (loaded)' : ' (not present — relying on env vars)'}`);
  console.log(`MCP shared secret configured: ${MCP_SHARED_SECRET.length} chars`);
  console.log(`Upload limits: ${MAX_UPLOAD_CHUNK_CHARS} chars/chunk, ${MAX_UPLOAD_CHUNKS} chunks max, ${MAX_PDF_BYTES} bytes total, ${Math.round(UPLOAD_TTL_MS / 60000)} min TTL`);
  console.log(`CORS allowlist: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : '(none — same-origin only)'}`);
});
