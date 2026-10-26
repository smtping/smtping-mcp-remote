// SMTPing remote MCP server (Streamable HTTP, stateless) with OAuth 2.1 + PKCE.
// Tokens, codes and client ids are AES-GCM sealed with TOKEN_SECRET: no database needed.
import { Smtping } from '@smtping/sdk';

const VERSION = '1.0.0';
const MAX_ROWS = 1000;
const WAIT_MS = 7000; // Netlify synchronous functions stop at 10 s.
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const ACCESS_TTL = 7 * 24 * 3600;
const REFRESH_TTL = 365 * 24 * 3600;
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, X-API-Key',
  'Access-Control-Expose-Headers': 'WWW-Authenticate, Mcp-Session-Id',
};

// ── Sealed tokens ──
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const now = () => Math.floor(Date.now() / 1000);
let keyP;
function key() {
  if (!keyP) {
    const s = process.env.TOKEN_SECRET || '';
    if (s.length < 32) throw new Error('TOKEN_SECRET is missing or shorter than 32 characters.');
    keyP = crypto.subtle.digest('SHA-256', enc.encode(s)).then((d) => crypto.subtle.importKey('raw', d, 'AES-GCM', false, ['encrypt', 'decrypt']));
  }
  return keyP;
}
async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(), enc.encode(JSON.stringify(obj)));
  return b64u(iv) + '.' + b64u(ct);
}
async function unseal(tok, type) {
  try {
    const [iv, ct] = String(tok || '').split('.');
    const o = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv) }, await key(), unb64u(ct))));
    if (o.t !== type || (o.exp && o.exp < now())) return null;
    return o;
  } catch { return null; }
}
const sha256 = async (s) => b64u(await crypto.subtle.digest('SHA-256', enc.encode(s)));

// ── HTTP helpers ──
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS, ...extra } });
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function form(req) {
  const t = req.headers.get('content-type') || '';
  if (t.includes('application/json')) return await req.json().catch(() => ({}));
  return Object.fromEntries(new URLSearchParams(await req.text()));
}

// ── OAuth metadata ──
const prm = (base) => ({
  resource: base + '/mcp',
  authorization_servers: [base],
  bearer_methods_supported: ['header'],
  resource_name: 'SMTPing Email Verification',
  logo_uri: base + '/icon-512.png',
  resource_documentation: 'https://smtping.com/docs',
});
const asm = (base) => ({
  issuer: base,
  logo_uri: base + '/icon-512.png',
  authorization_endpoint: base + '/authorize',
  token_endpoint: base + '/token',
  registration_endpoint: base + '/register',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
  scopes_supported: ['verify'],
  service_documentation: 'https://smtping.com/docs',
});

const okRedirect = (u) => { try { const x = new URL(u); return x.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname) || !['http:', 'javascript:', 'data:', 'file:'].includes(x.protocol); } catch { return false; } };

async function register(req) {
  if (req.method !== 'POST') return json({ error: 'invalid_request' }, 405);
  const b = await form(req);
  const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String) : [];
  if (!uris.length || !uris.every(okRedirect)) return json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https (or localhost) URLs.' }, 400);
  const name = String(b.client_name || 'MCP client').slice(0, 80);
  const client_id = await seal({ t: 'c', r: uris, n: name });
  return json({
    client_id, client_id_issued_at: now(), client_name: name, redirect_uris: uris,
    token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
  }, 201);
}

// ── Consent page ──
function page(title, body, status = 200) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} | SMTPing</title>
<style>body{margin:0;background:#f4f6f8;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#0f172a}.box{max-width:480px;margin:8vh auto;background:#fff;border-radius:14px;padding:36px;box-shadow:0 2px 16px rgba(15,23,42,.08)}.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:20px;margin-bottom:24px}.brand img{height:28px}h1{font-size:22px;line-height:1.3;margin:0 0 8px}p{color:#475569;margin:0 0 16px}ul{color:#475569;padding-left:20px;margin:0 0 20px}label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}input[type=password]{display:block;width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px}.hint{font-size:13px;margin:8px 0 20px}a{color:#089dff}.row{display:flex;gap:10px}button{flex:1;border:0;border-radius:8px;padding:12px 18px;font-size:15px;font-weight:600;cursor:pointer;background:#089dff;color:#fff}button.alt{background:#fff;color:#334155;border:1px solid #cbd5e1}.err{background:#fef2f2;color:#991b1b;padding:10px 14px;border-radius:8px;margin:0 0 16px}.note{font-size:13px;color:#64748b;margin:20px 0 0}@media(max-width:560px){.box{margin:0;border-radius:0;min-height:100vh;box-sizing:border-box;padding:28px 20px}}</style></head>
<body><div class="box"><div class="brand"><img src="https://smtping.com/smtping-logo.png" alt="">SMTPing</div>${body}</div></body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "frame-ancestors 'none'" } });
}
const errorPage = (msg) => page('Error', `<h1>This connection request is not valid</h1><p>${esc(msg)}</p><p>Start again from your AI app.</p>`, 400);

function consent(p, client, error = '') {
  const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'resource']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(p[k])}">`).join('');
  return page('Connect', `<h1>Connect ${esc(client.n)} to SMTPing</h1>
<p>${esc(client.n)} will be able to:</p>
<ul><li>verify email addresses and lists with your credits</li><li>check spamtrap, disposable, spambot and complainer lists</li><li>read your credit balance</li></ul>
${error ? `<div class="err">${esc(error)}</div>` : ''}
<form method="post">${hidden}
<label for="k">Your SMTPing API key</label>
<input id="k" type="password" name="api_key" autocomplete="off" required autofocus>
<p class="hint">Find it in <a href="https://app.smtping.com" target="_blank" rel="noopener">app.smtping.com</a>, under API keys. No account yet? <a href="https://app.smtping.com/register" target="_blank" rel="noopener">Create one free</a> (25 free credits per day).</p>
<div class="row"><button type="submit" name="decision" value="deny" class="alt" formnovalidate>Cancel</button><button type="submit" name="decision" value="allow">Connect</button></div></form>
<p class="note">Your key is encrypted inside the access token and never stored by this server. To disconnect, remove the connector in your AI app or rotate the key in SMTPing.</p>`);
}

function back(redirect_uri, params) {
  const u = new URL(redirect_uri);
  for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
  return new Response(null, { status: 302, headers: { Location: u.toString(), 'Cache-Control': 'no-store' } });
}

async function authorize(req, url) {
  const p = req.method === 'POST' ? await form(req) : Object.fromEntries(url.searchParams);
  const client = await unseal(p.client_id, 'c');
  if (!client) return errorPage('Unknown client. Remove the connector and add it again.');
  if (!p.redirect_uri || !client.r.includes(p.redirect_uri)) return errorPage('The redirect address does not match this client.');
  if (req.method === 'GET' && p.response_type !== 'code') return back(p.redirect_uri, { error: 'unsupported_response_type', state: p.state });
  if (!p.code_challenge || (p.code_challenge_method || 'plain') !== 'S256') return back(p.redirect_uri, { error: 'invalid_request', error_description: 'PKCE S256 is required', state: p.state });
  if (req.method === 'GET') return consent(p, client);

  if (p.decision !== 'allow') return back(p.redirect_uri, { error: 'access_denied', state: p.state });
  const k = String(p.api_key || '').trim();
  if (!k) return consent(p, client, 'Paste your API key.');
  try {
    await new Smtping({ apiKey: k, userAgent: `smtping-mcp-remote/${VERSION}`, maxRetries: 0, timeout: 8000 }).credits();
  } catch (e) {
    return consent(p, client, e.status === 401 || e.status === 403 ? 'This API key is not valid.' : 'SMTPing could not be reached. Try again in a moment.');
  }
  const code = await seal({ t: 'code', k, c: await sha256(p.client_id), r: p.redirect_uri, ch: p.code_challenge, exp: now() + 300 });
  return back(p.redirect_uri, { code, state: p.state });
}

async function issue(k) {
  return json({
    access_token: await seal({ t: 'a', k, exp: now() + ACCESS_TTL }),
    token_type: 'Bearer',
    expires_in: ACCESS_TTL,
    refresh_token: await seal({ t: 'r', k, exp: now() + REFRESH_TTL }),
    scope: 'verify',
  });
}

async function token(req) {
  if (req.method !== 'POST') return json({ error: 'invalid_request' }, 405);
  const b = await form(req);
  if (b.grant_type === 'authorization_code') {
    const c = await unseal(b.code, 'code');
    if (!c) return json({ error: 'invalid_grant', error_description: 'Code expired or invalid.' }, 400);
    if (c.r !== b.redirect_uri || c.c !== await sha256(b.client_id || '')) return json({ error: 'invalid_grant', error_description: 'Client or redirect_uri mismatch.' }, 400);
    if (!b.code_verifier || await sha256(b.code_verifier) !== c.ch) return json({ error: 'invalid_grant', error_description: 'PKCE verification failed.' }, 400);
    return issue(c.k);
  }
  if (b.grant_type === 'refresh_token') {
    const r = await unseal(b.refresh_token, 'r');
    if (!r) return json({ error: 'invalid_grant' }, 400);
    return issue(r.k);
  }
  return json({ error: 'unsupported_grant_type' }, 400);
}

// ── MCP tools ──
const ro = { readOnlyHint: true, openWorldHint: true };
const TOOLS = [
  { name: 'verify_email', title: 'Verify an email address', annotations: ro,
    description: 'Verifies one email address with SMTPing. Returns a status (valid, invalid, catch_all, spamtrap, disposable, etc.) and a band: safe (send), avoid (remove) or judgement (your call). Costs 1 credit.',
    inputSchema: { type: 'object', properties: { email: { type: 'string', description: 'The email address to verify' } }, required: ['email'] } },
  { name: 'verify_list', title: 'Verify a list of email addresses', annotations: { readOnlyHint: false, openWorldHint: true },
    description: 'Verifies a list of addresses as one SMTPing bulk job (deduplicated, up to 100,000). Lists of 10 or fewer return results directly. Larger lists return a job_id: call get_bulk_job with it until the job has succeeded. Costs 1 credit per unique address.',
    inputSchema: { type: 'object', properties: { emails: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'Email addresses to verify' } }, required: ['emails'] } },
  { name: 'get_bulk_job', title: 'Get a bulk job', annotations: ro,
    description: 'Returns the progress of a SMTPing bulk job, and its results once it has succeeded.',
    inputSchema: { type: 'object', properties: { job_id: { type: 'string', description: 'The job_id returned by verify_list' } }, required: ['job_id'] } },
  { name: 'check_threat', title: 'Check a threat list', annotations: ro,
    description: 'Looks up one address in a single SMTPing threat list: spamtrap, disposable, spambot or complainer.',
    inputSchema: { type: 'object', properties: { list: { type: 'string', enum: ['spamtrap', 'disposable', 'spambot', 'complainer'], description: 'Which list to check' }, email: { type: 'string', description: 'The email address to check' } }, required: ['list', 'email'] } },
  { name: 'get_credits', title: 'Get remaining credits', annotations: ro,
    description: 'Returns the remaining SMTPing credit balance and plan. Free.',
    inputSchema: { type: 'object', properties: {} } },
];

function summarize(rows) {
  const bands = { safe: 0, avoid: 0, judgement: 0 };
  const statuses = {};
  for (const r of rows) {
    if (bands[r.band] != null) bands[r.band]++;
    statuses[r.status] = (statuses[r.status] || 0) + 1;
  }
  return {
    total: rows.length, bands, statuses,
    results: rows.slice(0, MAX_ROWS).map((r) => ({ email: r.email, status: r.status, band: r.band })),
    ...(rows.length > MAX_ROWS ? { note: `Only the first ${MAX_ROWS} rows are shown. Export the full CSV from the SMTPing dashboard.` } : {}),
  };
}

async function run(name, a, k) {
  const s = new Smtping({ apiKey: k, userAgent: `smtping-mcp-remote/${VERSION}`, timeout: 8500, maxRetries: 1 });
  const need = (v, n) => { if (v === undefined || v === null || v === '') throw Object.assign(new Error(`Missing argument: ${n}`), { rpc: -32602 }); };
  switch (name) {
    case 'verify_email': need(a.email, 'email'); return s.verify(String(a.email));
    case 'check_threat': need(a.list, 'list'); need(a.email, 'email'); return s.check(String(a.list), String(a.email));
    case 'get_credits': return s.credits();
    case 'get_bulk_job': {
      need(a.job_id, 'job_id');
      const st = await s.bulk.get(String(a.job_id));
      if (st.status !== 'Succeeded') return st;
      return { job_id: a.job_id, status: st.status, ...summarize(await s.bulk.results(String(a.job_id))) };
    }
    case 'verify_list': {
      const emails = Array.isArray(a.emails) ? a.emails.map(String) : [];
      if (!emails.length) throw Object.assign(new Error('emails must be a non-empty array'), { rpc: -32602 });
      if (emails.length <= 10) return summarize(await s.verifyMany(emails));
      const job = await s.bulk.create(emails);
      try {
        return { job_id: job.jobId, ...summarize(await s.bulk.wait(job.jobId, { timeout: WAIT_MS - 1500, interval: 1500 })) };
      } catch (e) {
        if (e.name !== 'TimeoutError') throw e;
        return { job_id: job.jobId, status: 'Processing', total: job.totalEmails, next: 'Still running. Call get_bulk_job with this job_id in about a minute.' };
      }
    }
  }
  throw Object.assign(new Error(`Unknown tool: ${name}`), { rpc: -32602 });
}

async function handle(m, k, base) {
  const ok = (result) => ({ jsonrpc: '2.0', id: m.id, result });
  const err = (code, message) => ({ jsonrpc: '2.0', id: m.id ?? null, error: { code, message } });
  if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return m && m.id === undefined ? null : err(-32600, 'Invalid request');
  if (m.id === undefined) return null; // notification
  switch (m.method) {
    case 'initialize': {
      const v = m.params?.protocolVersion;
      return ok({
        protocolVersion: PROTOCOLS.includes(v) ? v : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'smtping', title: 'SMTPing Email Verification', version: VERSION, websiteUrl: 'https://smtping.com', icons: [{ src: base + '/icon-512.png', mimeType: 'image/png', sizes: ['512x512'] }, { src: base + '/icon-192.png', mimeType: 'image/png', sizes: ['192x192'] }] },
        instructions: 'SMTPing verifies email addresses before you send. Use verify_email for one address and verify_list for several. Results come in three bands: safe (send), avoid (remove) and judgement (your call). Unknown results are never charged.',
      });
    }
    case 'ping': return ok({});
    case 'tools/list': return ok({ tools: TOOLS });
    case 'tools/call': {
      const name = m.params?.name;
      if (!TOOLS.some((t) => t.name === name)) return err(-32602, `Unknown tool: ${name}`);
      try {
        const data = await run(name, m.params?.arguments || {}, k);
        return ok({ content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] });
      } catch (e) {
        if (e.rpc) return err(e.rpc, e.message);
        return ok({ isError: true, content: [{ type: 'text', text: `SMTPing error${e.status ? ` (HTTP ${e.status})` : ''}: ${e.message}` }] });
      }
    }
    case 'resources/list': return ok({ resources: [] });
    case 'prompts/list': return ok({ prompts: [] });
  }
  return err(-32601, `Method not found: ${m.method}`);
}

async function mcp(req, base) {
  const challenge = { 'WWW-Authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"` };
  const h = req.headers.get('authorization') || '';
  let k = '';
  if (/^bearer /i.test(h)) k = (await unseal(h.slice(7).trim(), 'a'))?.k || '';
  if (!k && req.headers.get('x-api-key')) k = req.headers.get('x-api-key').trim();
  if (!k) return json({ error: 'invalid_token', error_description: 'Connect with OAuth or send your SMTPing API key in X-API-Key.' }, 401, challenge);
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { Allow: 'POST' });
  let body;
  try { body = await req.json(); } catch { return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400); }
  const batch = Array.isArray(body);
  const out = (await Promise.all((batch ? body : [body]).map((m) => handle(m, k, base)))).filter(Boolean);
  if (!out.length) return new Response(null, { status: 202, headers: CORS });
  return json(batch ? out : out[0]);
}

export default async (req) => {
  const url = new URL(req.url);
  const base = (process.env.PUBLIC_URL || url.origin).replace(/\/+$/, '');
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  try {
    switch (url.pathname.replace(/\/+$/, '') || '/') {
      case '/.well-known/oauth-protected-resource':
      case '/.well-known/oauth-protected-resource/mcp': return json(prm(base));
      case '/.well-known/oauth-authorization-server':
      case '/.well-known/oauth-authorization-server/mcp':
      case '/.well-known/openid-configuration': return json(asm(base));
      case '/register': return await register(req);
      case '/authorize': return await authorize(req, url);
      case '/token': return await token(req);
      case '/mcp': return await mcp(req, base);
    }
    return json({ error: 'not_found' }, 404);
  } catch (e) {
    return json({ error: 'server_error', error_description: e.message }, 500);
  }
};

export const config = {
  path: [
    '/mcp', '/authorize', '/token', '/register',
    '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp',
    '/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp',
    '/.well-known/openid-configuration',
  ],
};
