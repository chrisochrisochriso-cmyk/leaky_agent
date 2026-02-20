// leaky_agent — Cloudflare Worker
// Endpoints:
//   GET /canary             → unique SCAN-{hex8} token, logs the visit to KV
//   GET /beacon?canary=&trap=&category=&severity=&agent=
//                           → zero-auth passive beacon logger
//   GET /stats              → aggregate of last 200 KV events (JSON)
//
// KV binding name: KV  (set in wrangler.toml)
// Deploy: cd workers && wrangler deploy

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Content-Type': 'application/json',
};

export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/canary') return handleCanary(request, env);
      if (path === '/beacon') return handleBeacon(request, env, url);
      if (path === '/stats')  return handleStats(env);
      return json({ error: 'not found' }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};

// ── /canary ──────────────────────────────────────────────────────────────────
// Generates a unique SCAN-{hex8} token and logs the page visit.
// Called by tracker.js on page load so every visit is counted even for
// browser agents that never click a button or trigger a trap.
async function handleCanary(request, env) {
  const canary = 'SCAN-' + randomHex(8);
  const ua = request.headers.get('User-Agent') || '';

  await appendEvent(env.KV, {
    type:     'canary_request',
    canary,
    trap:     'page_visit',
    category: 'visit',
    severity: 'info',
    agent:    identifyAgent(ua),
    ts:       new Date().toISOString(),
    referrer: request.headers.get('Referer') || 'direct',
  });

  return json({ canary });
}

// ── /beacon ───────────────────────────────────────────────────────────────────
// Zero-auth passive trap trigger. Any agent that can make an HTTP GET request
// can fire this. No credentials or curl required — works even for WebFetch-only
// agents that cannot execute JavaScript.
async function handleBeacon(request, env, url) {
  const p  = url.searchParams;
  const ua = request.headers.get('User-Agent') || '';

  await appendEvent(env.KV, {
    type:     'beacon',
    canary:   p.get('canary')   || 'BEACON-UNKNOWN',
    trap:     p.get('trap')     || 'passive_beacon',
    category: p.get('category') || 'injection',
    severity: p.get('severity') || 'critical',
    agent:    p.get('agent')    || identifyAgent(ua),
    ts:       new Date().toISOString(),
    referrer: request.headers.get('Referer') || 'direct',
  });

  return json({ ok: true });
}

// ── /stats ────────────────────────────────────────────────────────────────────
// Returns aggregate counts from the recent_log (last 200 events).
// Used by stats.html for the category/source breakdown panels.
async function handleStats(env) {
  const raw    = await env.KV.get('recent_log');
  const events = raw ? JSON.parse(raw) : [];

  const by_category = {};
  const by_trap     = {};
  const by_agent    = {};
  const by_source   = {};

  for (const e of events) {
    inc(by_category, e.category || 'unknown');
    inc(by_trap,     e.trap     || 'unknown');
    inc(by_agent,    e.agent    || 'Unknown');
    inc(by_source,   e.type     || 'unknown');
  }

  return json({
    total: events.length,
    by_category,
    by_trap,
    by_agent,
    by_source,
    recent: events.slice(-20).reverse(),
  });
}

// ── Storage ───────────────────────────────────────────────────────────────────
async function appendEvent(kv, event) {
  // Durable per-event key (TTL 90 days)
  await kv.put(
    `evt:${Date.now()}:${randomHex(4).toLowerCase()}`,
    JSON.stringify(event),
    { expirationTtl: 7776000 },
  );

  // Rolling recent log — last 200 events, used by /stats.
  // Best-effort: concurrent writes may occasionally drop an event.
  try {
    const raw = await kv.get('recent_log');
    const log = raw ? JSON.parse(raw) : [];
    log.push(event);
    if (log.length > 200) log.splice(0, log.length - 200);
    await kv.put('recent_log', JSON.stringify(log));
  } catch (_) {}
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function randomHex(n) {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').slice(0, n).toUpperCase();
}

function identifyAgent(ua) {
  if (/claude/i.test(ua))           return 'Claude';
  if (/gpt-4|openai/i.test(ua))     return 'GPT-4';
  if (/gemini/i.test(ua))           return 'Gemini';
  if (/llama/i.test(ua))            return 'LLaMA';
  if (/copilot/i.test(ua))          return 'Copilot';
  if (/agent|bot|spider/i.test(ua)) return 'Generic Agent/Bot';
  return 'Unknown';
}

function inc(obj, key) {
  obj[key] = (obj[key] || 0) + 1;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS_HEADERS });
}
