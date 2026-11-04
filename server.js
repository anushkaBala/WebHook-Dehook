const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const Database = require('better-sqlite3');

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 2000;
const SENSITIVE_KEY = /(?:email|phone|mobile|contact|customer_name|first_name|last_name|address)/i;
const SECRET_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)$/i;

function initDatabase(db) {
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, event_id TEXT,
      event_type TEXT, verified INTEGER NOT NULL, duplicate INTEGER NOT NULL,
      signature TEXT, headers TEXT NOT NULL, raw_body BLOB NOT NULL, payment_id TEXT
    );
    CREATE INDEX IF NOT EXISTS events_event_id_idx ON events(event_id);
    CREATE INDEX IF NOT EXISTS events_received_at_idx ON events(received_at DESC);
    CREATE INDEX IF NOT EXISTS events_payment_id_idx ON events(payment_id);
  `);
}

function verifySignature(rawBody, suppliedSignature, secrets) {
  if (!Buffer.isBuffer(rawBody) || typeof suppliedSignature !== 'string' || !/^[a-f\d]{64}$/i.test(suppliedSignature)) return false;
  const received = Buffer.from(suppliedSignature, 'hex');
  let verified = false;
  for (const secret of secrets) {
    if (!secret) continue;
    const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
    const matches = received.length === expected.length && crypto.timingSafeEqual(received, expected);
    verified = matches || verified;
  }
  return verified;
}

function getPaymentId(payload) {
  return payload?.payload?.payment?.entity?.id ?? payload?.payment?.entity?.id ?? null;
}

function maskString(value) {
  return value
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/(?<!\d)(?:\+?\d[\d ()-]{7,}\d)(?!\d)/g, '[REDACTED_PHONE]');
}

function redact(value, key = '') {
  if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'string') return maskString(value);
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redact(child, childKey)]));
  }
  return value;
}

function safeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, SECRET_HEADER.test(key) ? '[REDACTED]' : redact(value, key)]));
}

function diagnose({ row, db }) {
  const items = [];
  if (!row.verified) items.push({
    code: 'signature', title: 'Signature verification failed',
    technical: 'The X-Razorpay-Signature did not match an HMAC-SHA256 computed over the stored raw request bytes with the configured webhook secrets.',
    merchant: 'We could not confirm that this request came from Razorpay. Your server should check the webhook signature before acting on the payment.',
    fix: 'Verify the exact raw body before JSON parsing. Confirm the webhook secret for this endpoint and mode; it is different from the API key secret.'
  });
  if (row.duplicate) items.push({
    code: 'duplicate', title: 'Duplicate event ID',
    technical: 'This x-razorpay-event-id has already been received by this debugger.',
    merchant: 'Razorpay can retry a notification. Your order should not be fulfilled twice when the same notification arrives again.',
    fix: 'Record processed event IDs and make the payment update idempotent. Return 2xx for a safely handled retry.'
  });
  if (row.event_type === 'payment.captured' && row.payment_id) {
    const earlier = db.prepare("SELECT 1 FROM events WHERE payment_id = ? AND event_type = 'payment.authorized' AND id < ? LIMIT 1").get(row.payment_id, row.id);
    if (!earlier) items.push({
      code: 'out_of_order', title: 'Authorization event not seen earlier',
      technical: 'No earlier payment.authorized delivery for this payment ID is present in this debugger. This is a candidate ordering gap, not proof that Razorpay omitted it.',
      merchant: 'A payment update arrived before its earlier status update, or that earlier update was not recorded here. Check the current payment state before changing the order.',
      fix: 'Handle payment events as state transitions, tolerate delayed/retried events, and reconcile uncertain state with the payment API.'
    });
  }
  let payload;
  try { payload = JSON.parse(Buffer.from(row.raw_body).toString('utf8')); } catch { payload = null; }
  const amount = payload?.payload?.payment?.entity?.amount;
  if (Number.isInteger(amount) && amount >= 100) items.push({
    code: 'amount_units', title: 'Check the currency unit',
    technical: `The payload amount is ${amount}; Razorpay represents payment amounts in the smallest currency unit.`,
    merchant: `The amount shown is in the smallest currency unit, not whole rupees. For INR, ${amount} paise is ₹${(amount / 100).toFixed(2)}.`,
    fix: 'Use the payload currency and convert from its smallest unit for display; do not assume every currency uses two decimal places.'
  });
  if (!items.length) items.push({
    code: 'ok', title: 'No known issue detected',
    technical: 'No signature failure, duplicate, or known payment-order issue was detected by the available rules.',
    merchant: 'This delivery passed the checks available in this debugger. Confirm your application also updated the order correctly.',
    fix: 'If the order state is still unexpected, inspect the related payment timeline and reconcile the payment with the provider API.'
  });
  return items;
}

function isLoopbackHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '::1';
}

function constantTimeTextEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function parseHttpUrl(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  return ['http:', 'https:'].includes(url.protocol) ? url : null;
}

function createApp({ db, secrets = [], allowRemoteReplay = false, dashboardPassword = process.env.DASHBOARD_PASSWORD || '' } = {}) {
  const database = db || new Database(':memory:');
  initDatabase(database);
  const webhookSecrets = Array.isArray(secrets) ? secrets.filter(Boolean) : [];
  const app = express();
  let simulatorMode = 'normal';
  let simulatorDelayMs = 3000;

  // Razorpay signs the exact bytes. This route intentionally precedes every JSON parser.
  app.post('/webhooks/razorpay', express.raw({ type: '*/*', limit: MAX_BODY_BYTES }), (req, res) => {
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const signature = req.get('x-razorpay-signature') || '';
    const eventId = req.get('x-razorpay-event-id') || null;
    const verified = verifySignature(rawBody, signature, webhookSecrets);
    let payload = null;
    try { payload = JSON.parse(rawBody.toString('utf8')); } catch { /* malformed bodies remain inspectable */ }
    const eventType = (typeof payload?.event === 'string' ? payload.event : req.get('x-razorpay-event')) || null;
    const paymentId = getPaymentId(payload);
    const duplicate = Boolean(eventId && database.prepare('SELECT 1 FROM events WHERE event_id = ? LIMIT 1').get(eventId));
    const result = database.prepare(`INSERT INTO events
      (received_at, event_id, event_type, verified, duplicate, signature, headers, raw_body, payment_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(new Date().toISOString(), eventId, eventType,
      Number(verified), Number(duplicate), signature, JSON.stringify(req.headers), rawBody, paymentId);
    return res.status(200).json({ received: true, id: Number(result.lastInsertRowid), verified, duplicate });
  });

  // The demo receiver is intentionally unauthenticated so it can be a replay target.
  app.post('/demo/receiver', express.raw({ type: '*/*', limit: MAX_BODY_BYTES }), async (req, res) => {
    if (simulatorMode === 'fail') return res.status(500).json({ received: false, simulated: true });
    if (simulatorMode === 'slow') await new Promise((resolve) => setTimeout(resolve, simulatorDelayMs));
    return res.status(200).json({ received: true, simulated: simulatorMode !== 'normal', bytes: req.body?.length || 0 });
  });

  // Protect dashboard, stored event data, and test controls with HTTP Basic Auth.
  app.use((req, res, next) => {
    if (!dashboardPassword) return res.status(503).json({ error: 'Dashboard disabled until DASHBOARD_PASSWORD is configured.' });
    const [scheme, token] = (req.get('authorization') || '').split(' ');
    let credentials = '';
    try { credentials = scheme === 'Basic' ? Buffer.from(token || '', 'base64').toString('utf8') : ''; } catch { /* reject */ }
    if (scheme !== 'Basic' || !constantTimeTextEqual(credentials, `admin:${dashboardPassword}`)) {
      res.set('WWW-Authenticate', 'Basic realm="WebHook-Dehook", charset="UTF-8"');
      return res.status(401).json({ error: 'Dashboard authentication required.' });
    }
    return next();
  });
  app.use(express.json({ limit: '100kb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  app.get('/api/events', (req, res) => {
    const clauses = [];
    const params = [];
    if (typeof req.query.type === 'string' && req.query.type) { clauses.push('event_type = ?'); params.push(req.query.type.slice(0, 200)); }
    for (const field of ['verified', 'duplicate']) {
      if (req.query[field] === 'true' || req.query[field] === 'false') {
        clauses.push(`${field} = ?`); params.push(Number(req.query[field] === 'true'));
      }
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    res.json(database.prepare(`SELECT id, received_at, event_id, event_type, verified, duplicate, payment_id FROM events ${where} ORDER BY id DESC LIMIT 500`).all(...params));
  });

  app.get('/api/events/:id', (req, res) => {
    const row = database.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Event not found.' });
    let payload = null;
    try { payload = JSON.parse(Buffer.from(row.raw_body).toString('utf8')); } catch { /* leave payload null */ }
    return res.json({ id: row.id, received_at: row.received_at, event_id: row.event_id, event_type: row.event_type,
      verified: Boolean(row.verified), duplicate: Boolean(row.duplicate), payment_id: row.payment_id,
      headers: safeHeaders(JSON.parse(row.headers)), payload: redact(payload), diagnoses: diagnose({ row, db: database }) });
  });

  app.get('/api/payments/:paymentId/timeline', (req, res) => {
    const rows = database.prepare('SELECT id, received_at, event_id, event_type, verified, duplicate, payment_id FROM events WHERE payment_id = ? ORDER BY id ASC LIMIT 200').all(req.params.paymentId.slice(0, 200));
    const state = rows.reduce((current, event) => {
      if (event.event_type === 'payment.authorized') return 'authorized';
      if (event.event_type === 'payment.captured') return 'captured';
      if (event.event_type === 'payment.failed') return 'failed';
      return current;
    }, 'unknown');
    const types = rows.map((row) => row.event_type);
    const capturedBeforeAuthorized = types.includes('payment.captured') && (!types.includes('payment.authorized') || types.indexOf('payment.captured') < types.indexOf('payment.authorized'));
    return res.json({ payment_id: req.params.paymentId, state, out_of_order_candidate: capturedBeforeAuthorized, events: rows });
  });

  app.post('/api/events/:id/resolution-pack', (req, res) => {
    const row = database.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Event not found.' });
    const diagnoses = diagnose({ row, db: database }).filter((item) => item.code !== 'ok');
    const merchantReply = diagnoses.length
      ? `Thanks for reporting this payment notification issue. We found: ${diagnoses.map((item) => item.merchant).join(' ')} Our team is checking the event history and will confirm the order status before taking further action.`
      : 'Thanks for reporting this. The webhook passed the checks available to us. We are checking the related payment timeline and provider status before confirming the order update.';
    const internalNote = [`Event #${row.id} (${row.event_type || 'unknown'}), event ID ${row.event_id || 'not supplied'}, payment ${row.payment_id || 'not identified'}.`,
      ...diagnoses.map((item) => `${item.title}: ${item.technical} Recommended fix: ${item.fix}`),
      `Reproduction: inspect event #${row.id} in WebHook-Dehook; use its stored delivery and verify the merchant endpoint response.`].join('\n');
    const faq = diagnoses.map((item) => `### ${item.title}\n**Symptom:** A merchant reports a webhook/order update issue.\n**Cause:** ${item.technical}\n**Fix:** ${item.fix}`).join('\n\n');
    return res.json({ merchant_reply: merchantReply, internal_note: internalNote, faq_draft: faq || 'No failure rule matched. Document the observed symptom, payment timeline, provider state, and endpoint response.' });
  });

  app.post('/api/events/:id/replay', async (req, res) => {
    const row = database.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Event not found.' });
    const target = parseHttpUrl(req.body?.url);
    if (!target) return res.status(400).json({ error: 'Enter a valid HTTP(S) destination URL.' });
    if (!allowRemoteReplay && !isLoopbackHostname(target.hostname)) return res.status(403).json({ error: 'Remote replay is disabled. Use localhost or explicitly enable it only in a trusted, access-controlled deployment.' });
    const risky = row.duplicate || row.event_type === 'payment.captured';
    if (risky && req.body?.confirm_risky !== true) return res.status(409).json({ error: 'This replay could duplicate payment processing or fulfilment. Confirm the risk before proceeding.', confirmation_required: true });
    const originalHeaders = JSON.parse(row.headers);
    const headers = { 'content-type': originalHeaders['content-type'] || 'application/json' };
    if (row.signature) headers['x-razorpay-signature'] = row.signature;
    if (row.event_id) headers['x-razorpay-event-id'] = row.event_id;
    if (originalHeaders['x-razorpay-event']) headers['x-razorpay-event'] = originalHeaders['x-razorpay-event'];
    headers['x-dehook-replay'] = 'true';
    const started = Date.now();
    try {
      const response = await fetch(target, { method: 'POST', headers, body: Buffer.from(row.raw_body), signal: AbortSignal.timeout(10000), redirect: 'manual' });
      const text = (await response.text()).slice(0, MAX_RESPONSE_BYTES);
      return res.json({ status: response.status, status_text: response.statusText, response: text, elapsed_ms: Date.now() - started,
        retry_meaning: response.status >= 500 ? 'A 5xx response commonly signals a temporary failure; providers may retry delivery.' : response.status >= 400 ? 'A 4xx response usually signals a request/configuration issue; consult the provider retry policy.' : 'A 2xx response acknowledges receipt; it does not by itself prove the order was updated.' });
    } catch (error) {
      return res.status(502).json({ error: `Replay request failed: ${error.message}`, elapsed_ms: Date.now() - started });
    }
  });

  app.post('/api/conformance/run', async (req, res) => {
    const target = parseHttpUrl(req.body?.url);
    const testSecret = typeof req.body?.secret === 'string' ? req.body.secret : '';
    const threshold = Math.max(100, Math.min(30000, Number(req.body?.threshold_ms) || 2000));
    if (!target) return res.status(400).json({ error: 'Enter a valid HTTP(S) endpoint URL.' });
    if (!allowRemoteReplay && !isLoopbackHostname(target.hostname)) return res.status(403).json({ error: 'Conformance checks are restricted to localhost unless REPLAY_ALLOW_REMOTE=true is enabled in a trusted deployment.' });
    if (!testSecret || testSecret.length > 500) return res.status(400).json({ error: 'Enter a non-empty test webhook secret (maximum 500 characters).' });
    const makeEvent = (event, id, paymentId) => Buffer.from(JSON.stringify({ entity: 'event', account_id: 'acc_dehook_test', event,
      contains: ['payment'], payload: { payment: { entity: { id: paymentId, entity: 'payment', amount: 5000,
        currency: 'INR', status: event === 'payment.captured' ? 'captured' : 'authorized' } } }, created_at: Math.floor(Date.now() / 1000), id }));
    const results = [];
    async function send(name, body, signature, eventId, expected, fix, paymentId) {
      const started = Date.now();
      try {
        const response = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json', 'x-razorpay-signature': signature,
          'x-razorpay-event-id': eventId, 'x-razorpay-event': 'payment.authorized' }, body,
          signal: AbortSignal.timeout(10000), redirect: 'manual' });
        const elapsed = Date.now() - started;
        const pass = expected(response.status, elapsed);
        results.push({ check: name, passed: pass, status: response.status, elapsed_ms: elapsed,
          explanation: pass ? 'Observed response matched this check.' : `Endpoint returned HTTP ${response.status} in ${elapsed} ms.`, fix,
          payment_id: paymentId || undefined });
        return { status: response.status, elapsed_ms: elapsed };
      } catch (error) {
        const elapsed = Date.now() - started;
        results.push({ check: name, passed: false, status: null, elapsed_ms: elapsed, explanation: `Request failed: ${error.message}`, fix });
        return { status: null, elapsed_ms: elapsed };
      }
    }
    const unique = crypto.randomUUID();
    const paymentId = `pay_dehook_${unique.replaceAll('-', '').slice(0, 18)}`;
    const validBody = makeEvent('payment.authorized', `evt_${unique}_valid`, paymentId);
    const validSig = crypto.createHmac('sha256', testSecret).update(validBody).digest('hex');
    await send('Valid signed event', validBody, validSig, `evt_${unique}_valid`, (status, ms) => status >= 200 && status < 300 && ms <= threshold,
      `Return 2xx after safely accepting a valid signature. Investigate endpoint availability and keep response time below ${threshold} ms.`, paymentId);
    const tampered = Buffer.from(validBody.toString().replace('authorized', 'authorizEd'));
    await send('Tampered body with original signature', tampered, validSig, `evt_${unique}_tampered`, (status) => status >= 400 && status < 500,
      'Verify HMAC-SHA256 against the unchanged raw request bytes and reject a mismatch with 4xx.', paymentId);
    const wrongSig = crypto.createHmac('sha256', `${testSecret}_wrong`).update(validBody).digest('hex');
    await send('Wrong secret', validBody, wrongSig, `evt_${unique}_wrong`, (status) => status >= 400 && status < 500,
      'Use the configured webhook secret (not the API key secret) and reject a bad signature with 4xx.', paymentId);
    const duplicateId = `evt_${unique}_duplicate`;
    const duplicateBody = makeEvent('payment.authorized', duplicateId, paymentId);
    const duplicateSig = crypto.createHmac('sha256', testSecret).update(duplicateBody).digest('hex');
    const first = await send('Duplicate delivery (first attempt)', duplicateBody, duplicateSig, duplicateId, (status) => status >= 200 && status < 300,
      'Acknowledge a safely handled delivery with 2xx.', paymentId);
    const second = await send('Duplicate delivery (retry)', duplicateBody, duplicateSig, duplicateId, (status, ms) => status >= 200 && status < 300 && ms <= threshold,
      `Persist/check the event ID and make processing idempotent; acknowledge the retry with 2xx within ${threshold} ms.`, paymentId);
    results.push({ check: 'Duplicate delivery stability', passed: first.status >= 200 && first.status < 300 && second.status >= 200 && second.status < 300,
      status: second.status, elapsed_ms: second.elapsed_ms, explanation: 'A repeated event should not crash the endpoint or trigger duplicate fulfilment; external state is not observable by this check.',
      fix: 'Use a unique event-ID idempotency record and verify the order was fulfilled only once.' });
    const outOfOrderId = `pay_dehook_order_${unique.replaceAll('-', '').slice(0, 12)}`;
    const capturedBody = makeEvent('payment.captured', `evt_${unique}_captured`, outOfOrderId);
    const capturedSig = crypto.createHmac('sha256', testSecret).update(capturedBody).digest('hex');
    await send('Captured before authorized', capturedBody, capturedSig, `evt_${unique}_captured`, (status) => status >= 200 && status < 300,
      'Handle state transitions without assuming delivery order; reconcile payment state before fulfilment.', outOfOrderId);
    const report = { target: target.origin + target.pathname, threshold_ms: threshold, passed: results.filter((item) => item.passed).length,
      failed: results.filter((item) => !item.passed).length, results,
      limitation: 'The runner checks HTTP behavior only. It cannot observe the merchant database, prove exactly-once fulfilment, or safely infer business state. Run against a sandbox/test endpoint.' };
    return res.json(report);
  });

  app.post('/api/reconcile', async (req, res) => {
    const paymentId = typeof req.body?.payment_id === 'string' ? req.body.payment_id.trim() : '';
    const keyId = typeof req.body?.key_id === 'string' ? req.body.key_id.trim() : '';
    const keySecret = typeof req.body?.key_secret === 'string' ? req.body.key_secret : '';
    if (!/^pay_[A-Za-z0-9_-]{1,128}$/.test(paymentId) || !keyId || !keySecret) return res.status(400).json({ error: 'Provide a valid payment ID and Razorpay test-mode key ID and key secret.' });
    try {
      const response = await fetch(`https://api.razorpay.com/v1/payments/${encodeURIComponent(paymentId)}`, {
        headers: { authorization: `Basic ${Buffer.from(`${keyId}:${keySecret}`).toString('base64')}`, accept: 'application/json' },
        signal: AbortSignal.timeout(8000), redirect: 'manual'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) return res.status(response.status === 401 ? 401 : 502).json({ error: response.status === 401 ? 'Razorpay rejected the API credentials. Use test-mode API keys.' : `Razorpay payment lookup returned HTTP ${response.status}.`, status: response.status });
      const events = database.prepare('SELECT id, received_at, event_type, verified FROM events WHERE payment_id = ? ORDER BY id ASC').all(paymentId);
      const seenCaptured = events.some((event) => event.event_type === 'payment.captured');
      const implied = seenCaptured ? 'captured' : events.some((event) => event.event_type === 'payment.failed') ? 'failed' : events.some((event) => event.event_type === 'payment.authorized') ? 'authorized' : 'unknown';
      const missedCaptured = data.status === 'captured' && !seenCaptured;
      return res.json({ payment_id: paymentId, provider_status: data.status || 'unknown', webhook_implied_status: implied,
        mismatch: missedCaptured || (implied !== 'unknown' && implied !== data.status), missed_captured_webhook: missedCaptured, events,
        message: missedCaptured ? 'Razorpay API reports captured, but no payment.captured webhook was recorded here. A delivery may have been missed or sent to another endpoint.' : 'Compare the provider status with the events captured by this debugger.',
        pii_redacted: true });
    } catch (error) {
      return res.status(502).json({ error: `Razorpay API request failed: ${error.message}` });
    }
  });

  app.get('/api/simulator', (_req, res) => res.json({ mode: simulatorMode, delay_ms: simulatorDelayMs }));
  app.post('/api/simulator', (req, res) => {
    if (!['normal', 'fail', 'slow'].includes(req.body?.mode)) return res.status(400).json({ error: 'Mode must be normal, fail, or slow.' });
    simulatorMode = req.body.mode;
    const delay = Number(req.body?.delay_ms);
    if (Number.isFinite(delay)) simulatorDelayMs = Math.max(0, Math.min(30000, Math.round(delay)));
    return res.json({ mode: simulatorMode, delay_ms: simulatorDelayMs });
  });
  app.get('/api/health', (_req, res) => res.json({ ok: true, secret_configured: webhookSecrets.length > 0, dashboard_auth_configured: Boolean(dashboardPassword) }));
  app.use((err, _req, res, _next) => {
    if (err?.type === 'entity.too.large') return res.status(413).json({ error: `Request body exceeds ${MAX_BODY_BYTES} bytes.` });
    return res.status(500).json({ error: 'Unexpected server error.' });
  });
  return app;
}

if (require.main === module) {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'dehook.sqlite'));
  const secrets = (process.env.RAZORPAY_WEBHOOK_SECRETS || process.env.RAZORPAY_WEBHOOK_SECRET || '').split(',').map((secret) => secret.trim()).filter(Boolean);
  if (!process.env.DASHBOARD_PASSWORD) console.warn('DASHBOARD_PASSWORD is not configured; dashboard requests will be disabled.');
  const app = createApp({ db, secrets, allowRemoteReplay: process.env.REPLAY_ALLOW_REMOTE === 'true' });
  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => console.log(`WebHook-Dehook listening on http://localhost:${port}`));
}

module.exports = { createApp, verifySignature, diagnose, redact, isLoopbackHostname };
