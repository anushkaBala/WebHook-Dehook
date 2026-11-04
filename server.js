const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const Database = require('better-sqlite3');

const MAX_BODY_BYTES = 1024 * 1024;

function initDatabase(db) {
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      received_at TEXT NOT NULL,
      event_id TEXT,
      event_type TEXT,
      verified INTEGER NOT NULL,
      duplicate INTEGER NOT NULL,
      signature TEXT,
      headers TEXT NOT NULL,
      raw_body BLOB NOT NULL,
      payment_id TEXT
    );
    CREATE INDEX IF NOT EXISTS events_event_id_idx ON events(event_id);
    CREATE INDEX IF NOT EXISTS events_received_at_idx ON events(received_at DESC);
    CREATE INDEX IF NOT EXISTS events_payment_id_idx ON events(payment_id);
  `);
}

function verifySignature(rawBody, suppliedSignature, secrets) {
  if (!Buffer.isBuffer(rawBody) || typeof suppliedSignature !== 'string' || !/^[a-f\d]{64}$/i.test(suppliedSignature)) {
    return false;
  }
  const received = Buffer.from(suppliedSignature, 'hex');
  return secrets.some((secret) => {
    if (!secret) return false;
    const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
    return received.length === expected.length && crypto.timingSafeEqual(received, expected);
  });
}

function getPaymentId(payload) {
  return payload?.payload?.payment?.entity?.id ?? payload?.payment?.entity?.id ?? null;
}

function diagnose({ verified, duplicate, eventType, paymentId, db }) {
  const notes = [];
  if (!verified) {
    notes.push('Signature verification failed. Check that the exact raw request body was hashed and that the Razorpay webhook secret matches this endpoint and mode (Test and Live secrets are separate).');
  }
  if (duplicate) notes.push('Duplicate event ID: Razorpay may retry deliveries. Make your business-side event handling idempotent.');
  if (eventType === 'payment.captured' && paymentId) {
    const authorization = db.prepare(`
      SELECT id FROM events
      WHERE payment_id = ? AND event_type = 'payment.authorized' AND received_at <= ?
      LIMIT 1
    `);
    const current = db.prepare('SELECT received_at FROM events ORDER BY id DESC LIMIT 1').get();
    const earlier = current && authorization.get(paymentId, current.received_at);
    if (!earlier) {
      notes.push('Out-of-order candidate: this payment.captured event has no earlier payment.authorized event with the same payment ID in the events received here.');
    }
  }
  if (notes.length === 0) notes.push('No known signature, duplicate, or payment-order issue was detected.');
  return notes;
}

function isLoopbackHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '::1';
}

function createApp({ db, secrets = [], allowRemoteReplay = false } = {}) {
  const database = db || new Database(':memory:');
  initDatabase(database);
  const webhookSecrets = Array.isArray(secrets) ? secrets.filter(Boolean) : [];
  const app = express();
  let simulatorMode = 'normal';
  let simulatorDelayMs = 3000;

  // Keep this raw-body route before JSON middleware: Razorpay signs the exact bytes it sends.
  app.post('/webhooks/razorpay', express.raw({ type: '*/*', limit: MAX_BODY_BYTES }), (req, res) => {
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const signature = req.get('x-razorpay-signature') || '';
    const eventId = req.get('x-razorpay-event-id') || null;
    const verified = verifySignature(rawBody, signature, webhookSecrets);
    let payload = null;
    try { payload = JSON.parse(rawBody.toString('utf8')); } catch { /* Keep malformed payloads inspectable. */ }
    const eventType = (typeof payload?.event === 'string' ? payload.event : req.get('x-razorpay-event')) || null;
    const paymentId = getPaymentId(payload);
    const duplicate = Boolean(eventId && database.prepare('SELECT 1 FROM events WHERE event_id = ? LIMIT 1').get(eventId));
    const receivedAt = new Date().toISOString();
    const insert = database.prepare(`
      INSERT INTO events (received_at, event_id, event_type, verified, duplicate, signature, headers, raw_body, payment_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = insert.run(receivedAt, eventId, eventType, Number(verified), Number(duplicate), signature,
      JSON.stringify(req.headers), rawBody, paymentId);
    // Persist first, then acknowledge. Diagnosis/UI work happens on later requests.
    return res.status(200).json({ received: true, id: Number(result.lastInsertRowid), verified, duplicate });
  });

  app.use(express.json({ limit: '100kb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  app.get('/api/events', (req, res) => {
    const clauses = [];
    const params = [];
    if (typeof req.query.type === 'string' && req.query.type) {
      clauses.push('event_type = ?'); params.push(req.query.type.slice(0, 200));
    }
    if (req.query.verified === 'true' || req.query.verified === 'false') {
      clauses.push('verified = ?'); params.push(Number(req.query.verified === 'true'));
    }
    if (req.query.duplicate === 'true' || req.query.duplicate === 'false') {
      clauses.push('duplicate = ?'); params.push(Number(req.query.duplicate === 'true'));
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = database.prepare(`
      SELECT id, received_at, event_id, event_type, verified, duplicate, payment_id
      FROM events ${where} ORDER BY id DESC LIMIT 500
    `).all(...params);
    res.json(rows);
  });

  app.get('/api/events/:id', (req, res) => {
    const row = database.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Event not found.' });
    let payload = null;
    try { payload = JSON.parse(Buffer.from(row.raw_body).toString('utf8')); } catch { /* Raw body remains available. */ }
    const diagnoses = diagnose({ verified: Boolean(row.verified), duplicate: Boolean(row.duplicate), eventType: row.event_type, paymentId: row.payment_id, db: database });
    return res.json({
      id: row.id, received_at: row.received_at, event_id: row.event_id, event_type: row.event_type,
      verified: Boolean(row.verified), duplicate: Boolean(row.duplicate), signature: row.signature,
      headers: JSON.parse(row.headers), raw_body: Buffer.from(row.raw_body).toString('utf8'), payload, diagnoses
    });
  });

  app.post('/api/events/:id/replay', async (req, res) => {
    const row = database.prepare('SELECT * FROM events WHERE id = ?').get(Number(req.params.id));
    if (!row) return res.status(404).json({ error: 'Event not found.' });
    const target = req.body?.url;
    let url;
    try { url = new URL(target); } catch { return res.status(400).json({ error: 'Enter a valid HTTP(S) destination URL.' }); }
    if (!['http:', 'https:'].includes(url.protocol)) return res.status(400).json({ error: 'Only HTTP(S) destinations are supported.' });
    if (!allowRemoteReplay && !isLoopbackHostname(url.hostname)) {
      return res.status(403).json({ error: 'Remote replay is disabled. Use localhost for local development, or set REPLAY_ALLOW_REMOTE=true only in a trusted, access-controlled deployment.' });
    }
    const originalHeaders = JSON.parse(row.headers);
    const headers = { 'content-type': originalHeaders['content-type'] || 'application/json' };
    if (row.signature) headers['x-razorpay-signature'] = row.signature;
    if (row.event_id) headers['x-razorpay-event-id'] = row.event_id;
    if (originalHeaders['x-razorpay-event']) headers['x-razorpay-event'] = originalHeaders['x-razorpay-event'];
    headers['x-dehook-replay'] = 'true';
    try {
      const response = await fetch(url, {
        method: 'POST', headers, body: Buffer.from(row.raw_body), signal: AbortSignal.timeout(10000),
        redirect: 'manual'
      });
      const responseText = (await response.text()).slice(0, 2000);
      return res.json({ status: response.status, status_text: response.statusText, response: responseText });
    } catch (error) {
      return res.status(502).json({ error: `Replay request failed: ${error.message}` });
    }
  });

  app.get('/api/simulator', (_req, res) => res.json({ mode: simulatorMode, delay_ms: simulatorDelayMs }));
  app.post('/api/simulator', (req, res) => {
    const mode = req.body?.mode;
    if (!['normal', 'fail', 'slow'].includes(mode)) return res.status(400).json({ error: 'Mode must be normal, fail, or slow.' });
    simulatorMode = mode;
    const delay = Number(req.body?.delay_ms);
    if (Number.isFinite(delay)) simulatorDelayMs = Math.max(0, Math.min(30000, Math.round(delay)));
    return res.json({ mode: simulatorMode, delay_ms: simulatorDelayMs });
  });

  // A controlled local target for demonstrating failed deliveries and replay behavior.
  app.post('/demo/receiver', express.raw({ type: '*/*', limit: MAX_BODY_BYTES }), async (req, res) => {
    if (simulatorMode === 'fail') return res.status(500).json({ received: false, simulated: true });
    if (simulatorMode === 'slow') await new Promise((resolve) => setTimeout(resolve, simulatorDelayMs));
    return res.status(200).json({ received: true, simulated: simulatorMode !== 'normal', bytes: req.body?.length || 0 });
  });

  app.get('/api/health', (_req, res) => res.json({ ok: true, secret_configured: webhookSecrets.length > 0 }));
  app.use((err, _req, res, _next) => {
    if (err?.type === 'entity.too.large') return res.status(413).json({ error: `Request body exceeds ${MAX_BODY_BYTES} bytes.` });
    console.error(err);
    return res.status(500).json({ error: 'Unexpected server error.' });
  });
  return app;
}

if (require.main === module) {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'dehook.sqlite'));
  const secrets = (process.env.RAZORPAY_WEBHOOK_SECRETS || process.env.RAZORPAY_WEBHOOK_SECRET || '')
    .split(',').map((secret) => secret.trim()).filter(Boolean);
  const app = createApp({ db, secrets, allowRemoteReplay: process.env.REPLAY_ALLOW_REMOTE === 'true' });
  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => console.log(`WebHook-Dehook listening on http://localhost:${port}`));
}

module.exports = { createApp, verifySignature, diagnose, isLoopbackHostname };
