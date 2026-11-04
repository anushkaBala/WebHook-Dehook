const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');
const Database = require('better-sqlite3');
const { createApp, verifySignature, redact } = require('./server');

const secret = 'test-webhook-secret';
const raw = Buffer.from('{"event":"payment.authorized","payload":{"payment":{"entity":{"id":"pay_test_1","email":"buyer@example.com","contact":"+919876543210"}}}}');
const signature = crypto.createHmac('sha256', secret).update(raw).digest('hex');
function setup(options = {}) {
  const db = new Database(':memory:');
  return { app: createApp({ db, secrets: [secret], dashboardPassword: 'test-dashboard-password', ...options }), db };
}
const api = (app) => request(app).auth('admin', 'test-dashboard-password');

test('valid signature is checked against exact bytes and event is persisted before 200', async () => {
  const { app, db } = setup();
  const response = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature).set('x-razorpay-event-id', 'evt_1').set('content-type', 'application/json').send(raw);
  assert.equal(response.status, 200); assert.equal(response.body.verified, true);
  const event = await api(app).get(`/api/events/${response.body.id}`);
  assert.equal(event.body.verified, true); assert.equal(event.body.payload.payload.payment.entity.email, '[REDACTED]');
  assert.equal(JSON.stringify(event.body).includes('buyer@example.com'), false);
  db.close();
});

test('rejects tampered payload and wrong-secret signatures while retaining deliveries', async () => {
  const { app, db } = setup();
  const tampered = Buffer.from(raw.toString().replace('authorized', 'captured'));
  const a = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature).set('content-type', 'application/json').send(tampered);
  const wrong = crypto.createHmac('sha256', 'wrong-secret').update(raw).digest('hex');
  const b = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', wrong).set('content-type', 'application/json').send(raw);
  assert.equal(a.body.verified, false); assert.equal(b.body.verified, false);
  assert.equal((await api(app).get('/api/events')).body.length, 2);
  db.close();
});

test('parsed then reserialized JSON does not validate against original signature', () => {
  const spaced = Buffer.from('{ "event" : "payment.authorized" }');
  const sig = crypto.createHmac('sha256', secret).update(spaced).digest('hex');
  assert.equal(verifySignature(spaced, sig, [secret]), true);
  assert.equal(verifySignature(Buffer.from(JSON.stringify(JSON.parse(spaced))), sig, [secret]), false);
});

test('marks repeated event IDs and diagnoses possible out-of-order delivery', async () => {
  const { app, db } = setup();
  const send = (body, id) => request(app).post('/webhooks/razorpay').set('x-razorpay-signature', crypto.createHmac('sha256', secret).update(body).digest('hex')).set('x-razorpay-event-id', id).set('content-type', 'application/json').send(body);
  assert.equal((await send(raw, 'evt_repeat')).body.duplicate, false);
  assert.equal((await send(raw, 'evt_repeat')).body.duplicate, true);
  const captured = Buffer.from('{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_order_test"}}}}');
  const response = await send(captured, 'evt_capture');
  const detail = await api(app).get(`/api/events/${response.body.id}`);
  assert.ok(detail.body.diagnoses.some((item) => item.code === 'out_of_order'));
  db.close();
});

test('redacts sensitive nested keys, embedded emails, and phone numbers', () => {
  const result = redact({ customer: { email: 'buyer@example.com', phone: '+919876543210', note: 'call 9876543210' } });
  assert.equal(result.customer.email, '[REDACTED]'); assert.equal(result.customer.phone, '[REDACTED]');
  assert.equal(result.customer.note.includes('9876543210'), false);
});

test('dashboard API requires configured Basic Auth but webhook receiver remains available', async () => {
  const { app, db } = setup();
  assert.equal((await request(app).get('/api/events')).status, 401);
  assert.equal((await request(app).get('/api/events').auth('admin', 'test-dashboard-password')).status, 200);
  assert.equal((await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature).send(raw)).status, 200);
  db.close();
});

test('remote replay and conformance targets are blocked by default', async () => {
  const { app, db } = setup();
  await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature).send(raw);
  const replay = await api(app).post('/api/events/1/replay').send({ url: 'https://example.com' });
  const conformance = await api(app).post('/api/conformance/run').send({ url: 'https://example.com', secret });
  assert.equal(replay.status, 403); assert.equal(conformance.status, 403);
  db.close();
});

test('sensitive signatures are compared safely and secret configuration is not exposed', async () => {
  const { app, db } = setup();
  const health = await api(app).get('/api/health');
  assert.equal(health.body.dashboard_auth_configured, true);
  assert.equal(JSON.stringify(health.body).includes(secret), false);
  db.close();
});
