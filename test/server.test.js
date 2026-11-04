const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');
const Database = require('better-sqlite3');
const { createApp, verifySignature } = require('./server');

const secret = 'test-webhook-secret';
const raw = Buffer.from('{"event":"payment.authorized","payload":{"payment":{"entity":{"id":"pay_test_1"}}}}');
const signature = crypto.createHmac('sha256', secret).update(raw).digest('hex');

function setup() {
  const db = new Database(':memory:');
  return { app: createApp({ db, secrets: [secret] }), db };
}

test('accepts a valid signature over the exact raw body and stores it', async () => {
  const { app, db } = setup();
  const response = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature)
    .set('x-razorpay-event-id', 'evt_1').set('content-type', 'application/json').send(raw);
  assert.equal(response.status, 200);
  assert.equal(response.body.verified, true);
  const event = await request(app).get(`/api/events/${response.body.id}`);
  assert.equal(event.body.raw_body, raw.toString());
  assert.equal(event.body.event_type, 'payment.authorized');
  db.close();
});

test('rejects tampered payload and wrong-secret signatures without dropping the event', async () => {
  const { app, db } = setup();
  const tampered = Buffer.from(raw.toString().replace('authorized', 'captured'));
  const tamperedResponse = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature)
    .set('content-type', 'application/json').send(tampered);
  const wrongSignature = crypto.createHmac('sha256', 'wrong-secret').update(raw).digest('hex');
  const wrongResponse = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', wrongSignature)
    .set('content-type', 'application/json').send(raw);
  assert.equal(tamperedResponse.body.verified, false);
  assert.equal(wrongResponse.body.verified, false);
  assert.equal((await request(app).get('/api/events')).body.length, 2);
  db.close();
});

test('detects a repeated Razorpay event ID', async () => {
  const { app, db } = setup();
  const send = () => request(app).post('/webhooks/razorpay').set('x-razorpay-signature', signature)
    .set('x-razorpay-event-id', 'evt_repeat').set('content-type', 'application/json').send(raw);
  assert.equal((await send()).body.duplicate, false);
  assert.equal((await send()).body.duplicate, true);
  db.close();
});

test('checks raw bytes before JSON parsing; parsing and re-serializing changes the signature', () => {
  const spaced = Buffer.from('{ "event" : "payment.authorized" }');
  const spacedSignature = crypto.createHmac('sha256', secret).update(spaced).digest('hex');
  assert.equal(verifySignature(spaced, spacedSignature, [secret]), true);
  assert.equal(verifySignature(Buffer.from(JSON.stringify(JSON.parse(spaced))), spacedSignature, [secret]), false);
});

test('flags captured payments that arrive before authorization', async () => {
  const { app, db } = setup();
  const captured = Buffer.from('{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_order_test"}}}}');
  const sig = crypto.createHmac('sha256', secret).update(captured).digest('hex');
  const response = await request(app).post('/webhooks/razorpay').set('x-razorpay-signature', sig)
    .set('x-razorpay-event-id', 'evt_capture').set('content-type', 'application/json').send(captured);
  const event = await request(app).get(`/api/events/${response.body.id}`);
  assert.ok(event.body.diagnoses.some((note) => note.includes('Out-of-order candidate')));
  db.close();
});
