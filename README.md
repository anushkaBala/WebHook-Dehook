# Razorpay webhook debugger: verifies signatures on raw bodies, flags duplicates and out-of-order events, and replays payloads.

Razorpay webhook debugging for merchant integrations: capture deliveries, verify signatures against the original request bytes, inspect duplicates and payment-event ordering, and replay events to a local endpoint.

![Webhook debugging workflow](docs/images/webhook-debug-flow.svg)

## Features

- Raw-body HMAC-SHA256 signature verification before JSON parsing.
- SQLite event inbox with request headers, event ID/type, verification result, and receipt time.
- Duplicate event-ID detection and a best-effort warning for captured events with no earlier authorization delivery recorded here.
- Event filters, redacted event details, and merchant-friendly explanations alongside technical fixes.
- Dashboard/API password protection using HTTP Basic Auth and `DASHBOARD_PASSWORD`.
- Localhost-only replay by default, response status/duration, and failure simulator for normal, failed, and delayed responses.
- Tests for signature validation, tampering, wrong secrets, duplicate IDs, PII masking, dashboard auth, and target safety.

## Run locally

Requires Node.js 20+ and a native build toolchain for `better-sqlite3`.

```bash
npm install
export DASHBOARD_PASSWORD='choose-a-local-password'
export RAZORPAY_WEBHOOK_SECRET='your-test-webhook-secret'
npm start
```

Open <http://localhost:3000>. Dashboard HTTP Basic Auth username is `admin`; password is the value of `DASHBOARD_PASSWORD`. The inbound webhook receiver remains accessible without dashboard login. For Razorpay Test Mode, configure `https://<your-tunnel>/webhooks/razorpay` and forward the tunnel to port 3000.

The webhook secret is separate from the Razorpay API key secret. Test and Live webhook configurations have separate secrets. During secret rotation, configure comma-separated values with `RAZORPAY_WEBHOOK_SECRETS='current-secret,previous-secret'`.

## Docker Compose

```bash
export DASHBOARD_PASSWORD='choose-a-local-password'
export RAZORPAY_WEBHOOK_SECRET='your-test-webhook-secret'
docker compose up --build
```

## Demo flow

1. Start the server and send a Razorpay Test Mode event through a tunnel.
2. Select the event to inspect verification status, redacted payload, headers, and diagnosis.
3. Set the simulator to return 500 and replay to the local demo endpoint; switch to normal and replay again.
4. Review event ID and payment ordering diagnosis.

## API

- `POST /webhooks/razorpay` — receive and persist a webhook, then return 200.
- `GET /api/events` — list/filter events by type, signature result, or duplicate status.
- `GET /api/events/:id` — inspect PII-redacted details and diagnosis; raw body and signature are not returned.
- `POST /api/events/:id/replay` — replay stored bytes and original signature to an allowed HTTP(S) target.
- `GET|POST /api/simulator` — inspect or set `normal`, `fail`, or `slow` demo behavior.
- `GET /api/health` — basic health/configuration status.

## Tests

```bash
npm test
```

GitHub Actions runs the test suite on pushes and pull requests.

## Data handling

The event store retains the original raw payload for signature validation and replay. Email addresses, phone numbers, and sensitive keyed fields are masked in dashboard/API representations; the original SQLite database remains unredacted. Use synthetic/test-mode data and protect the local database.
