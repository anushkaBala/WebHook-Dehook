const endpoint = `${window.location.origin}/webhooks/razorpay`;
document.getElementById('endpoint').textContent = endpoint;
const list = document.getElementById('event-list');
const detail = document.getElementById('detail-panel');
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

async function checkHealth() {
  try {
    const response = await fetch('/api/health');
    const health = await response.json();
    document.getElementById('health').textContent = health.secret_configured ? 'Receiver ready' : 'Set webhook secret';
    document.querySelector('.live-dot').classList.toggle('warning', !health.secret_configured);
  } catch { document.getElementById('health').textContent = 'Receiver unavailable'; }
}

function queryString() {
  const params = new URLSearchParams();
  const type = document.getElementById('filter-type').value.trim();
  const verified = document.getElementById('filter-verified').value;
  const duplicate = document.getElementById('filter-duplicate').value;
  if (type) params.set('type', type);
  if (verified) params.set('verified', verified);
  if (duplicate) params.set('duplicate', duplicate);
  return params.toString();
}

async function loadEvents() {
  const response = await fetch(`/api/events?${queryString()}`);
  const events = await response.json();
  document.getElementById('count').textContent = events.length;
  if (!events.length) {
    list.innerHTML = '<div class="empty-state"><span>↯</span><strong>No matching events</strong><p>Adjust your filters or send a webhook to the endpoint above.</p></div>';
    return;
  }
  list.innerHTML = events.map((event) => `<button class="event-row" data-id="${event.id}"><span class="event-status ${event.verified ? 'ok' : 'bad'}"></span><span class="event-main"><strong>${esc(event.event_type || 'Unknown event')}</strong><small>${esc(event.event_id || 'No event ID')} · ${new Date(event.received_at).toLocaleString()}</small></span><span class="badges">${event.duplicate ? '<i class="badge duplicate">Duplicate</i>' : ''}<i class="badge ${event.verified ? 'verified' : 'failed'}">${event.verified ? 'Verified' : 'Failed'}</i></span></button>`).join('');
  list.querySelectorAll('.event-row').forEach((button) => button.addEventListener('click', () => loadDetail(button.dataset.id)));
}

async function loadDetail(id) {
  const response = await fetch(`/api/events/${id}`);
  if (!response.ok) return;
  const event = await response.json();
  detail.innerHTML = `<div class="detail-heading"><div><p class="eyebrow">EVENT #${event.id}</p><h2>${esc(event.event_type || 'Unknown event')}</h2></div><span class="badge ${event.verified ? 'verified' : 'failed'}">${event.verified ? 'Verified' : 'Signature failed'}</span></div>
  <div class="event-meta"><span><small>EVENT ID</small><code>${esc(event.event_id || '—')}</code></span><span><small>RECEIVED</small><code>${new Date(event.received_at).toLocaleString()}</code></span></div>
  <section class="diagnosis"><h3>Diagnosis</h3>${event.diagnoses.map((note) => `<p><span>↳</span>${esc(note)}</p>`).join('')}</section>
  <section class="detail-section"><h3>Replay delivery</h3><p class="muted">Sends the exact stored body and original signature. Localhost is allowed by default.</p><div class="replay-row"><input id="replay-url" aria-label="Replay URL" value="${esc(`${window.location.origin}/demo/receiver`)}"><button class="button primary" id="replay-button">Replay</button></div><p class="replay-result" id="replay-result"></p></section>
  <section class="detail-section"><h3>Payload</h3><pre>${esc(event.payload ? JSON.stringify(event.payload, null, 2) : event.raw_body)}</pre></section>
  <details class="detail-section"><summary>Request headers</summary><pre>${esc(JSON.stringify(event.headers, null, 2))}</pre></details>`;
  document.getElementById('replay-button').addEventListener('click', () => replay(id));
}

async function replay(id) {
  const button = document.getElementById('replay-button');
  const result = document.getElementById('replay-result');
  button.disabled = true; button.textContent = 'Sending…'; result.textContent = '';
  try {
    const response = await fetch(`/api/events/${id}/replay`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: document.getElementById('replay-url').value }) });
    const data = await response.json();
    result.textContent = response.ok ? `Destination responded ${data.status} ${data.status_text}${data.response ? ` · ${data.response}` : ''}` : data.error;
    result.className = `replay-result ${response.ok && data.status < 400 ? 'success' : 'failure'}`;
  } catch { result.textContent = 'Could not reach the replay endpoint.'; result.className = 'replay-result failure'; }
  finally { button.disabled = false; button.textContent = 'Replay'; }
}

async function loadSimulator() {
  const response = await fetch('/api/simulator');
  if (response.ok) document.getElementById('sim-mode').value = (await response.json()).mode;
}

document.getElementById('copy-endpoint').addEventListener('click', async () => {
  await navigator.clipboard.writeText(endpoint);
  document.getElementById('copy-endpoint').textContent = 'Copied';
  setTimeout(() => { document.getElementById('copy-endpoint').textContent = 'Copy'; }, 1200);
});
document.getElementById('refresh').addEventListener('click', loadEvents);
['filter-type', 'filter-verified', 'filter-duplicate'].forEach((id) => document.getElementById(id).addEventListener(id === 'filter-type' ? 'input' : 'change', loadEvents));
document.getElementById('save-sim').addEventListener('click', async () => {
  const mode = document.getElementById('sim-mode').value;
  const response = await fetch('/api/simulator', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mode }) });
  document.getElementById('sim-status').textContent = response.ok ? 'Applied' : 'Could not apply';
  setTimeout(() => { document.getElementById('sim-status').textContent = ''; }, 1800);
});
checkHealth(); loadEvents(); loadSimulator();
setInterval(loadEvents, 5000);
