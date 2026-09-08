const API_BASE = '/api';

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

async function checkAgent() {
  try {
    const response = await fetch(`${API_BASE}/health`);
    const data = await response.json();
    setText('status', '🟢 Agent Online');
  } catch (error) {
    setText('status', '🔴 Agent Offline');
  }
}

function renderFindings(findings = []) {
  const box = document.getElementById('findings');
  if (!box) return;
  if (!findings.length) {
    box.innerHTML = '<div class="ok">✓ No findings detected by the passive checks.</div>';
    return;
  }
  box.innerHTML = findings.map(f =>
    `<div class="finding"><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span><span>${escapeHtml(f.title)}</span></div>`
  ).join('');
}

function renderScan(data) {
  setText('security-score', `${data.security_score}/100`);
  setText('critical-issues', data.critical ?? 0);
  setText('high-issues', data.high ?? 0);
  setText('medium-issues', data.medium ?? 0);
  setText('low-issues', data.low ?? 0);
  setText('last-scan', data.scanned_at || new Date().toISOString());
  const tech = document.getElementById('technologies');
  if (tech) tech.innerHTML = (data.technologies?.length ? data.technologies : ['No server technology disclosed']).map(escapeHtml).join('<br>');
  setText('details', JSON.stringify({target:data.target, final_url:data.final_url, status:data.http_status, mode:data.mode}, null, 2));
  renderFindings(data.findings);
}

async function startScan() {
  const target = document.getElementById('target')?.value.trim();
  if (!target) { setText('scan-status', 'Enter a website URL first.'); return; }
  const button = document.getElementById('scan-button');
  if (button) button.disabled = true;
  setText('scan-status', '🔎 Running passive security checks...');
  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({target})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Scan failed');
    renderScan(data);
    setText('scan-status', '✅ Scan completed.');
    loadLogs();
  } catch (error) {
    setText('scan-status', `❌ ${error.message}`);
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadLogs() {
  const panel = document.getElementById('live-logs');
  if (!panel) return;
  try {
    const response = await fetch(`${API_BASE}/logs`);
    const data = await response.json();
    panel.textContent = (data.logs || []).map(x => `[${x.time}] ${x.message}${x.target ? ` — ${x.target}` : ''}`).join('\n') || 'No logs yet.';
  } catch (error) { panel.textContent = 'Log service unavailable.'; }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('scan-button')?.addEventListener('click', startScan);
  checkAgent();
  loadLogs();
});
setInterval(loadLogs, 5000);
