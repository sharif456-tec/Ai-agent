const API_BASE = window.SECURITY_API_BASE || '/api';

function setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = value; }

async function readJson(response) {
  const text = await response.text();
  if (!text.trim()) throw new Error(`Empty API response (HTTP ${response.status})`);
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`Invalid API response (HTTP ${response.status})`); }
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

async function checkAgent() {
  try { await readJson(await fetch(`${API_BASE}/health`, { cache: 'no-store' })); setText('status', '🟢 Agent Online'); }
  catch { setText('status', '🔴 Agent Offline'); }
}

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function renderFindings(findings = []) {
  const box = document.getElementById('findings'); if (!box) return;
  box.innerHTML = findings.length ? findings.map(f => `<div class="finding"><span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity).toUpperCase()}</span><span>${escapeHtml(f.title)}</span></div>`).join('') : '<div class="ok">✓ No findings detected by the passive checks.</div>';
}
function renderScan(data) {
  setText('security-score', `${data.security_score}/100`); setText('critical-issues', data.critical ?? 0); setText('high-issues', data.high ?? 0); setText('medium-issues', data.medium ?? 0); setText('low-issues', data.low ?? 0);
  setText('last-scan', data.scanned_at || new Date().toISOString());
  const tech = document.getElementById('technologies'); if (tech) tech.innerHTML = (data.technologies?.length ? data.technologies : ['No server technology disclosed']).map(escapeHtml).join('<br>');
  setText('details', JSON.stringify({target:data.target, final_url:data.final_url, status:data.http_status, mode:data.mode}, null, 2)); renderFindings(data.findings);
}
async function startScan() {
  const target = document.getElementById('target')?.value.trim(); if (!target) { setText('scan-status','Enter a website URL first.'); return; }
  const button = document.getElementById('scan-button'); if (button) button.disabled = true; setText('scan-status','🔎 Running passive security checks...');
  try { const data = await readJson(await fetch(`${API_BASE}/scan`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({target}) })); renderScan(data); setText('scan-status','✅ Scan completed.'); await loadLogs(); }
  catch (error) { setText('scan-status', `❌ ${error.message}`); }
  finally { if (button) button.disabled = false; }
}
async function loadLogs() {
  const panel = document.getElementById('live-logs'); if (!panel) return;
  try { const data = await readJson(await fetch(`${API_BASE}/logs`, { cache:'no-store' })); panel.textContent = (data.logs || []).map(x => `[${x.time}] ${x.message}${x.target ? ` — ${x.target}` : ''}`).join('\n') || 'No logs yet.'; }
  catch { panel.textContent = 'Log service unavailable.'; }
}
document.addEventListener('DOMContentLoaded', () => { document.getElementById('scan-button')?.addEventListener('click', startScan); checkAgent(); loadLogs(); });
setInterval(loadLogs, 5000); setInterval(checkAgent, 15000);
