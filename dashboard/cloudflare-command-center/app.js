const API_BASE = '/api';

async function checkAgent() {
  const status = document.getElementById('agent-status');
  try {
    const response = await fetch(`${API_BASE}/health`);
    const data = await response.json();
    status.textContent = `Agent: ${data.agent}`;
  } catch (error) {
    status.textContent = 'Agent: Offline';
  }
}

async function startScan() {
  const status = document.getElementById('scan-status');
  try {
    status.textContent = 'Scan started...';
    const response = await fetch(`${API_BASE}/scan`, { method: 'POST' });
    const data = await response.json();
    status.textContent = data.message || 'Scan queued';
  } catch (error) {
    status.textContent = 'Scan request failed';
  }
}

window.onload = checkAgent;
