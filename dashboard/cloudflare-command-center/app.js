const API_BASE = '/api';

async function checkAgent() {
  const status = document.getElementById('agent-status');
  try {
    const response = await fetch(`${API_BASE}/health`);
    const data = await response.json();
    status.textContent = `Agent: ${data.agent || 'Online'}`;
  } catch (error) {
    status.textContent = 'Agent: Offline';
  }
}

async function startScan() {
  const status = document.getElementById('scan-status');
  try {
    status.textContent = 'Scan started...';
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'command-center' })
    });
    const data = await response.json();
    status.textContent = data.message || 'Scan queued';
    loadLogs();
  } catch (error) {
    status.textContent = 'Scan request failed';
  }
}

async function loadLogs() {
  const panel = document.getElementById('live-logs');
  if (!panel) return;
  try {
    const response = await fetch(`${API_BASE}/logs`);
    const data = await response.json();
    panel.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    panel.textContent = 'No logs available';
  }
}

window.onload = () => {
  checkAgent();
  loadLogs();
};

setInterval(loadLogs, 5000);
