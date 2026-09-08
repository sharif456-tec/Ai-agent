const API_URL = '/api/health';

async function checkAgent() {
  const status = document.getElementById('agent-status');
  try {
    const response = await fetch(API_URL);
    const data = await response.json();
    status.textContent = `Agent: ${data.agent}`;
  } catch (error) {
    status.textContent = 'Agent: Offline';
  }
}

function startScan() {
  alert('Security scan request queued');
}

window.onload = checkAgent;
