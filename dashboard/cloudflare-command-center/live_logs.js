// Live Logs UI connector

async function loadLiveLogs() {
  try {
    const response = await fetch('/api/logs');
    const data = await response.json();

    const panel = document.getElementById('liveLogs');
    if (!panel) return;

    panel.innerHTML = '';
    (data.logs || []).forEach((log) => {
      const item = document.createElement('div');
      item.textContent = `[${log.time}] ${log.message}`;
      panel.appendChild(item);
    });
  } catch (error) {
    console.error('Live log connection failed', error);
  }
}

setInterval(loadLiveLogs, 3000);
loadLiveLogs();
