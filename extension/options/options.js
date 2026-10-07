const DEFAULT_BACKEND = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
  const backendInput = document.getElementById("backendUrl");
  const chkAutoScan = document.getElementById("chkAutoScanDownloads");
  const chkAutoPause = document.getElementById("chkAutoPauseThreats");
  const chkNotifications = document.getElementById("chkShowNotifications");

  const stored = await chrome.storage.sync.get([
    "backendUrl",
    "autoScanDownloads",
    "autoPauseThreats",
    "showNotifications"
  ]);

  let currentUrl = (stored.backendUrl || DEFAULT_BACKEND).trim().replace(/\/+$/, "");
  if (currentUrl === "http://localhost:8000") {
    currentUrl = "http://127.0.0.1:8000";
  }
  backendInput.value = currentUrl;
  chkAutoScan.checked = stored.autoScanDownloads !== false;
  chkAutoPause.checked = stored.autoPauseThreats !== false;
  chkNotifications.checked = stored.showNotifications !== false;

  document.getElementById("btnSave").addEventListener("click", saveSettings);
  document.getElementById("btnTest").addEventListener("click", testConnection);
});

async function saveSettings() {
  const url = document.getElementById("backendUrl").value.trim().replace(/\/+$/, "");
  const autoScanDownloads = document.getElementById("chkAutoScanDownloads").checked;
  const autoPauseThreats = document.getElementById("chkAutoPauseThreats").checked;
  const showNotifications = document.getElementById("chkShowNotifications").checked;

  await chrome.storage.sync.set({
    backendUrl: url,
    autoScanDownloads,
    autoPauseThreats,
    showNotifications
  });
  showStatus("Settings successfully saved!", true);
}

async function testConnection() {
  const url = document.getElementById("backendUrl").value.trim().replace(/\/+$/, "");
  showStatus("Testing connection to " + url + "...", true);

  try {
    let res;
    try {
      res = await fetch(`${url}/api/v1/health`, { method: "GET" });
    } catch (e) {
      if (url.includes("localhost")) {
        const fallback = url.replace("localhost", "127.0.0.1");
        res = await fetch(`${fallback}/api/v1/health`, { method: "GET" });
        document.getElementById("backendUrl").value = fallback;
      } else {
        throw e;
      }
    }
    if (res.ok) {
      const data = await res.json();
      showStatus(`Connected! Service: ${data.service} (v${data.version})`, true);
    } else {
      showStatus(`Backend responded with HTTP ${res.status}`, false);
    }
  } catch (err) {
    showStatus(`Connection failed: ${err.message}. Is the backend running?`, false);
  }
}

function showStatus(text, isOk) {
  const box = document.getElementById("statusBox");
  box.textContent = text;
  box.className = `status-box ${isOk ? "status-ok" : "status-err"}`;
  box.style.display = "block";
}
