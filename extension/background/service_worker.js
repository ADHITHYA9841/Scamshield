const DEFAULT_BACKEND = "http://127.0.0.1:8000";

// Map notification ID to download item ID for actionable response
const notificationDownloadMap = new Map();
let popupWindowId = null;
const scanStateByDownloadId = new Map();
let lastPopupOpenedAt = 0;

// Resilient fetch helper to seamlessly bridge localhost IPv6/IPv4 resolution quirks on Windows
async function fetchWithFallback(url, options) {
  try {
    return await fetch(url, options);
  } catch (err) {
    if (url.includes("localhost")) {
      const fallbackUrl = url.replace("localhost", "127.0.0.1");
      return await fetch(fallbackUrl, options);
    } else if (url.includes("127.0.0.1")) {
      const fallbackUrl = url.replace("127.0.0.1", "localhost");
      return await fetch(fallbackUrl, options);
    }
    throw err;
  }
}

// Clean up popupWindowId if user closes the window
chrome.windows.onRemoved.addListener((winId) => {
  if (winId === popupWindowId) {
    popupWindowId = null;
  }
});

// Set up Context Menus on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scamshield-analyze-text",
    title: "🛡️ Analyze Selected Text with ScamShield",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "scamshield-analyze-link",
    title: "🔗 Inspect Link with ScamShield",
    contexts: ["link"]
  });
});

async function getSettings() {
  const data = await chrome.storage.sync.get([
    "backendUrl",
    "virustotalApiKey",
    "autoScanDownloads",
    "autoPauseThreats",
    "showNotifications"
  ]);
  let backend = (data.backendUrl || DEFAULT_BACKEND).trim().replace(/\/+$/, "");
  if (backend === "http://localhost:8000") {
    backend = "http://127.0.0.1:8000";
  }
  return {
    backendUrl: backend,
    virustotalApiKey: data.virustotalApiKey || "",
    autoScanDownloads: data.autoScanDownloads !== false, // default true
    autoPauseThreats: data.autoPauseThreats !== false,   // default true
    showNotifications: data.showNotifications !== false // default true
  };
}

// -------------------------------------------------------------
// AUTOMATIC POPUP LAUNCHER
// Opens the ScamShield Inspector popup automatically when download begins
// -------------------------------------------------------------
async function openInspectionPopup() {
  const now = Date.now();
  if (popupWindowId !== null || now - lastPopupOpenedAt < 3000) {
    if (popupWindowId !== null) {
      try {
        await chrome.windows.update(popupWindowId, { focused: false });
      } catch (e) {
        popupWindowId = null;
      }
    }
    return;
  }
  lastPopupOpenedAt = now;

  // 1. Try standard action popup if supported by browser context
  if (chrome.action && typeof chrome.action.openPopup === "function") {
    try {
      await chrome.action.openPopup();
      return;
    } catch (e) {
      // openPopup requires user gesture in some Chrome versions; fall through to floating window
    }
  }

  // 2. Open sleek floating popup window on screen
  try {
    if (popupWindowId !== null) {
      try {
        const existing = await chrome.windows.get(popupWindowId);
        if (existing) {
          await chrome.windows.update(popupWindowId, { focused: true });
          return;
        }
      } catch (e) {
        popupWindowId = null;
      }
    }

    // Position window nicely in the top-right corner
    let left = 1100;
    let top = 80;
    try {
      const currentWin = await chrome.windows.getLastFocused();
      if (currentWin && currentWin.width) {
        left = Math.max(0, (currentWin.left || 0) + currentWin.width - 410);
        top = Math.max(0, (currentWin.top || 0) + 60);
      }
    } catch (e) {}

    const popupWin = await chrome.windows.create({
      url: chrome.runtime.getURL("popup/popup.html?auto=1"),
      type: "popup",
      width: 380,
      height: 640,
      left: left,
      top: top,
      focused: true
    });
    popupWindowId = popupWin.id;
  } catch (err) {
    console.warn("Could not auto-open popup window:", err);
  }
}

// Safe helper to extract filename from download item
function extractFilename(downloadItem) {
  if (downloadItem.filename && downloadItem.filename.trim()) {
    return downloadItem.filename.split(/[\\/]/).pop();
  }
  const url = downloadItem.url || downloadItem.finalUrl || "";
  if (url) {
    try {
      const pathname = new URL(url).pathname;
      const base = pathname.split("/").filter(Boolean).pop();
      if (base) return decodeURIComponent(base);
    } catch (e) {
      const parts = url.split(/[/?#]/).filter(Boolean);
      if (parts.length > 0) return parts[parts.length - 1];
    }
  }
  return "downloading_file";
}

// -------------------------------------------------------------
// CANCEL & DELETE / KEEP & RESUME ACTIONS
// -------------------------------------------------------------
async function cancelAndDeleteDownload(downloadId) {
  if (!downloadId) {
    const recent = await chrome.downloads.search({ limit: 1, orderBy: ["-startTime"] });
    if (recent && recent.length > 0) {
      downloadId = recent[0].id;
    }
  }
  if (!downloadId) {
    throw new Error("No download found to cancel.");
  }

  const items = await chrome.downloads.search({ id: downloadId });
  const item = items && items.length > 0 ? items[0] : null;

  if (item) {
    if (item.state === "in_progress") {
      try {
        await chrome.downloads.cancel(downloadId);
      } catch (err) {
        console.warn("Cancel in_progress error:", err);
      }
      try {
        await chrome.downloads.erase({ id: downloadId });
      } catch (err) {}
      return { success: true, action: "cancelled", message: "Download cancelled and removed." };
    } else if (item.state === "complete") {
      // File has already completed: delete file from disk & remove from Chrome history
      try {
        await chrome.downloads.removeFile(downloadId);
      } catch (err) {
        console.warn("Remove file from disk error:", err);
      }
      try {
        await chrome.downloads.erase({ id: downloadId });
      } catch (err) {}
      return { success: true, action: "deleted", message: "File deleted from disk and removed from downloads." };
    } else {
      // Interrupted or already cancelled
      try {
        await chrome.downloads.erase({ id: downloadId });
      } catch (err) {}
      return { success: true, action: "erased", message: "Download record removed." };
    }
  } else {
    // Fallback: attempt both cancel and removeFile
    try { await chrome.downloads.cancel(downloadId); } catch (e) {}
    try { await chrome.downloads.removeFile(downloadId); } catch (e) {}
    try { await chrome.downloads.erase({ id: downloadId }); } catch (e) {}
    return { success: true, action: "cancelled", message: "Download cancelled." };
  }
}

async function keepAndResumeDownload(downloadId) {
  if (!downloadId) {
    const recent = await chrome.downloads.search({ limit: 1, orderBy: ["-startTime"] });
    if (recent && recent.length > 0) {
      downloadId = recent[0].id;
    }
  }
  if (!downloadId) {
    throw new Error("No download found to resume.");
  }

  const items = await chrome.downloads.search({ id: downloadId });
  const item = items && items.length > 0 ? items[0] : null;

  if (item) {
    if (item.state === "in_progress") {
      if (item.paused) {
        await chrome.downloads.resume(downloadId);
        return { success: true, action: "resumed", message: "Download resumed." };
      } else {
        return { success: true, action: "in_progress", message: "Download is continuing." };
      }
    } else if (item.state === "complete") {
      try {
        await chrome.downloads.show(downloadId);
      } catch (e) {}
      return { success: true, action: "complete", message: "File is kept in your Downloads folder." };
    } else if (item.state === "interrupted") {
      if (item.canResume) {
        await chrome.downloads.resume(downloadId);
        return { success: true, action: "resumed", message: "Download resumed." };
      }
    }
  }

  // Fallback direct resume
  try {
    await chrome.downloads.resume(downloadId);
    return { success: true, action: "resumed", message: "Download resumed." };
  } catch (err) {
    return { success: true, action: "kept", message: "File is kept." };
  }
}

// -------------------------------------------------------------
// AUTOMATIC CHROME DOWNLOAD INSPECTOR
// -------------------------------------------------------------
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (scanStateByDownloadId.has(downloadItem.id)) {
    return;
  }
  scanStateByDownloadId.set(downloadItem.id, { status: "started", startedAt: Date.now() });

  const settings = await getSettings();

  // If user disabled auto download scanning in options, skip
  if (!settings.autoScanDownloads) {
    return;
  }

  const filename = extractFilename(downloadItem);
  const sourceUrl = downloadItem.url || downloadItem.finalUrl || "";
  const lowerName = filename.toLowerCase();

  // 1. Immediately indicate scanning state in badge and storage
  chrome.action.setBadgeText({ text: "SCAN" });
  chrome.action.setBadgeBackgroundColor({ color: "#3b82f6" });

  const activeScan = {
    status: "scanning",
    download_id: downloadItem.id,
    filename: filename,
    url: sourceUrl,
    file_size: downloadItem.fileSize || null,
    started_at: Date.now()
  };
  await chrome.storage.local.set({ activeDownloadScan: activeScan });

  // 2. Automatically launch the inspection popup window on screen
  openInspectionPopup().catch(() => {});

  // Broadcast to popup if already open
  chrome.runtime.sendMessage({ type: "DOWNLOAD_SCAN_STARTED", scan: activeScan }).catch(() => {});

  // Fast synchronous threat pre-pause: If filename is obviously dangerous, pause immediately
  const isDoubleExt = /\.(pdf|docx|xlsx|jpg|png|txt|zip)\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$/.test(lowerName);
  const dangerousExts = [".exe", ".apk", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".jar", ".iso", ".reg", ".dll", ".hta"];
  const isDangerousExt = dangerousExts.some(ext => lowerName.endsWith(ext));

  let prePaused = false;
  if ((isDoubleExt || isDangerousExt) && settings.autoPauseThreats) {
    try {
      await chrome.downloads.pause(downloadItem.id);
      prePaused = true;
    } catch (e) {
      console.warn("Could not pre-pause download:", e);
    }
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (settings.virustotalApiKey) {
      headers["x-virustotal-key"] = settings.virustotalApiKey;
    }

    const res = await fetchWithFallback(`${settings.backendUrl}/api/v1/analyze/download`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        url: sourceUrl,
        filename: filename,
        referrer: downloadItem.referrer || null,
        file_size: downloadItem.fileSize || null,
        mime_type: downloadItem.mime || null
      })
    });

    if (!res.ok) {
      console.warn("ScamShield download scan failed: HTTP", res.status);
      chrome.action.setBadgeText({ text: "ERR" });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
      scanStateByDownloadId.set(downloadItem.id, { status: "error", finishedAt: Date.now() });
      await chrome.storage.local.set({ activeDownloadScan: null });
      chrome.runtime.sendMessage({ type: "DOWNLOAD_SCAN_ERROR", error: `HTTP ${res.status}` }).catch(() => {});
      return;
    }

    const data = await res.json();
    scanStateByDownloadId.set(downloadItem.id, { status: "complete", finishedAt: Date.now() });
    data.download_id = downloadItem.id;
    data.scanned_at = Date.now();

    // Store in chrome.storage.local for popup instant retrieval
    const stored = await chrome.storage.local.get(["recentDownloadScans"]);
    const recentList = stored.recentDownloadScans || [];
    recentList.unshift(data);
    if (recentList.length > 15) recentList.pop();

    await chrome.storage.local.set({
      lastDownloadScan: data,
      recentDownloadScans: recentList,
      activeDownloadScan: null
    });

    // Broadcast scan completed to popup
    chrome.runtime.sendMessage({ type: "DOWNLOAD_SCAN_COMPLETED", scan: data }).catch(() => {});

    // Manage download pause / resume according to analysis verdict
    if (data.should_pause && settings.autoPauseThreats) {
      if (!prePaused) {
        try {
          await chrome.downloads.pause(downloadItem.id);
        } catch (pauseErr) {
          console.warn("Could not pause download:", pauseErr);
        }
      }
    } else if (prePaused && data.verdict === "SAFE") {
      // If it was pre-paused because of .exe but verified clean on official domain, unpause automatically
      try {
        await chrome.downloads.resume(downloadItem.id);
      } catch (resumeErr) {
        console.warn("Could not auto-resume verified download:", resumeErr);
      }
    }

    // Update Extension Badge
    if (data.verdict === "SCAM") {
      chrome.action.setBadgeText({ text: "SCAM" });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    } else if (data.verdict === "SUSPICIOUS") {
      chrome.action.setBadgeText({ text: "WARN" });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    } else {
      chrome.action.setBadgeText({ text: "SAFE" });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
      setTimeout(() => {
        chrome.action.setBadgeText({ text: "" });
      }, 10000);
    }

    // Trigger rich interactive notification for SCAM or SUSPICIOUS downloads
    if ((data.verdict === "SCAM" || data.verdict === "SUSPICIOUS") && settings.showNotifications) {
      const notifId = `scamshield-dl-${downloadItem.id}-${Date.now()}`;
      notificationDownloadMap.set(notifId, downloadItem.id);

      chrome.notifications.create(notifId, {
        type: "basic",
        iconUrl: "../icons/icon128.png",
        title: data.notification_title,
        message: data.notification_message,
        priority: 2,
        requireInteraction: true,
        buttons: [
          { title: "🚫 Cancel & Delete" },
          { title: "⚠️ Keep / Resume" }
        ]
      });
    }
  } catch (err) {
    console.error("ScamShield download inspection error:", err);
    scanStateByDownloadId.set(downloadItem.id, { status: "error", finishedAt: Date.now() });
    chrome.action.setBadgeText({ text: "ERR" });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    await chrome.storage.local.set({ activeDownloadScan: null });
    chrome.runtime.sendMessage({ type: "DOWNLOAD_SCAN_ERROR", error: err.message }).catch(() => {});
  }
});

chrome.downloads.onErased.addListener((downloadId) => {
  scanStateByDownloadId.delete(downloadId);
});

// Update scan filename if Chrome resolves it later via onChanged
chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.filename && delta.filename.current) {
    const finalName = delta.filename.current.split(/[\\/]/).pop();
    const stored = await chrome.storage.local.get(["activeDownloadScan", "lastDownloadScan"]);
    if (stored.activeDownloadScan && stored.activeDownloadScan.download_id === delta.id) {
      stored.activeDownloadScan.filename = finalName;
      await chrome.storage.local.set({ activeDownloadScan: stored.activeDownloadScan });
      chrome.runtime.sendMessage({ type: "DOWNLOAD_FILENAME_UPDATED", filename: finalName }).catch(() => {});
    }
  }
});

// Handle interactive notification buttons (Cancel / Resume download)
chrome.notifications.onButtonClicked.addListener(async (notifId, btnIndex) => {
  let downloadId = notificationDownloadMap.get(notifId);
  if (!downloadId) {
    const match = notifId.match(/^scamshield-dl-(\d+)/);
    if (match) {
      downloadId = parseInt(match[1], 10);
    }
  }

  if (btnIndex === 0) {
    // User chose "Cancel & Delete"
    try {
      await cancelAndDeleteDownload(downloadId);
      chrome.notifications.clear(notifId);
      chrome.action.setBadgeText({ text: "CLEAN" });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
      setTimeout(() => chrome.action.setBadgeText({ text: "" }), 5000);
    } catch (e) {
      console.warn("Error cancelling download from notification:", e);
    }
  } else if (btnIndex === 1) {
    // User chose "Keep / Resume" at their own risk
    try {
      await keepAndResumeDownload(downloadId);
      chrome.notifications.clear(notifId);
      chrome.action.setBadgeText({ text: "SAFE" });
      chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
      setTimeout(() => chrome.action.setBadgeText({ text: "" }), 5000);
    } catch (e) {
      console.warn("Error resuming download from notification:", e);
    }
  }
});

// -------------------------------------------------------------
// CONTEXT MENU INSPECTOR
// -------------------------------------------------------------
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const settings = await getSettings();

  if (info.menuItemId === "scamshield-analyze-text" && info.selectionText) {
    try {
      chrome.action.setBadgeText({ text: "...", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#3b82f6", tabId: tab.id });

      const res = await fetchWithFallback(`${settings.backendUrl}/api/v1/analyze/text`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: info.selectionText })
      });
      const data = await res.json();
      updateBadge(data.risk_score, data.verdict, tab.id);
    } catch (e) {
      chrome.action.setBadgeText({ text: "ERR", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tab.id });
    }
  } else if (info.menuItemId === "scamshield-analyze-link" && info.linkUrl) {
    try {
      chrome.action.setBadgeText({ text: "...", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#3b82f6", tabId: tab.id });

      const linkHeaders = { "Content-Type": "application/json" };
      if (settings.virustotalApiKey) {
        linkHeaders["x-virustotal-key"] = settings.virustotalApiKey;
      }

      const res = await fetchWithFallback(`${settings.backendUrl}/api/v1/analyze/url`, {
        method: "POST",
        headers: linkHeaders,
        body: JSON.stringify({ url: info.linkUrl })
      });
      const data = await res.json();
      updateBadge(data.risk_score, data.verdict, tab.id);
    } catch (e) {
      chrome.action.setBadgeText({ text: "ERR", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tab.id });
    }
  }
});

function updateBadge(score, verdict, tabId) {
  const text = score.toString();
  let color = "#10b981"; // Safe
  if (verdict === "SCAM") color = "#ef4444";
  else if (verdict === "SUSPICIOUS") color = "#f59e0b";

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// -------------------------------------------------------------
// RUNTIME MESSAGE HANDLER (From Popup UI)
// -------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CANCEL_DOWNLOAD") {
    cancelAndDeleteDownload(message.downloadId)
      .then((res) => {
        chrome.action.setBadgeText({ text: "CLEAN" });
        chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
        setTimeout(() => chrome.action.setBadgeText({ text: "" }), 5000);
        sendResponse(res);
      })
      .catch((err) => {
        console.warn("Cancel download error:", err);
        sendResponse({ success: false, error: err.message });
      });
    return true; // Keep channel open for async response
  } else if (message.type === "RESUME_DOWNLOAD") {
    keepAndResumeDownload(message.downloadId)
      .then((res) => {
        chrome.action.setBadgeText({ text: "SAFE" });
        chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
        setTimeout(() => chrome.action.setBadgeText({ text: "" }), 5000);
        sendResponse(res);
      })
      .catch((err) => {
        console.warn("Resume download error:", err);
        sendResponse({ success: false, error: err.message });
      });
    return true; // Keep channel open for async response
  }
});
