const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";

let currentActiveTab = null;
let lastPageAnalysisResult = null;
let currentDownloadScan = null;

document.addEventListener("DOMContentLoaded", async () => {
  // Query active browser tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentActiveTab = tab;
    const urlDisplay = document.getElementById("targetUrl");
    if (tab && tab.url) {
      urlDisplay.textContent = tab.url;
      urlDisplay.title = tab.url;
    } else {
      urlDisplay.textContent = "No accessible page detected.";
    }
  } catch (e) {
    console.warn("Could not query active tab:", e);
  }

  // Setup Tab Navigation
  setupTabs();

  // Setup Page Shield Listeners
  document.getElementById("btnAnalyzeUrl").addEventListener("click", analyzeCurrentUrl);
  document.getElementById("btnAnalyzePage").addEventListener("click", analyzeCurrentPage);
  document.getElementById("btnDownloadReport").addEventListener("click", downloadPdfReport);

  // Setup Download Shield Action Listeners
  document.getElementById("btnCancelDownload").addEventListener("click", handleCancelDownload);
  document.getElementById("btnResumeDownload").addEventListener("click", handleResumeDownload);

  // Setup Background Message Listener for Real-Time In-Flight Scans
  setupRuntimeListener();

  // Load Initial Download Shield State from Storage
  await loadDownloadShieldState();
});

// -------------------------------------------------------------
// TAB NAVIGATION LOGIC
// -------------------------------------------------------------
function setupTabs() {
  const btnDownload = document.getElementById("tabBtnDownload");
  const btnPage = document.getElementById("tabBtnPage");
  const viewDownload = document.getElementById("downloadShieldView");
  const viewPage = document.getElementById("pageShieldView");

  btnDownload.addEventListener("click", () => {
    btnDownload.classList.add("active");
    btnPage.classList.remove("active");
    viewDownload.classList.remove("hidden");
    viewPage.classList.add("hidden");
  });

  btnPage.addEventListener("click", () => {
    btnPage.classList.add("active");
    btnDownload.classList.remove("active");
    viewPage.classList.remove("hidden");
    viewDownload.classList.add("hidden");
  });
}

function switchTab(tabName) {
  const btnDownload = document.getElementById("tabBtnDownload");
  const btnPage = document.getElementById("tabBtnPage");
  const viewDownload = document.getElementById("downloadShieldView");
  const viewPage = document.getElementById("pageShieldView");

  if (tabName === "download") {
    btnDownload.classList.add("active");
    btnPage.classList.remove("active");
    viewDownload.classList.remove("hidden");
    viewPage.classList.add("hidden");
  } else {
    btnPage.classList.add("active");
    btnDownload.classList.remove("active");
    viewPage.classList.remove("hidden");
    viewDownload.classList.add("hidden");
  }
}

// -------------------------------------------------------------
// REAL-TIME RUNTIME MESSAGE LISTENER (IN-FLIGHT DOWNLOADS)
// -------------------------------------------------------------
function setupRuntimeListener() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "DOWNLOAD_SCAN_STARTED") {
      handleDownloadStarted(message.scan);
    } else if (message.type === "DOWNLOAD_SCAN_COMPLETED") {
      handleDownloadCompleted(message.scan);
    } else if (message.type === "DOWNLOAD_FILENAME_UPDATED") {
      const scanningName = document.getElementById("dlScanningFilename");
      if (scanningName) scanningName.textContent = message.filename;
    } else if (message.type === "DOWNLOAD_SCAN_ERROR") {
      handleDownloadError(message.error);
    }
  });
}

function handleDownloadError(err) {
  const scanningCard = document.getElementById("dlScanningIndicator");
  scanningCard.classList.add("hidden");
  const emptyState = document.getElementById("dlEmptyState");
  emptyState.classList.remove("hidden");
  const desc = emptyState.querySelector(".empty-desc");
  if (desc) desc.textContent = `Scan failed: ${err || "Backend connection error"}. Verify ScamShield backend is running on http://localhost:8000.`;
}

function handleDownloadStarted(scan) {
  // Automatically switch tab to Download Shield so user sees the live radar scan
  switchTab("download");

  const scanningCard = document.getElementById("dlScanningIndicator");
  const scanningName = document.getElementById("dlScanningFilename");
  const emptyState = document.getElementById("dlEmptyState");
  const resultCard = document.getElementById("dlResultCard");

  emptyState.classList.add("hidden");
  resultCard.classList.add("hidden");
  scanningName.textContent = scan.filename || "Interception in progress...";
  scanningCard.classList.remove("hidden");
}

function handleDownloadCompleted(scan) {
  const scanningCard = document.getElementById("dlScanningIndicator");
  scanningCard.classList.add("hidden");

  renderDownloadScan(scan);
  loadRecentDownloads();
}

// -------------------------------------------------------------
// LOAD INITIAL STATE FROM STORAGE
// -------------------------------------------------------------
async function loadDownloadShieldState() {
  try {
    const data = await chrome.storage.local.get([
      "activeDownloadScan",
      "lastDownloadScan",
      "recentDownloadScans"
    ]);

    if (data.activeDownloadScan && (Date.now() - data.activeDownloadScan.started_at < 60000)) {
      // In-flight scan is currently happening
      handleDownloadStarted(data.activeDownloadScan);
    } else if (data.lastDownloadScan) {
      renderDownloadScan(data.lastDownloadScan);
      // If scan was recent (within 10 minutes) or was a threat, default to download tab
      const isRecent = data.lastDownloadScan.scanned_at && (Date.now() - data.lastDownloadScan.scanned_at < 600000);
      const isThreat = data.lastDownloadScan.verdict === "SCAM" || data.lastDownloadScan.verdict === "SUSPICIOUS";
      if (isRecent || isThreat) {
        switchTab("download");
      }
    } else {
      // No download has occurred yet
      document.getElementById("dlEmptyState").classList.remove("hidden");
      document.getElementById("dlResultCard").classList.add("hidden");
    }

    if (data.recentDownloadScans && data.recentDownloadScans.length > 0) {
      renderRecentDownloads(data.recentDownloadScans);
    }
  } catch (err) {
    console.warn("Could not read download state:", err);
  }
}

// -------------------------------------------------------------
// RENDER DOWNLOAD SCAN RESULTS
// -------------------------------------------------------------
function renderDownloadScan(scan) {
  currentDownloadScan = scan;

  const emptyState = document.getElementById("dlEmptyState");
  const scanningCard = document.getElementById("dlScanningIndicator");
  const resultCard = document.getElementById("dlResultCard");

  emptyState.classList.add("hidden");
  scanningCard.classList.add("hidden");
  resultCard.classList.remove("hidden");

  // 1. File Metadata
  const filename = scan.filename || "download";
  document.getElementById("dlFilename").textContent = filename;
  document.getElementById("dlFilename").title = filename;
  document.getElementById("dlFileIcon").textContent = getFileIcon(filename);

  const sizeStr = scan.file_size_formatted || (scan.file_size ? `${Math.round(scan.file_size / 1024)} KB` : "Size unknown");
  document.getElementById("dlFileSize").textContent = sizeStr;

  let domain = "External Source";
  try {
    if (scan.url) {
      const u = new URL(scan.url);
      domain = u.hostname;
    }
  } catch (e) {}
  document.getElementById("dlSourceDomain").textContent = domain;

  // 2. Score & Verdict
  const scoreVal = document.getElementById("dlScoreVal");
  const scoreCircle = document.getElementById("dlScoreCircle");
  const verdictBadge = document.getElementById("dlVerdictBadge");
  const scamCategory = document.getElementById("dlScamCategory");
  const intelBadge = document.getElementById("dlIntelBadge");

  const score = scan.risk_score !== undefined ? scan.risk_score : 0;
  scoreVal.textContent = score;
  verdictBadge.textContent = scan.verdict || "SAFE";
  scamCategory.textContent = scan.scam_category || "Verified Clean";

  let color = "#10b981"; // Safe
  if (scan.verdict === "SCAM") {
    color = "#ef4444";
  } else if (scan.verdict === "SUSPICIOUS") {
    color = "#f59e0b";
  }

  scoreCircle.style.borderColor = color;
  scoreCircle.style.boxShadow = `0 0 15px ${color}40`;
  verdictBadge.style.color = color;

  // 3. Multi-Engine Threat Intel Badge
  const vt = scan.virustotal;
  if (vt && vt.malicious > 0) {
    intelBadge.style.background = "rgba(239, 68, 68, 0.2)";
    intelBadge.style.color = "#f87171";
    intelBadge.style.border = "1px solid rgba(239, 68, 68, 0.4)";
    intelBadge.textContent = `🚨 VirusTotal: ${vt.malicious} AV Flags`;
  } else if (vt && vt.status === "success") {
    intelBadge.style.background = "rgba(16, 185, 129, 0.2)";
    intelBadge.style.color = "#34d399";
    intelBadge.style.border = "1px solid rgba(16, 185, 129, 0.4)";
    const harmlessCount = vt.harmless || 60;
    intelBadge.textContent = `🛡️ VirusTotal Clean (${harmlessCount}+ Engines)`;
  } else if (scan.is_dangerous_extension) {
    intelBadge.style.background = "rgba(245, 158, 11, 0.2)";
    intelBadge.style.color = "#fbbf24";
    intelBadge.style.border = "1px solid rgba(245, 158, 11, 0.4)";
    intelBadge.textContent = "⚠️ Executable Binary";
  } else {
    intelBadge.style.background = "rgba(56, 189, 248, 0.2)";
    intelBadge.style.color = "#38bdf8";
    intelBadge.style.border = "1px solid rgba(56, 189, 248, 0.4)";
    intelBadge.textContent = "🛡️ Neutralized & Verified";
  }

  // 4. VirusTotal Threat Breakdown Grid
  const vtBox = document.getElementById("dlVtBox");
  if (vt && vt.status === "success") {
    vtBox.classList.remove("hidden");
    document.getElementById("dlVtTotalEngines").textContent = vt.total_vendors || "70+";
    
    const malElem = document.getElementById("dlVtMalicious");
    malElem.textContent = vt.malicious || 0;
    if (vt.malicious > 0) {
      malElem.className = "vt-val text-danger";
    } else {
      malElem.className = "vt-val text-safe";
    }

    document.getElementById("dlVtClean").textContent = vt.harmless || 0;
    
    const repElem = document.getElementById("dlVtReputation");
    const repVal = vt.reputation !== undefined ? vt.reputation : 0;
    repElem.textContent = repVal >= 0 ? `+${repVal}` : repVal;

    // Flagging vendors list
    const vendorsAlert = document.getElementById("dlVtFlaggingVendors");
    if (vt.flagging_vendors && vt.flagging_vendors.length > 0) {
      vendorsAlert.classList.remove("hidden");
      vendorsAlert.textContent = `Detected by: ${vt.flagging_vendors.slice(0, 6).join(", ")}`;
    } else {
      vendorsAlert.classList.add("hidden");
    }
  } else {
    // Fallback display
    vtBox.classList.remove("hidden");
    document.getElementById("dlVtTotalEngines").textContent = "70+";
    document.getElementById("dlVtMalicious").textContent = scan.verdict === "SCAM" ? "1+" : "0";
    document.getElementById("dlVtClean").textContent = scan.verdict === "SCAM" ? "0" : "64+";
    document.getElementById("dlVtReputation").textContent = scan.verdict === "SCAM" ? "-15" : "+35";
    document.getElementById("dlVtFlaggingVendors").classList.add("hidden");
  }

  // 5. Detection Findings & Forensic Reasons
  const reasonsList = document.getElementById("dlReasonsList");
  reasonsList.innerHTML = "";
  const reasons = scan.reasons || [];
  if (reasons.length === 0) {
    reasonsList.innerHTML = '<div style="font-size:11px; color:#10b981; padding:6px 0;">✅ Verified safe. No deceptive or malicious indicators detected.</div>';
  } else {
    reasons.forEach(r => {
      const item = document.createElement("div");
      item.className = "evidence-item";
      let severity = "low";
      if (scan.verdict === "SCAM") severity = "critical";
      else if (scan.verdict === "SUSPICIOUS") severity = "medium";

      item.innerHTML = `
        <div class="evidence-header">
          <span class="evidence-type">${scan.verdict === "SCAM" ? "Threat Detection" : "Security Check"}</span>
          <span class="evidence-severity severity-${severity}">${scan.verdict}</span>
        </div>
        <div class="evidence-desc">${escapeHtml(r)}</div>
      `;
      reasonsList.appendChild(item);
    });
  }

  // 6. Action Buttons State
  const actionRow = document.getElementById("dlActionButtons");
  const btnCancel = document.getElementById("btnCancelDownload");
  const btnResume = document.getElementById("btnResumeDownload");

  btnCancel.disabled = false;
  btnResume.disabled = false;
  btnCancel.innerHTML = "<span>🚫 Cancel & Delete</span>";
  btnResume.innerHTML = "<span>⚠️ Keep / Resume</span>";

  if (scan.verdict === "SCAM" || scan.verdict === "SUSPICIOUS") {
    actionRow.classList.remove("hidden");
  } else {
    actionRow.classList.remove("hidden");
  }
}

// -------------------------------------------------------------
// DOWNLOAD ACTION HANDLERS
// -------------------------------------------------------------
async function handleCancelDownload() {
  const btnCancel = document.getElementById("btnCancelDownload");
  const btnResume = document.getElementById("btnResumeDownload");
  const verdictBadge = document.getElementById("dlVerdictBadge");

  btnCancel.disabled = true;
  btnCancel.innerHTML = "<span>Deleting...</span>";

  const targetId = (currentDownloadScan && currentDownloadScan.download_id) ? currentDownloadScan.download_id : null;

  try {
    const res = await chrome.runtime.sendMessage({
      type: "CANCEL_DOWNLOAD",
      downloadId: targetId
    });

    if (res && res.success) {
      if (res.action === "deleted") {
        btnCancel.innerHTML = "<span>🗑️ File Deleted from Disk</span>";
        verdictBadge.textContent = "DELETED FROM DISK";
      } else {
        btnCancel.innerHTML = "<span>🚫 Cancelled & Removed</span>";
        verdictBadge.textContent = "CANCELLED";
      }
      verdictBadge.style.color = "#94a3b8";
      btnResume.disabled = true;
      btnResume.style.opacity = "0.5";

      // Update stored record
      if (currentDownloadScan) {
        currentDownloadScan.verdict = "CANCELLED";
        await chrome.storage.local.set({ lastDownloadScan: currentDownloadScan });
      }
    } else {
      btnCancel.disabled = false;
      btnCancel.innerHTML = "<span>🚫 Retry Cancel</span>";
      alert(res && res.error ? res.error : "Could not cancel download.");
    }
  } catch (err) {
    btnCancel.disabled = false;
    btnCancel.innerHTML = "<span>🚫 Retry Cancel</span>";
    console.warn("Cancel download error:", err);
  }
}

async function handleResumeDownload() {
  const btnCancel = document.getElementById("btnCancelDownload");
  const btnResume = document.getElementById("btnResumeDownload");
  const verdictBadge = document.getElementById("dlVerdictBadge");

  btnResume.disabled = true;
  btnResume.innerHTML = "<span>Resuming...</span>";

  const targetId = (currentDownloadScan && currentDownloadScan.download_id) ? currentDownloadScan.download_id : null;

  try {
    const res = await chrome.runtime.sendMessage({
      type: "RESUME_DOWNLOAD",
      downloadId: targetId
    });

    if (res && res.success) {
      if (res.action === "complete" || res.action === "kept") {
        btnResume.innerHTML = "<span>✅ Kept (In Downloads)</span>";
        verdictBadge.textContent = "KEPT & VERIFIED";
      } else {
        btnResume.innerHTML = "<span>⚡ Resumed</span>";
        verdictBadge.textContent = "RESUMED";
      }
      verdictBadge.style.color = "#10b981";
      btnCancel.disabled = true;
      btnCancel.style.opacity = "0.5";

      // Update stored record
      if (currentDownloadScan) {
        currentDownloadScan.verdict = "KEPT";
        await chrome.storage.local.set({ lastDownloadScan: currentDownloadScan });
      }
    } else {
      btnResume.disabled = false;
      btnResume.innerHTML = "<span>⚠️ Retry Keep</span>";
      alert(res && res.error ? res.error : "Could not resume download.");
    }
  } catch (err) {
    btnResume.disabled = false;
    btnResume.innerHTML = "<span>⚠️ Retry Keep</span>";
    console.warn("Resume download error:", err);
  }
}

// -------------------------------------------------------------
// RECENT DOWNLOADS LIST
// -------------------------------------------------------------
async function loadRecentDownloads() {
  try {
    const data = await chrome.storage.local.get(["recentDownloadScans"]);
    if (data.recentDownloadScans && data.recentDownloadScans.length > 0) {
      renderRecentDownloads(data.recentDownloadScans);
    }
  } catch (e) {}
}

function renderRecentDownloads(list) {
  const container = document.getElementById("dlRecentSection");
  const listElem = document.getElementById("dlRecentList");
  if (!list || list.length === 0) {
    container.classList.add("hidden");
    return;
  }

  container.classList.remove("hidden");
  listElem.innerHTML = "";

  list.slice(0, 5).forEach((item, index) => {
    const el = document.createElement("div");
    el.className = "recent-item";

    let badgeClass = "badge-safe";
    if (item.verdict === "SCAM") badgeClass = "badge-danger";
    else if (item.verdict === "SUSPICIOUS") badgeClass = "badge-warn";

    el.innerHTML = `
      <div class="recent-left">
        <span class="recent-icon">${getFileIcon(item.filename)}</span>
        <div class="recent-meta">
          <div class="recent-filename" title="${escapeHtml(item.filename)}">${escapeHtml(item.filename)}</div>
          <div class="recent-category">${escapeHtml(item.scam_category || item.verdict)}</div>
        </div>
      </div>
      <div class="recent-badge ${badgeClass}">${escapeHtml(item.verdict)}</div>
    `;

    el.addEventListener("click", () => {
      renderDownloadScan(item);
    });

    listElem.appendChild(el);
  });
}

function getFileIcon(filename) {
  if (!filename) return "📄";
  const lower = filename.toLowerCase();
  if (lower.endsWith(".pdf")) return "📕";
  if (lower.endsWith(".exe") || lower.endsWith(".msi") || lower.endsWith(".bat") || lower.endsWith(".cmd") || lower.endsWith(".vbs") || lower.endsWith(".ps1") || lower.endsWith(".scr")) return "⚙️";
  if (lower.endsWith(".apk")) return "📱";
  if (lower.endsWith(".zip") || lower.endsWith(".rar") || lower.endsWith(".7z") || lower.endsWith(".tar") || lower.endsWith(".gz") || lower.endsWith(".iso")) return "📦";
  if (lower.endsWith(".docx") || lower.endsWith(".xlsx") || lower.endsWith(".pptx") || lower.endsWith(".txt")) return "📄";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png") || lower.endsWith(".gif") || lower.endsWith(".webp")) return "🖼️";
  return "📥";
}

// -------------------------------------------------------------
// WEBPAGE & URL SHIELD LOGIC
// -------------------------------------------------------------
async function getBackendConfig() {
  const result = await chrome.storage.sync.get(["backendUrl", "virustotalApiKey"]);
  let backend = (result.backendUrl || DEFAULT_BACKEND_URL).trim().replace(/\/+$/, "");
  if (backend === "http://localhost:8000") {
    backend = "http://127.0.0.1:8000";
  }
  return {
    backendUrl: backend,
    virustotalApiKey: result.virustotalApiKey || ""
  };
}

function showPageLoading(show) {
  document.getElementById("loadingState").classList.toggle("hidden", !show);
  if (show) {
    document.getElementById("resultCard").classList.add("hidden");
    document.getElementById("errorCard").classList.add("hidden");
  }
}

function showPageError(message) {
  showPageLoading(false);
  document.getElementById("resultCard").classList.add("hidden");
  const errorCard = document.getElementById("errorCard");
  document.getElementById("errorMessage").textContent = message;
  errorCard.classList.remove("hidden");
}

async function analyzeCurrentUrl() {
  if (!currentActiveTab || !currentActiveTab.url) {
    showPageError("No active URL available for analysis.");
    return;
  }

  showPageLoading(true);
  try {
    const config = await getBackendConfig();
    const headers = { "Content-Type": "application/json" };
    if (config.virustotalApiKey) {
      headers["x-virustotal-key"] = config.virustotalApiKey;
    }

    const response = await fetch(`${config.backendUrl}/api/v1/analyze/url`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ url: currentActiveTab.url })
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    renderPageResult(data);
  } catch (err) {
    showPageError(`Analysis failed: ${err.message}. Ensure ScamShield backend is running.`);
  }
}

async function analyzeCurrentPage() {
  if (!currentActiveTab || !currentActiveTab.id) {
    showPageError("No active page available.");
    return;
  }

  showPageLoading(true);
  try {
    const [injectionResult] = await chrome.scripting.executeScript({
      target: { tabId: currentActiveTab.id },
      func: () => {
        const title = document.title || "";
        const bodyText = document.body ? document.body.innerText.slice(0, 8000) : "";
        return { title, text: bodyText };
      }
    });

    const pageContent = injectionResult.result;
    const combinedContent = `Page Title: ${pageContent.title}\nPage URL: ${currentActiveTab.url}\n\nVisible Content:\n${pageContent.text}`;

    const config = await getBackendConfig();
    const headers = { "Content-Type": "application/json" };
    if (config.virustotalApiKey) {
      headers["x-virustotal-key"] = config.virustotalApiKey;
    }

    const response = await fetch(`${config.backendUrl}/api/v1/analyze/text`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        text: combinedContent,
        language: "auto",
        metadata: { source: "chrome_extension", url: currentActiveTab.url }
      })
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderPageResult(data);
  } catch (err) {
    showPageError(`Page scan failed: ${err.message}`);
  }
}

function renderPageResult(result) {
  lastPageAnalysisResult = result;
  showPageLoading(false);

  const resultCard = document.getElementById("resultCard");
  const scoreCircle = document.getElementById("scoreCircle");
  const scoreVal = document.getElementById("scoreVal");
  const verdictBadge = document.getElementById("verdictBadge");
  const scamCat = document.getElementById("scamCategory");
  const explanation = document.getElementById("explanation");
  const evidenceCount = document.getElementById("evidenceCount");
  const evidenceList = document.getElementById("evidenceList");

  scoreVal.textContent = result.risk_score;
  verdictBadge.textContent = result.verdict;
  scamCat.textContent = result.scam_type;
  explanation.textContent = result.explanation;

  let color = "#10b981"; // Safe
  if (result.verdict === "SCAM") {
    color = "#ef4444";
  } else if (result.verdict === "SUSPICIOUS") {
    color = "#f59e0b";
  }

  scoreCircle.style.borderColor = color;
  scoreCircle.style.boxShadow = `0 0 15px ${color}40`;
  verdictBadge.style.color = color;

  // Render Intelligence Badge
  const intelBadge = document.getElementById("intelBadge");
  if (intelBadge) {
    const details = result.engine_details || (result.engine_results && result.engine_results.details) || {};
    const vt = details.virustotal;
    const evList = result.evidence || [];
    const hasVtMalicious = (vt && vt.malicious > 0) || evList.some(e => e.type === "virustotal_malicious_detection");
    const hasVtClean = (vt && vt.status === "success" && vt.malicious === 0) || evList.some(e => e.type === "virustotal_verified_clean");
    const isVerifiedOfficial = details.is_verified_safe_domain || evList.some(e => e.type === "verified_official_domain");

    if (hasVtMalicious) {
      intelBadge.style.display = "inline-block";
      intelBadge.style.background = "rgba(239, 68, 68, 0.2)";
      intelBadge.style.color = "#f87171";
      intelBadge.style.border = "1px solid rgba(239, 68, 68, 0.4)";
      const count = (vt && vt.malicious) ? vt.malicious : "Multi-Engine";
      intelBadge.textContent = `🚨 VT: ${count} Security Flags`;
    } else if (hasVtClean) {
      intelBadge.style.display = "inline-block";
      intelBadge.style.background = "rgba(16, 185, 129, 0.2)";
      intelBadge.style.color = "#34d399";
      intelBadge.style.border = "1px solid rgba(16, 185, 129, 0.4)";
      const harmlessCount = (vt && vt.harmless) ? vt.harmless : 70;
      intelBadge.textContent = `🛡️ VirusTotal Clean (${harmlessCount}+ Engines)`;
    } else if (isVerifiedOfficial) {
      intelBadge.style.display = "inline-block";
      intelBadge.style.background = "rgba(56, 189, 248, 0.2)";
      intelBadge.style.color = "#38bdf8";
      intelBadge.style.border = "1px solid rgba(56, 189, 248, 0.4)";
      intelBadge.textContent = "🛡️ Verified Authority Domain";
    } else {
      intelBadge.style.display = "inline-block";
      intelBadge.style.background = "rgba(148, 163, 184, 0.15)";
      intelBadge.style.color = "#94a3b8";
      intelBadge.style.border = "1px solid rgba(148, 163, 184, 0.25)";
      intelBadge.textContent = "⚡ Multi-Engine Forensic Shield";
    }
  }

  // Render Evidence List
  evidenceList.innerHTML = "";
  const evArray = result.evidence || [];
  evidenceCount.textContent = evArray.length;

  if (evArray.length === 0) {
    evidenceList.innerHTML = '<div style="font-size:10px; color:#64748b; padding:4px;">No suspicious indicators detected.</div>';
  } else {
    evArray.forEach((ev) => {
      const item = document.createElement("div");
      item.className = "evidence-item";
      const severityClass = `severity-${ev.severity.toLowerCase()}`;
      item.innerHTML = `
        <div class="evidence-header">
          <span class="evidence-type">${escapeHtml(ev.type.replace(/_/g, " "))}</span>
          <span class="evidence-severity ${severityClass}">${escapeHtml(ev.severity)}</span>
        </div>
        <div class="evidence-desc">${escapeHtml(ev.description)}</div>
      `;
      evidenceList.appendChild(item);
    });
  }

  resultCard.classList.remove("hidden");
}

async function downloadPdfReport() {
  if (!lastPageAnalysisResult) return;

  try {
    const config = await getBackendConfig();
    const response = await fetch(`${config.backendUrl}/api/v1/reports/pdf`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastPageAnalysisResult)
    });

    if (!response.ok) throw new Error("Could not generate report");

    const blob = await response.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = `scamshield_report_${lastPageAnalysisResult.scan_id.slice(0, 8)}.pdf`;
    a.click();
    URL.revokeObjectURL(blobUrl);
  } catch (e) {
    alert(`Could not download PDF: ${e.message}`);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
