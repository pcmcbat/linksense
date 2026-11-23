document.addEventListener("DOMContentLoaded", async () => {
  const elements = {
    hero: document.getElementById("heroBanner"), label: document.getElementById("verdict-label"), message: document.getElementById("status-message"),
    url: document.getElementById("site-url"), gauge: document.getElementById("gauge-progress"), gaugeValue: document.getElementById("gauge-value"),
    source: document.getElementById("source"), scanCount: document.getElementById("scan-count"), threatCount: document.getElementById("threat-count"),
    dot: document.getElementById("protection-dot"), footer: document.getElementById("footer-status"), refresh: document.getElementById("refresh-button"),
    whitelist: document.getElementById("whitelist-button"), toggle: document.getElementById("toggle-protection"), flagList: document.getElementById("flag-list"), errorList: document.getElementById("error-list"), historyList: document.getElementById("history-list"), manualForm: document.getElementById("manual-scan-form"), manualUrl: document.getElementById("manual-url"), manualStatus: document.getElementById("manual-scan-status"),
    threatPanel: document.getElementById("threat-panel"), threatTitle: document.getElementById("threat-title"), threatUrl: document.getElementById("threat-url"), allowThreatButton: document.getElementById("allow-threat-button"), blockThreatButton: document.getElementById("block-threat-button"),
    backendForm: document.getElementById("backend-form"), backendUrl: document.getElementById("backend-url"), backendStatus: document.getElementById("backend-status"),
    providerList: document.getElementById("provider-list")
  };
  const [tabs, stored] = await Promise.all([chrome.tabs.query({ active: true, currentWindow: true }), chrome.storage.local.get(["lastAnalysis", "scanCount", "threatCount", "history", "protectionActive", "whitelistedDomains", "reputationBackendUrl"]) ]);
  const tab = tabs[0];
  let active = stored.protectionActive !== false;
  const blockedTarget = (() => {
    try {
      const parsed = new URL(tab.url);
      return parsed.pathname.endsWith("/blocked.html") ? parsed.searchParams.get("url") || "" : "";
    } catch { return ""; }
  })();
  const scanTarget = blockedTarget || tab?.url || "";
  const domain = (() => { try { return new URL(scanTarget).hostname; } catch { return ""; } })();
  elements.backendUrl.value = stored.reputationBackendUrl || "http://127.0.0.1:8787/scan";

  function render(analysis = stored.lastAnalysis, counts = stored) {
    const renderProviders = providers => {
      elements.providerList.replaceChildren();
      if (!providers?.length) {
        const row = document.createElement("li");
        row.className = "empty";
        row.textContent = "No provider results yet";
        elements.providerList.appendChild(row);
        return;
      }
      providers.forEach(provider => {
        const row = document.createElement("li");
        const name = document.createElement("span");
        const result = document.createElement("strong");
        name.textContent = provider.name;
        result.textContent = provider.available ? provider.verdict : provider.pending ? "Pending" : "Unavailable";
        row.className = provider.available ? provider.verdict : provider.pending ? "pending" : "error";
        row.title = provider.error || "";
        row.append(name, result);
        elements.providerList.appendChild(row);
      });
    };
    const pendingThreat = (counts.pendingThreat ?? stored.pendingThreat ?? null) || (analysis && !analysis.blocked && (analysis.verdict === "malicious" || analysis.verdict === "suspicious") ? analysis : null);
    if (pendingThreat) {
      elements.threatPanel.classList.remove("hidden");
      elements.threatTitle.textContent = pendingThreat.verdict === "malicious" ? "Malicious website detected" : "Suspicious website detected";
      elements.threatUrl.textContent = pendingThreat.url || "Unknown URL";
      elements.allowThreatButton.onclick = () => {
        chrome.runtime.sendMessage({ type: "THREAT_DECISION", decision: "continue", url: pendingThreat.url, verdict: pendingThreat.verdict, tabId: tab?.id });
        elements.threatPanel.classList.add("hidden");
      };
      elements.blockThreatButton.onclick = () => {
        chrome.runtime.sendMessage({ type: "THREAT_DECISION", decision: "block", url: pendingThreat.url, verdict: pendingThreat.verdict, tabId: tab?.id });
        elements.threatPanel.classList.add("hidden");
      };
    } else {
      elements.threatPanel.classList.add("hidden");
    }

    const trustedDomains = (counts.whitelistedDomains ?? stored.whitelistedDomains ?? []).map(value => String(value).toLowerCase().replace(/^www\./, ""));
    const isTrustedDomain = !!domain && trustedDomains.includes(domain.toLowerCase().replace(/^www\./, ""));
    const match = analysis && analysis.url === scanTarget;
    const verdict = match ? analysis.partial && !analysis.blocked ? "pending" : analysis.verdict : "scanning";
    const copy = { scanning: ["Analyzing page", "Local checks are running."], safe: ["Looks safe", "No meaningful risk signals found."], suspicious: ["Use caution", "Some signals deserve a closer look."], malicious: ["Threat detected", "LinkSense found a high-risk pattern."], pending: ["Scan still running", "Remote intelligence is finishing."], unavailable: ["Scan unavailable", "Local checks are still available."] }[verdict] || ["Analyzing page", "Checking reputation signals."];
    const hybridScore = match ? (Number.isFinite(analysis.risk_score) ? analysis.risk_score : (Number.isFinite(analysis.score) ? analysis.score : 0)) : 0;
    elements.hero.className = `verdict-panel ${verdict}`;
    const signalSummary = (analysis?.signals || []).slice(0, 3).join(", ");
    const consensusMessage = match && analysis.consensus
      ? `${analysis.partial ? "Provisional consensus" : "Consensus"}: ${analysis.consensusVerdict} (${analysis.consensus.available}/${analysis.consensus.total} providers).`
      : "";
    const blockMessage = match && analysis.blocked
      ? `Blocked automatically after a provider reported risk. ${consensusMessage}`
      : consensusMessage;
    const detailedMessage = signalSummary && (verdict === "suspicious" || verdict === "malicious")
      ? `${copy[1]} Flags: ${signalSummary}.` : copy[1];
    elements.label.textContent = copy[0]; elements.message.textContent = active ? (blockMessage || detailedMessage) : "Protection is paused.";
    elements.url.textContent = scanTarget || "This page cannot be scanned"; elements.gaugeValue.textContent = match ? hybridScore : "--";
    elements.gauge.style.strokeDashoffset = `${264 - (264 * hybridScore / 100)}`; elements.source.textContent = match ? analysis.source || "Local scan" : "Local scan";
    renderProviders(match ? analysis.providers : []);

    const aiExplanation = document.getElementById("ai-explanation");
    const aiAction = document.getElementById("ai-recommended-action");
    const mlProb = document.getElementById("ml-probability");
    const heuristicScoreEl = document.getElementById("heuristic-score");
    const modelVersion = document.getElementById("model-version");
    const confidenceEl = document.getElementById("confidence");
    const recAction = match ? (analysis.recommended_action || (verdict === "malicious" ? "Avoid interacting with this URL." : verdict === "suspicious" ? "Proceed with caution and verify the destination." : verdict === "safe" ? "No specific action required." : "")) : "";
    if (aiExplanation) aiExplanation.textContent = match && analysis.explanation ? analysis.explanation : "No scan results yet.";
    if (aiAction) aiAction.textContent = recAction ? `Recommended action: ${recAction}` : "";
    if (mlProb) mlProb.textContent = match && Number.isFinite(analysis.ml_probability) ? `${Math.round(analysis.ml_probability * 100)}%` : "--";
    if (heuristicScoreEl) heuristicScoreEl.textContent = match && Number.isFinite(analysis.heuristic_score) ? `${analysis.heuristic_score}/100` : (match && Number.isFinite(analysis.score) ? `${analysis.score}/100` : "--");
    const model = match ? (analysis.model_version || (analysis.ml && analysis.ml.model_version) || null) : null;
    if (modelVersion) modelVersion.textContent = model || "--";
    if (confidenceEl) confidenceEl.textContent = match && analysis.confidence ? analysis.confidence : "--";

    elements.scanCount.textContent = counts.scanCount || 0; elements.threatCount.textContent = counts.threatCount || 0;
    const renderList = (element, items, emptyText) => { element.replaceChildren(); (items?.length ? items : [emptyText]).forEach(item => { const row = document.createElement("li"); row.textContent = item; row.className = item === emptyText ? "empty" : "listed"; element.appendChild(row); }); };
    renderList(elements.flagList, match ? analysis.signals : [], "No flags detected");
    renderList(elements.errorList, match ? analysis.errors : [], "No errors");
    elements.historyList.replaceChildren();
    const history = counts.history || stored.history || [];
    (history.length ? history : [{ url: "No scans yet", verdict: "empty" }]).slice(0, 5).forEach(entry => {
      const row = document.createElement("li");
      if (entry.verdict === "empty") { row.className = "empty"; row.textContent = entry.url; }
      else {
        const time = entry.checkedAt ? new Date(entry.checkedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--";
        const verdict = document.createElement("span"); verdict.className = `history-verdict ${entry.verdict}`; verdict.textContent = entry.verdict;
        const url = document.createElement("span"); url.className = "history-url"; url.title = entry.url; url.textContent = entry.url;
        const meta = document.createElement("span"); meta.className = "history-meta"; meta.textContent = `${entry.score}/100 · ${time}`;
        row.append(verdict, url, meta);
      }
      elements.historyList.appendChild(row);
    });
    elements.dot.className = `protection-dot ${active ? "active" : "paused"}`; elements.footer.textContent = active ? "Protection is active" : "Protection is paused";
    elements.toggle.textContent = active ? "Pause protection" : "Resume protection";
    elements.whitelist.disabled = !domain;
    elements.whitelist.textContent = isTrustedDomain ? "Untrust domain" : "Trust domain";
    const signalText = (analysis?.signals || []).join(" ").toLowerCase();
    const categories = { domain: /domain|homograph|typosquat/, url: /url|ip address|port|subdomain|shortener|keyword/, form: /form|credential|password|sensitive/, frame: /frame|embedded/ };
    document.querySelectorAll("[data-check]").forEach(item => { const category = categories[item.dataset.check]; item.className = category?.test(signalText) ? "flagged" : match ? "passed" : "pending"; });
  }
  render();
  elements.backendForm.addEventListener("submit", async event => {
    event.preventDefault();
    const value = elements.backendUrl.value.trim();
    try {
      const parsed = new URL(value);
      if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
        throw new Error("Use an HTTP or HTTPS endpoint without embedded credentials.");
      }
      await chrome.storage.local.set({ reputationBackendUrl: parsed.href });
      elements.backendStatus.className = "manual-scan-status safe";
      elements.backendStatus.textContent = "Backend URL saved. Provider keys remain on the backend.";
    } catch (error) {
      elements.backendStatus.className = "manual-scan-status error";
      elements.backendStatus.textContent = error.message || "Enter a valid backend URL.";
    }
  });
  chrome.storage.onChanged.addListener(changes => {
    if (changes.lastAnalysis || changes.scanCount || changes.threatCount || changes.history || changes.whitelistedDomains) {
      render(changes.lastAnalysis?.newValue ?? stored.lastAnalysis, {
        scanCount: changes.scanCount?.newValue ?? stored.scanCount,
        threatCount: changes.threatCount?.newValue ?? stored.threatCount,
        history: changes.history?.newValue ?? stored.history,
        whitelistedDomains: changes.whitelistedDomains?.newValue ?? stored.whitelistedDomains
      });
    }
  });
  elements.refresh.addEventListener("click", () => { if (tab?.id && /^https?:/i.test(tab.url || "")) chrome.tabs.reload(tab.id); });
  elements.toggle.addEventListener("click", async () => { active = !active; await chrome.storage.local.set({ protectionActive: active }); render(); });
  elements.whitelist.addEventListener("click", async () => {
    if (!domain) return;
    const stored = await chrome.storage.local.get("whitelistedDomains");
    const trusted = (stored.whitelistedDomains || []).map(value => value.toLowerCase().replace(/^www\./, "")).includes(domain.toLowerCase().replace(/^www\./, ""));
    chrome.runtime.sendMessage({ type: "TOGGLE_WHITELIST_DOMAIN", domain, remove: trusted });
  });
  elements.manualForm.addEventListener("submit", async event => {
    event.preventDefault();
    const url = elements.manualUrl.value.trim();
    if (!/^https?:\/\//i.test(url)) {
      elements.manualStatus.className = "manual-scan-status error";
      elements.manualStatus.textContent = "Enter a complete HTTP or HTTPS URL.";
      return;
    }
    elements.manualStatus.className = "manual-scan-status pending";
    elements.manualStatus.textContent = "Checking local signals and reputation...";
    try {
      const analysis = await chrome.runtime.sendMessage({ type: "SCAN_URL", url, tabId: tab?.id });
      if (!analysis || analysis.error) throw new Error(analysis?.error || "Scan failed");
      elements.providerList.replaceChildren();
      (analysis.providers || []).forEach(provider => {
        const row = document.createElement("li");
        const name = document.createElement("span");
        const result = document.createElement("strong");
        name.textContent = provider.name;
        result.textContent = provider.available ? provider.verdict : provider.pending ? "Pending" : "Unavailable";
        row.className = provider.available ? provider.verdict : provider.pending ? "pending" : "error";
        row.title = provider.error || "";
        row.append(name, result);
        elements.providerList.appendChild(row);
      });
      const label = analysis.blocked ? "Risk detected — blocked for future visits"
        : analysis.partial ? "Scan in progress"
        : analysis.verdict === "malicious" ? "Phishing risk detected"
        : analysis.verdict === "suspicious" ? "Suspicious URL" : "No phishing signals found";
      const signals = analysis.signals?.length ? ` Flags: ${analysis.signals.join(", ")}.` : "";
      const consensus = analysis.consensus
        ? ` ${analysis.partial ? "Provisional consensus" : "Consensus"}: ${analysis.consensusVerdict} (${analysis.consensus.available}/${analysis.consensus.total}).`
        : "";
      elements.manualStatus.className = `manual-scan-status ${analysis.partial && !analysis.blocked ? "pending" : analysis.verdict}`;
      elements.manualStatus.textContent = `${label} (${analysis.score}/100).${consensus}${signals}`;
    } catch (error) {
      elements.manualStatus.className = "manual-scan-status error";
      elements.manualStatus.textContent = "The URL could not be checked. Try again.";
    }
  });
  document.getElementById("clear-history").addEventListener("click", async () => { await chrome.storage.local.set({ history: [] }); });
});
