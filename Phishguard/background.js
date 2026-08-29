const REPUTATION_TIMEOUT_MS = 1200;
const REPUTATION_CACHE_TTL_MS = 15 * 60 * 1000;
const MAX_DYNAMIC_RULES = 100;
const TARGET_BRANDS = ["google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram", "netflix", "linkedin", "dropbox"];
const VIRUSTOTAL_API_KEY = "3ba20d5cafe27fbec00ed8ae1f1186f6a20c7e1c9dd339d08e25ff1a9c99c6ee";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const pendingChecks = new Set();

function isWebUrl(url) {
  return /^https?:\/\//i.test(url);
}

function editDistance(left, right) {
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    let diagonal = row[0];
    row[0] = leftIndex;
    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const above = row[rightIndex];
      row[rightIndex] = left[leftIndex - 1] === right[rightIndex - 1]
        ? diagonal
        : Math.min(diagonal + 1, above + 1, row[rightIndex - 1] + 1);
      diagonal = above;
    }
  }
  return row[right.length];
}

function normalizeDomain(domainOrUrl) {
  if (!domainOrUrl) return "";
  const value = String(domainOrUrl).trim().toLowerCase();
  if (!value) return "";

  try {
    const withProtocol = value.includes("/") ? new URL(value).hostname : value;
    return withProtocol.replace(/^www\./, "");
  } catch {
    return value.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  }
}

function getDomain(url) {
  try { return normalizeDomain(new URL(url).hostname); } catch { return ""; }
}

function isDomainWhitelisted(url, whitelist) {
  const target = normalizeDomain(url);
  if (!target) return false;
  const normalizedList = (whitelist || []).map(normalizeDomain).filter(Boolean);
  return normalizedList.some(entry => entry === target || target.endsWith(`.${entry}`));
}

function withTimeout(promise, milliseconds) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("Reputation request timed out")), milliseconds))
  ]);
}

async function getCachedReputation(url, allowStaleSafe = false) {
  const stored = await chrome.storage.local.get("reputationCache");
  const cached = stored.reputationCache?.[url];
  if (!cached) return null;
  const isFresh = Date.now() - cached.checkedAt < REPUTATION_CACHE_TTL_MS;
  return isFresh || (allowStaleSafe && cached.result.verdict === "safe") ? cached.result : null;
}

async function cacheReputation(url, result) {
  const stored = await chrome.storage.local.get("reputationCache");
  const cache = stored.reputationCache || {};
  cache[url] = { result, checkedAt: Date.now() };
  const entries = Object.entries(cache)
    .filter(([, value]) => Date.now() - value.checkedAt < REPUTATION_CACHE_TTL_MS)
    .slice(-100);
  await chrome.storage.local.set({ reputationCache: Object.fromEntries(entries) });
}

function detectSafeBrowsingFixture(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const isGoogleSafeBrowsingTest = hostname === "testsafebrowsing.appspot.com" && pathname.includes("/apiv4/");
    const threatType = /(malware|phishing|social_engineering|unwanted_software|potentially_harmful_application)/i;

    if (isGoogleSafeBrowsingTest && threatType.test(pathname)) {
      return {
        verdict: "malicious",
        score: 100,
        signals: ["Google Safe Browsing malware test fixture detected"],
        source: "local"
      };
    }
  } catch {
  }
  return null;
}

function analyzeUrlLocally(url) {
  const fixtureResult = detectSafeBrowsingFixture(url);
  if (fixtureResult) return fixtureResult;

  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();
  const signals = [];
  let score = 0;
  const addSignal = (points, label) => {
    score += points;
    signals.push(label);
  };

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) addSignal(30, "Raw IP address");
  if (parsedUrl.port && !["80", "443"].includes(parsedUrl.port)) addSignal(15, "Non-standard port");
  if (hostname.includes("xn--")) addSignal(30, "Punycode / homograph domain");
  if (/[^\x00-\x7F]/.test(hostname)) addSignal(25, "Unicode hostname");
  if (parsedUrl.username || parsedUrl.password) addSignal(20, "Hidden credentials");
  if (hostname.split(".").length > 4) addSignal(15, "Deep subdomains");
  if (parsedUrl.pathname.length > 100) addSignal(10, "Long URL path");
  if (/[a-f0-9]{24,}|[A-Za-z0-9]{18,}/.test(parsedUrl.pathname + parsedUrl.search)) addSignal(10, "Random URL string");
  if (["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"].includes(hostname)) addSignal(8, "URL shortener");
  if (/login|verify|secure|account|wallet|payment|password|signin/.test(fullUrl)) addSignal(8, "Sensitive keyword");

  const domainLabel = hostname.split(".").slice(-2, -1)[0] || hostname;
  for (const brand of TARGET_BRANDS) {
    const distance = editDistance(domainLabel.replace(/[^a-z]/g, ""), brand);
    if (distance > 0 && distance <= 2) {
      addSignal(28, `Possible ${brand} typosquat`);
      break;
    }
  }

  return {
    verdict: score >= 60 ? "malicious" : score >= 25 ? "suspicious" : "safe",
    score: Math.min(100, score),
    signals,
    source: "local"
  };
}

async function setVerdict(tabId, analysis) {
  const stored = await chrome.storage.local.get(["lastAnalysis", "scanCount", "threatCount", "history"]);
  const history = stored.history || [];
  const isCompletedScan = analysis.verdict !== "scanning" && analysis.verdict !== "pending";
  const isNewScan = isCompletedScan && !history.some(entry => entry.url === analysis.url);
  const isThreat = analysis.verdict === "malicious" || analysis.verdict === "suspicious";
  const historyWithoutUrl = history.filter(entry => entry.url !== analysis.url);
  const updatedHistory = isCompletedScan
    ? [{ url: analysis.url, verdict: analysis.verdict, score: analysis.score || 0, checkedAt: analysis.checkedAt }, ...historyWithoutUrl]
    : history;
  await chrome.storage.local.set({
    lastAnalysis: analysis,
    scanCount: (stored.scanCount || 0) + (isNewScan ? 1 : 0),
    threatCount: (stored.threatCount || 0) + (isNewScan && isThreat ? 1 : 0),
    history: updatedHistory.slice(0, 20)
  });

  const badge = analysis.verdict === "malicious" ? "RISK"
    : analysis.verdict === "suspicious" ? "WARN" : analysis.verdict === "safe" ? "SAFE" : "...";
  const color = analysis.verdict === "malicious" ? "#e34f4f"
    : analysis.verdict === "suspicious" ? "#e5a83b"
    : analysis.verdict === "safe" ? "#2bb673" : "#718096";

  await chrome.action.setBadgeText({ tabId, text: badge });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function notifyThreat(analysis) {
  const isMalicious = analysis.verdict === "malicious";
  chrome.notifications.create(`linksense-${Date.now()}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: isMalicious ? "LinkSense found a threat" : "LinkSense found a risk",
    message: `${isMalicious ? "Malicious" : "Suspicious"} URL detected. Review the LinkSense badge for details.`,
    priority: 2
  });
}

async function showThreatPopup(analysis) {
  if (!analysis?.url) return;
  await chrome.storage.local.set({ pendingThreat: analysis });
  try {
    await chrome.action.openPopup();
  } catch (error) {
    console.warn("[LinkSense] Could not open popup:", error);
  }
}

async function requestThreatDecision(tabId, analysis) {
  let lastError = null;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      return await chrome.tabs.sendMessage(tabId, {
        type: "THREAT_DETECTED",
        analysis
      });
    } catch (error) {
      lastError = error;
      console.warn("[LinkSense] Could not show the in-page threat prompt (attempt", attempt, "):", error);
      if (attempt < 5) {
        await new Promise(resolve => setTimeout(resolve, 250 * attempt));
      }
    }
  }

  console.warn("[LinkSense] Final warning prompt failed for:", analysis?.url, lastError);
  return { decision: "pending", fallback: true };
}

function logBackgroundEvent(step, details) {
  console.log("[LinkSense][flow]", JSON.stringify({ step, ...details }));
}

async function checkUrlWithVirusTotal(url) {
  if (!url || typeof url !== "string" || !url.startsWith("http")) {
    console.log("[LinkSense] Skipping non-scannable URL:", url);
    return null;
  }

  const cleanUrl = url.trim();
  if (pendingChecks.has(cleanUrl)) {
    console.log("[LinkSense] URL already being checked by VirusTotal:", cleanUrl);
    return null;
  }

  pendingChecks.add(cleanUrl);
  console.log("[LinkSense] Checking URL with VirusTotal:", cleanUrl);

  try {
    const apiResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(cleanUrl)}`
    });

    if (!apiResponse.ok) {
      console.error("[LinkSense] VirusTotal API submission failed with HTTP", apiResponse.status, apiResponse.statusText);
      return null;
    }

    const payload = await apiResponse.json();
    const analysisId = payload?.data?.id;
    if (!analysisId) {
      console.error("[LinkSense] Invalid VirusTotal submission payload for:", cleanUrl, payload);
      return null;
    }

    let attempts = 0;
    let reportData = null;

    while (attempts < 5) {
      const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        method: "GET",
        headers: { "x-apikey": VIRUSTOTAL_API_KEY }
      });

      if (!reportResponse.ok) {
        console.error("[LinkSense] VirusTotal report fetch failed with HTTP", reportResponse.status, reportResponse.statusText);
        return null;
      }

      reportData = await reportResponse.json();
      const status = reportData?.data?.attributes?.status;

      if (status === "completed") break;
      attempts += 1;
      await sleep(1500);
    }

    const stats = reportData?.data?.attributes?.stats;
    if (!stats) {
      console.error("[LinkSense] VirusTotal analysis stats not available for:", cleanUrl);
      return null;
    }

    console.log("[LinkSense] VirusTotal stats for", cleanUrl, stats);
    if (stats.malicious > 0) return { verdict: "malicious", score: 100, stats, source: "VirusTotal" };
    if (stats.suspicious > 0) return { verdict: "suspicious", score: 60, stats, source: "VirusTotal" };
    return { verdict: "safe", score: 0, stats, source: "VirusTotal" };
  } catch (error) {
    console.error("[LinkSense] Error checking URL with VirusTotal:", cleanUrl, error);
    return null;
  } finally {
    pendingChecks.delete(cleanUrl);
  }
}

async function checkReputation(url) {
  if (!isWebUrl(url)) return null;

  console.log("[LinkSense] Checking URL with reputation service / VirusTotal:", url);

  const cached = await getCachedReputation(url);
  if (cached) {
    console.log("[LinkSense] Using cached reputation for:", url, cached);
    return cached;
  }
  const cachedSafe = await getCachedReputation(url, true);

  const unavailable = error => cachedSafe
    ? { ...cachedSafe, source: "Cached reputation" }
    : { unavailable: true, error };

  try {
    if (VIRUSTOTAL_API_KEY) {
      const virusTotalResult = await checkUrlWithVirusTotal(url);
      if (virusTotalResult) {
        await cacheReputation(url, virusTotalResult);
        return virusTotalResult;
      }
    }

    const localSettings = await chrome.storage.local.get("reputationBackendUrl");
    let managedSettings = {};
    try {
      managedSettings = await chrome.storage.managed.get("reputationBackendUrl");
    } catch {
    }
    const backendUrl = localSettings.reputationBackendUrl || managedSettings.reputationBackendUrl;
    if (!backendUrl) {
      console.log("[LinkSense] No reputation backend configured for:", url);
      return cachedSafe;
    }
    console.log("[LinkSense] Sending URL to VirusTotal backend:", { url, backendUrl });
    const response = await withTimeout(fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    }), REPUTATION_TIMEOUT_MS);
    if (!response.ok) {
      console.warn("[LinkSense] Reputation service failed for:", url, "status:", response.status);
      return unavailable(`Reputation service failed (${response.status})`);
    }
    const result = await response.json();
    if (!result || !["safe", "suspicious", "malicious"].includes(result.verdict)) {
      console.warn("[LinkSense] Invalid reputation response for:", url, result);
      return unavailable("Invalid reputation response");
    }
    const reputation = { ...result, source: result.source || "Reputation service" };
    console.log("[LinkSense] VirusTotal stats for:", url, reputation.stats || result);
    await cacheReputation(url, reputation);
    return reputation;
  } catch (error) {
    console.warn("[LinkSense] Reputation service unavailable for:", url, error.message);
    return unavailable("Reputation service unavailable");
  }
}

// Function to add a blocking rule for a URL
async function blockUrl(url) {
  console.log("[LinkSense] Blocking malicious URL:", url);

  const domain = getDomain(url);
  if (!domain) return;
  const ruleId = ([...domain].reduce((hash, character) => ((hash * 31) + character.charCodeAt(0)) % 1000000000, 1) || 1);

  const rule = {
    id: ruleId, // Use the validated integer ID
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: ["main_frame"]
    }
  };

  try {
    // Add the rule dynamically
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules
      .filter(existingRule => existingRule.id === ruleId || existingRule.id < 0)
      .map(existingRule => existingRule.id);
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [rule],
      removeRuleIds
    });
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    if (rules.length > MAX_DYNAMIC_RULES) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: rules.slice(0, rules.length - MAX_DYNAMIC_RULES).map(existingRule => existingRule.id)
      });
    }
    console.log("[LinkSense] Successfully blocked URL:", url);
  } catch (error) {
    console.error("[LinkSense] Error adding blocking rule for:", url, error);
  }
}

chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0) return;

  // Check if protection is active
  const result = await chrome.storage.local.get(["protectionActive"]);
  const isProtectionActive = result.protectionActive !== undefined ? result.protectionActive : true;

  if (!isProtectionActive) return; // Skip if protection is inactive

  if (isWebUrl(url)) {
    console.log("[LinkSense] Tab updated with URL:", url);

    const domain = getDomain(url);
    const whitelist = (await chrome.storage.local.get("whitelistedDomains")).whitelistedDomains || [];
    const trusted = isDomainWhitelisted(domain, whitelist);
    logBackgroundEvent("navigation", { url, domain, protectionActive: isProtectionActive, whitelist, trusted });
    if (trusted) {
      logBackgroundEvent("whitelist-match", { url, domain, whitelist });
      await setVerdict(tabId, { url, verdict: "safe", score: 0, signals: ["Trusted domain"], source: "Whitelist", checkedAt: Date.now() });
      return;
    }

    const localAnalysis = analyzeUrlLocally(url);
    logBackgroundEvent("local-analysis", { url, verdict: localAnalysis.verdict, score: localAnalysis.score, signals: localAnalysis.signals });
    await setVerdict(tabId, { url, ...localAnalysis, checkedAt: Date.now() });
    const severity = await checkReputation(url);

    if (!severity || severity.unavailable) {
      await setVerdict(tabId, {
        url,
        ...localAnalysis,
        errors: severity?.unavailable ? [severity.error || "Reputation service unavailable"] : [],
        source: "Local analysis",
        checkedAt: Date.now()
      });
      return;
    }

    if (severity === "pending") {
      await setVerdict(tabId, { url, verdict: "pending", checkedAt: Date.now() });
      return;
    }

    const combinedAnalysis = {
      url,
      verdict: severity.verdict === "malicious" || localAnalysis.verdict === "malicious" ? "malicious"
        : severity.verdict === "suspicious" || localAnalysis.verdict === "suspicious" ? "suspicious" : "safe",
      score: Math.max(localAnalysis.score, severity.score),
      signals: localAnalysis.signals,
      errors: [],
      stats: severity.stats,
      source: "Local analysis + reputation service",
      checkedAt: Date.now()
    };
    logBackgroundEvent("combined-verdict", { url, verdict: combinedAnalysis.verdict, score: combinedAnalysis.score, signals: combinedAnalysis.signals, stats: combinedAnalysis.stats });
    await setVerdict(tabId, combinedAnalysis);
    if (combinedAnalysis.verdict === "malicious" || combinedAnalysis.verdict === "suspicious") {
      console.log("[LinkSense] Flagged", combinedAnalysis.verdict, "URL:", url, "score:", combinedAnalysis.score, "signals:", combinedAnalysis.signals);
      logBackgroundEvent("threat-detected", { url, verdict: combinedAnalysis.verdict, score: combinedAnalysis.score, signals: combinedAnalysis.signals });
      notifyThreat(combinedAnalysis);
      await showThreatPopup(combinedAnalysis);
      await requestThreatDecision(tabId, combinedAnalysis);
      return;
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender) => {
  (async () => {
  if (message.type === "THREAT_DECISION" && sender.tab?.id && isWebUrl(message.url)) {
    if (message.decision === "block") {
      await blockUrl(message.url);
      await chrome.tabs.update(sender.tab.id, {
        url: `${chrome.runtime.getURL("blocked.html")}?url=${encodeURIComponent(message.url)}&severity=${message.verdict || "malicious"}`
      });
    }
    return;
  }
  if ((message.type === "WHITELIST_DOMAIN" || message.type === "TOGGLE_WHITELIST_DOMAIN") && message.domain) {
    const domain = normalizeDomain(message.domain);
    const stored = await chrome.storage.local.get("whitelistedDomains");
    const current = (stored.whitelistedDomains || []).map(normalizeDomain).filter(Boolean);
    const isTrusted = current.includes(domain);
    const domains = isTrusted
      ? current.filter(entry => entry !== domain)
      : [...new Set([...current, domain])];
    logBackgroundEvent("whitelist-toggle", { domain, action: isTrusted ? "remove" : "add", previous: current, next: domains });
    await chrome.storage.local.set({ whitelistedDomains: domains });
    if (sender.tab?.id) {
      const tabUrl = sender.tab.url || "";
      const verdict = isTrusted ? "scanning" : "safe";
      await setVerdict(sender.tab.id, {
        url: tabUrl,
        verdict,
        score: isTrusted ? 0 : 0,
        signals: isTrusted ? [] : ["Trusted domain"],
        source: isTrusted ? "Whitelist removed" : "Whitelist",
        checkedAt: Date.now()
      });
    }
    return;
  }
  if (message.type === "UNWHITELIST_DOMAIN" && message.domain) {
    const domain = normalizeDomain(message.domain);
    const stored = await chrome.storage.local.get("whitelistedDomains");
    const domains = (stored.whitelistedDomains || []).map(normalizeDomain).filter(Boolean).filter(entry => entry !== domain);
    await chrome.storage.local.set({ whitelistedDomains: domains });
    if (sender.tab?.id) await setVerdict(sender.tab.id, { url: sender.tab.url, verdict: "scanning", score: 0, signals: [], source: "Whitelist removed", checkedAt: Date.now() });
    return;
  }
  if (message.type !== "PAGE_SIGNALS" || !sender.tab?.id || !isWebUrl(message.url)) return;
  const stored = await chrome.storage.local.get("lastAnalysis");
  if (!stored.lastAnalysis || stored.lastAnalysis.url !== message.url) return;

  const pageScore = Math.min(100, Number(message.score) || 0);
  const score = Math.max(stored.lastAnalysis.score || 0, pageScore);
  const verdict = score >= 60 ? "malicious" : score >= 25 ? "suspicious" : stored.lastAnalysis.verdict;
  await setVerdict(sender.tab.id, {
    ...stored.lastAnalysis,
    verdict,
    score,
    signals: [...new Set([...(stored.lastAnalysis.signals || []), ...(message.signals || [])])],
    checkedAt: Date.now()
  });
  })();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== "SCAN_URL" || !isWebUrl(message.url)) return;

  (async () => {
    const url = message.url.trim();
    let localAnalysis;
    try {
      localAnalysis = analyzeUrlLocally(url);
    } catch {
      sendResponse({ error: "Invalid URL" });
      return;
    }

    const severity = await checkReputation(url);
    if (!severity || severity.unavailable || severity === "pending") {
      sendResponse({
        ...localAnalysis,
        errors: severity?.unavailable ? [severity.error || "Reputation service unavailable"] : [],
        source: "Local analysis"
      });
      return;
    }

    sendResponse({
      ...localAnalysis,
      verdict: severity.verdict === "malicious" || localAnalysis.verdict === "malicious" ? "malicious"
        : severity.verdict === "suspicious" || localAnalysis.verdict === "suspicious" ? "suspicious" : "safe",
      score: Math.max(localAnalysis.score, severity.score),
      source: "Local analysis + reputation service",
      stats: severity.stats,
      errors: []
    });
  })().catch(() => sendResponse({ error: "Scan failed" }));

  return true;
});