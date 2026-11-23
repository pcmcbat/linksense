const REPUTATION_TIMEOUT_MS = 50000;
const REPUTATION_CACHE_TTL_MS = 15 * 60 * 1000;
const REPUTATION_CACHE_VERSION = 2;
const MAX_DYNAMIC_RULES = 100;
const FOLLOWUP_ALARM = "linksense-provider-followup";
const DEFAULT_REPUTATION_BACKEND_URL = "http://127.0.0.1:8787/scan";
const TARGET_BRANDS = ["google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram", "netflix", "linkedin", "dropbox"];

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

async function getCachedReputation(url) {
  const stored = await chrome.storage.local.get("reputationCache");
  const cached = stored.reputationCache?.[url];
  if (!cached) return null;
  if (cached.version !== REPUTATION_CACHE_VERSION
    || !Array.isArray(cached.result?.providers)
    || !cached.result.consensus) return null;
  const isFresh = Date.now() - cached.checkedAt < REPUTATION_CACHE_TTL_MS;
  return isFresh ? cached.result : null;
}

async function cacheReputation(url, result) {
  const stored = await chrome.storage.local.get("reputationCache");
  const cache = stored.reputationCache || {};
  cache[url] = { result, checkedAt: Date.now(), version: REPUTATION_CACHE_VERSION };
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
  const previousResult = history.find(entry => entry.url === analysis.url);
  const isNewThreat = isThreat && (!previousResult || !["malicious", "suspicious"].includes(previousResult.verdict));
  const historyWithoutUrl = history.filter(entry => entry.url !== analysis.url);
  const updatedHistory = isCompletedScan
    ? [{ url: analysis.url, verdict: analysis.verdict, score: analysis.score || 0, checkedAt: analysis.checkedAt }, ...historyWithoutUrl]
    : history;
  await chrome.storage.local.set({
    lastAnalysis: analysis,
    scanCount: (stored.scanCount || 0) + (isNewScan ? 1 : 0),
    threatCount: (stored.threatCount || 0) + (isNewThreat ? 1 : 0),
    history: updatedHistory.slice(0, 20)
  });

  const isRisky = analysis.blocked === true || analysis.verdict === "malicious" || analysis.verdict === "suspicious";
  const badge = isRisky ? "RISK" : analysis.partial ? "..." : analysis.verdict === "safe" ? "SAFE" : "...";
  const color = isRisky && analysis.verdict === "malicious" ? "#e34f4f"
    : analysis.verdict === "suspicious" ? "#e5a83b"
    : analysis.verdict === "safe" && !analysis.partial ? "#2bb673" : "#718096";

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

function logBackgroundEvent(step, details) {
  console.log("[LinkSense][flow]", JSON.stringify({ step, ...details }));
}

async function checkReputation(url) {
  if (!isWebUrl(url)) return null;

  const cached = await getCachedReputation(url);
  if (cached) {
    return cached;
  }
  const unavailable = error => ({ unavailable: true, error });

  try {
    const localSettings = await chrome.storage.local.get("reputationBackendUrl");
    let managedSettings = {};
    try {
      managedSettings = await chrome.storage.managed.get("reputationBackendUrl");
    } catch {
    }
    const backendUrl = localSettings.reputationBackendUrl || managedSettings.reputationBackendUrl || DEFAULT_REPUTATION_BACKEND_URL;
    const response = await withTimeout(fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(REPUTATION_TIMEOUT_MS)
    }), REPUTATION_TIMEOUT_MS);
    if (!response.ok) {
      return unavailable(`Reputation service failed (${response.status})`);
    }
    const result = await response.json();
    if (result?.unavailable === true || result?.partial === true) return result;
    if (!result || !["safe", "suspicious", "malicious"].includes(result.verdict)
      || !["safe", "suspicious", "malicious"].includes(result.consensusVerdict)
      || !["safe", "suspicious", "malicious"].includes(result.riskVerdict)
      || !Array.isArray(result.providers) || !result.consensus) {
      return unavailable("Invalid reputation response");
    }
    const reputation = {
      ...result,
      block: result.block === true || result.riskVerdict === "suspicious" || result.riskVerdict === "malicious",
      source: result.source || "Five-provider reputation service"
    };
    await cacheReputation(url, reputation);
    return reputation;
  } catch (error) {
    console.warn("[LinkSense] Reputation backend unavailable:", error.message);
    return unavailable("Reputation service unavailable");
  }
}

function combineAnalysis(url, localAnalysis, reputation) {
  const providers = reputation?.providers || [];
  const reportedRisk = reputation?.block === true
    || reputation?.riskVerdict === "suspicious"
    || reputation?.riskVerdict === "malicious";
  const localThreat = localAnalysis.verdict === "malicious";
  const verdict = localThreat ? "malicious"
    : reportedRisk ? reputation.riskVerdict
    : reputation?.verdict || localAnalysis.verdict;
  const signals = [
    ...(localAnalysis.signals || []),
    ...providers.filter(provider => provider.available && provider.verdict !== "safe")
      .map(provider => `${provider.name}: ${provider.verdict}`)
  ];

  return {
    url,
    verdict,
    consensusVerdict: reputation?.consensusVerdict || reputation?.verdict || localAnalysis.verdict,
    riskVerdict: reputation?.riskVerdict || (localThreat ? "malicious" : null),
    blocked: reportedRisk || localThreat,
    score: Math.max(localAnalysis.score || 0, reportedRisk ? reputation.score || 0 : 0),
    signals: [...new Set(signals)],
    errors: reputation?.errors || [],
    providers,
    consensus: reputation?.consensus || null,
    partial: reputation?.partial === true,
    source: reputation?.source || localAnalysis.source || "Local analysis",
    // New AI fields forwarded from the FastAPI backend (gracefully undefined
    // when the legacy Node backend or local-only analysis is used).
    risk_score: reputation?.risk_score,
    ml_probability: reputation?.ml_probability,
    ml: reputation?.ml,
    heuristic_score: reputation?.heuristic_score ?? localAnalysis.score,
    explanation: reputation?.explanation,
    recommended_action: reputation?.recommended_action,
    classification: reputation?.classification,
    confidence: reputation?.confidence,
    provider_availability: reputation?.provider_availability,
    model_version: reputation?.model_version || reputation?.ml?.model_version,
    checked_at: reputation?.checked_at ?? Date.now(),
    checkedAt: Date.now()
  };
}

async function queueProviderFollowup(url, tabId, manual = false) {
  if (!Number.isInteger(tabId)) return;
  const stored = await chrome.storage.local.get("pendingProviderScans");
  const pending = stored.pendingProviderScans || {};
  pending[url] = { tabId, manual, queuedAt: Date.now() };
  await chrome.storage.local.set({ pendingProviderScans: pending });
  chrome.alarms.create(FOLLOWUP_ALARM, { delayInMinutes: 1 });
}

async function clearProviderFollowup(url) {
  const stored = await chrome.storage.local.get("pendingProviderScans");
  const pending = stored.pendingProviderScans || {};
  if (!pending[url]) return;
  delete pending[url];
  await chrome.storage.local.set({ pendingProviderScans: pending });
  if (!Object.keys(pending).length) await chrome.alarms.clear(FOLLOWUP_ALARM);
}

function getBlockedTarget(tabUrl) {
  try {
    const parsed = new URL(tabUrl);
    return parsed.pathname.endsWith("/blocked.html") ? parsed.searchParams.get("url") : null;
  } catch {
    return null;
  }
}

chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== FOLLOWUP_ALARM) return;
  const stored = await chrome.storage.local.get("pendingProviderScans");
  const pending = stored.pendingProviderScans || {};

  for (const [url, entry] of Object.entries(pending)) {
    const severity = await checkReputation(url);
    if (severity?.partial) continue;
    delete pending[url];
    if (!severity || severity.unavailable) continue;

    const analysis = combineAnalysis(url, analyzeUrlLocally(url), severity);
    try {
      const tab = await chrome.tabs.get(entry.tabId);
      if (tab.url === url || getBlockedTarget(tab.url || "") === url) {
        await setVerdict(entry.tabId, analysis);
        if (analysis.blocked && tab.url === url) await enforceThreat(entry.tabId, analysis);
      } else if (analysis.blocked) {
        await blockUrl(url);
        if (entry.manual) {
          notifyThreat(analysis);
          await chrome.action.setBadgeText({ tabId: entry.tabId, text: "RISK" });
          await chrome.action.setBadgeBackgroundColor({ tabId: entry.tabId, color: "#e34f4f" });
        }
      }
    } catch (error) {
      console.warn("[LinkSense] Could not update a completed provider scan:", error);
      if (analysis.blocked) await blockUrl(url);
    }
  }

  await chrome.storage.local.set({ pendingProviderScans: pending });
  if (Object.keys(pending).length) chrome.alarms.create(FOLLOWUP_ALARM, { delayInMinutes: 1 });
});

// Function to add a blocking rule for a URL
function getBlockRuleId(url) {
  const domain = getDomain(url);
  if (!domain) return null;
  return [...domain].reduce((hash, character) => ((hash * 31) + character.charCodeAt(0)) % 1000000000, 1) || 1;
}

async function blockUrl(url) {
  const domain = getDomain(url);
  if (!domain) return;
  const ruleId = getBlockRuleId(url);

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
    return true;
  } catch (error) {
    console.error("[LinkSense] Error adding blocking rule for:", url, error);
    return false;
  }
}

async function removeBlockRule(url) {
  const ruleId = getBlockRuleId(url);
  if (!ruleId) return false;
  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    if (rules.some(rule => rule.id === ruleId)) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId] });
    }
    return true;
  } catch (error) {
    console.error("[LinkSense] Error removing the temporary block rule:", error);
    return false;
  }
}

async function isTabOnUrl(tabId, url) {
  try {
    return (await chrome.tabs.get(tabId)).url === url;
  } catch (error) {
    console.warn("[LinkSense] Could not confirm the tab URL:", error);
    return false;
  }
}

async function enforceThreat(tabId, analysis) {
  notifyThreat(analysis);
  const ruleAdded = await blockUrl(analysis.url);
  if (!ruleAdded) console.error("[LinkSense] Unable to add the automatic block rule for:", analysis.url);
  if (!(await isTabOnUrl(tabId, analysis.url))) return;
  try {
    await chrome.tabs.update(tabId, {
      url: `${chrome.runtime.getURL("blocked.html")}?url=${encodeURIComponent(analysis.url)}&severity=${analysis.verdict}`
    });
  } catch (error) {
    console.error("[LinkSense] Could not redirect the risky tab to the warning page:", error);
  }
}

chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0) return;

  // Check if protection is active
  const result = await chrome.storage.local.get(["protectionActive"]);
  const isProtectionActive = result.protectionActive !== undefined ? result.protectionActive : true;

  if (isWebUrl(url)) {
    const bypassState = await chrome.storage.local.get("allowedOnce");
    const allowedOnce = bypassState.allowedOnce || {};
    if (allowedOnce[url] && allowedOnce[url] > Date.now()) {
      delete allowedOnce[url];
      await chrome.storage.local.set({ allowedOnce });
      const previous = await chrome.storage.local.get("lastAnalysis");
      await setVerdict(tabId, {
        ...(previous.lastAnalysis?.url === url ? previous.lastAnalysis : {}),
        url,
        verdict: "suspicious",
        blocked: false,
        source: "User override",
        signals: ["You chose to continue to this risky website"],
        checkedAt: Date.now()
      });
      return;
    }
  }

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
    if (!(await isTabOnUrl(tabId, url))) {
      const staleResult = severity && !severity.unavailable
        ? combineAnalysis(url, localAnalysis, severity)
        : combineAnalysis(url, localAnalysis, null);
      if (staleResult.blocked) {
        const ruleAdded = await blockUrl(url);
        if (!ruleAdded) console.error("[LinkSense] Unable to add the block rule for the scanned URL:", url);
        notifyThreat(staleResult);
      }
      return;
    }

    if (!severity || severity.unavailable) {
      const localResult = combineAnalysis(url, localAnalysis, severity);
      localResult.errors = severity?.errors?.length
        ? severity.errors
        : severity?.error ? [severity.error] : [];
      localResult.providers = severity?.providers || [];
      localResult.source = "Local analysis";
      await setVerdict(tabId, localResult);
      if (severity?.partial) await queueProviderFollowup(url, tabId);
      if (localResult.blocked) await enforceThreat(tabId, localResult);
      return;
    }

    const combinedAnalysis = combineAnalysis(url, localAnalysis, severity);
    if (combinedAnalysis.partial) await queueProviderFollowup(url, tabId);
    else await clearProviderFollowup(url);
    logBackgroundEvent("combined-verdict", {
      url,
      verdict: combinedAnalysis.verdict,
      consensusVerdict: combinedAnalysis.consensusVerdict,
      blocked: combinedAnalysis.blocked,
      score: combinedAnalysis.score
    });
    await setVerdict(tabId, combinedAnalysis);
    if (combinedAnalysis.blocked) {
      logBackgroundEvent("threat-detected", {
        url,
        verdict: combinedAnalysis.verdict,
        consensusVerdict: combinedAnalysis.consensusVerdict,
        providers: combinedAnalysis.providers.filter(provider => provider.available && provider.verdict !== "safe").map(provider => provider.name)
      });
      await enforceThreat(tabId, combinedAnalysis);
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender) => {
  (async () => {
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
    if (!isTrusted) {
      const removed = await removeBlockRule(`https://${domain}`);
      if (!removed) console.error("[LinkSense] Could not remove the block rule for trusted domain:", domain);
    }
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
  const tabId = sender.tab?.id || (Number.isInteger(message.tabId) ? message.tabId : null);
  if (message.type !== "THREAT_DECISION" || !tabId || !isWebUrl(message.url)) return;

  (async () => {
    if (message.decision === "block") {
      await blockUrl(message.url);
      await chrome.tabs.update(tabId, {
        url: `${chrome.runtime.getURL("blocked.html")}?url=${encodeURIComponent(message.url)}&severity=${message.verdict || "malicious"}`
      });
    } else if (message.decision === "continue") {
      const removed = await removeBlockRule(message.url);
      if (!removed) throw new Error("Could not remove the block rule");
      const stored = await chrome.storage.local.get("allowedOnce");
      const allowedOnce = Object.fromEntries(
        Object.entries(stored.allowedOnce || {}).filter(([, expiresAt]) => expiresAt > Date.now())
      );
      allowedOnce[message.url] = Date.now() + 2 * 60 * 1000;
      await chrome.storage.local.set({ allowedOnce });
      await chrome.tabs.update(tabId, { url: message.url });
    }
    sendResponse({ ok: true });
  })().catch(error => {
    console.error("[LinkSense] Threat decision failed:", error);
    sendResponse({ error: "Could not apply this decision" });
  });
  return true;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== "SCAN_URL" || !isWebUrl(message.url)) return;

  (async () => {
    let url;
    let localAnalysis;
    try {
      url = new URL(message.url.trim()).href;
      localAnalysis = analyzeUrlLocally(url);
    } catch {
      sendResponse({ error: "Invalid URL" });
      return;
    }

    const severity = await checkReputation(url);
    if (!severity || severity.unavailable || severity === "pending") {
      const analysis = combineAnalysis(url, localAnalysis, null);
      analysis.errors = severity?.errors?.length
        ? severity.errors
        : severity?.error ? [severity.error] : [];
      analysis.providers = severity?.providers || [];
      analysis.source = "Local analysis";
      if (severity?.partial) await queueProviderFollowup(url, message.tabId, true);
      sendResponse(analysis);
      return;
    }

    const analysis = combineAnalysis(url, localAnalysis, severity);
    if (severity?.unavailable) {
      analysis.errors = severity.errors?.length ? severity.errors : [severity.error || "Reputation service unavailable"];
      analysis.source = "Local analysis";
    }
    if (analysis.partial) await queueProviderFollowup(url, message.tabId, true);
    else await clearProviderFollowup(url);
    if (analysis.blocked) {
      const blocked = await blockUrl(url);
      if (!blocked) analysis.errors.push("Could not add a block rule for this URL.");
    }
    if (Number.isInteger(message.tabId)) {
      const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (activeTabs[0]?.id === message.tabId && activeTabs[0].url === url) {
        await setVerdict(message.tabId, analysis);
        if (analysis.blocked) await enforceThreat(message.tabId, analysis);
      } else if (analysis.blocked) {
        await chrome.action.setBadgeText({ tabId: message.tabId, text: "RISK" });
        await chrome.action.setBadgeBackgroundColor({ tabId: message.tabId, color: "#e34f4f" });
      }
    }
    sendResponse(analysis);
  })().catch(error => {
    console.error("[LinkSense] Manual URL scan failed:", error);
    sendResponse({ error: "Scan failed" });
  });

  return true;
});