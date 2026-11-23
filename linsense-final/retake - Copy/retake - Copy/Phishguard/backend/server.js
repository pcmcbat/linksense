const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const dns = require("node:dns").promises;
const net = require("node:net");

loadEnvironmentFile();

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const PROVIDERS = ["urlscan.io", "AbuseIPDB", "AlienVault OTX", "Pulsedive", "MetaDefender Cloud"];
const CACHE_TTL_MS = 15 * 60 * 1000;
const cache = new Map();
const inFlight = new Map();

function loadEnvironmentFile() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  const contents = fs.readFileSync(envPath, "utf8");
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!match || match[1].startsWith("#") || process.env[match[1]]) continue;
    const value = match[2].replace(/^(["'])(.*)\1$/, "$2");
    process.env[match[1]] = value;
  }
}

function sleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function fetchJson(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const body = await response.text();
    let data;
    try {
      data = body ? JSON.parse(body) : {};
    } catch {
      data = null;
    }
    if (!response.ok) {
      const nestedError = Array.isArray(data?.errors) ? data.errors[0] : null;
      const detail = data?.message || data?.error || data?.description || data?.error_message
        || nestedError?.detail || nestedError?.description || nestedError?.title;
      const message = typeof detail === "string" ? detail.slice(0, 400) : "";
      throw new Error(`HTTP ${response.status}${message ? `: ${message}` : ""}`);
    }
    if (!data) throw new Error("Provider returned invalid JSON");
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function failed(name, error) {
  const message = String(error?.message || "");
  const status = message.match(/HTTP (\d{3})/);
  const detail = message.split(": ").slice(1).join(": ").trim();
  const causeCode = error?.cause?.code;
  const reason = status
    ? `Provider returned HTTP ${status[1]}${detail ? `: ${detail.slice(0, 400)}` : ""}`
    : error?.name === "AbortError" ? "Provider request timed out"
    : causeCode ? `Network request failed (${causeCode})`
    : error?.name === "TypeError" ? "Network request failed"
    : message === "Provider returned invalid JSON" ? message
    : message === "Pulsedive has no assessed risk for this indicator" ? message
    : message === "Pulsedive risk is unavailable" ? message
    : "Provider request failed";
  console.error(`[LinkSense backend] ${name} failed: ${reason}`);
  return { name, available: false, verdict: null, error: reason };
}

function missingKey(name) {
  return { name, available: false, verdict: null, error: "API key is not configured" };
}

function successful(name, verdict, details = {}) {
  return { name, available: true, verdict, ...details };
}

function classifyOtx(data) {
  const pulses = data?.pulse_info?.count;
  if (!Number.isFinite(pulses)) throw new Error("Invalid OTX response");
  const threatTerms = /\b(malware|phishing|malicious|ransomware|trojan|botnet|command.and.control|c2|credential theft|spyware)\b/i;
  const threatPulses = (data?.pulse_info?.pulses || []).filter(pulse =>
    threatTerms.test(`${pulse.name || ""} ${(pulse.tags || []).join(" ")}`)
  ).length;
  const explicitlyWhitelisted = (data?.validation || []).some(item =>
    /whitelist|popular domain/i.test(`${item.name || ""} ${item.message || ""}`)
  );
  return {
    verdict: threatPulses > 0 && !explicitlyWhitelisted ? "suspicious" : "safe",
    pulseCount: pulses,
    threatPulseCount: threatPulses,
    whitelisted: explicitlyWhitelisted
  };
}

async function checkUrlscan(url) {
  const key = process.env.URLSCAN_API_KEY;
  if (!key) return missingKey("urlscan.io");
  try {
    const submission = await fetchJson("https://urlscan.io/api/v1/scan", {
      method: "POST",
      headers: { "API-Key": key, "Content-Type": "application/json" },
      body: JSON.stringify({ url, visibility: "private" })
    });
    if (!submission.uuid) throw new Error("Missing scan identifier");

    await sleep(30000);
    let result;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        result = await fetchJson(`https://urlscan.io/api/v1/result/${encodeURIComponent(submission.uuid)}/`, {
          headers: { "API-Key": key }
        });
        break;
      } catch (error) {
        if (!String(error.message).includes("HTTP 404") || attempt === 3) throw error;
        await sleep(4000);
      }
    }
    const overall = result?.verdicts?.overall || {};
    if (typeof overall.malicious !== "boolean" || !Number.isFinite(Number(overall.score))) {
      throw new Error("Invalid scan result");
    }
    const score = Number(overall.score);
    const verdict = overall.malicious ? "malicious" : score >= 30 ? "suspicious" : "safe";
    return successful("urlscan.io", verdict, { score, scanId: submission.uuid });
  } catch (error) {
    return failed("urlscan.io", error);
  }
}

function isPublicIpv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [first, second, third] = address.split(".").map(Number);
  return !(first === 0 || first === 10 || first === 127 || first >= 224
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && [0, 2, 168].includes(second))
    || (first === 198 && [18, 19, 51].includes(second))
    || (first === 203 && second === 0 && third === 113));
}

async function checkAbuseIpDb(hostname) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return missingKey("AbuseIPDB");
  try {
    const addresses = net.isIP(hostname) === 4
      ? [{ address: hostname }]
      : await dns.lookup(hostname, { all: true, verbatim: true });
    const ips = [...new Set(addresses.map(entry => entry.address).filter(isPublicIpv4))].slice(0, 2);
    if (!ips.length) return { name: "AbuseIPDB", available: false, verdict: null, error: "No public IPv4 address found" };

    const scores = await Promise.all(ips.map(async ip => {
      const params = new URLSearchParams({ ipAddress: ip, maxAgeInDays: "90" });
      const data = await fetchJson(`https://api.abuseipdb.com/api/v2/check?${params}`, {
        headers: { Key: key, Accept: "application/json" }
      });
      const score = data?.data?.abuseConfidenceScore;
      if (!Number.isFinite(score)) throw new Error("Invalid AbuseIPDB response");
      return score;
    }));
    const score = Math.max(...scores);
    const verdict = score >= 75 ? "malicious" : score >= 50 ? "suspicious" : "safe";
    return successful("AbuseIPDB", verdict, { score, checkedIps: ips.length });
  } catch (error) {
    return failed("AbuseIPDB", error);
  }
}

async function checkOtx(hostname) {
  const key = process.env.OTX_API_KEY;
  if (!key) return missingKey("AlienVault OTX");
  try {
    const data = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(hostname)}/general`, {
      headers: { "X-OTX-API-KEY": key }
    });
    const result = classifyOtx(data);
    return successful("AlienVault OTX", result.verdict, result);
  } catch (error) {
    return failed("AlienVault OTX", error);
  }
}

async function checkPulsedive(hostname) {
  const key = process.env.PULSEDIVE_API_KEY;
  if (!key) return missingKey("Pulsedive");
  try {
    const params = new URLSearchParams({ indicator: hostname, key });
    const data = await fetchJson(`https://pulsedive.com/api/indicator.php?${params}`);
    if (data?.error || data?.success === false) throw new Error("Indicator lookup failed");
    const riskValue = data?.risk || data?.indicator?.risk;
    if (!riskValue) throw new Error("Pulsedive risk is unavailable");
    const risk = String(riskValue).toLowerCase();
    const verdict = ["high", "critical"].includes(risk) ? "malicious"
      : ["low", "medium"].includes(risk) ? "suspicious"
      : ["none", "very low"].includes(risk) ? "safe"
      : null;
    if (!verdict) throw new Error("Pulsedive has no assessed risk for this indicator");
    return successful("Pulsedive", verdict, { risk });
  } catch (error) {
    return failed("Pulsedive", error);
  }
}

async function checkMetaDefender(url) {
  const key = process.env.METADEFENDER_API_KEY;
  if (!key) return missingKey("MetaDefender Cloud");
  try {
    const submission = await fetchJson("https://api.metadefender.com/v4/url", {
      method: "POST",
      headers: { apikey: key, "Content-Type": "application/json" },
      body: JSON.stringify({ url: [url] })
    });
    if (Array.isArray(submission.data) && submission.data.length) {
      const result = classifyMetaDefender(submission.data[0]);
      return successful("MetaDefender Cloud", result.verdict, result);
    }
    if (!submission.data_id) throw new Error("Missing scan identifier");

    let report;
    let completed = false;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      report = await fetchJson(`https://api.metadefender.com/v4/url/${encodeURIComponent(submission.data_id)}`, {
        headers: { apikey: key }
      });
      const progress = Number(report?.scan_results?.progress_percentage);
      if (Number.isFinite(progress) && progress >= 100) {
        completed = true;
        break;
      }
      if (attempt < 4) await sleep(2000);
    }
    const detected = Number(report?.scan_results?.total_detected_avs) || 0;
    if (!completed || !report?.scan_results) throw new Error("Scan report unavailable");
    if (!Number.isFinite(report.scan_results.total_detected_avs)) throw new Error("Invalid MetaDefender response");
    return successful("MetaDefender Cloud", detected > 0 ? "malicious" : "safe", {
      detections: detected,
      engines: Number(report.scan_results.total_avs) || 0
    });
  } catch (error) {
    return failed("MetaDefender Cloud", error);
  }
}

function classifyMetaDefender(data) {
  const lookup = data?.lookup_results;
  const detected = Number(lookup?.detected_by ?? data?.scan_results?.total_detected_avs);
  if (!Number.isFinite(detected)) throw new Error("MetaDefender detection count is unavailable");
  const assessment = (lookup?.sources || []).map(source => String(source.assessment || source.verdict || "")).join(" ");
  const malicious = /\b(malicious|phishing|infected|suspicious)\b/i.test(assessment);
  return {
    verdict: detected > 0 || malicious ? "malicious" : "safe",
    detections: detected,
    engines: Number(lookup?.total) || Number(data?.scan_results?.total_avs) || 0
  };
}

function aggregateResults(results) {
  const votes = results.filter(result => result.available && ["safe", "suspicious", "malicious"].includes(result.verdict));
  if (!votes.length) {
    return {
      unavailable: true,
      partial: results.some(result => result.pending),
      error: "All provider checks are unavailable",
      providers: results,
      errors: results.map(result => `${result.name}: ${result.error}`)
    };
  }
  const counts = { safe: 0, suspicious: 0, malicious: 0 };
  votes.forEach(result => { counts[result.verdict] += 1; });
  const severity = { safe: 0, suspicious: 1, malicious: 2 };
  const consensusVerdict = Object.keys(counts).sort((left, right) => counts[right] - counts[left] || severity[right] - severity[left])[0];
  const riskVerdict = votes.reduce((highest, result) => severity[result.verdict] > severity[highest] ? result.verdict : highest, "safe");
  const blocked = votes.some(result => result.verdict !== "safe");
  const score = Math.round((counts.suspicious * 60 + counts.malicious * 100) / Math.max(votes.length, 1));
  const errors = results.filter(result => !result.available).map(result => `${result.name}: ${result.error}`);

  return {
    partial: results.some(result => result.pending),
    verdict: consensusVerdict,
    consensusVerdict,
    riskVerdict,
    block: blocked,
    score,
    consensus: { votes: counts, available: votes.length, total: PROVIDERS.length },
    providers: results,
    errors,
    source: `5-provider consensus (${votes.length}/${PROVIDERS.length} available)`
  };
}

async function scanUrl(url) {
  const cached = cache.get(url);
  if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) return cached.result;
  const existing = inFlight.get(url);
  if (existing) return existing.snapshot();

  const hostname = new URL(url).hostname.toLowerCase();
  const checks = [
    checkUrlscan(url),
    checkAbuseIpDb(hostname),
    checkOtx(hostname),
    checkPulsedive(hostname),
    checkMetaDefender(url)
  ];
  const state = { results: Array(PROVIDERS.length).fill(null), result: null, signalRisk: null };
  let resolveRisk;
  const riskSignal = new Promise(resolve => { resolveRisk = resolve; });
  state.snapshot = () => {
    const results = state.results.map((result, index) => result || {
      name: PROVIDERS[index],
      available: false,
      verdict: null,
      pending: true,
      error: "Scan is still running"
    });
    return { ...aggregateResults(results), partial: true };
  };
  inFlight.set(url, state);

  const completeScan = Promise.all(checks.map((check, index) => check.then(result => {
    state.results[index] = result;
    if (result.available && result.verdict !== "safe" && !state.signalRisk) {
      state.signalRisk = true;
      resolveRisk(true);
    }
    return result;
  }))).then(results => {
    state.result = aggregateResults(results);
    cache.set(url, { result: state.result, checkedAt: Date.now() });
    while (cache.size > 500) cache.delete(cache.keys().next().value);
    return state.result;
  }).finally(() => {
    if (inFlight.get(url) === state) inFlight.delete(url);
  });

  let timeoutId;
  const maxWait = new Promise(resolve => {
    timeoutId = setTimeout(() => resolve(null), 25000);
  });
  const outcome = await Promise.race([
    completeScan.then(result => ({ complete: true, result })),
    riskSignal.then(() => ({ complete: false })),
    maxWait.then(() => ({ complete: false }))
  ]);
  clearTimeout(timeoutId);
  return outcome.complete ? outcome.result : state.snapshot();
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(body));
}

const server = http.createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    sendJson(response, 204, {});
    return;
  }
  if (request.method === "GET" && request.url === "/health") {
    sendJson(response, 200, {
      status: "ok",
      configuredProviders: {
        urlscan: Boolean(process.env.URLSCAN_API_KEY),
        abuseipdb: Boolean(process.env.ABUSEIPDB_API_KEY),
        otx: Boolean(process.env.OTX_API_KEY),
        pulsedive: Boolean(process.env.PULSEDIVE_API_KEY),
        metadefender: Boolean(process.env.METADEFENDER_API_KEY)
      }
    });
    return;
  }
  if (request.method !== "POST" || request.url !== "/scan") {
    sendJson(response, 404, { error: "Not found" });
    return;
  }

  try {
    let body = "";
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 16384) {
        sendJson(response, 413, { error: "Request too large" });
        return;
      }
    }
    const input = JSON.parse(body);
    const parsed = new URL(input?.url);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
      sendJson(response, 400, { error: "A valid HTTP or HTTPS URL is required" });
      return;
    }
    sendJson(response, 200, await scanUrl(parsed.href));
  } catch (error) {
    const status = error instanceof SyntaxError || error instanceof TypeError ? 400 : 502;
    sendJson(response, status, { error: status === 400 ? "A valid HTTP or HTTPS URL is required" : "Reputation scan failed" });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => console.log(`[LinkSense backend] Listening on http://${HOST}:${PORT}`));
}

module.exports = { aggregateResults, classifyMetaDefender, classifyOtx, isPublicIpv4, scanUrl, server };
