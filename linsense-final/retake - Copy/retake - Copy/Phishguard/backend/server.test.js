const test = require("node:test");
const assert = require("node:assert/strict");
const { aggregateResults, classifyMetaDefender, classifyOtx, isPublicIpv4 } = require("./server");

test("uses the most repeated provider verdict while preserving one-provider risk", () => {
  const result = aggregateResults([
    { name: "urlscan.io", available: true, verdict: "safe" },
    { name: "AbuseIPDB", available: true, verdict: "safe" },
    { name: "AlienVault OTX", available: true, verdict: "safe" },
    { name: "Pulsedive", available: true, verdict: "safe" },
    { name: "MetaDefender Cloud", available: true, verdict: "suspicious" }
  ]);

  assert.equal(result.verdict, "safe");
  assert.equal(result.consensusVerdict, "safe");
  assert.equal(result.riskVerdict, "suspicious");
  assert.equal(result.block, true);
  assert.deepEqual(result.consensus.votes, { safe: 4, suspicious: 1, malicious: 0 });
});

test("breaks a tied consensus toward the more severe verdict", () => {
  const result = aggregateResults([
    { name: "urlscan.io", available: true, verdict: "safe" },
    { name: "AbuseIPDB", available: true, verdict: "malicious" }
  ]);
  assert.equal(result.verdict, "malicious");
  assert.equal(result.block, true);
});

test("does not turn unavailable providers into a safe result", () => {
  const result = aggregateResults([
    { name: "urlscan.io", available: false, pending: true, error: "still running" },
    { name: "AbuseIPDB", available: false, error: "not configured" }
  ]);
  assert.equal(result.unavailable, true);
  assert.equal(result.partial, true);
  assert.equal(result.verdict, undefined);
});

test("returns a partial risk immediately without counting unfinished providers as safe", () => {
  const result = aggregateResults([
    { name: "urlscan.io", available: true, verdict: "suspicious" },
    { name: "AbuseIPDB", available: false, pending: true, error: "still running" },
    { name: "AlienVault OTX", available: false, pending: true, error: "still running" }
  ]);
  assert.equal(result.partial, true);
  assert.equal(result.block, true);
  assert.equal(result.consensus.available, 1);
  assert.equal(result.consensus.votes.safe, 0);
});

test("filters non-public and malformed IPv4 addresses", () => {
  assert.equal(isPublicIpv4("8.8.8.8"), true);
  assert.equal(isPublicIpv4("127.0.0.1"), false);
  assert.equal(isPublicIpv4("192.168.1.1"), false);
  assert.equal(isPublicIpv4("not-an-ip"), false);
});

test("does not classify a whitelisted OTX domain as risky because of unrelated pulses", () => {
  const result = classifyOtx({
    pulse_info: {
      count: 50,
      pulses: [{ name: "malware campaign", tags: ["malicious"] }]
    },
    validation: [{ name: "Whitelisted domain", message: "Whitelisted domain example.com" }]
  });
  assert.equal(result.verdict, "safe");
  assert.equal(result.whitelisted, true);
});

test("classifies threat-tagged OTX pulses as suspicious without a whitelist", () => {
  const result = classifyOtx({
    pulse_info: {
      count: 1,
      pulses: [{ name: "Credential theft campaign", tags: ["phishing"] }]
    },
    validation: []
  });
  assert.equal(result.verdict, "suspicious");
});

test("classifies the MetaDefender URL lookup response shape", () => {
  const result = classifyMetaDefender({
    lookup_results: {
      detected_by: 0,
      sources: [{ provider: "Offline Reputation", assessment: "benign" }]
    }
  });
  assert.equal(result.verdict, "safe");
  assert.equal(result.detections, 0);
});

test("flags MetaDefender malware detections", () => {
  const result = classifyMetaDefender({
    lookup_results: {
      detected_by: 1,
      sources: [{ provider: "Example AV", assessment: "malicious" }]
    }
  });
  assert.equal(result.verdict, "malicious");
});
