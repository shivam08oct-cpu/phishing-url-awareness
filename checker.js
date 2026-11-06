/**
 * EWB Phishing URL Awareness Checker
 * JavaScript port of phishing_checker.py — runs entirely in the browser.
 * No URL is ever fetched or visited.
 */

const INFO_PREFIXES = [
  "No URL entered",
  "Could not identify",
  "No listed warning",
  "This text is not a valid URL format",
];

function hasWarnings(findings) {
  if (!findings || findings.length === 0) return false;
  return !INFO_PREFIXES.some((p) => findings[0].startsWith(p));
}

function inspectURL(raw) {
  const url = raw.trim();
  const findings = [];

  if (!url) return [{ text: "No URL entered.", type: "info" }];

  const candidate = url.includes("://") ? url : "http://" + url;

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return [{ text: "This text is not a valid URL format.", type: "info" }];
  }

  const host = (parsed.hostname || "").toLowerCase();

  if (!host) return [{ text: "Could not identify a hostname.", type: "info" }];

  // Check 1 — @ symbol in the full URL string
  if (candidate.includes("@")) {
    findings.push({
      text: "Contains an @ symbol; inspect carefully.",
      type: "warn",
    });
  }

  // Check 2 — Unusually long URL
  if (url.length > 100) {
    findings.push({
      text: `Unusually long URL (${url.length} characters, over 100).`,
      type: "warn",
    });
  }

  // Check 3 — IP address hostname
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    findings.push({
      text: "Uses an IP address instead of a familiar domain.",
      type: "warn",
    });
  }

  // Check 4 — Many subdomains (5+ labels)
  const labels = host.split(".").filter(Boolean);
  if (labels.length >= 5) {
    findings.push({
      text: "Contains many hostname segments / subdomains.",
      type: "warn",
    });
  }

  // Check 5 — Punycode
  if (host.includes("xn--")) {
    findings.push({
      text: "Contains a punycode-style hostname (possible homograph attack).",
      type: "warn",
    });
  }

  // Check 6 — HTTP (not HTTPS)
  if (parsed.protocol === "http:") {
    findings.push({
      text: "Uses HTTP. HTTPS alone does not prove trust.",
      type: "warn",
    });
  }

  if (findings.length === 0) {
    findings.push({
      text: "No listed warning signs found. This does NOT prove safety.",
      type: "ok",
    });
  }

  return findings;
}
