const urlInput = document.getElementById("url");
const analyzeBtn = document.getElementById("analyze");
const findingsEl = document.getElementById("findings");
const tipsEl = document.getElementById("tips");
const fill = document.getElementById("fill");
const scoreEl = document.getElementById("score");

// Simple lists (expand later)
const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rebrand.ly","lnkd.in"];
const riskyTLDs = ["zip","mov","xyz","top","gq","tk","cf"];
const brands = ["paypal","microsoft","google","facebook","apple","amazon","bank","hsbc","barclays","netflix","instagram","linkedin","github"];

function analyzeUrl(input) {
  findingsEl.innerHTML = "";
  tipsEl.innerHTML = "";

  let score = 0;
  const findings = [];
  const tips = [];

  // Normalize and basic parse
  let raw = input.trim();
  if (!raw) {
    render(score, findings, ["Paste a URL to analyze."]); 
    return;
  }

  // Add scheme if missing
  if (!/^[a-z]+:\/\//i.test(raw)) raw = "https://" + raw;

  let u;
  try { u = new URL(raw); }
  catch {
    render(100, ["Invalid URL format."], ["Use full domain like example.com/login"]); 
    return;
  }

  const host = u.hostname;
  const hostLower = host.toLowerCase();
  const path = u.pathname + u.search;

  // 1) HTTP (not HTTPS)
  if (u.protocol !== "https:") {
    score += 30; findings.push("Uses HTTP (not encrypted)."); tips.push("Prefer HTTPS (padlock) for logins.");
  }

  // 2) IP address in host
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 35; findings.push("IP address instead of domain."); tips.push("Attackers hide behind raw IPs; avoid.");
  }

  // 3) Excessive subdomains
  const labels = host.split(".");
  if (labels.length >= 4) {
    score += 15; findings.push("Many subdomains: " + host); tips.push("Extra subdomains can mask fake sites.");
  }

  // 4) '@' in URL (credential forwarding trick)
  if (u.href.includes("@")) {
    score += 25; findings.push("Contains '@' which can hide the real destination."); tips.push("Everything before '@' can be ignored by browsers.");
  }

  // 5) Percent-encoding spam
  const pctCount = (u.href.match(/%[0-9a-f]{2}/gi) || []).length;
  if (pctCount >= 5) {
    score += 10; findings.push("Heavy percent-encoding in URL."); tips.push("Obfuscated URLs often conceal redirects.");
  }

  // 6) Suspicious TLDs
  const tld = labels.at(-1);
  if (riskyTLDs.includes(tld)) {
    score += 10; findings.push(`Suspicious TLD “.${tld}”.`); tips.push("Be careful with novelty TLDs.");
  }

  // 7) Shorteners
  if (shorteners.includes(hostLower)) {
    score += 25; findings.push("Known URL shortener."); tips.push("Unshorten and verify destination before login.");
  }

  // 8) Look-alike brands / typosquats (very simple heuristics)
  const asciiHost = toASCII(hostLower);
  const flat = asciiHost.replace(/[\W_]/g, "");
  for (const b of brands) {
    if (flat.includes(b) && !hostLower.endsWith(`${b}.com`) && !hostLower.endsWith(`${b}.co.uk`)) {
      score += 20; findings.push(`Possible typosquat / brand lure: “${b}” in ${host}`); 
      tips.push("Type the brand’s domain manually or use bookmarks.");
      break;
    }
  }

  // 9) Confusables / Punycode
  if (hostLower.startsWith("xn--")) {
    score += 20; findings.push("Punycode domain (possible homoglyph)."); tips.push("Visually similar letters can fake brands.");
  }

  // 10) Query bloat / login bait
  if (/\blogin|verify|update|secure|pay\b/i.test(path) && (u.search.length > 20)) {
    score += 10; findings.push("Suspicious login/verify flow with parameters."); tips.push("Navigate from the official homepage instead.");
  }

  // 11) Very long URL
  if (u.href.length > 120) {
    score += 10; findings.push("Unusually long URL."); tips.push("Length can hide redirections and tokens.");
  }

  score = Math.max(0, Math.min(100, score));

  render(score, findings.length ? findings : ["No obvious red flags."], tips.length ? tips : ["Verify padlock + domain. Avoid entering credentials from links you didn’t initiate."]);
}

function render(score, findings, tips) {
  document.getElementById("score").textContent = `${score}/100`;
  const pct = score; // fill %
  document.getElementById("fill").style.width = pct + "%";
  findingsEl.innerHTML = "";
  tipsEl.innerHTML = "";
  findings.forEach(f => { const li = document.createElement("li"); li.textContent = f; findingsEl.appendChild(li); });
  tips.forEach(t => { const li = document.createElement("li"); li.textContent = t; tipsEl.appendChild(li); });
}

// Minimal IDNA to ASCII (fallback for older browsers)
function toASCII(host) {
  try { return host.normalize("NFKC"); } catch { return host; }
}

analyzeBtn.addEventListener("click", () => analyzeUrl(urlInput.value));
urlInput.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); analyzeUrl(urlInput.value); } });
