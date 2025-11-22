// PhishEye service worker (background).
// Privacy: Analysis performed locally; no page content is sent to external servers by default.

const LAST_RESULT_KEY = "lastResult";
const TRUSTED_HOSTS_KEY = "trustedHosts";

const DEMO_TRUSTED_ISSUERS = [
  "Google Trust Services",
  "DigiCert",
  "Let's Encrypt",
  "Amazon",
  "Sectigo",
  "GlobalSign"
];

function setBadge(verdict) {
  let text = '';
  let color = '#888';
  if (verdict === 'safe') { text = 'OK'; color = '#2e7d32'; }
  else if (verdict === 'suspicious') { text = '!'; color = '#f9a825'; }
  else if (verdict === 'phishing') { text = 'X'; color = '#c62828'; }
  chrome.action.setBadgeText({ text });
  if (text) chrome.action.setBadgeBackgroundColor({ color });
}

function mergeResults(heuristic, certInfo) {
  if (!heuristic && !certInfo) return null;
  const result = {
    url: (heuristic && heuristic.url) || (certInfo && certInfo.url) || '',
    verdict: (heuristic && heuristic.verdict) || (certInfo && certInfo.verdict) || 'safe',
    reasons: [...(heuristic?.reasons || []), ...(certInfo?.reasons || [])],
    timestamp: Date.now(),
    source: heuristic && certInfo ? 'both' : heuristic ? 'heuristic' : 'cert'
  };
  const hasPhishing = [heuristic?.verdict, certInfo?.verdict].includes('phishing');
  const hasSuspicious = [heuristic?.verdict, certInfo?.verdict].includes('suspicious');
  if (hasPhishing) result.verdict = 'phishing';
  else if (hasSuspicious && result.verdict !== 'phishing') result.verdict = 'suspicious';
  return result;
}

async function setLastResult(result) {
  if (!result) return;
  await chrome.storage.local.set({ [LAST_RESULT_KEY]: result });
  setBadge(result.verdict);
}

async function getTrustedHosts() {
  const data = await chrome.storage.local.get(TRUSTED_HOSTS_KEY);
  return new Set(data[TRUSTED_HOSTS_KEY] || []);
}

async function addTrustedHost(host) {
  const set = await getTrustedHosts();
  set.add(host);
  await chrome.storage.local.set({ [TRUSTED_HOSTS_KEY]: Array.from(set) });
}

async function isTrustedHost(urlString) {
  try {
    const u = new URL(urlString);
    const set = await getTrustedHosts();
    return set.has(u.hostname);
  } catch {
    return false;
  }
}

async function analyzeCertificateIfAvailable(details) {
  const url = details?.url || '';
  const apiAvailable = !!(chrome.webRequest && chrome.webRequest.getSecurityInfo);
  if (!apiAvailable) {
    console.log('[PhishEye] webRequest.getSecurityInfo not available; falling back to heuristics only.');
    return null;
  }
  try {
    if (details.type !== 'main_frame') return null;
    const securityInfo = await chrome.webRequest.getSecurityInfo(details.requestId, { certificateChain: true, rawDER: false });
    if (!securityInfo) return null;

    const reasons = [];
    let score = 0;

    if (securityInfo.validity?.end && Date.now() > new Date(securityInfo.validity.end).getTime()) {
      reasons.push('Certificate is expired');
      score += 6;
    }

    const algo = (securityInfo?.signature && securityInfo.signature.algorithm) || '';
    const algLower = String(algo).toLowerCase();
    if (algLower.includes('sha1') || algLower.includes('md5')) {
      reasons.push('Weak certificate signature algorithm (SHA-1/MD5)');
      score += 5;
    }

    const subject = securityInfo?.subject || '';
    const issuer = securityInfo?.issuer || '';
    if (subject && issuer && subject === issuer) {
      reasons.push('Self-signed certificate (subject equals issuer)');
      score += 7;
    }

    if (issuer) {
      const matched = DEMO_TRUSTED_ISSUERS.some(tr => issuer.includes(tr));
      if (!matched) {
        reasons.push(`Certificate issuer not recognized: ${issuer}`);
        score += 4;
      }
    }

    let verdict = 'safe';
    if (score > 6) verdict = 'phishing';
    else if (score >= 3) verdict = 'suspicious';

    return { url, verdict, reasons, timestamp: Date.now(), source: 'cert' };
  } catch (e) {
    console.log('[PhishEye] Error analyzing certificate:', e);
    return null;
  }
}

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    try {
      if (details.type !== 'main_frame') return;

      const trusted = await isTrustedHost(details.url);
      if (trusted) {
        await setLastResult({
          url: details.url,
          verdict: 'safe',
          reasons: ['Host is marked as trusted by user'],
          timestamp: Date.now(),
          source: 'heuristic'
        });
        return;
      }

      const certResult = await analyzeCertificateIfAvailable(details);
      if (certResult) {
        const existing = (await chrome.storage.local.get(LAST_RESULT_KEY))[LAST_RESULT_KEY];
        const merged = mergeResults(existing, certResult);
        await setLastResult(merged || certResult);
      }
    } catch (e) {
      console.log('[PhishEye] onCompleted handler error:', e);
    }
  },
  { urls: ['<all_urls>'] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message?.type === 'heuristicResult') {
        const heuristic = message.payload;
        const trusted = await isTrustedHost(heuristic.url);
        if (trusted) {
          heuristic.verdict = 'safe';
          heuristic.reasons = ['Host is marked as trusted by user', ...heuristic.reasons];
          heuristic.source = 'heuristic';
        }
        const existing = (await chrome.storage.local.get(LAST_RESULT_KEY))[LAST_RESULT_KEY];
        const merged = mergeResults(heuristic, existing?.source === 'cert' ? existing : null) || heuristic;
        await setLastResult(merged);
        sendResponse({ ok: true });
      } else if (message?.type === 'getLastResult') {
        const data = await chrome.storage.local.get(LAST_RESULT_KEY);
        sendResponse({ ok: true, result: data[LAST_RESULT_KEY] || null });
      } else if (message?.type === 'markTrusted' && message?.host) {
        await addTrustedHost(message.host);
        sendResponse({ ok: true });
      } else if (message?.type === 'getTrustedHosts') {
        const set = await getTrustedHosts();
        sendResponse({ ok: true, hosts: Array.from(set) });
      } else {
        sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
});
