// PhishEye content script (document_end).
// Privacy: Analysis performed locally; no page content is sent to external servers by default.

(function () {
  const WEIGHTS = {
    httpsMissing: 3,
    faviconMismatch: 3,
    formActionMismatch: 5,
    formOnHttpsToHttp: 4,
    keyword: 2,
    iframe: 2,
    punycode: 3,
    longHostname: 1
  };

  // Common legitimate auth providers/domains to avoid false positives
  const ALLOWLIST_BASE_DOMAINS = [
    'google.com', 'gmail.com', 'openai.com', 'auth0.com', 'okta.com', 'onelogin.com',
    'microsoft.com', 'login.microsoftonline.com', 'apple.com', 'icloud.com',
    'github.com', 'facebook.com', 'twitter.com', 'x.com', 'yahoo.com'
  ];

  // Common CDN bases to ignore for favicon loads (legit pattern)
  const ALLOWLIST_CDN_BASES = [
    'gstatic.com','googleusercontent.com','cloudfront.net','akamaihd.net','akamai.net',
    'bootstrapcdn.com','jsdelivr.net','cdn.jsdelivr.net','unpkg.com','cloudflare.com','cloudflare.net',
    'fonts.gstatic.com','fonts.googleapis.com','githubassets.com','website-files.com','prod.website-files.com','cdn.prod.website-files.com'
  ];

  const SUSPICIOUS_KEYWORDS = [
    'verify your account',
    'update your password',
    'urgent action required',
    'confirm your identity',
    'unauthorized login attempt',
    'restricted',
    'security alert',
    'login immediately',
    'enter your credentials'
  ];

  function getBaseDomain(hostname) {
    try {
      const h = String(hostname || '').toLowerCase();
      if (!h || h === 'localhost') return h;
      const parts = h.split('.');
      if (parts.length <= 2) return h;
      const last = parts[parts.length - 1];
      const secondLast = parts[parts.length - 2];
      const sld = secondLast + '.' + last;
      const commonSLDs = new Set(['co.uk','org.uk','gov.uk','ac.uk','com.au','net.au','co.in','com.br','com.mx']);
      if (commonSLDs.has(sld)) {
        return parts.slice(-3).join('.');
      }
      return parts.slice(-2).join('.');
    } catch { return hostname; }
  }

  function hasLoginIndicators(ctx = document) {
    if (ctx.querySelector('input[type="password"], input[autocomplete="current-password"], input[autocomplete="password"]')) return true;

    const candidates = Array.from(ctx.querySelectorAll('input[name], input[id], button, a[role="button"], a'))
      .map(el => (el.getAttribute('name') || el.id || el.textContent || el.getAttribute('aria-label') || '').toLowerCase());
    const hints = ['login','log in','sign in','signin','password','pass','auth','account','continue','next','verify'];
    if (candidates.some(t => hints.some(h => t.includes(h)))) return true;

    const forms = Array.from(ctx.querySelectorAll('form'));
    for (const f of forms) {
      const inputs = Array.from(f.querySelectorAll('input')).filter(el => !['hidden','checkbox','radio'].includes((el.type||'').toLowerCase()));
      const hasCredCount = inputs.filter(el => {
        const n = (el.name || el.id || '').toLowerCase();
        return ['user','email','pass','login'].some(k => n.includes(k));
      }).length;
      if (inputs.length >= 2 && hasCredCount >= 1) return true;
    }
    return false;
  }

  function scanSameOriginIframesForLogin() {
    const iframes = Array.from(document.querySelectorAll('iframe'));
    for (const fr of iframes) {
      try {
        const doc = fr.contentDocument;
        if (doc && hasLoginIndicators(doc)) return true;
      } catch (_) {
        // cross-origin, ignore
      }
    }
    return false;
  }

  function getHostnameFromUrl(href) {
    try { return new URL(href, location.href).hostname; } catch { return ''; }
  }

  function collectFaviconHostnames() {
    const links = Array.from(document.querySelectorAll('link[rel~="icon"], link[rel~="shortcut icon"]'));
    const hosts = new Set();
    for (const link of links) {
      const href = link.getAttribute('href') || '';
      if (!href || href.startsWith('data:')) continue;
      const host = getHostnameFromUrl(href);
      if (host) hosts.add(host);
    }
    return Array.from(hosts);
  }

  function analyzeForms() {
    const forms = Array.from(document.forms || []);
    const reasons = [];
    let score = 0;
    const pageHost = location.hostname;
    const pageBase = getBaseDomain(pageHost);
    const pageProtocol = location.protocol;

    for (const form of forms) {
      const action = (form.getAttribute('action') || '').trim();
      if (!action || action === '#' || action.toLowerCase().startsWith('javascript:')) continue;
      const actionHost = getHostnameFromUrl(action);
      const actionBase = getBaseDomain(actionHost);

      if (actionHost) {
        if (actionBase && actionBase !== pageBase) {
          reasons.push(`Form posts to a different base domain: ${actionHost}`);
          score += WEIGHTS.formActionMismatch;
        }
        try {
          const actionUrl = new URL(action, location.href);
          if (pageProtocol === 'https:' && actionUrl.protocol === 'http:') {
            reasons.push('Form posts over HTTP from an HTTPS page');
            score += WEIGHTS.formOnHttpsToHttp;
          }
        } catch {}
      }
    }
    return { reasons, score };
  }

  function searchSuspiciousKeywords() {
    const text = (document.body?.innerText || '') + ' ' + (document.title || '');
    const reasons = [];
    let score = 0;
    for (const k of SUSPICIOUS_KEYWORDS) {
      if (text.toLowerCase().includes(k.toLowerCase())) {
        reasons.push(`Suspicious phrase detected: "${k}"`);
        score += WEIGHTS.keyword;
      }
    }
    return { reasons, score };
  }

  function analyzeHeuristics() {
    const pageHost = location.hostname;
    const pageBase = getBaseDomain(pageHost);
    const pageProtocol = location.protocol;

    // Allowlist override for widely trusted domains
    if (ALLOWLIST_BASE_DOMAINS.includes(pageBase)) {
      return { url: location.href, verdict: 'safe', reasons: ['Domain is allowlisted (trusted provider)'], score: 0, timestamp: Date.now(), source: 'heuristic' };
    }

    const loginContext = hasLoginIndicators() || scanSameOriginIframesForLogin();

    const reasons = [];
    let score = 0;

    if (loginContext) {
      // Full scoring for login-like pages
      if (pageProtocol !== 'https:') { reasons.push('Page is not using HTTPS'); score += WEIGHTS.httpsMissing; }

      const favHosts = collectFaviconHostnames();
      for (const fh of favHosts) {
        const favBase = getBaseDomain(fh);
        if (favBase && ALLOWLIST_CDN_BASES.includes(favBase)) continue;
        if (fh && favBase && favBase !== pageBase) { reasons.push(`Favicon loads from different base domain: ${fh}`); score += WEIGHTS.faviconMismatch; break; }
      }

      const formRes = analyzeForms();
      reasons.push(...formRes.reasons);
      score += formRes.score;

      const kwRes = searchSuspiciousKeywords();
      reasons.push(...kwRes.reasons);
      score += kwRes.score;

      const iframeCount = document.querySelectorAll('iframe').length;
      if (iframeCount >= 2) { reasons.push(`Page contains ${iframeCount} iframe(s)`); score += WEIGHTS.iframe; }
    } else {
      // Light scoring for non-login pages: avoid "skipped" and only flag strong signals
      if (pageProtocol !== 'https:') { reasons.push('Page is not using HTTPS'); score += WEIGHTS.httpsMissing; }
      if (pageHost.includes('xn--')) { reasons.push('Hostname contains punycode (xn--)'); score += WEIGHTS.punycode; }
      if (pageHost.length > 30) { reasons.push('Hostname is unusually long (>30 chars)'); score += WEIGHTS.longHostname; }
      // Count keywords only if multiple suspicious phrases appear to reduce noise
      const kwRes = searchSuspiciousKeywords();
      const keywordCount = kwRes.reasons.length;
      if (keywordCount >= 2) { reasons.push(...kwRes.reasons); score += WEIGHTS.keyword * keywordCount; }
      // Do NOT consider favicon/form/iframe in light mode to prevent false positives
    }

    let verdict = 'safe';
    if (score > 6) verdict = 'phishing';
    else if (score >= 3) verdict = 'suspicious';

    return { url: location.href, verdict, reasons, score, timestamp: Date.now(), source: 'heuristic' };
  }

  function insertWarningBanner(verdict) {
    if (verdict !== 'phishing') return;
    if (document.getElementById('__phisheye_banner')) return;

    const banner = document.createElement('div');
    banner.id = '__phisheye_banner';
    banner.style.position = 'fixed';
    banner.style.top = '0';
    banner.style.left = '0';
    banner.style.right = '0';
    banner.style.zIndex = '2147483647';
    banner.style.background = '#c62828';
    banner.style.color = 'white';
    banner.style.fontFamily = 'system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif';
    banner.style.padding = '10px 16px';
    banner.style.boxShadow = '0 2px 6px rgba(0,0,0,0.3)';
    banner.style.display = 'flex';
    banner.style.justifyContent = 'space-between';
    banner.style.alignItems = 'center';

    const left = document.createElement('div');
    left.textContent = 'PhishEye warning: This page appears to be a phishing login. Do not enter credentials. Analysis performed locally; no page content is sent to external servers by default.';

    const right = document.createElement('div');
    const btn = document.createElement('button');
    btn.textContent = 'Dismiss';
    btn.style.background = 'white';
    btn.style.color = '#c62828';
    btn.style.border = 'none';
    btn.style.borderRadius = '4px';
    btn.style.padding = '6px 10px';
    btn.style.cursor = 'pointer';
    btn.addEventListener('click', () => banner.remove());
    right.appendChild(btn);

    banner.appendChild(left);
    banner.appendChild(right);
    document.documentElement.appendChild(banner);
    document.documentElement.style.scrollPaddingTop = '52px';
  }

  async function isTrustedHost(hostname) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'getTrustedHosts' }, (res) => {
        if (!res?.ok) return resolve(false);
        resolve((res.hosts || []).includes(hostname));
      });
    });
  }

  function rerunAndSend() {
    const h = analyzeHeuristics();
    chrome.runtime.sendMessage({ type: 'heuristicResult', payload: h }, () => {});
    if (h.verdict === 'phishing') insertWarningBanner(h.verdict);
  }

  function watchForLoginIndicators(timeoutMs = 5000) {
    let done = false;
    const observer = new MutationObserver(() => {
      if (done) return;
      if (hasLoginIndicators() || scanSameOriginIframesForLogin()) {
        done = true;
        observer.disconnect();
        rerunAndSend();
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => { if (!done) observer.disconnect(); }, timeoutMs);
  }

  async function run() {
    try {
      const heuristic = analyzeHeuristics();
      const hostTrusted = await isTrustedHost(location.hostname);
      if (!hostTrusted) insertWarningBanner(heuristic.verdict);
      chrome.runtime.sendMessage({ type: 'heuristicResult', payload: heuristic }, () => {});
      watchForLoginIndicators(5000);
    } catch (e) {
      console.log('[PhishEye] Heuristic analysis error:', e);
    }
  }

  run();
})();
