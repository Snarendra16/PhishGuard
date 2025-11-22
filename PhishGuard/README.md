## PhishEye — Real-Time Fake Login Page Detector (Manifest V3)

Privacy-first Chrome extension that flags suspicious login pages using local heuristics plus optional certificate analysis when available. Analysis performed locally; no page content is sent to external servers by default.

### What it does
- Heuristic detectors: HTTPS presence, favicon domain mismatch, form action mismatch or insecure, suspicious keywords, iframes, punycode, long hostnames.
- Certificate analysis attempt in background: tries `chrome.webRequest.getSecurityInfo` (not available in Chrome; available in some browsers). Falls back cleanly.
- Verdict thresholds: score < 3 → safe; 3–6 → suspicious; > 6 → phishing.
- UX: Red banner on phishing pages, badge updates (OK/!/X), popup shows details + Mark Trusted.

### Install (load unpacked)
1. Open Chrome → `chrome://extensions/`.
2. Enable Developer mode (top-right).
3. Click “Load unpacked” and select this `phisheye/` folder.
4. Optional: Enable “Allow access to file URLs” to test local files.

### Test pages (local)
- In `phisheye/test-pages/` run:
  - `python -m http.server 8000`
- Open:
  - Legitimate: `http://localhost:8000/legitimate_login.html`
  - Phishing: `http://localhost:8000/phishing_login.html`
- On Chrome, background console will show: `webRequest.getSecurityInfo not available; falling back to heuristics only.`

### Demo script (≈2 minutes)
- Go to `https://example.com` → badge "OK"; popup shows safe verdict. Mention: privacy—analysis is local.
- Open `http://localhost:8000/legitimate_login.html` → likely safe/suspicious-low.
- Open `http://localhost:8000/phishing_login.html` → banner appears; badge "X"; popup shows reasons (favicon mismatch, external HTTP form, keywords, iframe).
- Click popup “Mark Trusted” and refresh → warning bypassed for that host.

### Heuristic weights
- HTTPS missing = 3
- Favicon mismatch = 3
- Form posts to different host = 5
- Form posts insecure while page HTTPS = 4
- Suspicious keywords found = 2 per keyword
- Iframe presence = 2
- Punycode domains = 3
- Long hostname (>30) = 1
- Certificate issues (if available): Expired 6, Self-signed 7, Weak signature 5, Unknown issuer 4

### Permissions
- `storage`, `scripting`, `activeTab`, `tabs`, `webRequest`, `webRequestBlocking`
- `host_permissions: ["<all_urls>"]` for testing (tighten for production).

### Privacy & limitations
- Content scripts cannot access full TLS certs; background attempts `getSecurityInfo` when supported.
- In Chrome, certificate API is typically unavailable; logs will show fallback.
- Heuristics can have false positives/negatives; verify before acting.
- No analytics or external exfiltration; analysis performed locally by default.

### Structure
- `manifest.json`: MV3 manifest
- `service_worker.js`: navigation listener, certificate attempt, badge + storage
- `content_script.js`: heuristics, phishing banner, sends results
- `popup.html/css/js`: popup UI and actions (Copy URL, Mark Trusted)
- `icons/`: placeholder icons
- `test-pages/`: local demo pages
