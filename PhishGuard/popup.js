function formatTs(ts) { try { return new Date(ts).toLocaleString(); } catch { return '-'; } }
function setVerdictStylePill(pill, verdict) {
  pill.classList.remove('ok','warn','bad');
  if (verdict === 'safe') pill.classList.add('ok');
  else if (verdict === 'suspicious') pill.classList.add('warn');
  else if (verdict === 'phishing') pill.classList.add('bad');
}
async function getLastResult() { return new Promise((resolve) => chrome.runtime.sendMessage({ type: 'getLastResult' }, (res) => resolve(res?.ok ? (res.result || null) : null))); }
async function markTrustedHost(host) { return new Promise((resolve) => chrome.runtime.sendMessage({ type: 'markTrusted', host }, (res) => resolve(res?.ok === true))); }

function computeSafetyScore(result) {
  if (!result) return { score: 50, label: 'Unknown', color: '#888' };
  const reasonsCount = Array.isArray(result.reasons) ? result.reasons.length : 0;
  if (result.verdict === 'safe') {
    const score = Math.min(100, 92 + Math.max(0, 5 - reasonsCount));
    return { score, label: 'Secure', color: '#22c55e' };
  }
  if (result.verdict === 'suspicious') {
    const score = Math.max(35, 70 - reasonsCount * 5);
    return { score, label: 'Suspicious', color: '#f59e0b' };
  }
  if (result.verdict === 'phishing') {
    const score = Math.max(5, 28 - reasonsCount * 5);
    return { score, label: 'Phishing Risk', color: '#ef4444' };
  }
  return { score: 50, label: 'Unknown', color: '#888' };
}

function renderScoreCard(result) {
  const { score, label, color } = computeSafetyScore(result);
  const numEl = document.getElementById('scoreNumber');
  const labelEl = document.getElementById('scoreLabel');
  const fillEl = document.getElementById('scoreFill');
  numEl.textContent = `${score}/100`;
  labelEl.textContent = label;
  fillEl.style.width = `${score}%`;
  fillEl.style.background = color;
}

document.addEventListener('DOMContentLoaded', async () => {
  const verdictPill = document.getElementById('verdictPill');
  const urlEl = document.getElementById('url');
  const tsEl = document.getElementById('ts');
  const reasonsUl = document.getElementById('reasons');
  const copyBtn = document.getElementById('copyUrl');
  const trustBtn = document.getElementById('markTrusted');

  const result = await getLastResult();
  renderScoreCard(result);

  if (!result) {
    verdictPill.textContent = 'No data yet'; setVerdictStylePill(verdictPill, ''); urlEl.textContent = '-'; tsEl.textContent = '-';
  } else {
    verdictPill.textContent = result.verdict;
    setVerdictStylePill(verdictPill, result.verdict);
    urlEl.textContent = result.url; urlEl.title = result.url; tsEl.textContent = formatTs(result.timestamp);
    reasonsUl.innerHTML = '';
    const reasons = Array.isArray(result.reasons) ? result.reasons : [];
    if (reasons.length === 0) { const li = document.createElement('li'); li.textContent = 'No reasons available'; reasonsUl.appendChild(li); }
    else for (const r of reasons) { const li = document.createElement('li'); li.textContent = r; reasonsUl.appendChild(li); }
  }

  copyBtn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(result?.url || ''); copyBtn.textContent = 'Copied'; setTimeout(() => (copyBtn.textContent = 'Copy URL'), 1100); }
    catch { copyBtn.textContent = 'Copy failed'; setTimeout(() => (copyBtn.textContent = 'Copy URL'), 1100); }
  });

  trustBtn.addEventListener('click', async () => {
    try { if (!result?.url) return; const host = new URL(result.url).hostname; const ok = await markTrustedHost(host);
      trustBtn.textContent = ok ? 'Trusted ✓' : 'Failed'; setTimeout(() => (trustBtn.textContent = 'Mark Trusted'), 1100);
    } catch { trustBtn.textContent = 'Failed'; setTimeout(() => (trustBtn.textContent = 'Mark Trusted'), 1100); }
  });
});
