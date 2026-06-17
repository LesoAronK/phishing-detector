/* PhishGuard — Frontend JS */

const PHISHING_SAMPLE = `Subject: URGENT: Your PayPal account has been suspended!
From: security@paypal-verify.tk

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been temporarily suspended for security reasons. You must verify your identity immediately to restore access.

Click here NOW to verify your account: http://bit.ly/paypal-secure-verify

WARNING: Failure to verify within 24 hours will result in PERMANENT account closure!

Your account currently shows:
- Unauthorized login attempt from Russia
- Credit card needs to be revalidated
- Transaction of $499.99 is pending approval

Act now before your account expires! This is your FINAL NOTICE.

Dear valued member, confirm your billing details immediately.

PayPal Security Team`;

const SAFE_SAMPLE = `Subject: Team meeting rescheduled — Thursday 2pm

Hi everyone,

I hope you're all doing well. I wanted to let you know that our weekly team meeting has been moved from Tuesday to Thursday at 2:00 PM due to a schedule conflict.

The agenda remains the same:
- Q3 project updates
- Review of the new proposal from Sarah
- Planning for the upcoming client presentation

Please find attached the updated meeting agenda and the draft proposal for your review beforehand. Looking forward to seeing everyone Thursday.

Kind regards,
Michael
Product Team Lead`;

// Sample buttons
document.querySelectorAll('.sample-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const type = btn.dataset.type;
    document.getElementById('emailInput').value = type === 'phishing' ? PHISHING_SAMPLE : SAFE_SAMPLE;
    updateCharCount();
  });
});

// Char counter
const textarea = document.getElementById('emailInput');
const charCount = document.getElementById('charCount');
function updateCharCount() {
  charCount.textContent = textarea.value.length.toLocaleString();
}
textarea.addEventListener('input', updateCharCount);

// ── Main analyze function ────────────────────────────────────────────────────

async function analyzeEmail() {
  const text = textarea.value.trim();
  if (!text) {
    showError('Please paste an email to scan.');
    return;
  }

  const btn = document.getElementById('analyzeBtn');
  btn.classList.add('loading');
  btn.innerHTML = '<div class="spinner"></div><span>Analyzing…</span>';

  try {
    const resp = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: text })
    });

    const data = await resp.json();

    if (!resp.ok) {
      showError(data.error || 'Analysis failed.');
      return;
    }

    showResults(data);
  } catch (err) {
    showError('Network error. Make sure the server is running.');
  } finally {
    btn.classList.remove('loading');
    btn.innerHTML = '<span class="btn-text">Scan Email</span><span class="btn-icon">→</span>';
  }
}

function showResults(data) {
  document.getElementById('placeholder').style.display = 'none';
  const content = document.getElementById('resultsContent');
  content.style.display = 'block';

  const isPhishing = data.prediction === 1;

  // Verdict card
  const card = document.getElementById('verdictCard');
  card.className = 'verdict-card ' + (isPhishing ? 'phishing' : 'safe');
  document.getElementById('verdictIcon').textContent = isPhishing ? '🚨' : '✅';
  document.getElementById('verdictLabel').textContent = isPhishing ? 'Phishing Detected' : 'Email Looks Safe';
  document.getElementById('verdictConfidence').textContent =
    `${data.confidence} confidence · ${isPhishing ? data.phishing_probability : data.safe_probability}% probability`;

  // Prob bars (animate after a tick)
  setTimeout(() => {
    document.getElementById('safeBar').style.width = data.safe_probability + '%';
    document.getElementById('phishBar').style.width = data.phishing_probability + '%';
  }, 60);
  document.getElementById('safePct').textContent = data.safe_probability + '%';
  document.getElementById('phishPct').textContent = data.phishing_probability + '%';

  // Feature chips
  const feats = data.features;
  const chipData = [
    { val: feats.url_count, name: 'URLs Found' },
    { val: feats.phishing_keywords, name: 'Phish Keywords' },
    { val: feats.safe_keywords, name: 'Safe Keywords' },
    { val: feats.suspicious_urls, name: 'Suspicious URLs' },
    { val: feats.caps_ratio + '%', name: 'Caps Ratio' },
    { val: feats.exclamation_count, name: 'Exclamations' },
  ];
  document.getElementById('featureGrid').innerHTML = chipData.map(c => `
    <div class="metric-chip">
      <div class="metric-chip-val">${c.val}</div>
      <div class="metric-chip-name">${c.name}</div>
    </div>
  `).join('');

  // Risk factors
  const rfContainer = document.getElementById('riskFactors');
  if (data.risk_factors.length === 0) {
    rfContainer.innerHTML = '<p style="font-size:13px;color:var(--text-muted)">No significant risk factors detected.</p>';
  } else {
    rfContainer.innerHTML = data.risk_factors.map(f => `
      <div class="risk-factor ${f.severity}">
        <span class="risk-icon">${f.icon}</span>
        <span>${f.label}</span>
      </div>
    `).join('');
  }

  // Scroll to results
  document.getElementById('resultsPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showError(msg) {
  document.getElementById('placeholder').style.display = 'none';
  const content = document.getElementById('resultsContent');
  content.style.display = 'block';
  content.innerHTML = `
    <div style="text-align:center;padding:40px 20px;color:var(--danger)">
      <div style="font-size:40px;margin-bottom:12px">⚠️</div>
      <div style="font-weight:700;margin-bottom:6px">Error</div>
      <div style="font-size:13px;color:var(--text-muted)">${msg}</div>
    </div>`;
}

// Allow Enter+Ctrl to submit
textarea.addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyzeEmail();
});
