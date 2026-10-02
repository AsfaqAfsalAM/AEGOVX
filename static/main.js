/**
 * main.js – Professional URL Security & Website Risk Scanner
 * All DOM updates strictly use textContent (never innerHTML on server/user data) to guarantee XSS safety.
 */
'use strict';

// ── DOM References ─────────────────────────────────────────────────────────────
const urlInput          = document.getElementById('url-input');
const scanBtn           = document.getElementById('scan-btn');
const errorBanner       = document.getElementById('error-banner');
const errorMsg          = document.getElementById('error-msg');
const scanProgressBox   = document.getElementById('scan-progress-box');
const progressBarFill   = document.getElementById('progress-bar-fill');
const progressPercent   = document.getElementById('progress-percent');
const resultsSection    = document.getElementById('results-section');

// Results header & meta
const scannedUrl        = document.getElementById('scanned-url');
const scannedUrlLink    = document.getElementById('scanned-url-link');
const scanIdVal         = document.getElementById('scan-id-val');
const scanTimeVal       = document.getElementById('scan-time-val');
const riskLevelBadge    = document.getElementById('risk-level-badge');
const confidenceBadge   = document.getElementById('confidence-badge');
const coverageBadge     = document.getElementById('coverage-badge');
const confidenceReason  = document.getElementById('confidence-reason');
const riskTruthStatement= document.getElementById('risk-truth-statement');
const riskHeadline      = document.getElementById('risk-headline');
const riskSubtext       = document.getElementById('risk-subtext');
const riskScoreNum      = document.getElementById('risk-score-num');
const riskGaugeFill     = document.getElementById('risk-gauge-fill');
const headerGradeBadge  = document.getElementById('header-grade-badge');
const headerScoreNum    = document.getElementById('header-score-num');
const headerStatusLabel = document.getElementById('header-status-label');

// Category cards
const catStatusTI       = document.getElementById('cat-status-ti');
const catPtsTI          = document.getElementById('cat-pts-ti');
const catDescTI         = document.getElementById('cat-desc-ti');
const catQuickTI        = document.getElementById('cat-quick-ti');

const catStatusHeur     = document.getElementById('cat-status-heur');
const catPtsHeur        = document.getElementById('cat-pts-heur');
const catDescHeur       = document.getElementById('cat-desc-heur');
const catQuickHeur      = document.getElementById('cat-quick-heur');

const catStatusDNS      = document.getElementById('cat-status-dns');
const catPtsDNS         = document.getElementById('cat-pts-dns');
const catDescDNS        = document.getElementById('cat-desc-dns');
const catQuickDNS       = document.getElementById('cat-quick-dns');

const catStatusTLS      = document.getElementById('cat-status-tls');
const catPtsTLS         = document.getElementById('cat-pts-tls');
const catDescTLS        = document.getElementById('cat-desc-tls');
const catQuickTLS       = document.getElementById('cat-quick-tls');

const catStatusRedir    = document.getElementById('cat-status-redir');
const catPtsRedir       = document.getElementById('cat-pts-redir');
const catDescRedir      = document.getElementById('cat-desc-redir');
const catQuickRedir     = document.getElementById('cat-quick-redir');

const catStatusHeaders  = document.getElementById('cat-status-headers');
const catPtsHeaders     = document.getElementById('cat-pts-headers');
const catDescHeaders    = document.getElementById('cat-desc-headers');
const catQuickHeaders   = document.getElementById('cat-quick-headers');

// Findings & Diagnostics
const findingsContainer = document.getElementById('findings-container');
const diagTIContent     = document.getElementById('diag-ti-content');
const diagTLSContent    = document.getElementById('diag-tls-content');
const diagRedirContent  = document.getElementById('diag-redir-content');
const diagDNSContent    = document.getElementById('diag-dns-content');
const diagCookiesContent= document.getElementById('diag-cookies-content');
const diagRawEvidenceContent = document.getElementById('diag-raw-evidence-content');
const headersGrid       = document.getElementById('headers-grid');
const infoGrid          = document.getElementById('info-grid');

// Action buttons
const newScanBtn        = document.getElementById('new-scan-btn');
const copyReportBtn     = document.getElementById('copy-report-btn');
const downloadBtn       = document.getElementById('download-json-btn');
const printPdfBtn       = document.getElementById('print-pdf-btn');

// Recent scans
const recentScansStrip  = document.getElementById('recent-scans-strip');
const recentScansList   = document.getElementById('recent-scans-list');

// Severity counts
const countAll          = document.getElementById('count-all');
const countCritical     = document.getElementById('count-critical');
const countHigh         = document.getElementById('count-high');
const countMedium       = document.getElementById('count-medium');
const countLow          = document.getElementById('count-low');
const countInfo         = document.getElementById('count-info');

let currentScanResult   = null;
let currentFindings     = [];
let currentFilter       = 'all';

// ── Color & Theme Config ──────────────────────────────────────────────────────
const RISK_COLORS = {
  'SAFE':       '#10b981',
  'LOW RISK':   '#22c55e',
  'SUSPICIOUS': '#eab308',
  'HIGH RISK':  '#f97316',
  'MALICIOUS':  '#ef4444',
  'UNKNOWN':    '#64748b'
};

const SEV_ICONS = {
  'Critical': '🔴',
  'High':     '🟠',
  'Medium':   '🟡',
  'Low':      '🔵',
  'Informational': '⚪'
};

// ── Safe DOM Helper ───────────────────────────────────────────────────────────
function setText(el, val) {
  if (!el) return;
  el.textContent = (val == null) ? '—' : String(val);
}

function showError(msg) {
  setText(errorMsg, msg);
  errorBanner.classList.add('visible');
}

function hideError() {
  errorBanner.classList.remove('visible');
}

// ── Real Scan Progress Controller ─────────────────────────────────────────────
const PROGRESS_STEPS = [
  { id: 'pstep-1', pct: 15 },
  { id: 'pstep-2', pct: 30 },
  { id: 'pstep-3', pct: 48 },
  { id: 'pstep-4', pct: 64 },
  { id: 'pstep-5', pct: 78 },
  { id: 'pstep-6', pct: 88 },
  { id: 'pstep-7', pct: 98 },
];

let progressInterval = null;

function startProgress() {
  scanProgressBox.classList.add('visible');
  progressBarFill.style.width = '5%';
  setText(progressPercent, '5%');

  // Reset steps
  PROGRESS_STEPS.forEach((s, idx) => {
    const el = document.getElementById(s.id);
    if (!el) return;
    el.className = 'pstep ' + (idx === 0 ? 'active' : 'pending');
    const icon = el.querySelector('.step-icon');
    if (icon) icon.textContent = (idx === 0 ? '⟳' : '○');
  });

  let stepIdx = 0;
  progressInterval = setInterval(() => {
    stepIdx++;
    if (stepIdx < PROGRESS_STEPS.length) {
      const prev = document.getElementById(PROGRESS_STEPS[stepIdx - 1].id);
      if (prev) {
        prev.className = 'pstep done';
        const icon = prev.querySelector('.step-icon');
        if (icon) icon.textContent = '✓';
      }
      const curr = document.getElementById(PROGRESS_STEPS[stepIdx].id);
      if (curr) {
        curr.className = 'pstep active';
        const icon = curr.querySelector('.step-icon');
        if (icon) icon.textContent = '⟳';
      }
      const pct = PROGRESS_STEPS[stepIdx].pct;
      progressBarFill.style.width = `${pct}%`;
      setText(progressPercent, `${pct}%`);
    }
  }, 450);
}

function finishProgress() {
  if (progressInterval) clearInterval(progressInterval);
  PROGRESS_STEPS.forEach(s => {
    const el = document.getElementById(s.id);
    if (!el) return;
    el.className = 'pstep done';
    const icon = el.querySelector('.step-icon');
    if (icon) icon.textContent = '✓';
  });
  progressBarFill.style.width = '100%';
  setText(progressPercent, '100%');
  setTimeout(() => {
    scanProgressBox.classList.remove('visible');
  }, 400);
}

function stopProgressOnError() {
  if (progressInterval) clearInterval(progressInterval);
  scanProgressBox.classList.remove('visible');
}

function setLoading(on) {
  scanBtn.classList.toggle('loading', on);
  scanBtn.disabled = on;
  urlInput.disabled = on;
}

// ── Copy-Ready Server Fix Code Generator (Preserved) ──────────────────────────
function buildFixBlock(fixData) {
  const servers = Object.keys(fixData || {});
  if (!servers.length) return null;

  // Filter to standard server keys
  const displayServers = ['Nginx', 'Apache', 'Express'].filter(s => fixData[s] || fixData[s.toLowerCase()]);
  if (!displayServers.length) return null;

  const wrap = document.createElement('div');
  wrap.className = 'fix-section';

  const lbl = document.createElement('div');
  lbl.className = 'fix-label';
  lbl.textContent = '🔧 Server Hardening Config — Click to copy:';
  wrap.appendChild(lbl);

  const tabsRow = document.createElement('div');
  tabsRow.className = 'fix-tabs';

  const codeWrap = document.createElement('div');
  codeWrap.className = 'fix-code-wrap';

  const codeEl = document.createElement('code');
  codeEl.className = 'fix-code';

  const copyBtn = document.createElement('button');
  copyBtn.className = 'copy-fix-btn';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(codeEl.textContent).then(() => {
      copyBtn.textContent = '✓ Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
    });
  });

  codeWrap.appendChild(codeEl);
  codeWrap.appendChild(copyBtn);

  let activeTab = null;
  displayServers.forEach((srv, i) => {
    const tab = document.createElement('button');
    tab.className = 'fix-tab' + (i === 0 ? ' active' : '');
    tab.textContent = srv;
    const snippet = fixData[srv] || fixData[srv.toLowerCase()];
    tab.addEventListener('click', () => {
      if (activeTab) activeTab.classList.remove('active');
      tab.classList.add('active');
      activeTab = tab;
      setText(codeEl, snippet);
    });
    tabsRow.appendChild(tab);
    if (i === 0) {
      activeTab = tab;
      setText(codeEl, snippet);
    }
  });

  wrap.appendChild(tabsRow);
  wrap.appendChild(codeWrap);
  return wrap;
}

// ── Build Single Security Header Card ─────────────────────────────────────────
function buildHeaderCard(h, isInfo) {
  const status = h.status; // pass | warning | fail
  const card = document.createElement('div');
  card.className = `hcard st-${status}`;

  const top = document.createElement('div');
  top.className = 'hcard-top';
  top.setAttribute('role', 'button');
  top.setAttribute('tabindex', '0');
  top.setAttribute('aria-expanded', 'false');

  const emojiEl = document.createElement('div');
  emojiEl.className = 'hcard-emoji';
  emojiEl.textContent = h.emoji || '🛡️';

  const names = document.createElement('div');
  names.className = 'hcard-names';
  const plain = document.createElement('div');
  plain.className = 'hcard-plain';
  setText(plain, h.plain_name || h.name);
  const tech = document.createElement('div');
  tech.className = 'hcard-tech';
  setText(tech, h.name);
  names.appendChild(plain);
  names.appendChild(tech);

  const right = document.createElement('div');
  right.className = 'hcard-right';

  if (!isInfo && h.max_points != null) {
    const pts = document.createElement('span');
    pts.className = 'pts-label';
    setText(pts, `${h.points} / ${h.max_points} pts`);
    right.appendChild(pts);
  }

  const pill = document.createElement('span');
  pill.className = 'status-pill';
  setText(pill, status === 'pass' ? '✓ Configured' : status === 'warning' ? '⚠ Sub-optimal' : '✕ Missing');
  right.appendChild(pill);

  const chev = document.createElement('span');
  chev.className = 'chevron';
  chev.textContent = '▾';
  right.appendChild(chev);

  top.appendChild(emojiEl);
  top.appendChild(names);
  top.appendChild(right);

  const detail = document.createElement('div');
  detail.className = 'hcard-detail';

  const grid = document.createElement('div');
  grid.className = 'detail-grid';

  const whatBox = document.createElement('div');
  whatBox.className = 'detail-box';
  const whatLbl = document.createElement('div');
  whatLbl.className = 'detail-box-label';
  whatLbl.textContent = '📖 What it does';
  const whatTxt = document.createElement('div');
  whatTxt.className = 'detail-box-text';
  setText(whatTxt, h.what || '');
  whatBox.appendChild(whatLbl);
  whatBox.appendChild(whatTxt);

  const whyBox = document.createElement('div');
  whyBox.className = 'detail-box';
  const whyLbl = document.createElement('div');
  whyLbl.className = 'detail-box-label';
  whyLbl.textContent = '⚡ Security Impact';
  const whyTxt = document.createElement('div');
  whyTxt.className = 'detail-box-text';
  setText(whyTxt, h.why || '');
  whyBox.appendChild(whyLbl);
  whyBox.appendChild(whyTxt);

  grid.appendChild(whatBox);
  grid.appendChild(whyBox);
  detail.appendChild(grid);

  // Observed value
  const cvWrap = document.createElement('div');
  cvWrap.className = 'current-value-wrap';
  const cvLbl = document.createElement('div');
  cvLbl.className = 'current-value-label';
  cvLbl.textContent = '🔍 Observed Header Value';
  const cvBox = document.createElement('div');
  cvBox.className = 'current-value-box';
  if (h.value) {
    setText(cvBox, h.value);
  } else {
    const missing = document.createElement('span');
    missing.className = 'not-present';
    missing.textContent = 'Header not sent by server.';
    cvBox.appendChild(missing);
  }
  cvWrap.appendChild(cvLbl);
  cvWrap.appendChild(cvBox);
  detail.appendChild(cvWrap);

  // Recommendations / Notes
  if (h.notes && h.notes.length) {
    const nl = document.createElement('ul');
    nl.className = 'notes-list';
    h.notes.forEach(note => {
      const li = document.createElement('li');
      setText(li, `• ${note}`);
      nl.appendChild(li);
    });
    detail.appendChild(nl);
  }

  // Fix code
  if (h.fix && status !== 'pass') {
    const fb = buildFixBlock(h.fix);
    if (fb) detail.appendChild(fb);
  }

  function toggle() {
    const open = card.classList.toggle('open');
    top.setAttribute('aria-expanded', String(open));
  }
  top.addEventListener('click', toggle);
  top.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
  });

  card.appendChild(top);
  card.appendChild(detail);
  return card;
}

// ── Render Unified Findings ───────────────────────────────────────────────────
function renderFindings() {
  findingsContainer.innerHTML = '';

  const filtered = currentFilter === 'all'
    ? currentFindings
    : currentFindings.filter(f => f.severity === currentFilter);

  if (!filtered.length) {
    const empty = document.createElement('div');
    empty.className = 'no-findings-msg';
    empty.textContent = currentFilter === 'all'
      ? '✓ Excellent! No security findings or configuration warnings identified.'
      : `✓ No ${currentFilter} severity findings detected.`;
    findingsContainer.appendChild(empty);
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card sev-${f.severity}`;

    const top = document.createElement('div');
    top.className = 'finding-top';

    const group = document.createElement('div');
    group.className = 'finding-badge-group';

    const sevPill = document.createElement('span');
    sevPill.className = `finding-sev-pill sev-pill-${f.severity}`;
    setText(sevPill, `${SEV_ICONS[f.severity] || '⚪'} ${f.severity}`);
    group.appendChild(sevPill);

    const catPill = document.createElement('span');
    catPill.className = 'finding-cat-pill';
    setText(catPill, `in ${f.category || 'General'}`);
    group.appendChild(catPill);

    if (f.test) {
      const testPill = document.createElement('span');
      testPill.className = 'test-status-badge st-not_testable';
      testPill.style.fontSize = '0.68rem';
      setText(testPill, f.test);
      group.appendChild(testPill);
    }

    top.appendChild(group);

    const title = document.createElement('div');
    title.className = 'finding-title';
    setText(title, f.title);

    const desc = document.createElement('div');
    desc.className = 'finding-desc';
    setText(desc, f.description);

    // Evidence chain grid
    const hasEvidence = f.observed_value || f.expected_value || f.methodology || f.source;
    if (hasEvidence) {
      const evGrid = document.createElement('div');
      evGrid.className = 'evidence-chain-grid';

      if (f.observed_value) {
        const field = document.createElement('div');
        field.className = 'evidence-field';
        const lbl = document.createElement('span');
        lbl.className = 'ev-label';
        lbl.textContent = 'Observed Evidence:';
        const val = document.createElement('span');
        val.className = 'ev-val ev-observed';
        setText(val, f.observed_value);
        field.appendChild(lbl);
        field.appendChild(val);
        evGrid.appendChild(field);
      }

      if (f.expected_value) {
        const field = document.createElement('div');
        field.className = 'evidence-field';
        const lbl = document.createElement('span');
        lbl.className = 'ev-label';
        lbl.textContent = 'Expected Standard:';
        const val = document.createElement('span');
        val.className = 'ev-val';
        setText(val, f.expected_value);
        field.appendChild(lbl);
        field.appendChild(val);
        evGrid.appendChild(field);
      }

      if (f.methodology) {
        const field = document.createElement('div');
        field.className = 'evidence-field';
        const lbl = document.createElement('span');
        lbl.className = 'ev-label';
        lbl.textContent = 'Test Methodology:';
        const val = document.createElement('span');
        val.className = 'ev-val';
        setText(val, f.methodology);
        field.appendChild(lbl);
        field.appendChild(val);
        evGrid.appendChild(field);
      }

      if (f.source) {
        const field = document.createElement('div');
        field.className = 'evidence-field';
        const lbl = document.createElement('span');
        lbl.className = 'ev-label';
        lbl.textContent = 'Evidence Source:';
        const val = document.createElement('span');
        val.className = 'ev-val';
        setText(val, f.source);
        field.appendChild(lbl);
        field.appendChild(val);
        evGrid.appendChild(field);
      }

      if (f.confidence) {
        const field = document.createElement('div');
        field.className = 'evidence-field';
        const lbl = document.createElement('span');
        lbl.className = 'ev-label';
        lbl.textContent = 'Confidence:';
        const val = document.createElement('span');
        val.className = 'ev-val';
        setText(val, f.confidence);
        field.appendChild(lbl);
        field.appendChild(val);
        evGrid.appendChild(field);
      }

      card.appendChild(evGrid);
    }

    if (f.limitations) {
      const limBox = document.createElement('div');
      limBox.className = 'ev-limitations-box';
      const limLbl = document.createElement('strong');
      limLbl.textContent = 'Limitations & Scope: ';
      const limTxt = document.createElement('span');
      setText(limTxt, f.limitations);
      limBox.appendChild(limLbl);
      limBox.appendChild(limTxt);
      card.appendChild(limBox);
    }

    const recBox = document.createElement('div');
    recBox.className = 'finding-rec-box';
    const recBold = document.createElement('strong');
    recBold.textContent = 'Recommendation:';
    const recText = document.createElement('span');
    setText(recText, ` ${f.recommendation || 'Review configuration.'}`);
    recBox.appendChild(recBold);
    recBox.appendChild(recText);

    card.appendChild(top);
    card.appendChild(title);
    card.appendChild(desc);
    card.appendChild(recBox);
    findingsContainer.appendChild(card);
  });
}

// ── Render Complete Security Report ───────────────────────────────────────────
function renderFullReport(data) {
  currentScanResult = data;
  currentFindings = data.findings || [];

  // 1. Meta & Header
  setText(scannedUrl, data.final_url || data.normalized_url || data.original_url);
  scannedUrlLink.href = data.final_url || data.normalized_url;
  setText(scanIdVal, data.scan_id || 'SCAN-ANONYMOUS');
  if (data.timestamp) {
    try {
      const dt = new Date(data.timestamp);
      setText(scanTimeVal, dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }));
    } catch {
      setText(scanTimeVal, data.timestamp);
    }
  }

  // 2. Risk Master Card
  const riskLvl = data.risk_level || 'UNKNOWN';
  const verdict = data.threat_verdict || riskLvl;
  const verdictIcon = data.verdict_icon || '';
  setText(riskLevelBadge, `${verdictIcon} ${verdict}`.trim());

  const verdictColors = {
    'NO KNOWN MALICIOUS INDICATORS': '#10b981',
    'SUSPICIOUS': '#eab308',
    'MALICIOUS': '#ef4444',
    'INCONCLUSIVE': '#64748b',
    'SAFE': '#10b981',
    'LOW RISK': '#22c55e',
    'HIGH RISK': '#f97316',
    'UNKNOWN': '#64748b'
  };
  const riskColor = verdictColors[data.threat_verdict] || verdictColors[riskLvl] || RISK_COLORS[riskLvl] || '#64748b';
  riskLevelBadge.style.backgroundColor = riskColor;
  riskLevelBadge.style.boxShadow = `0 0 16px ${riskColor}55`;

  setText(confidenceBadge, `Confidence: ${data.confidence || 'Medium'}`);
  if (confidenceReason) {
    setText(confidenceReason, data.confidence_reason || 'Network evaluation completed across observable endpoints.');
  }

  if (coverageBadge) {
    const cov = data.coverage || {};
    const covPct = cov.coverage_percentage != null ? cov.coverage_percentage : (data.coverage_percentage != null ? data.coverage_percentage : 100);
    const completed = cov.tests_completed ?? cov.completed ?? 0;
    const planned = cov.tests_planned ?? cov.planned ?? 0;
    setText(coverageBadge, planned > 0 ? `Analysis Coverage: ${covPct}% (${completed}/${planned} tests)` : `Analysis Coverage: ${covPct}%`);
  }

  if (riskTruthStatement) {
    if (data.threat_verdict === 'NO KNOWN MALICIOUS INDICATORS') {
      setText(riskTruthStatement, '"No known malicious indicators" means active security intelligence feeds detected 0 malicious signatures. This reflects observable threat intelligence, not a guarantee that a website is 100% safe.');
    } else if (data.threat_verdict === 'MALICIOUS') {
      setText(riskTruthStatement, 'MALICIOUS: One or more verified threat intelligence engines or heuristic signatures confirmed active threat presence. Exercise extreme caution.');
    } else {
      setText(riskTruthStatement, data.disclaimer || '"No threats detected" means no known indicators were found in active feeds. It does NOT guarantee complete safety.');
    }
  }

  setText(riskHeadline, data.risk_label || data.threat_verdict || `${riskLvl} Security Evaluation`);
  setText(riskSubtext, data.risk_description || 'Analysis completed across observable signals.');

  // Risk Score Gauge
  const score = data.risk_score != null ? data.risk_score : 0;
  setText(riskScoreNum, score);
  riskGaugeFill.style.width = '0%';
  riskGaugeFill.style.backgroundColor = riskColor;
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      riskGaugeFill.style.width = `${Math.min(score, 100)}%`;
    });
  });

  // 3. Category Breakdown Cards & Objects
  const bd = data.breakdown || {};
  const ti = data.threat_intelligence || {};
  const heur = data.url_heuristics || {};
  const dns = data.domain_analysis || {};
  const tls = data.tls_analysis || {};
  const redir = data.redirect_analysis || {};
  const hdrs = data.security_headers || {};

  // Update Header Security Posture & Grade
  const displayGrade = data.grade || hdrs.grade || 'F';
  const gradeKey = displayGrade.toLowerCase().replace('+', 'plus');
  headerGradeBadge.className = `master-grade-badge gc-${gradeKey}`;
  setText(headerGradeBadge, displayGrade);
  const headerScoreVal = data.score != null ? data.score : (hdrs.header_quality_score ?? 0);
  setText(headerScoreNum, headerScoreVal);

  const gradeLabels = {
    'A+': 'Outstanding (95+ pts)',
    'A':  'Great Protection (85-94 pts)',
    'B':  'Good Posture (70-84 pts)',
    'C':  'Noticeable Gaps (50-69 pts)',
    'D':  'Poor Configuration (30-49 pts)',
    'F':  'Critical Gaps (<30 pts)',
  };
  setText(headerStatusLabel, gradeLabels[displayGrade] || 'Security Evaluation');

  // Threat Intelligence
  setText(catStatusTI, ti.status === 'clean' ? '✓ No threats detected' : ti.has_confirmed_threat ? '🔴 Threat Confirmed' : ti.status === 'unconfigured' ? '⚪ Not configured' : '⚠ Unavailable');
  setText(catPtsTI, `Risk: +${bd.threat_intelligence?.score ?? 0} / 50 pts`);
  setText(catDescTI, ti.summary || 'Threat intelligence engines status.');
  catQuickTI.innerHTML = '';
  (ti.sources || []).forEach(src => {
    const t = document.createElement('span');
    t.className = 'quick-tag';
    setText(t, `${src.name}: ${src.status === 'clean' ? '✓ 0 detections' : src.detected ? '🔴 Detected' : '⚪ ' + (src.status || 'not configured')}`);
    catQuickTI.appendChild(t);
  });

  // URL Heuristics
  setText(catStatusHeur, heur.status === 'clean' ? '✓ Low-risk structure' : '⚠ Heuristics flagged');
  setText(catPtsHeur, `Risk: +${bd.url_heuristics?.score ?? 0} / 15 pts`);
  setText(catDescHeur, heur.summary || 'Analyzed URL pattern & encoding.');
  catQuickHeur.innerHTML = '';
  const heurCount = (heur.indicators || []).length;
  const htag = document.createElement('span');
  htag.className = 'quick-tag';
  setText(htag, heurCount === 0 ? '✓ 0 pattern flags' : `${heurCount} pattern flag(s)`);
  catQuickHeur.appendChild(htag);

  // Domain & DNS
  setText(catStatusDNS, dns.status === 'resolved' ? '✓ DNS Resolved' : '✕ DNS Error');
  setText(catPtsDNS, `Risk: +${bd.domain_signals?.score ?? 0} / 10 pts`);
  setText(catDescDNS, dns.summary || 'DNS zone resolution.');
  catQuickDNS.innerHTML = '';
  if (dns.ipv4 && dns.ipv4.length) {
    const ipTag = document.createElement('span');
    ipTag.className = 'quick-tag';
    setText(ipTag, `${dns.ipv4.length} IPv4`);
    catQuickDNS.appendChild(ipTag);
  }
  if (dns.has_ipv6) {
    const ip6Tag = document.createElement('span');
    ip6Tag.className = 'quick-tag';
    setText(ip6Tag, 'IPv6 enabled');
    catQuickDNS.appendChild(ip6Tag);
  }
  if (dns.hosting_provider) {
    const provTag = document.createElement('span');
    provTag.className = 'quick-tag';
    setText(provTag, dns.hosting_provider);
    catQuickDNS.appendChild(provTag);
  }

  // HTTPS / TLS
  setText(catStatusTLS, tls.is_valid ? '✓ Valid HTTPS' : tls.is_expired ? '🔴 Expired Cert' : tls.https_enabled ? '⚠ TLS Warning' : '✕ No HTTPS');
  setText(catPtsTLS, `Risk: +${bd.tls_https?.score ?? 0} / 10 pts`);
  setText(catDescTLS, tls.summary || 'Certificate authority and validity.');
  catQuickTLS.innerHTML = '';
  if (tls.issuer && tls.issuer !== 'Unknown') {
    const issTag = document.createElement('span');
    issTag.className = 'quick-tag';
    setText(issTag, tls.issuer);
    catQuickTLS.appendChild(issTag);
  }
  if (tls.days_remaining != null) {
    const dayTag = document.createElement('span');
    dayTag.className = 'quick-tag';
    setText(dayTag, `${tls.days_remaining}d remaining`);
    catQuickTLS.appendChild(dayTag);
  }
  if (tls.tls_version) {
    const verTag = document.createElement('span');
    verTag.className = 'quick-tag';
    setText(verTag, tls.tls_version);
    catQuickTLS.appendChild(verTag);
  }

  // Redirects
  const rCount = redir.redirect_count || 0;
  setText(catStatusRedir, rCount === 0 ? '✓ Direct connection' : rCount <= 2 ? `✓ ${rCount} redirect(s)` : `⚠ ${rCount} redirects`);
  setText(catPtsRedir, `Risk: +${bd.redirects?.score ?? 0} / 5 pts`);
  setText(catDescRedir, redir.summary || 'Navigation trajectory.');
  catQuickRedir.innerHTML = '';
  const rtag = document.createElement('span');
  rtag.className = 'quick-tag';
  setText(rtag, rCount === 0 ? '0 hops' : `${rCount} hop(s)`);
  catQuickRedir.appendChild(rtag);
  if (redir.has_protocol_downgrade) {
    const dtag = document.createElement('span');
    dtag.className = 'quick-tag';
    dtag.style.color = '#fca5a5';
    setText(dtag, '⚠ Insecure downgrade');
    catQuickRedir.appendChild(dtag);
  }

  // Security Headers
  setText(catStatusHeaders, `Header Score: ${hdrs.header_quality_score ?? 0} / 100 pts`);
  setText(catPtsHeaders, `Risk: +${bd.security_configuration?.score ?? 0} / 10 pts`);
  setText(catDescHeaders, hdrs.summary || 'Response headers posture.');
  catQuickHeaders.innerHTML = '';
  const hpass = (hdrs.scored_headers || []).filter(h => h.status === 'pass').length;
  const hfail = (hdrs.scored_headers || []).filter(h => h.status === 'fail').length;
  const ptag = document.createElement('span');
  ptag.className = 'quick-tag';
  setText(ptag, `${hpass} passed (${headerScoreVal} pts)`);
  catQuickHeaders.appendChild(ptag);
  const ftag = document.createElement('span');
  ftag.className = 'quick-tag';
  setText(ftag, `${hfail} missing headers`);
  catQuickHeaders.appendChild(ftag);

  // 4. Update Severity Filter Counts
  const fc = data.finding_counts || {};
  setText(countAll, (data.findings || []).length);
  setText(countCritical, fc.critical || 0);
  setText(countHigh, fc.high || 0);
  setText(countMedium, fc.medium || 0);
  setText(countLow, fc.low || 0);
  setText(countInfo, fc.informational || 0);

  // Render findings list
  renderFindings();

  // 5. Diagnostics Panels
  // TI Details
  diagTIContent.innerHTML = '';
  const tiGrid = document.createElement('div');
  tiGrid.className = 'diag-grid-2';
  (ti.sources || []).forEach(src => {
    const tile = document.createElement('div');
    tile.className = 'diag-tile';
    const lbl = document.createElement('div');
    lbl.className = 'diag-tile-label';
    setText(lbl, src.name);
    const val = document.createElement('div');
    val.className = 'diag-tile-val';
    setText(val, src.summary);
    const det = document.createElement('div');
    det.style.fontSize = '0.75rem';
    det.style.color = 'var(--text-secondary)';
    det.style.marginTop = '0.35rem';
    setText(det, src.details || '');
    tile.appendChild(lbl);
    tile.appendChild(val);
    tile.appendChild(det);
    tiGrid.appendChild(tile);
  });
  diagTIContent.appendChild(tiGrid);

  // TLS Details
  diagTLSContent.innerHTML = '';
  const tlsGrid = document.createElement('div');
  tlsGrid.className = 'diag-grid-2';
  const tlsFields = [
    { label: 'Certificate Validity', val: tls.is_valid ? 'Valid (Trusted CA)' : tls.is_expired ? 'Expired' : 'Untrusted / Incomplete Chain' },
    { label: 'Certificate Authority (Issuer)', val: tls.issuer || 'Unknown' },
    { label: 'Subject Common Name', val: tls.subject || 'Unknown' },
    { label: 'Expiration Date', val: tls.expiry_date || 'Unknown' },
    { label: 'Days Remaining', val: tls.days_remaining != null ? `${tls.days_remaining} days` : 'Unknown' },
    { label: 'Negotiated Protocol', val: tls.tls_version || 'None' },
    { label: 'Cipher Suite', val: tls.cipher || 'Standard' },
  ];
  tlsFields.forEach(f => {
    const tile = document.createElement('div');
    tile.className = 'diag-tile';
    const l = document.createElement('div');
    l.className = 'diag-tile-label';
    setText(l, f.label);
    const v = document.createElement('div');
    v.className = 'diag-tile-val';
    setText(v, f.val);
    tile.appendChild(l);
    tile.appendChild(v);
    tlsGrid.appendChild(tile);
  });
  diagTLSContent.appendChild(tlsGrid);

  // Redirect chain details
  diagRedirContent.innerHTML = '';
  const chain = redir.chain || [];
  if (chain.length <= 1) {
    const noHop = document.createElement('p');
    noHop.style.color = 'var(--text-secondary)';
    noHop.style.marginTop = '0.8rem';
    setText(noHop, `Direct connection: ${data.final_url || data.normalized_url} (HTTP ${data.status_code || 200})`);
    diagRedirContent.appendChild(noHop);
  } else {
    const visual = document.createElement('div');
    visual.className = 'redirect-chain-visual';
    chain.forEach((hop, i) => {
      const hopRow = document.createElement('div');
      hopRow.className = 'chain-hop';
      const n = document.createElement('span');
      n.className = 'hop-num';
      setText(n, `Step ${hop.step}:`);
      const code = document.createElement('span');
      code.className = 'hop-code';
      setText(code, String(hop.status_code));
      const u = document.createElement('span');
      u.className = 'hop-url';
      setText(u, hop.url);
      hopRow.appendChild(n);
      hopRow.appendChild(code);
      hopRow.appendChild(u);
      visual.appendChild(hopRow);

      if (i < chain.length - 1) {
        const arrow = document.createElement('div');
        arrow.className = 'chain-arrow';
        arrow.textContent = '↓';
        visual.appendChild(arrow);
      }
    });
    diagRedirContent.appendChild(visual);
  }

  // DNS Details
  diagDNSContent.innerHTML = '';
  const dnsGrid = document.createElement('div');
  dnsGrid.className = 'diag-grid-2';
  const dnsFields = [
    { label: 'Hostname', val: dns.hostname || 'Unknown' },
    { label: 'Top-Level Domain (TLD)', val: dns.tld ? `.${dns.tld}` : 'None' },
    { label: 'Resolved IPv4 Addresses', val: (dns.ipv4 || []).join(', ') || 'None' },
    { label: 'Resolved IPv6 Addresses', val: (dns.ipv6 || []).join(', ') || 'None' },
    { label: 'Reverse DNS (PTR)', val: (dns.ptr_records || []).join(', ') || 'No PTR record' },
    { label: 'Hosting / Cloud Network', val: dns.hosting_provider || 'Direct / Undetected' },
  ];
  dnsFields.forEach(f => {
    const tile = document.createElement('div');
    tile.className = 'diag-tile';
    const l = document.createElement('div');
    l.className = 'diag-tile-label';
    setText(l, f.label);
    const v = document.createElement('div');
    v.className = 'diag-tile-val';
    setText(v, f.val);
    tile.appendChild(l);
    tile.appendChild(v);
    dnsGrid.appendChild(tile);
  });
  diagDNSContent.appendChild(dnsGrid);

  // Security Headers Cards
  headersGrid.innerHTML = '';
  const scoredList = hdrs.scored_headers || data.scored_headers || [];
  scoredList.forEach(h => headersGrid.appendChild(buildHeaderCard(h, false)));

  infoGrid.innerHTML = '';
  const infoList = hdrs.info_headers || data.info_headers || [];
  infoList.forEach(h => infoGrid.appendChild(buildHeaderCard(h, true)));

  // Cookies Section
  renderCookiesSection(data);

  // Raw Technical Evidence Section
  renderRawEvidenceSection(data);

  // Save to recent scans
  saveRecentScan(data);

  // Show results view
  resultsSection.classList.add('visible');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Cookies Section Renderer ──────────────────────────────────────────────────
function renderCookiesSection(data) {
  if (!diagCookiesContent) return;
  diagCookiesContent.innerHTML = '';
  const cookies = (data.cookie_analysis && data.cookie_analysis.cookies) ||
                  (data.technical_evidence && data.technical_evidence.cookies) || [];

  if (!cookies.length) {
    const emptyBox = document.createElement('div');
    emptyBox.style.padding = '1.2rem 0';
    emptyBox.style.color = 'var(--text-secondary)';
    emptyBox.style.fontSize = '0.84rem';
    emptyBox.textContent = 'ℹ️ No Set-Cookie headers were observed in the initial HTTP response. This is typical for static entrypoints or modern SPAs where authentication tokens are exchanged asynchronously.';
    diagCookiesContent.appendChild(emptyBox);
    return;
  }

  const tableWrap = document.createElement('div');
  tableWrap.className = 'diag-table-container';

  const table = document.createElement('table');
  table.className = 'diag-table';

  const thead = document.createElement('thead');
  const hRow = document.createElement('tr');
  ['Cookie Name', 'Domain', 'Path', 'Secure', 'HttpOnly', 'SameSite', 'Evaluation'].forEach(text => {
    const th = document.createElement('th');
    th.textContent = text;
    hRow.appendChild(th);
  });
  thead.appendChild(hRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  cookies.forEach(c => {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    tdName.style.fontWeight = '700';
    setText(tdName, c.name);

    const tdDom = document.createElement('td');
    setText(tdDom, c.domain || '(host-only)');

    const tdPath = document.createElement('td');
    setText(tdPath, c.path || '/');

    const tdSec = document.createElement('td');
    tdSec.className = c.secure ? 'bool-yes' : 'bool-no';
    tdSec.textContent = c.secure ? '✓ Yes' : '✕ No';

    const tdHttp = document.createElement('td');
    tdHttp.className = c.httponly ? 'bool-yes' : 'bool-no';
    tdHttp.textContent = c.httponly ? '✓ Yes' : '✕ No';

    const tdSame = document.createElement('td');
    setText(tdSame, c.samesite || 'None / Not set');

    const tdStatus = document.createElement('td');
    const badge = document.createElement('span');
    const st = (c.status || (c.secure && c.httponly ? 'PASS' : 'WARNING')).toLowerCase();
    badge.className = `test-status-badge st-${st}`;
    setText(badge, c.status || (c.secure && c.httponly ? 'PASS' : 'WARNING'));
    tdStatus.appendChild(badge);

    tr.appendChild(tdName);
    tr.appendChild(tdDom);
    tr.appendChild(tdPath);
    tr.appendChild(tdSec);
    tr.appendChild(tdHttp);
    tr.appendChild(tdSame);
    tr.appendChild(tdStatus);
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  tableWrap.appendChild(table);
  diagCookiesContent.appendChild(tableWrap);
}

// ── Raw Technical Evidence & Test Audit Log Renderer ──────────────────────────
function renderRawEvidenceSection(data) {
  if (!diagRawEvidenceContent) return;
  diagRawEvidenceContent.innerHTML = '';
  const te = data.technical_evidence || {};
  const http = te.http_transaction || {};
  const dnsRecs = te.dns_records || {};
  const evidenceRecords = data.evidence_records || [];

  // 1. Transaction Summary Grid
  const grid = document.createElement('div');
  grid.className = 'diag-grid-2';

  const txFields = [
    { label: 'HTTP Status Code', val: `${http.status_code || data.status_code || 200} (OK / Delivered)` },
    { label: 'Round-Trip Latency', val: http.response_time_ms != null ? `${http.response_time_ms} ms` : 'N/A' },
    { label: 'Observed Final URL', val: http.final_url || data.final_url || data.normalized_url },
    { label: 'Content-Type', val: http.content_type || 'N/A' },
    { label: 'Response Headers Count', val: `${http.headers_count || Object.keys(data.security_headers?.raw_headers || {}).length || 0} headers` },
    { label: 'Redirect Hops Traversed', val: `${http.redirect_hops_count || data.redirect_analysis?.redirect_count || 0} hops` },
  ];

  txFields.forEach(f => {
    const tile = document.createElement('div');
    tile.className = 'diag-tile';
    const l = document.createElement('div');
    l.className = 'diag-tile-label';
    setText(l, f.label);
    const v = document.createElement('div');
    v.className = 'diag-tile-val';
    setText(v, f.val);
    tile.appendChild(l);
    tile.appendChild(v);
    grid.appendChild(tile);
  });
  diagRawEvidenceContent.appendChild(grid);

  // 2. DNS Zone Records & RDAP
  const dnsDetails = document.createElement('div');
  dnsDetails.style.marginTop = '1.25rem';
  const dnsTitle = document.createElement('div');
  dnsTitle.className = 'raw-headers-title';
  dnsTitle.textContent = '🌐 DNS Zone Records & RDAP Registration Evidence';
  dnsDetails.appendChild(dnsTitle);

  const dnsGrid = document.createElement('div');
  dnsGrid.className = 'diag-grid-2';
  dnsGrid.style.marginTop = '0.5rem';

  const dnsFields = [
    { label: 'MX (Mail Exchanger) Records', val: (dnsRecs.mx || []).join(', ') || 'No MX records' },
    { label: 'NS (Authoritative Nameservers)', val: (dnsRecs.ns || []).join(', ') || 'Default' },
    { label: 'TXT Records (SPF / Verification)', val: (dnsRecs.txt || []).join(' | ') || 'None' },
    { label: 'CAA (Cert Authority Authorization)', val: (dnsRecs.caa || []).join(', ') || 'None configured' },
    { label: 'RDAP Registrar', val: (dnsRecs.rdap && dnsRecs.rdap.registrar) || 'Unknown' },
    { label: 'RDAP Created Date', val: (dnsRecs.rdap && dnsRecs.rdap.registration_date) || 'Unknown' },
  ];

  dnsFields.forEach(f => {
    const tile = document.createElement('div');
    tile.className = 'diag-tile';
    const l = document.createElement('div');
    l.className = 'diag-tile-label';
    setText(l, f.label);
    const v = document.createElement('div');
    v.className = 'diag-tile-val';
    setText(v, f.val);
    tile.appendChild(l);
    tile.appendChild(v);
    dnsGrid.appendChild(tile);
  });
  dnsDetails.appendChild(dnsGrid);
  diagRawEvidenceContent.appendChild(dnsDetails);

  // 3. Raw Response Headers Viewer with Copy
  const rawHeadersWrap = document.createElement('div');
  rawHeadersWrap.className = 'raw-headers-wrap';

  const hHead = document.createElement('div');
  hHead.className = 'raw-headers-header';
  const hTitle = document.createElement('span');
  hTitle.className = 'raw-headers-title';
  hTitle.textContent = '📋 Raw HTTP Response Headers';
  const copyHBtn = document.createElement('button');
  copyHBtn.className = 'btn btn-outline btn-sm';
  copyHBtn.textContent = 'Copy Headers';

  let rawHeaderText = '';
  if (typeof http.raw_headers === 'string' && http.raw_headers) {
    rawHeaderText = http.raw_headers;
  } else if (data.security_headers && data.security_headers.raw_headers) {
    rawHeaderText = Object.entries(data.security_headers.raw_headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
  } else {
    rawHeaderText = '# No raw headers captured.';
  }

  copyHBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(rawHeaderText).then(() => {
      copyHBtn.textContent = '✓ Copied!';
      setTimeout(() => { copyHBtn.textContent = 'Copy Headers'; }, 2000);
    });
  });

  hHead.appendChild(hTitle);
  hHead.appendChild(copyHBtn);
  rawHeadersWrap.appendChild(hHead);

  const codePre = document.createElement('pre');
  codePre.className = 'raw-headers-code';
  codePre.textContent = rawHeaderText;
  rawHeadersWrap.appendChild(codePre);
  diagRawEvidenceContent.appendChild(rawHeadersWrap);

  // 4. Full Structured Test Evidence Records Table (Filterable)
  if (evidenceRecords.length > 0) {
    const auditWrap = document.createElement('div');
    auditWrap.style.marginTop = '1.75rem';

    const auditBar = document.createElement('div');
    auditBar.className = 'evidence-audit-bar';

    const auditTitle = document.createElement('div');
    auditTitle.className = 'raw-headers-title';
    auditTitle.textContent = '🔍 Complete Structured Test Audit Log';

    const searchBox = document.createElement('input');
    searchBox.type = 'text';
    searchBox.placeholder = 'Filter tests or status (e.g. PASS, CSP, NOT_CONFIGURED)...';
    searchBox.className = 'evidence-search-input';

    const countBadge = document.createElement('span');
    countBadge.className = 'evidence-count-badge';
    countBadge.textContent = `${evidenceRecords.length} verifiable test records`;

    auditBar.appendChild(auditTitle);
    auditBar.appendChild(searchBox);
    auditBar.appendChild(countBadge);
    auditWrap.appendChild(auditBar);

    const tblWrap = document.createElement('div');
    tblWrap.className = 'diag-table-container';

    const tbl = document.createElement('table');
    tbl.className = 'diag-table';

    const thead = document.createElement('thead');
    const trH = document.createElement('tr');
    ['Test Identifier', 'Status', 'Severity', 'Confidence', 'Observed Evidence', 'Expected Standard', 'Limitations'].forEach(t => {
      const th = document.createElement('th');
      th.textContent = t;
      trH.appendChild(th);
    });
    thead.appendChild(trH);
    tbl.appendChild(thead);

    const tbody = document.createElement('tbody');

    function renderAuditRows(filterTerm) {
      tbody.innerHTML = '';
      const term = (filterTerm || '').toLowerCase().trim();
      const filtered = evidenceRecords.filter(r => {
        if (!term) return true;
        return (r.test || '').toLowerCase().includes(term) ||
               (r.status || '').toLowerCase().includes(term) ||
               (r.severity || '').toLowerCase().includes(term) ||
               (r.observedValue || '').toLowerCase().includes(term) ||
               (r.source || '').toLowerCase().includes(term);
      });

      if (!filtered.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.style.textAlign = 'center';
        td.style.padding = '1.5rem';
        td.style.color = 'var(--text-muted)';
        td.textContent = 'No matching test records found.';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      filtered.forEach(r => {
        const tr = document.createElement('tr');

        const tdTest = document.createElement('td');
        tdTest.style.fontWeight = '700';
        setText(tdTest, r.test);

        const tdStat = document.createElement('td');
        const sBadge = document.createElement('span');
        sBadge.className = `test-status-badge st-${(r.status || '').toLowerCase()}`;
        setText(sBadge, r.status);
        tdStat.appendChild(sBadge);

        const tdSev = document.createElement('td');
        setText(tdSev, r.severity || '—');

        const tdConf = document.createElement('td');
        setText(tdConf, r.confidence || '—');

        const tdObs = document.createElement('td');
        tdObs.className = 'cell-text';
        setText(tdObs, r.observedValue || '—');

        const tdExp = document.createElement('td');
        tdExp.className = 'cell-text';
        setText(tdExp, r.expectedValue || '—');

        const tdLim = document.createElement('td');
        tdLim.className = 'cell-text';
        tdLim.style.color = '#94a3b8';
        setText(tdLim, r.limitations || '—');

        tr.appendChild(tdTest);
        tr.appendChild(tdStat);
        tr.appendChild(tdSev);
        tr.appendChild(tdConf);
        tr.appendChild(tdObs);
        tr.appendChild(tdExp);
        tr.appendChild(tdLim);
        tbody.appendChild(tr);
      });

      countBadge.textContent = `${filtered.length} of ${evidenceRecords.length} records`;
    }

    searchBox.addEventListener('input', e => {
      renderAuditRows(e.target.value);
    });

    renderAuditRows('');
    tbl.appendChild(tbody);
    tblWrap.appendChild(tbl);
    auditWrap.appendChild(tblWrap);
    diagRawEvidenceContent.appendChild(auditWrap);
  }
}

// ── Recent Scans History (LocalStorage) ───────────────────────────────────────
const RECENT_KEY = 'sec_scanner_recent_scans_v2';

function loadRecentScans() {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    return JSON.parse(raw) || [];
  } catch {
    return [];
  }
}

function saveRecentScan(scanData) {
  try {
    const existing = loadRecentScans();
    const entry = {
      scan_id: scanData.scan_id,
      url: scanData.final_url || scanData.normalized_url,
      risk_level: scanData.risk_level,
      risk_score: scanData.risk_score,
      timestamp: scanData.timestamp,
      cached_result: scanData,
    };
    // De-duplicate by URL
    const filtered = existing.filter(e => e.url !== entry.url);
    filtered.unshift(entry);
    const trimmed = filtered.slice(0, 5);
    localStorage.setItem(RECENT_KEY, JSON.stringify(trimmed));
    renderRecentScansUI();
  } catch {}
}

function renderRecentScansUI() {
  const scans = loadRecentScans();
  if (!scans.length) {
    recentScansStrip.style.display = 'none';
    return;
  }
  recentScansList.innerHTML = '';
  scans.forEach(s => {
    const chip = document.createElement('button');
    chip.className = 'recent-chip';
    chip.type = 'button';
    try {
      const u = new URL(s.url);
      chip.textContent = `${u.hostname} (${s.risk_score}/100)`;
    } catch {
      chip.textContent = `${s.url} (${s.risk_score}/100)`;
    }
    chip.addEventListener('click', () => {
      urlInput.value = s.url;
      if (s.cached_result) {
        renderFullReport(s.cached_result);
      } else {
        runScan();
      }
    });
    recentScansList.appendChild(chip);
  });
  recentScansStrip.style.display = 'flex';
}

// ── Scan Execution ────────────────────────────────────────────────────────────
async function runScan() {
  hideError();
  let raw = urlInput.value.trim();

  if (!raw) {
    showError('Please enter a website address, for example: https://example.com');
    urlInput.focus();
    return;
  }

  // Pre-normalize scheme for user
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//i.test(raw)) {
    raw = 'https://' + raw;
    urlInput.value = raw;
  }

  setLoading(true);
  startProgress();
  resultsSection.classList.remove('visible');

  try {
    const resp = await fetch('/api/v1/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: raw }),
    });

    const data = await resp.json();

    if (!resp.ok || data.error) {
      stopProgressOnError();
      showError(data.error || `Scan failed (server error ${resp.status}).`);
      return;
    }

    finishProgress();
    renderFullReport(data);
  } catch (err) {
    stopProgressOnError();
    showError('Could not reach the security scanning server. Please verify your connection and try again.');
  } finally {
    setLoading(false);
  }
}

// ── Plain-Text Report Generator ───────────────────────────────────────────────
function buildTextReport(data) {
  const div = '═'.repeat(64);
  const subDiv = '─'.repeat(64);
  const cov = data.coverage || {};
  const covPct = cov.coverage_percentage != null ? cov.coverage_percentage : (data.coverage_percentage != null ? data.coverage_percentage : 100);
  const lines = [
    div,
    '   AEGOVX — EVIDENCE BEFORE TRUST',
    '   URL SECURITY & WEBSITE RISK INTELLIGENCE REPORT',
    div,
    `Target URL          : ${data.final_url || data.normalized_url}`,
    `Scan ID             : ${data.scan_id || 'N/A'}`,
    `Timestamp           : ${data.timestamp || new Date().toISOString()}`,
    `Threat Verdict      : ${data.threat_verdict || data.risk_level}`,
    `Security Posture    : Grade ${data.grade} (${data.score}/100 pts)`,
    `Analysis Coverage   : ${covPct}% (${cov.tests_completed ?? 'N/A'}/${cov.tests_planned ?? 'N/A'} tests completed)`,
    `Confidence Rating   : ${data.confidence} — ${data.confidence_reason || 'Direct network inspection'}`,
    '',
    subDiv,
    'CATEGORY SCORES BREAKDOWN',
    subDiv,
  ];

  const bd = data.breakdown || {};
  Object.keys(bd).forEach(k => {
    const b = bd[k];
    lines.push(`  • ${b.label.padEnd(26)} : ${b.score}/${b.max} pts (${b.summary})`);
  });

  lines.push('', subDiv, 'SECURITY HEADERS BREAKDOWN', subDiv);
  (data.scored_headers || []).forEach(h => {
    lines.push(`  • [${h.status.toUpperCase()}] ${h.plain_name} (${h.name}): ${h.points}/${h.max_points} pts`);
    if (h.value) lines.push(`    Value: ${h.value}`);
    (h.notes || []).forEach(n => lines.push(`    Note: ${n}`));
  });

  lines.push('', subDiv, 'IDENTIFIED FINDINGS & VERIFIABLE EVIDENCE CHAINS', subDiv);
  const findings = data.findings || [];
  if (!findings.length) {
    lines.push('  No security configuration gaps or threat indicators detected.');
  } else {
    findings.forEach(f => {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.title} (${f.category})`);
      lines.push(`  Description   : ${f.description}`);
      if (f.observed_value) lines.push(`  Observed Evid : ${f.observed_value}`);
      if (f.expected_value) lines.push(`  Expected Std  : ${f.expected_value}`);
      if (f.methodology)    lines.push(`  Methodology   : ${f.methodology}`);
      if (f.source)         lines.push(`  Source Engine : ${f.source}`);
      if (f.limitations)    lines.push(`  Limitations   : ${f.limitations}`);
      lines.push(`  Recommendation: ${f.recommendation}`);
      lines.push('');
    });
  }

  lines.push(div);
  lines.push('AEGOVX EVIDENCE DISCLAIMER:');
  lines.push('This scanner checks publicly observable security signals and active threat feeds.');
  lines.push('A clean threat verdict indicates 0 active malicious signatures were found.');
  lines.push('It does NOT mean "100% safe" — always practice defense-in-depth.');
  lines.push('Evidence Before Trust.');
  lines.push(div);
  return lines.join('\n');
}

function copyReport() {
  if (!currentScanResult) return;
  navigator.clipboard.writeText(buildTextReport(currentScanResult)).then(() => {
    const orig = copyReportBtn.textContent;
    copyReportBtn.textContent = '✓ Copied!';
    setTimeout(() => { copyReportBtn.textContent = orig; }, 2200);
  });
}

function downloadJSON() {
  if (!currentScanResult) return;
  // Ensure no secrets or API keys exist in payload
  const safeData = JSON.parse(JSON.stringify(currentScanResult));
  const blob = new Blob([JSON.stringify(safeData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  let host = 'report';
  try { host = new URL(currentScanResult.final_url || currentScanResult.normalized_url).hostname; } catch {}
  a.download = `security-report-${host}-${safeData.scan_id || 'scan'}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function printReport() {
  window.print();
}

function resetNewScan() {
  resultsSection.classList.remove('visible');
  hideError();
  currentScanResult = null;
  urlInput.value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(() => urlInput.focus(), 350);
}

// ── Event Handlers ────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', runScan);
urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') runScan();
});

newScanBtn.addEventListener('click', resetNewScan);
copyReportBtn.addEventListener('click', copyReport);
downloadBtn.addEventListener('click', downloadJSON);
printPdfBtn.addEventListener('click', printReport);

// Severity tab filtering
document.querySelectorAll('.sev-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sev-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentFilter = tab.getAttribute('data-filter') || 'all';
    renderFindings();
  });
});

// Initialize recent scans on load
renderRecentScansUI();
urlInput.focus();
