// sidepanel.js
// AutoShield Side Panel — UI logic, backend communication, rendering
// CSP COMPLIANT (Manifest V3)

const BACKEND = 'http://127.0.0.1:8000';

// ─── State ──────────────────────────────────────────────────────────
let currentTab = 'security';
let securityResults = [];
let complianceResults = null;
let currentUrl = '';
let port = null;
let isScanning = false;

// ─── Init ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Static buttons
  document.getElementById("btnScan")?.addEventListener("click", runScan);
  document.getElementById("btnDeep")?.addEventListener("click", runDeepScan);
  document.getElementById("btnClear")?.addEventListener("click", clearAll);

  // Tab buttons
  document.getElementById("tab-security")?.addEventListener("click", () => switchTab('security'));
  document.getElementById("tab-compliance")?.addEventListener("click", () => switchTab('compliance'));

  // Global Click Delegate (for dynamic elements)
  document.addEventListener('click', handleGlobalClick);

  connectToBackground();
  getCurrentTabUrl();
});

function handleGlobalClick(e) {
  const target = e.target;

  // 1. Card Toggle (Security & Compliance)
  const cardHead = target.closest('.card-head');
  if (cardHead && cardHead.dataset.toggleBody) {
    toggleCard(cardHead.dataset.toggleBody, cardHead.dataset.toggleChev);
    return;
  }

  // 2. Inner Tab Switcher (Security Analysis/Fix)
  if (target.classList.contains('inner-tab')) {
    const cardIdx = target.dataset.cardIdx;
    const tabType = target.dataset.tabType;
    if (cardIdx && tabType) {
      switchInnerTab(cardIdx, tabType, target);
    }
    return;
  }

  // 3. Copy Button
  if (target.classList.contains('copy-btn')) {
    const code = target.dataset.code;
    if (code) {
      copyFix(target, code);
    }
    return;
  }

  // 4. Compliance Clean List Toggle
  const cleanHeader = target.closest('.section-header');
  if (cleanHeader && cleanHeader.id === 'clean-list-header') {
    const cl = document.getElementById('clean-list');
    if (cl) cl.style.display = cl.style.display === 'none' ? 'block' : 'none';
    return;
  }
}

function logStep(message) {
  const logDiv = document.getElementById("log");
  if (!logDiv) return;
  const entry = document.createElement("div");
  entry.textContent = "• " + message;
  entry.style.fontSize = "10px";
  entry.style.color = "#aaa";
  logDiv.appendChild(entry);
  logDiv.scrollTop = logDiv.scrollHeight;
}

function connectToBackground() {
  port = chrome.runtime.connect({ name: 'autoshield-sidepanel' });
  port.onMessage.addListener(handleBackgroundMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    setTimeout(connectToBackground, 1000);
  });
}

function getCurrentTabUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      currentUrl = tabs[0].url || '';
      const badge = document.getElementById('urlBadge');
      if (badge) {
        const display = currentUrl.replace(/^https?:\/\//, '').slice(0, 35);
        badge.textContent = display || 'No page';
        badge.title = currentUrl;
      }
    }
  });
}

// ─── Tab Switching ────────────────────────────────────────────────────
function switchTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
  document.getElementById('tab-' + name)?.classList.add('active');
  document.getElementById('panel-' + name)?.classList.add('active');
}

// ─── Scan Triggers ────────────────────────────────────────────────────
async function runScan() {
  if (isScanning) { return; }
  getCurrentTabUrl();
  setStatus('Extracting page data...', 'scanning', true);
  logStep('🚀 Scan initiated');
  setBtnsDisabled(true);
  isScanning = true;

  if (port) {
    port.postMessage({ type: 'triggerExtraction', useLLM: false });
  } else {
    setStatus('Extension connection lost — refresh the panel', 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

async function runDeepScan() {
  if (isScanning) { return; }
  getCurrentTabUrl();

  if (!currentUrl || currentUrl.startsWith('chrome://')) {
    setStatus('Cannot scan browser internal pages', 'error');
    return;
  }

  setStatus('Running deep scan (LLM enabled)...', 'scanning', true);
  logStep('🧠 Deep scan with LLM reasoning');
  setBtnsDisabled(true);
  isScanning = true;

  try {
    fetch(`${BACKEND}/analyze-runtime?url=${encodeURIComponent(currentUrl)}`, {
      method: 'POST'
    }).catch(() => {});

    if (port) {
      port.postMessage({ type: 'triggerExtraction', useLLM: true });
    }
  } catch (e) {
    setStatus(`Deep scan failed: ${e.message}`, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

function clearAll() {
  securityResults = [];
  complianceResults = null;
  document.getElementById('security-out').innerHTML = '<div class="empty"><span class="empty-icon">🔒</span>Click <strong>[Scan]</strong> to analyze<br/>the current page for<br/>security vulnerabilities</div>';
  document.getElementById('compliance-out').innerHTML = '<div class="empty"><span class="empty-icon">©</span>Click <strong>[Scan]</strong> to check<br/>media assets for<br/>copyright &amp; compliance</div>';
  document.getElementById('summary').classList.remove('visible');
  const logDiv = document.getElementById('log');
  if (logDiv) logDiv.innerHTML = '';
  setStatus('Cleared', '');
}

// ─── Message Handler ──────────────────────────────────────────────────
function handleBackgroundMessage(msg) {
  if (msg.type === 'progress') {
    logStep(msg.step);
  }
  if (msg.type === 'pageDataExtracted') {
    logStep('📦 Data received from page');
    setStatus('Analyzing with RAG + AI...', 'scanning', true);
    analyzePageData(msg.data, msg.useLLM || false);
  }
  if (msg.type === 'extractionError') {
    setStatus('Extraction failed: ' + msg.error, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

// ─── Main Analysis ────────────────────────────────────────────────────
async function analyzePageData(pageData, useLLM = false) {
  logStep('🧠 Running AI analysis...');
  try {
    const [secResult, compResult] = await Promise.allSettled([
      analyzeSecurityData(pageData, useLLM),
      analyzeComplianceData(pageData),
    ]);

    if (secResult.status === 'fulfilled') {
      securityResults = secResult.value;
      renderSecurityResults(securityResults);
    }

    if (compResult.status === 'fulfilled') {
      complianceResults = compResult.value;
      renderComplianceResults(complianceResults);
    }

    const totalSec = securityResults.length;
    const totalComp = complianceResults?.issues?.length || 0;
    logStep('✅ Scan complete');
    setStatus(`Done — ${totalSec} security + ${totalComp} compliance findings`, 'done');
    updateSummary(securityResults);
    setBtnsDisabled(false);
    isScanning = false;

  } catch (e) {
    logStep('❌ Analysis failed: ' + e.message);
    setStatus('Analysis error: ' + e.message, 'error');
    setBtnsDisabled(false);
    isScanning = false;
  }
}

// ─── Security Analysis ────────────────────────────────────────────────
async function analyzeSecurityData(pageData, useLLM = false) {
  const findings = buildSecurityFindings(pageData);
  const results = [];

  setStatus(`Analyzing ${findings.length} finding(s)...`, 'scanning', true);

  for (const finding of findings.slice(0, 15)) {
    try {
      const res = await fetch(`${BACKEND}/rag/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code_snippet: finding.snippet,
          cwe_id: finding.cwe_id,
          severity: finding.severity,
          vuln_type: finding.vuln_type,
          file_path: currentUrl,
          line: 0,
          tool: 'autoshield-chrome',
          use_llm: useLLM,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        results.push({ ...data, _original: finding });
      } else {
        results.push(buildFallbackResult(finding));
      }
    } catch (_) {
      results.push(buildFallbackResult(finding));
    }
  }

  return results;
}

// ─── Fallback Result (backend unreachable) ────────────────────────────
function buildFallbackResult(finding) {
  const QUICK_FIXES = {
    'CWE-693': { fix: 'Add a Content-Security-Policy meta tag to your <head>.', code: "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">" },
    'CWE-922': { fix: "Don't store auth tokens or sensitive data in localStorage. Use HttpOnly cookies set by the server instead.", code: "// Use server-set HttpOnly cookies for auth tokens\n// Avoid: localStorage.setItem('token', jwt)" },
    'CWE-79':  { fix: 'Replace innerHTML with textContent, or sanitize with DOMPurify before DOM insertion.', code: "element.textContent = userInput; // safe\n// or: element.innerHTML = DOMPurify.sanitize(userInput);" },
    'CWE-829': { fix: 'Add integrity= and crossorigin= attributes to external script tags (SRI).', code: '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-..."\n  crossorigin="anonymous"></script>' },
    'CWE-319': { fix: 'Change form action to https:// and enable HSTS on your server.', code: '<form action="https://yourdomain.com/login" method="POST">' },
    'CWE-352': { fix: 'Add a CSRF token hidden field to all state-changing forms.', code: '<input type="hidden" name="csrf_token" value="{{ csrf_token }}">' },
    'CWE-1021': { fix: 'Add sandbox attribute to external iframes.', code: '<iframe src="https://external.com" sandbox="allow-scripts allow-same-origin"></iframe>' },
  };

  const q = QUICK_FIXES[finding.cwe_id] || { fix: 'Review this finding and apply secure coding best practices.', code: '' };

  return {
    vuln_type: finding.vuln_type || 'Unknown Issue',
    cwe_id: finding.cwe_id || '',
    risk_category: finding.severity ? finding.severity.toUpperCase() : 'MEDIUM',
    risk_score: finding.severity === 'critical' ? 90 : finding.severity === 'high' ? 70 : finding.severity === 'medium' ? 45 : 20,
    owasp_category: '',
    reasoning: 'Backend is offline — showing local static analysis only.',
    recommended_fix: q.fix,
    fix_code: q.code,
    key_risks: [],
    llm_available: false,
    _original: finding,
    _fallback: true,
  };
}

// ─── Build Security Findings from extracted page data ─────────────────
function buildSecurityFindings(pageData) {
  const findings = [];
  const sec = pageData.security || {};

  sec.inlineScripts?.forEach((script) => {
    if (script.hasEval)
      findings.push({ vuln_type: 'eval() usage detected', cwe_id: 'CWE-95', severity: 'high', snippet: script.snippet, location: `inline script #${script.index}` });
    if (script.hasDocumentWrite)
      findings.push({ vuln_type: 'document.write() usage', cwe_id: 'CWE-79', severity: 'medium', snippet: script.snippet, location: `inline script #${script.index}` });
    if (script.hasInnerHTML)
      findings.push({ vuln_type: 'innerHTML assignment (potential XSS)', cwe_id: 'CWE-79', severity: 'medium', snippet: script.snippet, location: `inline script #${script.index}` });
  });

  const externalNoSRI = sec.externalScripts?.filter((s) => s.isExternal && !s.hasSRI) || [];
  if (externalNoSRI.length > 0)
    findings.push({ vuln_type: 'External scripts without Subresource Integrity (SRI)', cwe_id: 'CWE-829', severity: externalNoSRI.length > 3 ? 'high' : 'medium', snippet: externalNoSRI.map((s) => s.src).join('\n'), location: `${externalNoSRI.length} external script(s)` });

  if (sec.mixedContent?.length > 0)
    findings.push({ vuln_type: 'Mixed content (HTTP resources on HTTPS page)', cwe_id: 'CWE-311', severity: 'high', snippet: sec.mixedContent.map((m) => `${m.tag}[${m.attr}]=${m.url}`).join('\n'), location: `${sec.mixedContent.length} mixed content resource(s)` });

  sec.forms?.forEach((form) => {
    if (form.hasPasswordField && form.isHttpAction)
      findings.push({ vuln_type: 'Password field submits over HTTP', cwe_id: 'CWE-319', severity: 'critical', snippet: `Form action: ${form.action}`, location: `form #${form.index}` });
    if (form.hasPasswordField && !form.hasCSRFToken)
      findings.push({ vuln_type: 'Password form missing CSRF protection', cwe_id: 'CWE-352', severity: 'medium', snippet: `Form action: ${form.action}, method: ${form.method}`, location: `form #${form.index}` });
  });

  if (!sec.metaTags?.csp)
    findings.push({ vuln_type: 'Content Security Policy (CSP) not set', cwe_id: 'CWE-693', severity: 'medium', snippet: 'No Content-Security-Policy meta tag detected.', location: 'page headers/meta' });

  const unsandboxedIframes = sec.iframes?.filter((f) => f.isExternal && !f.sandbox) || [];
  if (unsandboxedIframes.length > 0)
    findings.push({ vuln_type: 'External iframes without sandbox attribute', cwe_id: 'CWE-1021', severity: 'medium', snippet: unsandboxedIframes.map((f) => f.src).join('\n'), location: `${unsandboxedIframes.length} unsandboxed iframe(s)` });

  const storageIssues = [...(sec.storageUsage?.localStorage || []), ...(sec.storageUsage?.sessionStorage || [])];
  if (storageIssues.length > 0)
    findings.push({ vuln_type: 'Sensitive data keys found in browser storage', cwe_id: 'CWE-922', severity: 'high', snippet: storageIssues.map((s) => s.key).join(', '), location: 'localStorage / sessionStorage' });

  return findings;
}

// ─── Compliance Analysis ──────────────────────────────────────────────
async function analyzeComplianceData(pageData) {
  const comp = pageData.compliance || {};
  try {
    const res = await fetch(`${BACKEND}/rag/compliance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        page_url:           currentUrl,
        security:           pageData.security || {},
        images:             comp.images             || [],
        videos:             comp.videos             || [],
        audios:             comp.audios             || [],
        fonts:              comp.fonts              || [],
        stylesheets:        comp.externalStylesheets|| [],
        text_blocks:        comp.textBlocks         || [],
        iframe_embeds:      comp.iframeEmbeds       || [],
        license_indicators: comp.licenseIndicators  || {},
      }),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.summary && !data.summary.copyrightText) {
        data.summary.copyrightText = (comp.licenseIndicators || {}).copyrightText || '';
      }
      logStep('🤖 Compliance: LLM backend used');
      return data;
    }
  } catch (_) {
    logStep('⚠ Compliance backend unreachable — using client-side fallback');
  }

  const issues = [];
  const clean  = [];
  const sec = pageData.security || {};

  if (!sec.metaTags?.csp)
    issues.push({ category: 'Security Headers', title: 'Missing CSP', severity: 'HIGH',
      recommendation: 'Add a strict Content-Security-Policy header.' });
  if (!sec.metaTags?.xFrameOptions)
    issues.push({ category: 'Security Headers', title: 'Missing X-Frame-Options', severity: 'MEDIUM',
      recommendation: 'Add X-Frame-Options or CSP frame-ancestors.' });
  if (!sec.metaTags?.referrerPolicy)
    issues.push({ category: 'Security Headers', title: 'Missing Referrer-Policy', severity: 'LOW',
      recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin.' });
  if (sec.mixedContent?.length)
    issues.push({ category: 'Mixed Content', title: 'Mixed content HTTP resources', severity: 'HIGH',
      recommendation: 'Load all page resources over HTTPS.', evidence: `${sec.mixedContent.length} resource(s)` });
  if (sec.inlineScripts?.length)
    issues.push({ category: 'Content Security Policy', title: 'Inline scripts', severity: 'MEDIUM',
      recommendation: 'Move inline scripts to external files and enforce CSP without unsafe-inline.', evidence: `${sec.inlineScripts.length} script(s)` });
  if (sec.inlineScripts?.some((s) => s.hasEval) || sec.dangerousPatterns?.some((p) => p.pattern === 'eval()'))
    issues.push({ category: 'Code Execution', title: 'eval usage', severity: 'HIGH',
      recommendation: 'Remove eval/new Function and use safe parsing or dispatch.' });
  const noSri = sec.externalScripts?.filter((s) => s.isExternal && !s.hasSRI) || [];
  if (noSri.length)
    issues.push({ category: 'Supply Chain', title: 'Third-party scripts without integrity', severity: 'MEDIUM',
      recommendation: 'Add integrity and crossorigin attributes to third-party scripts.', evidence: `${noSri.length} script(s)` });

  comp.images?.forEach((img) => {
    if (!img.src || img.src.startsWith('data:')) return;
    if (img.isExternal)
      issues.push({ type: 'image', src: img.src, domain: img.domain || '', severity: 'REVIEW',
        issue: 'External image — license unknown',
        recommendation: 'Verify you have rights to use this image or host it locally.' });
  });

  comp.videos?.forEach((v) => {
    if (v.src && v.isExternal)
      issues.push({ type: 'video', src: v.src, domain: v.domain || '', severity: 'REVIEW',
        issue: 'External video resource — license unknown',
        recommendation: 'Verify licensing or use an official embed player.' });
  });

  comp.audios?.forEach((a) => {
    if (a.src && a.isExternal)
      issues.push({ type: 'audio', src: a.src, domain: a.domain || '', severity: 'REVIEW',
        issue: 'External audio resource — license unknown',
        recommendation: 'Verify licensing before using this audio.' });
  });

  comp.iframeEmbeds?.forEach((frame) => {
    if (frame.isYouTube || frame.isVimeo || frame.isSpotify || frame.isSoundCloud)
      clean.push({ type: 'embed', src: frame.src, status: 'ok', note: 'Official platform embed — generally OK' });
  });

  comp.fonts?.forEach((f) => {
    clean.push({ type: 'font', src: f.src, status: 'free-source', note: `Font via ${f.domain || f.via || 'external'}` });
  });

  const li = comp.licenseIndicators || {};
  const complianceScore = scoreCompliance(issues);
  return { compliance_score: complianceScore, issues, clean, summary: {
    copyrightText:      li.copyrightText || '',
    compliance_score:   complianceScore,
    issues_count:       issues.length,
    total_assets:       (comp.images?.length || 0) + (comp.videos?.length || 0) + (comp.fonts?.length || 0),
    llm_used:           false,
  }};
}

// ─── Render Security Results ────────────────────────────────────────
function renderSecurityResults(results) {
  const out = document.getElementById('security-out');
  if (!results || results.length === 0) {
    out.innerHTML = '<div class="empty"><span class="empty-icon">✅</span>No security issues detected<br/>on this page</div>';
    return;
  }

  out.innerHTML = '';
  const header = document.createElement('div');
  header.className = 'section-header';
  header.innerHTML = `Vulnerabilities <span class="section-count">${results.length}</span>`;
  out.appendChild(header);

  results.forEach((r, i) => {
    const cat = (r.risk_category || 'MEDIUM').toUpperCase();
    const score = r.risk_score || 0;
    const hasFix = !!(r.fix_code && r.fix_code.trim());
    const hasAnalysis = !!(r.reasoning || r.recommended_fix || (r.key_risks && r.key_risks.length));
    const hasBody = hasFix || hasAnalysis;
    const usedLLM = r.llm_available === true;

    const card = document.createElement('div');
    card.className = 'card';

    const headDiv = document.createElement('div');
    headDiv.className = 'card-head';
    if (hasBody) {
      headDiv.dataset.toggleBody = `s-${i}`;
      headDiv.dataset.toggleChev = `s-chev-${i}`;
      headDiv.style.cursor = 'pointer';
    }

    headDiv.innerHTML = `
      <span class="sev-tag sev-${cat}">${cat}</span>
      <div style="min-width:0;flex:1">
        <div class="card-title-row">
          <span class="card-title">${esc(r.vuln_type || r.cwe_id || 'Unknown')}</span>
          ${hasFix ? `<span class="fix-pill">✦ Fix</span>` : ''}
          ${usedLLM ? `<span class="llm-pill">⚡ LLM</span>` : ''}
        </div>
        <div class="card-meta">
          ${esc(r.cwe_id || '')}${r._original?.location ? ' · ' + esc(r._original.location) : ''}
          ${r.owasp_category && r.owasp_category !== 'Unknown' ? ' · ' + esc(r.owasp_category) : ''}
        </div>
        <div class="score-row">
          <div class="score-track"><div class="score-fill" style="width:${score}%;background:${scoreColor(score)}"></div></div>
          <span class="score-num">${score}/100</span>
        </div>
      </div>
      ${hasBody ? `<span class="chevron open" id="s-chev-${i}">&gt;</span>` : '<span style="width:12px;display:inline-block"></span>'}
    `;
    card.appendChild(headDiv);

    if (hasBody) {
      const bodyDiv = document.createElement('div');
      bodyDiv.id = `s-${i}`;
      bodyDiv.className = 'card-body open';

      if (r._fallback && !r.recommended_fix) {
        bodyDiv.innerHTML = `<div class="body-sec offline-note">⚠ Backend offline — start your FastAPI server.</div>`;
      } else if (hasFix && hasAnalysis) {
        bodyDiv.innerHTML = `
          <div class="inner-tabs">
            <button class="inner-tab active" data-card-idx="${i}" data-tab-type="analysis">Analysis</button>
            <button class="inner-tab" data-card-idx="${i}" data-tab-type="fix">Fix Code</button>
          </div>
          <div id="s-${i}-analysis">${buildAnalysisHTML(r)}</div>
          <div id="s-${i}-fix" style="display:none">${buildFixHTML(r)}</div>
        `;
      } else if (hasFix) {
        bodyDiv.innerHTML = buildFixHTML(r);
      } else {
        bodyDiv.innerHTML = buildAnalysisHTML(r);
      }
      card.appendChild(bodyDiv);
    }
    out.appendChild(card);
  });
}

function buildAnalysisHTML(r) {
  let html = '';
  if (r.reasoning) html += `<div class="body-sec"><div class="sec-label">Analysis</div><div class="body-text">${esc(r.reasoning)}</div></div>`;
  if (r.key_risks?.length) html += `<div class="body-sec"><div class="sec-label">Key Risks</div><ul class="asset-list">${r.key_risks.map(k => `<li class="asset-item"><span class="asset-status st-issue">risk</span><span>${esc(k)}</span></li>`).join('')}</ul></div>`;
  if (r.recommended_fix) html += `<div class="body-sec"><div class="sec-label">How to Fix</div><div class="body-text fix-hint">${esc(r.recommended_fix)}</div></div>`;
  return html || `<div class="body-sec"><div class="body-text">No data</div></div>`;
}

function buildFixHTML(r) {
  let html = '';
  if (r.recommended_fix) html += `<div class="body-sec"><div class="sec-label">What to do</div><div class="body-text fix-hint">${esc(r.recommended_fix)}</div></div>`;
  if (r.fix_code) {
    html += `<div class="fix-wrap">
      <div class="fix-head"><span>Suggested Fix</span><button class="copy-btn" data-code="${esc(r.fix_code)}">Copy</button></div>
      <div class="fix-code">${esc(r.fix_code)}</div>
    </div>`;
  }
  return html;
}

// ─── Render Compliance Results ────────────────────────────────────────
function renderComplianceResults(data) {
  const out = document.getElementById('compliance-out');
  if (!data) { out.innerHTML = '<div class="empty">No data</div>'; return; }
  out.innerHTML = '';

  const s = data.summary || {};
  const bannerParts = [];
  if (data.compliance_score !== undefined) bannerParts.push(`<div style="color:var(--text-dim)">Score: ${esc(data.compliance_score)}/100</div>`);
  if (s.copyrightText)        bannerParts.push(`<div style="color:var(--text-dim)">📄 ${esc(s.copyrightText)}</div>`);
  if (s.paid_stock_warnings > 0) bannerParts.push(`<div style="color:#cc7700">⚠ ${s.paid_stock_warnings} potential paid stock source(s)</div>`);
  if (s.free_assets > 0)     bannerParts.push(`<div style="color:var(--green)">✓ ${s.free_assets} asset(s) from known free sources</div>`);
  if (s.total_assets > 0)    bannerParts.push(`<div style="color:var(--text-lo)">📦 ${s.total_assets} total asset(s) scanned</div>`);
  if (data.llm_used)         bannerParts.push(`<div style="color:var(--blue)">⚡ LLM-powered analysis</div>`);

  if (bannerParts.length) {
    const banner = document.createElement('div');
    banner.style.cssText = 'padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg2);font-size:9px;color:var(--text-lo);line-height:1.8';
    banner.innerHTML = bannerParts.join('');
    out.appendChild(banner);
  }

  if (data.issues?.length) {
    const issHeader = document.createElement('div');
    issHeader.className = 'section-header';
    issHeader.innerHTML = `Issues <span class="section-count">${data.issues.length}</span>`;
    out.appendChild(issHeader);

    data.issues.forEach((issue, i) => {
      const card = document.createElement('div');
      card.className = 'card';
      const typeIcon = { image:'🖼', video:'🎬', audio:'🔊', font:'🔤', stylesheet:'🎨', text:'📝', embed:'📺' }[issue.type] || '📎';
      const title = issue.title || issue.issue || issue.category || 'Compliance issue';
      const meta = issue.category || issue.domain || issue.src || issue.evidence || '';
      const evidence = issue.src || issue.evidence || '';
      card.innerHTML = `
        <div class="card-head" data-toggle-body="c-${i}" data-toggle-chev="c-chev-${i}" style="cursor:pointer">
          <span class="sev-tag sev-${issue.severity}">${issue.severity}</span>
          <div style="min-width:0;flex:1">
            <div class="card-title-row">
              <span style="font-size:9px;margin-right:4px">${typeIcon}</span>
              <span class="card-title">${esc(title)}</span>
            </div>
            <div class="card-meta asset-url">${esc(meta)}</div>
          </div>
          <span class="chevron open" id="c-chev-${i}">&gt;</span>
        </div>
        <div class="card-body open" id="c-${i}">
          ${evidence ? `<div class="body-sec"><div class="sec-label">Evidence</div><div class="body-text" style="word-break:break-all;font-size:9px;color:var(--text-lo)">${esc(evidence)}</div></div>` : ''}
          ${issue.recommendation ? `<div class="body-sec"><div class="sec-label">Recommendation</div><div class="body-text fix-hint">${esc(issue.recommendation)}</div></div>` : ''}
        </div>
      `;
      out.appendChild(card);
    });
  }

  if (data.clean?.length) {
    const cleanHeader = document.createElement('div');
    cleanHeader.className = 'section-header';
    cleanHeader.id = 'clean-list-header';
    cleanHeader.style.cursor = 'pointer';
    cleanHeader.innerHTML = `Clean Assets <span class="section-count">${data.clean.length}</span> (click to expand)`;
    out.appendChild(cleanHeader);

    const cleanList = document.createElement('div');
    cleanList.id = 'clean-list';
    cleanList.style.display = 'none';
    data.clean.forEach((item) => {
      const row = document.createElement('div');
      row.style.cssText = 'padding:5px 12px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center;font-size:9px';
      const typeIcon = { image:'🖼', video:'🎬', audio:'🔊', font:'🔤', stylesheet:'🎨', text:'📝', embed:'📺' }[item.type] || '📎';
      row.innerHTML = `<span class="asset-status st-free">${item.status}</span><span>${typeIcon}</span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(item.note || item.src)}</span>`;
      cleanList.appendChild(row);
    });
    out.appendChild(cleanList);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────
function toggleCard(bodyId, chevId) {
  const body = document.getElementById(bodyId);
  const chev = document.getElementById(chevId);
  if (!body) return;
  const open = body.classList.toggle('open');
  if (chev) chev.classList.toggle('open', open);
}

function switchInnerTab(cardIdx, tab, clickedBtn) {
  const aPanel = document.getElementById(`s-${cardIdx}-analysis`);
  const fPanel = document.getElementById(`s-${cardIdx}-fix`);
  if (!aPanel || !fPanel) return;
  const bodyDiv = document.getElementById(`s-${cardIdx}`);
  bodyDiv?.querySelectorAll('.inner-tab').forEach(t => t.classList.remove('active'));
  clickedBtn?.classList.add('active');
  if (tab === 'analysis') { aPanel.style.display = ''; fPanel.style.display = 'none'; }
  else { aPanel.style.display = 'none'; fPanel.style.display = ''; }
}

function copyFix(btn, code) {
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'Copied!';
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.textContent = 'Copy'; btn.style.color = ''; }, 1500);
  });
}

function updateSummary(results) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  results.forEach((r) => {
    const k = (r.risk_category || 'MEDIUM').toUpperCase();
    if (c[k] !== undefined) c[k]++;
  });
  document.getElementById('s-crit').textContent = c.CRITICAL;
  document.getElementById('s-high').textContent = c.HIGH;
  document.getElementById('s-med').textContent = c.MEDIUM;
  document.getElementById('s-low').textContent = c.LOW;
  if (results.length > 0) document.getElementById('summary').classList.add('visible');
}

function setStatus(text, cls, pulse) {
  const el = document.getElementById('statusbar');
  if (!el) return;
  el.className = 'statusbar' + (cls ? ' ' + cls : '');
  el.innerHTML = (pulse ? '<span class="dot"></span>' : '') + text;
}

function setBtnsDisabled(disabled) {
  ['btnScan', 'btnDeep', 'btnClear'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = disabled;
  });
}

function scoreColor(s) {
  if (s >= 85) return '#cc3333';
  if (s >= 65) return '#ffe8c9';
  if (s >= 40) return '#ffbb02';
  return '#4a8a3a';
}

function scoreCompliance(issues) {
  const weights = { CRITICAL: 20, HIGH: 15, MEDIUM: 9, LOW: 4, REVIEW: 5 };
  const penalty = (issues || []).reduce((sum, issue) => {
    const key = String(issue.severity || 'LOW').toUpperCase();
    return sum + (weights[key] || 4);
  }, 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
