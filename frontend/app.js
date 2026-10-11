/**
 * BANKISM — AI Banking Security Firewall Frontend Controller
 * Connects the Live Attack Lab, 9-Stage Visualizer, Mock Banking Ledger,
 * and Independent Verification Engine.
 */

// Application State
const state = {
  scenarios: [],
  accounts: [],
  ledger: [],
  history: [],
  analytics: null,
  activeTest: null,
  activeEvidence: null,
  isRunningBatch: false,
};

// DOM Elements
const el = {
  // Tabs
  navTabs: document.querySelectorAll('.nav-tab'),
  tabPanes: document.querySelectorAll('.tab-pane'),
  subTabBtns: document.querySelectorAll('.sub-tab-btn'),
  subTabPanes: document.querySelectorAll('.subtab-pane'),

  // Header status
  appModeText: document.getElementById('appModeText'),
  appModeBadge: document.getElementById('appModeBadge'),

  // Metrics
  metricTotalTests: document.getElementById('metricTotalTests'),
  metricAttacksContained: document.getElementById('metricAttacksContained'),
  metricLegitProcessed: document.getElementById('metricLegitProcessed'),
  metricVerifFailures: document.getElementById('metricVerifFailures'),
  metricInconclusive: document.getElementById('metricInconclusive'),
  metricUnauthorizedExecuted: document.getElementById('metricUnauthorizedExecuted'),
  metricSampleSize: document.getElementById('metricSampleSize'),
  metricContainmentRate: document.getElementById('metricContainmentRate'),

  // Attack Lab
  scenariosGrid: document.getElementById('scenariosGrid'),
  scenarioCategoryFilter: document.getElementById('scenarioCategoryFilter'),
  btnRunAllScenarios: document.getElementById('btnRunAllScenarios'),
  customAttackForm: document.getElementById('customAttackForm'),
  customPrompt: document.getElementById('customPrompt'),
  btnToggleAdvanced: document.getElementById('btnToggleAdvanced'),
  advancedParamsPanel: document.getElementById('advancedParamsPanel'),
  shortcuts: document.querySelectorAll('.btn-shortcut'),
  btnClearCustomForm: document.getElementById('btnClearCustomForm'),

  // Advanced inputs
  paramCustomerId: document.getElementById('paramCustomerId'),
  paramSourceAccount: document.getElementById('paramSourceAccount'),
  paramDestAccount: document.getElementById('paramDestAccount'),
  paramAmount: document.getElementById('paramAmount'),
  paramMemo: document.getElementById('paramMemo'),
  paramIdempotency: document.getElementById('paramIdempotency'),
  paramIsAuth: document.getElementById('paramIsAuth'),
  paramSimulateLLMFailure: document.getElementById('paramSimulateLLMFailure'),
  paramSimulateBypass: document.getElementById('paramSimulateBypass'),

  // Visualizer
  activeTestIdBadge: document.getElementById('activeTestIdBadge'),
  pipelineStagesList: document.getElementById('pipelineStagesList'),
  verdictBadges: document.getElementById('verdictBadges'),
  verdictContent: document.getElementById('verdictContent'),

  // Mock Bank
  accountsGrid: document.getElementById('accountsGrid'),
  ledgerCountBadge: document.getElementById('ledgerCountBadge'),
  ledgerTableBody: document.getElementById('ledgerTableBody'),
  btnRefreshLedger: document.getElementById('btnRefreshLedger'),

  // History & Analytics
  historyTableBody: document.getElementById('historyTableBody'),
  analyticsSummaryBox: document.getElementById('analyticsSummaryBox'),
  categoryBarsContainer: document.getElementById('categoryBarsContainer'),

  // Modals
  evidenceModal: document.getElementById('evidenceModal'),
  modalEvidenceTitle: document.getElementById('modalEvidenceTitle'),
  modalEvidenceTestId: document.getElementById('modalEvidenceTestId'),
  modalEvidenceBody: document.getElementById('modalEvidenceBody'),
  btnCloseEvidenceModal: document.getElementById('btnCloseEvidenceModal'),
  btnCloseEvidenceModal2: document.getElementById('btnCloseEvidenceModal2'),
  btnDownloadEvidenceJson: document.getElementById('btnDownloadEvidenceJson'),

  btnOpenResetModal: document.getElementById('btnOpenResetModal'),
  resetModal: document.getElementById('resetModal'),
  btnCloseResetModal: document.getElementById('btnCloseResetModal'),
  btnCancelReset: document.getElementById('btnCancelReset'),
  btnConfirmReset: document.getElementById('btnConfirmReset'),
  resetClearLedger: document.getElementById('resetClearLedger'),
  resetClearEvidence: document.getElementById('resetClearEvidence'),

  toastContainer: document.getElementById('toastContainer'),
};

// ================= INITIALIZATION =================
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupEventListeners();
  loadInitialData();
});

function setupNavigation() {
  // Main tabs
  el.navTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      el.navTabs.forEach((t) => t.classList.remove('active'));
      el.tabPanes.forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.getElementById(`tab-${target}`);
      if (pane) pane.classList.add('active');

      if (target === 'mockbank') loadMockBankData();
      if (target === 'history') loadHistoryData();
      if (target === 'analytics') loadAnalyticsData();
    });
  });

  // Lab sub-tabs
  el.subTabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const sub = btn.dataset.subtab;
      el.subTabBtns.forEach((b) => b.classList.remove('active'));
      el.subTabPanes.forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      const subPane = document.getElementById(`subtab-${sub}`);
      if (subPane) subPane.classList.add('active');
    });
  });
}

function setupEventListeners() {
  // Advanced parameters toggle
  el.btnToggleAdvanced.addEventListener('click', () => {
    const isHidden = el.advancedParamsPanel.style.display === 'none';
    el.advancedParamsPanel.style.display = isHidden ? 'block' : 'none';
    el.btnToggleAdvanced.querySelector('.toggle-icon').textContent = isHidden ? '▲' : '▼';
  });

  // Category filter
  el.scenarioCategoryFilter.addEventListener('change', renderScenarios);

  // Shortcut clicks
  el.shortcuts.forEach((btn) => {
    btn.addEventListener('click', () => {
      el.customPrompt.value = btn.dataset.prompt;
      if (btn.dataset.amt) el.paramAmount.value = btn.dataset.amt;
      if (btn.dataset.src) el.paramSourceAccount.value = btn.dataset.src;
      if (btn.dataset.memo) el.paramMemo.value = btn.dataset.memo;
      showToast('Loaded judge shortcut payload into sandbox input.', 'info');
    });
  });

  // Clear button
  el.btnClearCustomForm.addEventListener('click', () => {
    el.customAttackForm.reset();
    el.paramIsAuth.checked = true;
    el.paramSourceAccount.value = 'ACC_ALICE_101';
  });

  // Custom attack submit
  el.customAttackForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitCustomAttack();
  });

  // Run all batch button
  el.btnRunAllScenarios.addEventListener('click', runAllScenariosBatch);

  // Refresh mock bank
  el.btnRefreshLedger.addEventListener('click', loadMockBankData);

  // Reset modal handlers
  el.btnOpenResetModal.addEventListener('click', () => (el.resetModal.style.display = 'flex'));
  el.btnCloseResetModal.addEventListener('click', () => (el.resetModal.style.display = 'none'));
  el.btnCancelReset.addEventListener('click', () => (el.resetModal.style.display = 'none'));
  el.btnConfirmReset.addEventListener('click', executeResetSandbox);

  // Evidence modal handlers
  el.btnCloseEvidenceModal.addEventListener('click', () => (el.evidenceModal.style.display = 'none'));
  el.btnCloseEvidenceModal2.addEventListener('click', () => (el.evidenceModal.style.display = 'none'));
  el.btnDownloadEvidenceJson.addEventListener('click', downloadEvidenceJson);
}

// ================= API CALLS & DATA LOADING =================
async function loadInitialData() {
  await Promise.all([
    checkHealth(),
    loadScenarios(),
    loadAnalyticsData(),
    loadMockBankData(),
  ]);
}

async function checkHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    el.appModeText.textContent = data.operating_mode === 'LLM_ASSISTED' ? 'AI-Assisted Engine' : 'Rule-Based Fallback Mode';
  } catch (err) {
    el.appModeText.textContent = 'Rule-Based Fallback Mode';
  }
}

async function loadScenarios() {
  try {
    const res = await fetch('/api/scenarios');
    state.scenarios = await res.json();
    renderScenarios();
  } catch (err) {
    el.scenariosGrid.innerHTML = `<div class="text-danger">Failed to load scenarios: ${err.message}</div>`;
  }
}

async function loadAnalyticsData() {
  try {
    const res = await fetch('/api/analytics');
    state.analytics = await res.json();
    updateMetricsBanner(state.analytics);
    renderAnalyticsView(state.analytics);
  } catch (err) {
    console.error('Analytics load error:', err);
  }
}

async function loadMockBankData() {
  try {
    const [accRes, txRes] = await Promise.all([
      fetch('/api/mock-bank/accounts'),
      fetch('/api/mock-bank/transactions?limit=50'),
    ]);
    state.accounts = await accRes.json();
    state.ledger = await txRes.json();
    renderMockBankView();
  } catch (err) {
    console.error('Mock bank load error:', err);
  }
}

async function loadHistoryData() {
  try {
    const res = await fetch('/api/history?limit=100');
    state.history = await res.json();
    renderHistoryTable();
  } catch (err) {
    console.error('History load error:', err);
  }
}

// ================= RENDERING SCENARIOS =================
function renderScenarios() {
  const selectedCat = el.scenarioCategoryFilter.value;
  const filtered = selectedCat === 'ALL'
    ? state.scenarios
    : state.scenarios.filter((s) => s.threat_category === selectedCat);

  if (!filtered.length) {
    el.scenariosGrid.innerHTML = `<div class="empty-state">No scenarios match the selected category.</div>`;
    return;
  }

  el.scenariosGrid.innerHTML = filtered.map((sc) => {
    let expectedBadgeClass = 'expected-block';
    if (sc.expected_outcome === 'TRANSFER_EXECUTED' || sc.expected_outcome === 'READ_ONLY_AUTHORIZED') {
      expectedBadgeClass = 'expected-allow';
    } else if (sc.expected_outcome === 'HELD_FOR_REVIEW') {
      expectedBadgeClass = 'expected-review';
    }

    const checksHtml = sc.relevant_policy_checks
      .map((c) => `<span class="policy-check-tag">${c}</span>`)
      .join('');

    return `
      <div class="scenario-card" id="card-${sc.scenario_id}">
        <div class="scenario-top">
          <span class="scenario-id-tag">${sc.scenario_id.toUpperCase()}</span>
          <span class="badge badge-cyan">${sc.threat_category}</span>
        </div>
        <h4 class="scenario-title">${sc.name}</h4>
        <p class="scenario-desc">${sc.description}</p>
        
        <div class="scenario-example-box">
          <div class="scenario-example-label">Example Request / Payload:</div>
          <div class="scenario-example-code">${escapeHtml(sc.example_request)}</div>
        </div>

        <div class="scenario-checks-list">
          ${checksHtml}
        </div>

        <div class="scenario-footer">
          <span class="scenario-expected-pill ${expectedBadgeClass}">Expected: ${sc.expected_outcome}</span>
          <button class="btn btn-primary btn-sm" onclick="runSingleScenario('${sc.scenario_id}')">
            <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Run Test
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// ================= TEST EXECUTION =================
window.runSingleScenario = async function(scenarioId) {
  const sc = state.scenarios.find((s) => s.scenario_id === scenarioId);
  if (!sc) return;

  const card = document.getElementById(`card-${scenarioId}`);
  if (card) card.style.opacity = '0.6';

  showToast(`Executing Curated Scenario: ${sc.name}...`, 'info');

  try {
    const res = await fetch('/api/tests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scenario_id: sc.scenario_id,
        request_text: sc.example_request,
      }),
    });

    const verdict = await res.json();
    state.activeTest = verdict;

    // Switch to visualizer tab and render
    switchToVisualizerTab();
    renderLiveVisualizer(verdict);

    // Refresh state
    await Promise.all([loadAnalyticsData(), loadMockBankData()]);
    showToast(`Test ${verdict.test_id} complete. Verification: ${verdict.verification.status}`, verdict.verification.status === 'PASS' ? 'success' : 'danger');
  } catch (err) {
    showToast(`Error running test: ${err.message}`, 'danger');
  } finally {
    if (card) card.style.opacity = '1';
  }
};

async function submitCustomAttack() {
  const prompt = el.customPrompt.value.trim();
  if (!prompt) return;

  const payload = {
    request_text: prompt,
    notes: 'Judge custom sandbox test',
    authenticated_customer_id: el.paramCustomerId.value,
    is_authenticated: el.paramIsAuth.checked,
    source_account_id: el.paramSourceAccount.value.trim() || 'ACC_ALICE_101',
    destination_account_id: el.paramDestAccount.value.trim() || null,
    amount: el.paramAmount.value ? parseFloat(el.paramAmount.value) : null,
    memo: el.paramMemo.value.trim() || null,
    idempotency_key: el.paramIdempotency.value.trim() || null,
    simulate_llm_failure: el.paramSimulateLLMFailure.checked,
    simulate_unauthorized_bypass: el.paramSimulateBypass.checked,
  };

  showToast('Passing custom attack through 9-stage security pipeline...', 'info');

  try {
    const res = await fetch('/api/tests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const verdict = await res.json();
    state.activeTest = verdict;

    switchToVisualizerTab();
    renderLiveVisualizer(verdict);

    await Promise.all([loadAnalyticsData(), loadMockBankData()]);
    showToast(`Test ${verdict.test_id} finished. Decision: ${verdict.decision}`, 'info');
  } catch (err) {
    showToast(`Pipeline failed: ${err.message}`, 'danger');
  }
}

async function runAllScenariosBatch() {
  if (state.isRunningBatch) return;
  state.isRunningBatch = true;
  el.btnRunAllScenarios.disabled = true;
  el.btnRunAllScenarios.textContent = 'Running 14 Scenarios Batch...';

  showToast('Starting sequential execution of all 14 curated scenarios...', 'info');

  for (let i = 0; i < state.scenarios.length; i++) {
    const sc = state.scenarios[i];
    try {
      const res = await fetch('/api/tests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: sc.scenario_id,
          request_text: sc.example_request,
        }),
      });
      const verdict = await res.json();
      state.activeTest = verdict;
    } catch (err) {
      console.error(`Error on scenario ${sc.scenario_id}:`, err);
    }
  }

  state.isRunningBatch = false;
  el.btnRunAllScenarios.disabled = false;
  el.btnRunAllScenarios.innerHTML = `
    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"/></svg>
    Run All 14 Scenarios Batch
  `;

  await Promise.all([loadAnalyticsData(), loadMockBankData()]);
  switchToVisualizerTab();
  if (state.activeTest) renderLiveVisualizer(state.activeTest);
  showToast('All 14 Scenarios Batch complete! Analytics updated.', 'success');
}

function switchToVisualizerTab() {
  el.navTabs.forEach((t) => t.classList.remove('active'));
  el.tabPanes.forEach((p) => p.classList.remove('active'));
  const vizTab = document.querySelector('[data-tab="dashboard"]');
  if (vizTab) vizTab.classList.add('active');
  const vizPane = document.getElementById('tab-dashboard');
  if (vizPane) vizPane.classList.add('active');
}

// ================= LIVE VISUALIZER RENDERING =================
function renderLiveVisualizer(verdict) {
  el.activeTestIdBadge.textContent = verdict.test_id;

  // Render 9 Stages
  el.pipelineStagesList.innerHTML = verdict.stages.map((st, index) => {
    let stageClass = 'stage-skipped';
    let badgeClass = 'badge-skipped';

    if (st.status === 'PASSED') {
      stageClass = 'stage-passed';
      badgeClass = 'badge-passed';
    } else if (st.status === 'FAILED') {
      stageClass = 'stage-failed';
      badgeClass = 'badge-failed';
    } else if (st.status === 'INCONCLUSIVE') {
      stageClass = 'stage-inconclusive';
      badgeClass = 'badge-inconclusive';
    }

    const detailsStr = JSON.stringify(st.details, null, 2);

    return `
      <div class="stage-item ${stageClass}">
        <div class="stage-header-row">
          <div class="stage-name-group">
            <span class="stage-number">0${index + 1}</span>
            <span class="stage-name">${st.name}</span>
          </div>
          <div class="stage-meta">
            <span class="stage-duration">${st.duration_ms} ms</span>
            <span class="stage-badge ${badgeClass}">${st.status}</span>
          </div>
        </div>
        <div class="stage-details-box">
          <pre style="margin:0; font-size: 0.74rem;">${escapeHtml(detailsStr)}</pre>
        </div>
      </div>
    `;
  }).join('');

  // Render Verdict Hero
  let heroClass = 'decision-block';
  let tagClass = 'tag-block';
  if (verdict.decision === 'APPROVE') {
    heroClass = 'decision-approve';
    tagClass = 'tag-approve';
  } else if (verdict.decision === 'REVIEW') {
    heroClass = 'decision-review';
    tagClass = 'tag-review';
  }

  let riskClass = 'risk-low';
  if (verdict.risk_level === 'CRITICAL') riskClass = 'risk-critical';
  else if (verdict.risk_level === 'HIGH') riskClass = 'risk-high';
  else if (verdict.risk_level === 'MEDIUM') riskClass = 'risk-medium';

  let auditClass = 'audit-pass';
  if (verdict.verification.status === 'FAIL') auditClass = 'audit-fail';
  else if (verdict.verification.status === 'INCONCLUSIVE') auditClass = 'audit-inconclusive';

  const checks = verdict.security_checks;

  el.verdictContent.innerHTML = `
    <div class="verdict-hero ${heroClass}">
      <div class="verdict-primary-row">
        <div class="decision-display">
          <span class="decision-tag ${tagClass}">${verdict.decision}</span>
          <span class="risk-tag ${riskClass}">RISK: ${verdict.risk_level}</span>
        </div>
        <span class="badge badge-cyan">${verdict.threat_category}</span>
      </div>
      <div class="verdict-rationale">
        <strong>Firewall Rationale:</strong> ${escapeHtml(verdict.rationale)}
      </div>
    </div>

    <!-- INDEPENDENT AUDITOR RESULT -->
    <div class="verification-audit-box">
      <div class="audit-box-header">
        <span class="audit-title">Independent State Verifier</span>
        <span class="audit-status-tag ${auditClass}">VERDICT: ${verdict.verification.status}</span>
      </div>
      <div class="audit-reason">
        <strong>Expected:</strong> ${verdict.verification.expected_outcome} | 
        <strong>Observed:</strong> ${verdict.verification.observed_outcome}<br>
        <strong>Auditor Proof:</strong> ${escapeHtml(verdict.verification.rationale)}
      </div>
    </div>

    <!-- SECURITY CHECKS GRID -->
    <div class="checks-grid">
      <div class="check-item">
        <span class="check-name">Input Validation</span>
        <span class="badge ${getCheckBadge(checks.input_validation)}">${checks.input_validation}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Threat Analysis</span>
        <span class="badge ${getCheckBadge(checks.threat_analysis)}">${checks.threat_analysis}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Authentication</span>
        <span class="badge ${getCheckBadge(checks.authentication)}">${checks.authentication}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Authorization</span>
        <span class="badge ${getCheckBadge(checks.authorization)}">${checks.authorization}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Per-Tx Limit</span>
        <span class="badge ${getCheckBadge(checks.transaction_limit)}">${checks.transaction_limit}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Daily Cumulative</span>
        <span class="badge ${getCheckBadge(checks.cumulative_limit)}">${checks.cumulative_limit}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Idempotency Key</span>
        <span class="badge ${getCheckBadge(checks.idempotency)}">${checks.idempotency}</span>
      </div>
      <div class="check-item">
        <span class="check-name">Execution Gate</span>
        <span class="badge ${verdict.execution.executed ? 'badge-passed' : 'badge-failed'}">
          ${verdict.execution.status}
        </span>
      </div>
    </div>

    <button class="btn btn-outline" style="width: 100%; justify-content: center;" onclick="openEvidenceModal('${verdict.test_id}')">
      <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      Inspect Cryptographic Evidence & Balance Snapshot Proof
    </button>
  `;
}

function getCheckBadge(status) {
  if (status === 'PASS') return 'badge-passed';
  if (status === 'FAIL') return 'badge-failed';
  if (status === 'REVIEW') return 'badge-inconclusive';
  return 'badge-skipped';
}

// ================= EVIDENCE REPORT MODAL =================
window.openEvidenceModal = async function(testId) {
  try {
    const res = await fetch(`/api/tests/${testId}/evidence`);
    if (!res.ok) throw new Error('Evidence report not found');
    const ev = await res.json();
    state.activeEvidence = ev;

    el.modalEvidenceTestId.textContent = ev.test_id;
    el.modalEvidenceTitle.textContent = `Audit Certificate: ${ev.test_id}`;

    // Balance diff table
    const pre = ev.pre_test_balances;
    const post = ev.post_test_balances;
    const diffRows = Object.keys(pre).map((accId) => {
      const preBal = pre[accId];
      const postBal = post[accId];
      const delta = Math.round((postBal - preBal) * 100) / 100;
      let deltaColor = 'var(--text-muted)';
      if (delta > 0) deltaColor = 'var(--green-success)';
      if (delta < 0) deltaColor = 'var(--red-danger)';

      return `
        <tr>
          <td><strong>${accId}</strong></td>
          <td>₹${preBal.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
          <td>₹${postBal.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
          <td style="color: ${deltaColor}; font-weight: 700;">
            ${delta > 0 ? '+' : ''}₹${delta.toLocaleString('en-IN', { minimumFractionDigits: 2 })}
          </td>
        </tr>
      `;
    }).join('');

    // Ledger transactions created
    const ledgerRows = ev.ledger_entries_created.length
      ? ev.ledger_entries_created.map((entry) => `
        <li><strong>TX ID:</strong> ${entry.transaction_id} | <strong>Amount:</strong> ₹${entry.amount} | <strong>Destination:</strong> ${entry.destination_account_id} | <strong>Status:</strong> ${entry.status}</li>
      `).join('')
      : '<em>No ledger records were created for this test (execution was completely blocked or read-only).</em>';

    el.modalEvidenceBody.innerHTML = `
      <div class="evidence-cert">
        <div class="cert-section">
          <div class="cert-section-title">Test Context & Input Inspection</div>
          <div class="cert-grid">
            <div>
              <div class="cert-field-label">Original Untrusted Request</div>
              <div class="cert-field-val" style="word-break: break-word;">${escapeHtml(ev.original_request)}</div>
            </div>
            <div>
              <div class="cert-field-label">Mode & Timestamp</div>
              <div class="cert-field-val">${ev.mode} | ${new Date(ev.timestamp).toLocaleString()}</div>
            </div>
            <div>
              <div class="cert-field-label">Threat Classification</div>
              <div class="cert-field-val">${ev.ai_analysis.threat_category} (${ev.ai_analysis.risk_level})</div>
            </div>
            <div>
              <div class="cert-field-label">Threat Analyzer Engine</div>
              <div class="cert-field-val">${ev.ai_analysis.analyzer_mode}</div>
            </div>
          </div>
        </div>

        <div class="cert-section">
          <div class="cert-section-title">Pre-Test vs Post-Test Balance Invariant Audit</div>
          <table class="diff-table">
            <thead>
              <tr>
                <th>Mock Account</th>
                <th>Pre-Test Balance</th>
                <th>Post-Test Balance</th>
                <th>Net Delta</th>
              </tr>
            </thead>
            <tbody>
              ${diffRows}
            </tbody>
          </table>
        </div>

        <div class="cert-section">
          <div class="cert-section-title">Ledger Records & Downstream Invariant</div>
          <div style="font-size: 0.82rem; color: var(--text-main); margin-bottom: 0.5rem;">
            ${ledgerRows}
          </div>
        </div>

        <div class="cert-section">
          <div class="cert-section-title">Independent Verifier Audit Verdict</div>
          <div style="font-size: 0.86rem; color: var(--text-bright); margin-bottom: 0.35rem;">
            <strong>Verification Result:</strong> <span class="badge ${ev.verification_result.status === 'PASS' ? 'badge-passed' : 'badge-failed'}">${ev.verification_result.status}</span>
          </div>
          <div style="font-size: 0.82rem; color: var(--text-main); line-height: 1.4;">
            ${escapeHtml(ev.verification_result.rationale)}
          </div>
        </div>
      </div>
    `;

    el.evidenceModal.style.display = 'flex';
  } catch (err) {
    showToast(`Failed to load evidence: ${err.message}`, 'danger');
  }
};

function downloadEvidenceJson() {
  if (!state.activeEvidence) return;
  const jsonStr = JSON.stringify(state.activeEvidence, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `evidence-${state.activeEvidence.test_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ================= MOCK BANK RENDERING =================
function renderMockBankView() {
  // Accounts
  el.accountsGrid.innerHTML = state.accounts.map((acc) => `
    <div class="account-card">
      <div class="account-card-top">
        <div>
          <div class="account-customer">${acc.customer_name}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${acc.account_type} ACCOUNT</div>
        </div>
        <span class="account-id-badge">${acc.account_id}</span>
      </div>
      <div class="account-balance-val">₹${acc.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</div>
      <div class="account-limits-box">
        <div><strong>Per-Transaction Ceiling:</strong> ₹${acc.per_tx_limit.toLocaleString('en-IN')}</div>
        <div><strong>Daily Cumulative Limit:</strong> ₹${acc.daily_limit.toLocaleString('en-IN')}</div>
        <div><strong>Saved Beneficiaries:</strong> ${acc.saved_beneficiaries.join(', ') || 'None'}</div>
      </div>
    </div>
  `).join('');

  // Ledger
  el.ledgerCountBadge.textContent = `${state.ledger.length} Transactions`;
  if (!state.ledger.length) {
    el.ledgerTableBody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No transactions recorded in ledger. Ledger is pristine.</td></tr>`;
    return;
  }

  el.ledgerTableBody.innerHTML = state.ledger.map((entry) => `
    <tr>
      <td><span style="font-family: var(--font-mono); color: var(--cyan-primary);">${entry.transaction_id}</span></td>
      <td>${new Date(entry.timestamp).toLocaleTimeString()}</td>
      <td>${entry.source_account_id}</td>
      <td>${entry.destination_account_id}</td>
      <td style="font-weight: 700;">₹${entry.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
      <td>${escapeHtml(entry.memo || '-')}</td>
      <td><span class="badge badge-passed">${entry.status}</span></td>
      <td><span class="badge badge-cyan">${entry.policy_decision || 'APPROVE'}</span></td>
      <td><span style="font-family: var(--font-mono); font-size: 0.72rem;">${entry.test_id || 'SETUP'}</span></td>
    </tr>
  `).join('');
}

// ================= RESET SANDBOX =================
async function executeResetSandbox() {
  try {
    const res = await fetch('/api/mock-bank/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        confirm: true,
        clear_ledger: el.resetClearLedger.checked,
        clear_evidence: el.resetClearEvidence.checked,
      }),
    });
    const data = await res.json();
    el.resetModal.style.display = 'none';

    await Promise.all([loadMockBankData(), loadAnalyticsData(), loadHistoryData()]);
    showToast('Mock Banking sandbox successfully reset to initial deterministic state.', 'success');
  } catch (err) {
    showToast(`Reset failed: ${err.message}`, 'danger');
  }
}

// ================= HISTORY & ANALYTICS RENDERING =================
function renderHistoryTable() {
  if (!state.history.length) {
    el.historyTableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No test records in audit history yet.</td></tr>`;
    return;
  }

  el.historyTableBody.innerHTML = state.history.map((row) => {
    let verifBadge = 'badge-passed';
    if (row.verification_status === 'FAIL') verifBadge = 'badge-failed';
    else if (row.verification_status === 'INCONCLUSIVE') verifBadge = 'badge-inconclusive';

    return `
      <tr>
        <td><strong style="font-family: var(--font-mono); color: var(--cyan-primary);">${row.test_id}</strong></td>
        <td>${new Date(row.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-outline">${row.mode}</span></td>
        <td>${row.threat_category}</td>
        <td><span class="badge ${row.verdict === 'BLOCK' ? 'badge-failed' : 'badge-passed'}">${row.verdict}</span></td>
        <td><span class="badge badge-outline">${row.execution_status}</span></td>
        <td><span class="badge ${verifBadge}">${row.verification_status}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="openEvidenceModal('${row.test_id}')">
            View Evidence
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function updateMetricsBanner(an) {
  el.metricTotalTests.textContent = an.total_tests;
  el.metricAttacksContained.textContent = an.attacks_contained;
  el.metricLegitProcessed.textContent = an.legitimate_processed;
  el.metricVerifFailures.textContent = an.verification_failures;
  el.metricInconclusive.textContent = an.inconclusive_tests;
  el.metricUnauthorizedExecuted.textContent = an.unauthorized_executed;

  el.metricSampleSize.textContent = `Denominator: ${an.tested_attack_sample_size} Attack Tests`;
  el.metricContainmentRate.textContent = `${an.containment_rate_percent}% Containment Rate`;
}

function renderAnalyticsView(an) {
  el.analyticsSummaryBox.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 0.85rem;">
      <div style="font-size: 0.95rem; color: var(--text-bright);">
        <strong>Attack Containment Rate:</strong> 
        <span style="font-size: 1.3rem; font-weight: 800; color: var(--green-success); margin-left: 0.5rem;">
          ${an.containment_rate_percent}%
        </span>
      </div>
      <p style="font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">
        Calculated strictly from <strong>${an.tested_attack_sample_size}</strong> verified attack simulations. 
        Inconclusive tests (${an.inconclusive_tests}) and benign requests (${an.legitimate_processed}) are strictly 
        segregated and excluded from the defense rate numerator.
      </p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; font-size: 0.82rem; margin-top: 0.5rem;">
        <div style="background: var(--bg-surface); padding: 0.75rem; border-radius: 6px; border: 1px solid var(--border-dim);">
          <div style="color: var(--text-muted);">Verified Contained Attacks</div>
          <div style="font-size: 1.2rem; font-weight: 700; color: var(--green-success);">${an.attacks_contained}</div>
        </div>
        <div style="background: var(--bg-surface); padding: 0.75rem; border-radius: 6px; border: 1px solid var(--border-dim);">
          <div style="color: var(--text-muted);">Unauthorized Ledger Breaches</div>
          <div style="font-size: 1.2rem; font-weight: 700; color: var(--red-danger);">${an.unauthorized_executed}</div>
        </div>
      </div>
    </div>
  `;

  // Bars
  const cats = an.threat_category_breakdown;
  const catKeys = Object.keys(cats);
  if (!catKeys.length) {
    el.categoryBarsContainer.innerHTML = '<p class="text-muted">No tests run yet.</p>';
    return;
  }

  const maxVal = Math.max(...Object.values(cats), 1);
  el.categoryBarsContainer.innerHTML = catKeys.map((k) => {
    const count = cats[k];
    const pct = Math.round((count / maxVal) * 100);
    return `
      <div style="margin-bottom: 0.85rem;">
        <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.3rem;">
          <span style="font-weight: 600;">${k}</span>
          <span style="color: var(--cyan-primary); font-family: var(--font-mono);">${count} tests</span>
        </div>
        <div style="background: var(--bg-surface); height: 8px; border-radius: 4px; overflow: hidden;">
          <div style="background: var(--cyan-primary); height: 100%; width: ${pct}%;"></div>
        </div>
      </div>
    `;
  }).join('');
}

// ================= TOASTS & UTILS =================
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'danger') toast.style.borderColor = 'var(--red-danger)';
  if (type === 'success') toast.style.borderColor = 'var(--green-success)';
  toast.textContent = message;

  el.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
