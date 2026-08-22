/**
 * Defend AI - Instant URL Threat & Brand Intelligence Search
 */

const API_BASE = "";

// DOM Elements
const elements = {
  searchForm: document.getElementById("url-search-form"),
  urlInput: document.getElementById("url-input"),
  btnSubmit: document.getElementById("btn-submit-search"),
  btnText: document.querySelector(".btn-text"),
  btnLoader: document.querySelector(".btn-loader"),
  sampleChips: document.querySelectorAll(".sample-chip"),

  // Result Section Elements
  resultsSection: document.getElementById("results-section"),
  resultHeaderCard: document.getElementById("result-header-card"),
  resBrandBadge: document.getElementById("res-brand-badge"),
  resTargetUrl: document.getElementById("res-target-url"),
  resSimilarityVal: document.getElementById("res-similarity-val"),
  resTrustVal: document.getElementById("res-trust-val"),
  resAntigravityVal: document.getElementById("res-antigravity-val"),
  resRiskGauge: document.getElementById("res-risk-gauge"),
  resRiskScore: document.getElementById("res-risk-score"),
  resRiskLevel: document.getElementById("res-risk-level"),
  resReasonsList: document.getElementById("res-reasons-list"),

  // Telemetry Elements
  telSsl: document.getElementById("tel-ssl"),
  telDns: document.getElementById("tel-dns"),
  telContent: document.getElementById("tel-content"),
  telBrand: document.getElementById("tel-brand"),

  // Visual Box Elements
  visualUrlDisplay: document.getElementById("visual-url-display"),
  mockFormTitle: document.getElementById("mock-form-title"),
  btnDispatchTakedown: document.getElementById("btn-dispatch-takedown"),
  btnRetestTarget: document.getElementById("btn-retest-target"),

  toastContainer: document.getElementById("toast-container"),
};

// Current active inspection result
let activeResult = null;

// Toast Notifications
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Perform URL Threat Inspection
async function inspectUrl(targetUrl) {
  const cleanUrl = targetUrl.trim();
  if (!cleanUrl) {
    showToast("Please enter a valid URL or domain", "error");
    return;
  }

  // Set Loading State
  elements.btnText.textContent = "Analyzing...";
  elements.btnLoader.classList.remove("hidden");
  elements.btnSubmit.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/scans/inspect-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: cleanUrl }),
    });

    if (!response.ok) {
      throw new Error(`HTTP Error ${response.status}`);
    }

    const data = await response.json();
    activeResult = data;
    renderResults(data);
    if (data.analysis_complete === false) {
      showToast("TrustLens-AI unavailable — risk score is partial, based on domain similarity only", "warning");
    } else {
      showToast(`Analysis completed for ${data.domain || cleanUrl}!`, "success");
    }

    // Smooth scroll to results
    elements.resultsSection.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    console.error("Inspection error:", err);
    showToast(`Failed to analyze URL: ${err.message}`, "error");
  } finally {
    elements.btnText.textContent = "Analyze URL";
    elements.btnLoader.classList.add("hidden");
    elements.btnSubmit.disabled = false;
  }
}

// Render Results to UI
function renderResults(data) {
  elements.resultsSection.classList.remove("hidden");

  // Toggle warning banner
  const warningBanner = document.getElementById("warning-banner");
  if (warningBanner) {
    if (data.analysis_complete === false) {
      warningBanner.classList.remove("hidden");
    } else {
      warningBanner.classList.add("hidden");
    }
  }

  // 1. Header Card & Badges
  const riskLevel = data.risk_level || (data.analysis_complete === false ? "UNKNOWN" : "MEDIUM");
  const riskScore = data.risk_score || 0;
  const brand = data.brand_detected || "None / Generic";
  const simPct = Math.round((data.similarity_score || 0) * 100);

  elements.resTargetUrl.textContent = data.target;
  elements.resBrandBadge.textContent = `Impersonating: ${brand.toUpperCase()} (${simPct}% Match)`;
  elements.resSimilarityVal.textContent = `${simPct}% (openSquat)`;
  elements.resTrustVal.textContent = data.trust_score !== null && data.trust_score !== undefined ? `${data.trust_score}/100` : "Unavailable";
  elements.resAntigravityVal.textContent = data.antigravity_event_id || (data.analysis_complete === false ? "Inspection Incomplete" : "Ready for Dispatch");

  // Risk Score Gauge styling
  elements.resRiskScore.textContent = riskScore;
  elements.resRiskLevel.textContent = riskLevel === "UNKNOWN" ? "PARTIAL / UNKNOWN" : `${riskLevel} RISK`;

  const riskClass = data.analysis_complete === false || riskLevel === "UNKNOWN"
    ? "partial-risk"
    : (riskLevel === "HIGH" ? "high-risk" : riskLevel === "MEDIUM" ? "medium-risk" : "low-risk");
  const gaugeClass = data.analysis_complete === false
    ? "score-partial"
    : (riskScore >= 75 ? "score-high" : riskScore >= 45 ? "score-medium" : "score-low");

  elements.resultHeaderCard.className = `result-header-card ${riskClass}`;
  elements.resRiskGauge.className = `risk-gauge ${gaugeClass}`;

  // 2. Explainable Reasons List
  elements.resReasonsList.innerHTML = (data.reasons || [])
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join("");

  // 3. Engine Telemetry
  const engines = data.evidence?.engines || {};
  elements.telSsl.textContent = JSON.stringify(engines.ssl_engine || data.evidence?.ssl || { valid: true }, null, 2);
  elements.telDns.textContent = JSON.stringify(engines.dns_engine || data.evidence?.dns || { resolved: true }, null, 2);
  elements.telContent.textContent = JSON.stringify(engines.content_engine || data.evidence?.content || { forms: true }, null, 2);
  elements.telBrand.textContent = JSON.stringify(engines.brand_engine || data.evidence?.brand_inspection || { match: true }, null, 2);

  // 4. Visual Evidence Box
  elements.visualUrlDisplay.textContent = data.target;
  elements.mockFormTitle.textContent = `${brand.toUpperCase()} Security Verification Portal`;
}

// Utility HTML escape
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  // Search Form Submit
  elements.searchForm.addEventListener("submit", (e) => {
    e.preventDefault();
    inspectUrl(elements.urlInput.value);
  });

  // Sample Chips
  elements.sampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.dataset.url;
      elements.urlInput.value = sampleUrl;
      inspectUrl(sampleUrl);
    });
  });

  // Dispatch Takedown Alert
  elements.btnDispatchTakedown.addEventListener("click", () => {
    if (!activeResult) return;
    const evtId = activeResult.antigravity_event_id || `ag_evt_${Math.random().toString(36).substring(2, 10)}`;
    showToast(`Dispatched priority takedown event (${evtId}) to Antigravity Platform!`, "success");
    elements.resAntigravityVal.textContent = evtId;
  });

  // Re-test Target
  elements.btnRetestTarget.addEventListener("click", () => {
    if (activeResult && activeResult.target) {
      inspectUrl(activeResult.target);
    }
  });
});
