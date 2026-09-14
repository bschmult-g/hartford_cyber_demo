/**
 * Project Beacon - The Hartford Cyber Underwriting PoT
 * Frontend Controller
 */

let currentStep = 0;
let currentDomain = "foremycorp.com";
let currentOrgName = "Foremy corp";
let activePreset = null;

// Initialize on load
document.addEventListener("DOMContentLoaded", () => {
  syncDomainFromEmail();
  checkRedirectSession();
});

async function checkRedirectSession() {
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get("session_id");
  if (sessionId) {
    try {
      const resp = await fetch(`/api/session/${sessionId}`);
      if (resp.ok) {
        const data = await resp.json();
        navigateToStep(5);
        renderQuoteResult(data);
      }
    } catch (e) {
      console.error("Failed to load redirect session:", e);
    }
  }
}

function startQuoteFlow() {
  navigateToStep(1);
}

function navigateToStep(stepNumber) {
  currentStep = stepNumber;

  // Hide all views
  const views = [
    document.getElementById("viewLanding"),
    document.getElementById("viewStep1"),
    document.getElementById("viewStep2"),
    document.getElementById("viewStep3"),
    document.getElementById("viewStep4"),
    document.getElementById("viewStep5")
  ];
  views.forEach(v => {
    if (v) v.classList.remove("active");
  });

  const stepperNav = document.getElementById("stepperNav");

  if (stepNumber === 0) {
    views[0].classList.add("active");
    stepperNav.style.display = "none";
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }

  stepperNav.style.display = "flex";
  views[stepNumber].classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });

  // Update Stepper Indicators
  const step1 = document.getElementById("stepIndicator1");
  const step2 = document.getElementById("stepIndicator2");
  const step3 = document.getElementById("stepIndicator3");
  const step4 = document.getElementById("stepIndicator4");

  [step1, step2, step3, step4].forEach(el => {
    if (el) {
      el.classList.remove("active");
      el.classList.remove("completed");
    }
  });

  if (stepNumber >= 1 && stepNumber <= 3) {
    step1.classList.add("active");
  } else if (stepNumber === 4) {
    step1.classList.add("completed");
    step2.classList.add("active");
  } else if (stepNumber === 5) {
    step1.classList.add("completed");
    step2.classList.add("completed");
    step3.classList.add("completed");
    step4.classList.add("active");
    
    // Update domain displayed in step 5
    syncDomainFromEmail();
  }
}

function setSegment(btn, groupName) {
  const parent = btn.parentElement;
  const buttons = parent.querySelectorAll(".segmented-btn");
  buttons.forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
}

function syncDomainFromEmail() {
  const emailInput = document.getElementById("ownerEmail");
  const registeredNameInput = document.getElementById("registeredBusinessName");
  
  if (registeredNameInput && registeredNameInput.value) {
    currentOrgName = registeredNameInput.value.trim();
  }

  if (emailInput && emailInput.value && emailInput.value.includes("@")) {
    const parts = emailInput.value.split("@");
    if (parts.length > 1 && parts[1].includes(".")) {
      currentDomain = parts[1].trim().toLowerCase();
    }
  }

  const detectedDomainDisplay = document.getElementById("detectedDomainDisplay");
  if (detectedDomainDisplay) {
    detectedDomainDisplay.textContent = currentDomain;
  }
  const scanDomainName = document.getElementById("scanDomainName");
  if (scanDomainName) {
    scanDomainName.textContent = currentDomain;
  }
  const oauthModalDomain = document.getElementById("oauthModalDomain");
  if (oauthModalDomain) {
    oauthModalDomain.textContent = currentDomain;
  }
}

/* ==================== REAL GOOGLE OAUTH & TELEMETRY FLOW ==================== */

let oauthPopup = null;

async function triggerGoogleOAuth() {
  syncDomainFromEmail();

  const scanBox = document.getElementById("scanProgressBox");
  const quoteCard = document.getElementById("quoteResultCard");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");

  verifyBtn.style.display = "none";
  quoteCard.classList.remove("active");
  scanBox.classList.add("active");

  const s1 = document.getElementById("scanStep1");
  const s2 = document.getElementById("scanStep2");
  const s3 = document.getElementById("scanStep3");
  const s4 = document.getElementById("scanStep4");

  // Reset steps
  [s1, s2, s3, s4].forEach(s => {
    s.classList.remove("done");
    const sp = s.querySelector(".scan-spinner");
    if (sp) sp.style.display = "inline-block";
  });

  s1.querySelector("span").textContent = "Requesting Google OAuth 2.0 authorization URL...";
  s2.querySelector("span").textContent = "Awaiting Super Admin consent on accounts.google.com...";
  s3.querySelector("span").textContent = "Querying live Google Workspace Admin SDK & Directory APIs...";
  s4.querySelector("span").textContent = "Resolving live DNS (SPF/DMARC) & computing actuarial quote...";

  try {
    const urlResp = await fetch(`/api/auth/google/url?domain=${encodeURIComponent(currentDomain)}&organization_name=${encodeURIComponent(currentOrgName)}`);
    const authData = await urlResp.json();
    
    if (!authData.auth_url) {
      throw new Error(authData.detail || "Failed to generate Google OAuth URL");
    }

    markStepDone(s1, "Google OAuth 2.0 Endpoints Initialized");

    // Open real Google OAuth in a popup window
    const width = 540;
    const height = 680;
    const left = Math.max(0, (window.innerWidth - width) / 2 + window.screenX);
    const top = Math.max(0, (window.innerHeight - height) / 2 + window.screenY);

    oauthPopup = window.open(
      authData.auth_url,
      "google_oauth_beacon",
      `width=${width},height=${height},top=${top},left=${left},status=no,resizable=yes`
    );

    if (!oauthPopup || oauthPopup.closed || typeof oauthPopup.closed === "undefined") {
      // Popup was blocked by browser; fallback to direct navigation
      console.warn("Popup blocked. Redirecting current window directly to Google OAuth.");
      window.location.href = authData.auth_url;
      return;
    }

    // Set up message listener for the popup response
    const handleAuthMessage = (event) => {
      if (event.origin !== window.location.origin) return;

      if (event.data && event.data.type === "BEACON_OAUTH_SUCCESS") {
        window.removeEventListener("message", handleAuthMessage);
        markStepDone(s2, "Super Admin Identity Authenticated via Google");
        markStepDone(s3, "Google Workspace Security Posture Successfully Extracted");
        markStepDone(s4, "Live DNS Verified & Cryptographic Attestation Issued");

        setTimeout(() => {
          scanBox.classList.remove("active");
          renderQuoteResult(event.data.payload);
        }, 600);
      } else if (event.data && event.data.type === "BEACON_OAUTH_ERROR") {
        window.removeEventListener("message", handleAuthMessage);
        scanBox.classList.remove("active");
        verifyBtn.style.display = "flex";
        alert("Google Verification Error: " + (event.data.error || "Authentication failed"));
      }
    };

    window.addEventListener("message", handleAuthMessage);

    // Watch for unexpected popup closure
    const popupCheckTimer = setInterval(() => {
      if (oauthPopup && oauthPopup.closed) {
        clearInterval(popupCheckTimer);
        setTimeout(() => {
          if (scanBox.classList.contains("active") && !quoteCard.classList.contains("active")) {
            scanBox.classList.remove("active");
            verifyBtn.style.display = "flex";
          }
        }, 1500);
      }
    }, 1000);

  } catch (err) {
    console.error("OAuth init failed:", err);
    scanBox.classList.remove("active");
    verifyBtn.style.display = "flex";
    alert("Could not start Google Verification: " + err.message);
  }
}

function markStepDone(element, text) {
  element.classList.add("done");
  const spinner = element.querySelector(".scan-spinner");
  if (spinner) spinner.style.display = "none";
  const span = element.querySelector("span");
  if (span) span.textContent = `✓ ${text}`;
}

function renderQuoteResult(data) {
  const quoteCard = document.getElementById("quoteResultCard");
  const tierBadge = document.getElementById("quoteTierBadge");
  const quoteDecision = document.getElementById("quoteDecision");
  const summaryText = document.getElementById("quoteSummaryText");
  const annualPrice = document.getElementById("quoteAnnualPrice");
  const monthlyPrice = document.getElementById("quoteMonthlyPrice");
  const discountTag = document.getElementById("quoteDiscountPct");
  const attestToken = document.getElementById("attestToken");
  const attestHash = document.getElementById("attestHash");

  const rating = data.rating;
  const attest = data.attestation;

  tierBadge.className = "";
  if (rating.decision === "APPROVED") {
    tierBadge.classList.add("badge-preferred");
    tierBadge.textContent = rating.tier_display || "PREFERRED RISK (Tier 1)";
    quoteDecision.textContent = "APPROVED INSTANTLY";
    quoteDecision.style.color = "#166534";
  } else if (rating.decision === "CONDITIONAL_APPROVAL") {
    tierBadge.classList.add("badge-conditional");
    tierBadge.textContent = rating.tier_display || "CONDITIONAL QUOTE";
    quoteDecision.textContent = "CONDITIONAL APPROVAL";
    quoteDecision.style.color = "#92400E";
  } else {
    tierBadge.classList.add("badge-declined");
    tierBadge.textContent = rating.tier_display || "DECLINED";
    quoteDecision.textContent = "DECLINED (HIGH RISK)";
    quoteDecision.style.color = "#991B1B";
  }

  summaryText.textContent = rating.summary;

  if (rating.final_annual_premium) {
    annualPrice.innerHTML = `$${rating.final_annual_premium.toLocaleString()}<span style="font-size:14px; font-weight:500;">/yr</span>`;
    monthlyPrice.innerHTML = `$${rating.final_monthly_premium.toLocaleString()}<span style="font-size:14px; font-weight:500;">/mo</span>`;
    discountTag.textContent = `Saved ${rating.total_discount_pct}% (-$${rating.discount_amount.toLocaleString()})`;
    discountTag.style.display = "block";
  } else {
    annualPrice.innerHTML = `N/A`;
    monthlyPrice.innerHTML = `N/A`;
    discountTag.style.display = "none";
  }

  if (attest) {
    attestToken.textContent = attest.policy_attestation_token;
    attestHash.textContent = attest.sha256_fingerprint;
  }

  quoteCard.classList.add("active");
  const verifyBtn = document.getElementById("btnTriggerGoogleVerify");
  verifyBtn.style.display = "flex";
}

function bindPolicy() {
  alert(`Policy bound successfully for ${currentOrgName}!\nPolicy #: HIG-CYBER-2026-${Math.floor(100000 + Math.random() * 900000)}\nCertificate issued ephemerally under zero-retention guarantee.`);
}

/* ==================== STUDIO DRAWER & WHAT-IF ==================== */

function toggleStudioDrawer() {
  const drawer = document.getElementById("studioDrawer");
  drawer.classList.toggle("open");
}

function loadDemoScenario(domain) {
  activePreset = domain;
  currentDomain = domain;
  
  if (domain === "foremycorp.com") {
    currentOrgName = "Foremy corp";
    document.getElementById("ownerEmail").value = "sarah@foremycorp.com";
  } else if (domain === "partialcompliance.com") {
    currentOrgName = "Acme Distribution LLC";
    document.getElementById("ownerEmail").value = "it@partialcompliance.com";
  } else if (domain === "vulnerableretail.com") {
    currentOrgName = "Legacy Retail Boutique";
    document.getElementById("ownerEmail").value = "admin@vulnerableretail.com";
  }

  syncDomainFromEmail();
  navigateToStep(5);
  toggleStudioDrawer();
  confirmOAuthConsent();
}

async function runLiveDnsCheck() {
  const input = document.getElementById("liveDnsDomainInput");
  const resultsDiv = document.getElementById("liveDnsResults");
  const domain = input.value.trim();

  if (!domain) return;

  resultsDiv.style.display = "block";
  resultsDiv.innerHTML = `<span style="color:#2563EB;">Querying live DNS for ${escapeHtml(domain)}...</span>`;

  try {
    const resp = await fetch(`/api/dns-live-check?domain=${encodeURIComponent(domain)}`);
    const data = await resp.json();
    const p = data.dns_posture;

    let spfBadge = p.spf_present ? `<span style="color:#166534; font-weight:bold;">✓ PRESENT</span>` : `<span style="color:#991B1B; font-weight:bold;">✕ MISSING</span>`;
    let dmarcBadge = p.dmarc_policy !== "missing" ? `<span style="color:#166534; font-weight:bold;">✓ p=${escapeHtml(p.dmarc_policy)}</span>` : `<span style="color:#991B1B; font-weight:bold;">✕ MISSING</span>`;

    resultsDiv.innerHTML = `
      <div style="font-weight:700; margin-bottom:4px; color:#111827;">Live Telemetry for ${escapeHtml(domain)}:</div>
      <div>SPF Record: ${spfBadge}</div>
      <div style="font-size:10px; color:#6B7280; font-family:monospace; margin-bottom:4px;">${escapeHtml(p.spf_val || 'None detected')}</div>
      <div>DMARC Policy: ${dmarcBadge}</div>
      <div style="font-size:10px; color:#6B7280; font-family:monospace;">${escapeHtml(p.dmarc_val || 'None detected')}</div>
    `;
  } catch (err) {
    resultsDiv.innerHTML = `<span style="color:#991B1B;">DNS query failed.</span>`;
  }
}

async function runWhatIfSimulation() {
  const mfa = document.getElementById("whatifMfa").checked;
  const dmarc = document.getElementById("whatifDmarc").value;
  const dlp = document.getElementById("whatifDlp").checked;
  const vault = document.getElementById("whatifVault").checked;

  const payload = {
    mfa_enforced: mfa,
    mfa_enrolled_pct: mfa ? 100.0 : 20.0,
    spf_valid: true,
    dmarc_policy: dmarc,
    dlp_rules_active: dlp,
    vault_retention_active: vault
  };

  try {
    const resp = await fetch("/api/simulate-what-if", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    const r = data.rating;

    const tag = document.getElementById("whatifDecisionTag");
    const rate = document.getElementById("whatifRateTag");
    const summary = document.getElementById("whatifSummaryTag");

    if (r.decision === "APPROVED") {
      tag.textContent = "APPROVED - PREFERRED RISK";
      tag.style.color = "#166534";
      rate.textContent = `$${r.final_annual_premium.toLocaleString()}/yr`;
      summary.textContent = `25% Preferred Discount applied. Instant issuance.`;
    } else if (r.decision === "CONDITIONAL_APPROVAL") {
      tag.textContent = "CONDITIONAL APPROVAL";
      tag.style.color = "#B45309";
      rate.textContent = `$${r.final_annual_premium.toLocaleString()}/yr`;
      summary.textContent = `Standard rate. Save up to $1,275/yr by tightening DMARC and DLP.`;
    } else {
      tag.textContent = "DECLINED (HIGH RISK)";
      tag.style.color = "#991B1B";
      rate.textContent = "INELIGIBLE";
      summary.textContent = "Un-enforced MFA is an auto-decline due to ransomware exposure.";
    }
  } catch (err) {
    console.error("Simulation error:", err);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

/* ==================== CUSTOMER TRANSPARENCY MODAL CONTROLLER ==================== */

function openTransparencyModal(defaultTab = 'tabApis') {
  const modal = document.getElementById("transparencyModal");
  if (modal) {
    modal.style.display = "flex";
    switchTransparencyTab(defaultTab);
  }
}

function closeTransparencyModal() {
  const modal = document.getElementById("transparencyModal");
  if (modal) {
    modal.style.display = "none";
  }
}

function handleModalOverlayClick(event) {
  if (event.target && event.target.id === "transparencyModal") {
    closeTransparencyModal();
  }
}

function switchTransparencyTab(tabId) {
  const tabBtns = [
    { id: 'tabApis', btnId: 'btnTabApis' },
    { id: 'tabPrivacy', btnId: 'btnTabPrivacy' },
    { id: 'tabCrypto', btnId: 'btnTabCrypto' }
  ];

  tabBtns.forEach(t => {
    const tabEl = document.getElementById(t.id);
    const btnEl = document.getElementById(t.btnId);

    if (tabEl) {
      if (t.id === tabId) {
        tabEl.classList.add("active");
      } else {
        tabEl.classList.remove("active");
      }
    }

    if (btnEl) {
      if (t.id === tabId) {
        btnEl.classList.add("active");
      } else {
        btnEl.classList.remove("active");
      }
    }
  });
}
