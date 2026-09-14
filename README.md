# Project Beacon: Automated Cyber Underwriting Proof of Technology (PoT)

### A Strategic Integration between The Hartford (HIG) and Google Cloud

Project Beacon modernizes cyber insurance underwriting for small commercial businesses by replacing friction-heavy manual questionnaires (and the dreaded drop-off call wall) with real-time, authenticated security telemetry from Google Workspace and live DNS validation.

---

## Key Features

1. **Pixel-Accurate Hartford Flow**:
   - Mirrors The Hartford's actual cyber insurance onboarding flow:
     - **Landing Page**: `thehartford.com/cyber-insurance` with "Quote Today".
     - **Step 1 (Basics)**: Business structure, registered business name (`Foremy corp`), reCAPTCHA.
     - **Step 2 (Location)**: Location type, street address, and multi-location validation.
     - **Step 3 (Business & Contact)**: Non-profit toggle, industry categorization, employee count, owner contact.
     - **Step 4 (Coverages)**: Coverage selection highlighting Cyber Liability & Data Breach.
     - **Step 5 (The Paradigm Shift)**: Compares the traditional **"Call us to finish your quote (1-800-581-3703)"** drop-off wall against the new **"Auto-Verify with Google Workspace"** 10-second fast-track.
2. **Ephemeral Posture Telemetry**:
   - **Multi-Factor Authentication (2SV)**: Checks organization-wide enforcement via Google Admin SDK Reports & Directory APIs.
   - **Email Spoofing Defense**: Real-time live DNS resolution of SPF (`v=spf1`) and DMARC (`_dmarc.<domain>`, `p=reject`/`quarantine`).
   - **Cloud Data Loss Prevention (DLP)**: Validates active PII/PCI inspection rules.
   - **Google Vault & Retention**: Confirms immutable audit logging and recovery posture.
3. **Actuarial Rating & "Fix-to-Save" Engine**:
   - **Preferred Risk (Tier 1)**: Instant approval up to $2,000,000 policy with a **25% premium discount** ($8,500 $\rightarrow$ $6,375/year).
   - **Conditional Quote (Tier 2)**: Approves standard rate with actionable remediation advice (e.g. *"Tighten DMARC from 'none' to 'quarantine' to save an extra $680/year"*).
   - **High Risk / Declined (Tier 3)**: Un-enforced MFA results in an immediate decline, directly addressing the #1 cause of ransomware losses.
4. **Zero-Retention Guarantee**:
   - Processes all technical telemetry in memory.
   - Generates a signed SHA-256 attestation token with zero retention of customer infrastructure settings or employee logs.
5. **Interactive Underwriter & What-If Studio**:
   - Built-in slide-out studio for stakeholders to test canned personas, live DNS probes on real domains (e.g. `thehartford.com`), and dynamic actuarial sliders.

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Application
```bash
python3 app.py
```
Or with uvicorn:
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Open in Browser
Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) to start the demo.

---

## Demo Script for Stakeholders

1. **Slide 2 Landing**: Start at the Hartford Cyber Insurance landing page and click **"Quote Today"**.
2. **Steps 1–4**: Walk through the standard small business application fields.
3. **Step 5 The Reveal**: Point out the left card—the traditional "Call 1-800-581-3703" wall where 70%+ of SMB cyber quotes drop off due to 45-question questionnaires.
4. **The Project Beacon Fast-Track**: Click **"Auto-Verify with Google"** on the right card.
5. **Instant Underwriting**: Watch the live telemetry probe verify MFA, SPF/DMARC, DLP, and Vault in 3 seconds, instantly approving a $2,000,000 policy with a 25% Preferred Risk discount ($6,375/year).
6. **Live Audience Interaction**: Open the **"Underwriter Telemetry & What-If Studio"** at the bottom right. Type in the client's actual corporate domain to demonstrate real-time DNS telemetry resolution live!
