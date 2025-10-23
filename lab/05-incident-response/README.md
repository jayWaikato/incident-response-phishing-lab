
## 🔍 Incident Investigation

### Phase 10: Incident Response & Triage

**Objective:** Perform SOC analyst investigation and document findings

#### 10.1 Incident Overview

**Incidents Dashboard:**
- **Time Range:** 1 Week
- **Total Incidents:** 4

**Incident Breakdown:**

| # | Incident Name | ID | Tags | Severity | Investigation State | Categories | Impacted Assets | Active Alerts |
|---|---------------|----|----|----------|---------------------|------------|-----------------|---------------|
| 1 | Unfamiliar sign-in properties involving one user | 20 | - | 🟠 Medium | Initial access | 👤 internal threat | 0/1 |
| 2 | Atypical travel involving one user | 24 | Critical asset | 🟢 Low | Initial access | 👤 internal threat | 0/1 |
| 3 | api token involving one user | 17 | Critical asset | 🟢 Low | Suspicious activity | 👤 jay champaneri 🌐 Microsoft 365 | 5/5 |
| 4 | Unfamiliar sign-in properties involving one user | 21 | - | 🟠 Medium | Initial access | 👤 internal threat | 0/1 |

**Screenshot Reference:** `18-incidents-dashboard.png`

---

#### 10.2 Incident #1: Unfamiliar Sign-in Properties (Initial Detection)

**Incident Details:**
- **Incident ID:** 20
- **Severity:** Medium
- **Status:** Resolved
- **Priority:** Unassigned
- **Category:** Initial access
- **Impacted User:** `jayinternalthreat@studmemt.onmicrosoft.com`

**Alert Story:**

**Timeline:**
```
10/23/2025 11:23:42 PM - jayinternalthreat attempted to sign-in from IP address 20.124.88.102
```

**What Happened:**
Sign-in exhibited unfamiliar properties:
- **User name:** jayinternalthreat
- **IP address:** 20.124.88.102
- **Sign-in location:** Washington, Virginia, US
- **User Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0 OS/10.0.19044
- **Sign-in request ID:** b7d51d98-b580-48a2-8fac-9e2ba1ca1500

**Alert Triggered By:** Microsoft Entra ID Protection detection

**Screenshot Reference:** `19-incident-unfamiliar-signin-timeline.png`

---

**Alert Management:**

**Status:** Resolved  
**Assigned to:** jaychampaneri@studmemt.onmicrosoft.com  
**Classification:** True positive - Phishing  
**Comment:** "Remediated with password change"

**Screenshot Reference:** `20-alert-management-resolution.png`

---

#### 10.3 Incident #2: Atypical Travel Detection

**Incident Details:**
- **Incident ID:** 24
- **Name:** Atypical travel involving one user
- **Severity:** Low
- **Status:** Resolved
- **Tags:** Critical asset
- **Investigation State:** Initial access
- **Impacted User:** `jayinternalthreat`

**Attack Story - Incident Graph:**

**Network Topology:**
```
20.124.88.102 ←→ jayinternalthreat ←→ 161.29.226.90
  (Source IP)      (Compromised User)    (Destination IP)
```

**2 IP Addresses Involved:**
1. `161.29.226.90`
2. `20.124.88.102`

**Screenshot Reference:** `21-atypical-travel-incident-graph.png`

---

**Incident Summary:**

**Alerts and Categories:**
- **Active Alerts:** 0/1
- **Tactics:** 1 (Initial access)
- **Other Categories:** 0

**Scope:**
- **Top Impacted Assets:** None listed
- **Impacted Users:** 1 (internal threat)
- **Entity:** internal threat
- **Risk Level:** -

**Screenshot Reference:** `22-atypical-travel-summary.png`

---

**Incident Management:**

**Incident Name:** Atypical travel involving one user  
**Severity:** High (escalated from Low)  
**Incident Tags:** (Type to find or create tags)  
**Assign to:** jaychampaneri@studmemt.onmicrosoft.com  
**Status:** In Progress  
**Classification:** True positive - Compromised account

**Screenshot Reference:** `23-atypical-travel-management.png`

---

#### 10.4 Incident #3: API Token Suspicious Activity

**Incident Details:**
- **Incident ID:** 17
- **Name:** api token involving one user
- **Severity:** Low
- **Status:** New
- **Tags:** Critical asset
- **Investigation State:** Suspicious activity
- **Impacted Assets:** 
  - 👤 jay champaneri
  - 🌐 Microsoft 365
- **Active Alerts:** 5/5

**Screenshot Reference:** `24-api-token-incident.png`

---

### Phase 11: Root Cause Analysis

#### 11.1 Alert Deep Dive - Unfamiliar Sign-in Properties

**Investigation Focus:** Why did the alert trigger?

**This alert is triggered by a Microsoft Entra ID Protection detection:**

**Detection Logic:**
The alert evaluates past sign-in properties including:
- ASN (Autonomous System Number)
- Browser type
- Device characteristics
- IP address
- Geographic location
- EASId (Exchange ActiveSync ID)
- TenantIPSubnet

**Detection Trigger:**
Sign-ins with unfamiliar properties across multiple dimensions are flagged as potentially malicious.

**Screenshot Reference:** `25-alert-detection-explanation.png`

---

#### 11.2 Security Activities Timeline

**Chronological Event Sequence:**

**Oct 23, 2025:**
- **11:23:42 PM** - Initial unfamiliar sign-in detected
  - User: `jayinternalthreat`
  - IP: `20.124.88.102`
  - Location: Washington, Virginia, US
  - Detection: Unfamiliar ASN, Browser, Device, IP, Location, EASId, TenantIPSubnet

**Risky Sign-in Events (2 recorded):**
1. **11:24:36 PM** - Sign in | internal threat | 20.124.88.102 | Washington, Virginia, US | remediated
2. **11:24:29 PM** - Sign in | internal threat | 20.124.88.102 | Washington, Virginia, US | remediated

**Screenshot Reference:** `26-security-timeline.png`

---

## 🛡️ Triage & Response

### Phase 12: Incident Response Actions

#### 12.1 Alert Triage - Unfamiliar Sign-in

**Alert Classification:**
- **Status:** Resolved
- **Classification:** True positive - Phishing
- **Comment:** "Remediated with password change"

**Remediation Actions Taken:**
1. ✅ Confirmed malicious activity (token replay attack)
2. ✅ Forced password reset for `jayinternalthreat@studmemt.onmicrosoft.com`
3. ✅ Revoked all active sessions
4. ✅ Documented incident for threat intelligence

**Screenshot Reference:** `27-alert-triage-resolution.png`

---

#### 12.2 Atypical Travel Incident Response

**Incident Management:**
- **Severity:** Escalated to **High** (from Low)
- **Status:** In Progress
- **Assigned To:** jaychampaneri@studmemt.onmicrosoft.com
- **Classification:** True positive - Compromised account

**Response Actions:**
1. 🔍 Investigated source and destination IPs
2. 🔍 Analyzed geographic impossibility (travel time inconsistency)
3. ✅ Confirmed account compromise
4. ✅ Initiated incident response procedures

**Screenshot Reference:** `28-atypical-travel-response.png`

---
