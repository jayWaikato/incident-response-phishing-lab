# Custom Sentinel Detection Rules & Automated Response

## 🎯 Overview

This section documents custom-built analytics rules deployed in Microsoft Sentinel to detect phishing attacks, credential theft, and session hijacking. These rules integrate with automated response playbooks to enable rapid incident response.

## 🔍 Rule 1: Possible AiTM Phishing Attempt Against Microsoft Entra ID

### Purpose
Detects Adversary-in-the-Middle (AiTM) phishing attacks where threat actors hijack user sign-in sessions to bypass MFA through session cookie theft and replay attacks.

### Detection Logic

**What It Detects:**
This rule correlates two critical data points:
1. **High-risk successful sign-ins** to Microsoft Entra ID
2. **Network connections to the same IP** immediately before authentication

This pattern indicates a user connected to a phishing site (step 2), entered credentials which were stolen, and the attacker then used those credentials to sign in from the same IP (step 1).

### KQL Query

```kusto
let time_threshold = 10m;
let RiskySignins = materialize (SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0  // Successful sign-ins only
| where RiskLevelDuringSignIn =~ "high" or RiskLevelAggregated =~ "high"
| extend SignInTime = TimeGenerated, 
    Name=split(UserPrincipalName, "@")[0], 
    UPNSuffix=split(UserPrincipalName, "@")[1]
);
let ips = todynamic(toscalar(RiskySignins | summarize make_list(IPAddress)));
RiskySignins
| join kind=inner (_Im_WebSession(starttime=ago(1d), ipaddr_has_any_prefix=ips, eventresult="Success", pack=True))
    on $left.IPAddress == $right.DstIpAddr
| where EventStartTime < TimeGenerated
| extend TimeDelta = TimeGenerated - EventStartTime
| where TimeDelta <= time_threshold  // Connection within 10 minutes before sign-in
| extend NetworkEventStartTime = EventStartTime, NetworkEventEndTime = EventEndTime
| extend SrcUsername = column_ifexists("SrcUsername", "Unknown")
| project-reorder SignInTime, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed, 
    DeviceDetail, LocationDetails, NetworkLocationDetails, RiskEventTypes, UserAgent, 
    NetworkEventStartTime, NetworkEventEndTime, SrcIpAddr, DstIpAddr, DstPortNumber, 
    Dvc, DvcHostname, SrcBytes, NetworkProtocol, SrcUsername
```

### Query Breakdown

#### Step 1: Identify Risky Sign-ins
```kusto
let RiskySignins = materialize (SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0  // Only successful authentications
| where RiskLevelDuringSignIn =~ "high" or RiskLevelAggregated =~ "high"
```

**What this captures:**
- ✅ Successful authentications (ResultType == 0)
- ✅ High risk score from Entra ID Protection
- ✅ Last 24 hours of activity

**Risk indicators include:**
- Unfamiliar location
- Anonymous IP/VPN usage
- Atypical travel patterns
- Leaked credentials detection
- Malware-linked IP addresses

#### Step 2: Extract IP Addresses
```kusto
let ips = todynamic(toscalar(RiskySignins | summarize make_list(IPAddress)));
```

**Purpose:** Creates a dynamic list of all risky IP addresses to search for in network logs

#### Step 3: Correlate with Network Activity
```kusto
| join kind=inner (_Im_WebSession(starttime=ago(1d), ipaddr_has_any_prefix=ips, eventresult="Success", pack=True))
    on $left.IPAddress == $right.DstIpAddr
```

**What this does:**
- Searches web session logs for connections to the risky IPs
- `_Im_WebSession` is the normalized web activity parser
- Joins on matching IP addresses

#### Step 4: Time-based Correlation
```kusto
| where EventStartTime < TimeGenerated
| extend TimeDelta = TimeGenerated - EventStartTime
| where TimeDelta <= time_threshold  // 10 minutes
```

**Critical logic:**
- Network connection (`EventStartTime`) must happen **before** authentication (`TimeGenerated`)
- Time difference must be ≤ 10 minutes
- This proves the user visited the phishing site shortly before the attacker authenticated

### Attack Scenario Detected

```
Timeline of AiTM Phishing Attack:

T+0m    User receives phishing email
T+2m    User clicks malicious link → visits phishing site at 20.124.88.102
        [Network connection logged: user → 20.124.88.102]
        
T+3m    User enters credentials on fake login page
        Attacker's Evilginx captures:
        - Username & password
        - Session cookies
        - MFA tokens
        
T+4m    Attacker replays stolen session from 20.124.88.102
        [High-risk sign-in logged: unusual IP, suspicious characteristics]
        
        ⚠️ DETECTION TRIGGERED ⚠️
        Correlation found: Network connection + Risky sign-in from same IP
```

### Rule Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| **Query Frequency** | 1 hour | How often the rule runs |
| **Query Period** | 1 day | Lookback window for data |
| **Trigger Threshold** | > 0 results | Alert on any match |
| **Suppression** | Disabled | Generate alert for each detection |

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| **Initial Access** | T1078 | T1078.004 | Valid Accounts: Cloud Accounts |
| **Credential Access** | T1557 | - | Adversary-in-the-Middle |
| **Defense Evasion** | T1111 | - | Two-Factor Authentication Interception |

### Incident Configuration

**Grouping Strategy:**
- **Enabled:** Yes
- **Reopen Closed Incidents:** Yes (if new evidence within 5 hours)
- **Lookback Duration:** 5 hours
- **Matching Method:** All Entities (groups by user and IP)

**Why this matters:** Multiple alerts for the same user/IP are grouped into one incident for efficient investigation.

### Alert Customization

**Alert Title Format:**
```
Possible AiTM Phishing Attempt Against {{UserPrincipalName}} From {{IPAddress}}
```

**Example Output:**
```
Possible AiTM Phishing Attempt Against jayinternalthreat@studmemt.onmicrosoft.com From 20.124.88.102
```

### Entity Mapping

Entities extracted for investigation:
- **Account:** User principal name (split into Name and UPNSuffix)
- **IP Address:** Source IP of the attack

### Real-World Detection Example

**Lab Incident Detected:**
```
Alert Generated: Nov 2, 2025 14:57 PM
User: jayinternalthreat@studmemt.onmicrosoft.com
IP Address: 20.124.88.102
Risk Level: High

Timeline:
• 23:24:36 - Network connection to phishing site (Evilginx)
• 23:24:39 - Credentials entered, token captured
• 23:24:42 - Attacker authenticates using stolen session
• 23:24:57 - Alert triggered by Sentinel

Time Delta: 21 seconds (within 10-minute threshold)
Status: True Positive - Confirmed AiTM attack
```

### Screenshots

![AiTM Detection Flow](screenshots/detection-rules/aitm-phishing-detection.png)
*Network correlation showing user connection to phishing site followed by suspicious authentication*

![Account Blocked](screenshots/detection-rules/account-blocked-notification.png)
*Automated response: Account blocked after detection, requiring identity verification*

---

## 📧 Rule 2: High-Risk Phishing Email Delivered

### Purpose
Detects phishing emails that bypass initial filtering and get delivered to user mailboxes, enabling rapid response before users interact with malicious content.

### Detection Logic

**Multi-Factor Analysis:**
This rule uses multiple indicators to identify phishing emails:

1. **Suspicious Subject Lines** containing urgency keywords
2. **Sender Address Anomalies** (e.g., numeric characters in legitimate-looking domains)
3. **URL Count** (multiple links often indicate phishing)
4. **Delivery Status** (actually delivered to inbox, not just blocked)

### KQL Query

```kusto
EmailEvents
| where TimeGenerated > ago(5m)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered", "DeliveredAsSpam")
| where Subject has_any ("urgent", "verify", "suspended", "confirm", "unusual activity")
    or SenderFromAddress matches regex @"[0-9]{4,}"
| where RecipientEmailAddress endswith "@studmemt.onmicrosoft.com"
| join kind=leftouter (
    EmailUrlInfo
    | where TimeGenerated > ago(5m)
    | summarize URLCount = count() by NetworkMessageId
) on NetworkMessageId
| where URLCount > 2 or isnotnull(URLCount)
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, URLCount
```

### Query Breakdown

#### Detection Indicator 1: Urgency Keywords
```kusto
| where Subject has_any ("urgent", "verify", "suspended", "confirm", "unusual activity")
```

**Common phishing subject lines:**
- ❌ "URGENT: Your account will be suspended"
- ❌ "Verify your identity immediately"
- ❌ "Unusual activity detected - confirm now"
- ❌ "Action required: Update your password"

#### Detection Indicator 2: Suspicious Sender Address
```kusto
or SenderFromAddress matches regex @"[0-9]{4,}"
```

**What this catches:**
- Emails from addresses like: `admin1234@company.com`
- Automated phishing campaigns using numbered accounts
- Compromised accounts with numeric suffixes

#### Detection Indicator 3: Multiple URLs
```kusto
| join kind=leftouter (
    EmailUrlInfo
    | summarize URLCount = count() by NetworkMessageId
) on NetworkMessageId
| where URLCount > 2
```

**Why this matters:**
- Legitimate emails typically have 0-1 links
- Phishing emails often include:
  - Malicious login link
  - Fake "unsubscribe" link
  - Tracking pixels
  - Secondary fallback links

### Rule Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| **Query Frequency** | 5 minutes | Near real-time detection |
| **Query Period** | 5 minutes | Match frequency for efficiency |
| **Severity** | 🔴 High | Direct threat to users |
| **Trigger Threshold** | > 0 | Alert on any match |

### MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| **Initial Access** | T1566 | Phishing |

### Alert Customization

**Alert Title:**
```
Alert from email
```

**Alert Description:**
```
Alert from {{RecipientEmailAddress}} generated at {{TimeGenerated}}
```

**Custom Details:**
- **Email Subject:** Extracted for quick assessment

### Incident Configuration

- **Create Incident:** Yes
- **Grouping:** By all entities (email, sender, recipient)
- **Lookback:** 5 hours
- **Reopen Closed:** Yes

### Use Case: Proactive Defense

**Scenario 1: Email Delivered to Quarantine**
```
Status: DeliveredAsSpam
Action: Alert generated but low priority (already isolated)
Response: Monitor for similar campaigns
```

**Scenario 2: Email Delivered to Inbox**
```
Status: Delivered
Action: HIGH PRIORITY - User can interact with email
Response: 
1. Immediate alert to SOC
2. Trigger playbook to:
   - Soft-delete email from mailbox
   - Send warning to user
   - Create incident for investigation
```

### Real-World Detection

**Lab Example:**
```
Time: Oct 23, 2025 12:05:25 PM
From: jaychampaneri1234@gmail.com
To: jayinternalthreat@studmemt.onmicrosoft.com
Subject: Re:
URLs: 1
Status: Quarantined (caught post-delivery)

Detection Triggered: ✅
Reason: Sender contains numeric pattern
Action: Email quarantined, incident created
```

### Screenshots

![Email Quarantine Alert](screenshots/detection-rules/high-risk-phishing-email.png)
*Phishing email detected and quarantined with "Phish" classification*

---

## 🛡️ Rule 3: Detect Risky Sign-in and Take Action

### Purpose
Monitors for authentication attempts from anonymized or suspicious IP addresses (VPNs, Tor, proxies) which are common in phishing attacks trying to hide attacker location.

### Detection Logic

Leverages Entra ID's built-in risk detection for anonymous IP addresses, which includes:
- Tor exit nodes
- Commercial VPN services
- Anonymous proxies
- Hosting provider IP ranges (cloud VMs)

### KQL Query

```kusto
AADUserRiskEvents 
| where RiskEventType == "anonymizedIPAddress"
```

### Query Explanation

**Data Source:** `AADUserRiskEvents`
- Contains all risk detections from Entra ID Protection
- Includes machine learning-based anomaly detection
- Real-time and offline risk calculations

**Risk Event Type:** `anonymizedIPAddress`

**Detected Scenarios:**
| Anonymization Method | Detection | Risk Level |
|---------------------|-----------|------------|
| **Tor Network** | Tor exit node IP detected | High |
| **Commercial VPN** | NordVPN, ExpressVPN, etc. | Medium |
| **Proxy Services** | Anonymous proxy detected | Medium |
| **Cloud VMs** | AWS/Azure/GCP instances | Low-Medium |

### Why This Matters

**Legitimate Use Cases (Low Risk):**
- Remote workers using corporate VPN
- Privacy-conscious employees
- Travel to regions requiring VPN

**Malicious Use Cases (High Risk):**
- Attackers hiding true location after phishing
- Credential stuffing attacks
- Session hijacking with stolen tokens
- Lateral movement attempts

### Rule Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| **Query Frequency** | 5 minutes | Near real-time monitoring |
| **Query Period** | 5 minutes | Matches frequency |
| **Severity** | 🟠 Medium | Requires investigation |
| **Trigger Threshold** | > 0 | Alert on any detection |

### MITRE ATT&CK Mapping

| Tactic | Description |
|--------|-------------|
| **Initial Access** | Use of anonymous infrastructure to hide attack origin |

### Entity Mapping

Three entity types extracted:
1. **Account:** User display name
2. **IP Address:** Anonymous IP address used
3. **Host:** Source system

### Automated Response Actions

**When this alert fires:**

1. **Conditional Access Policy Triggered:**
   - Require MFA re-verification
   - Block sign-in if risk too high
   - Require compliant device

2. **User Risk Policy Activated:**
   ```
   If RiskLevel == High:
       → Force password change
       → Revoke all sessions
       → Notify security team
   ```

3. **Playbook Actions** (from screenshots):
   - Display "Your account is at risk" message
   - Require identity verification via authenticator app
   - Force password update
   - Block access until verification complete