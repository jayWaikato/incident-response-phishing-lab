# incident-response-phishing-lab

# Microsoft 365 Phishing Attack Simulation & Incident Response Lab

## 🎯 Project Overview

This project demonstrates an end-to-end phishing attack simulation and incident response workflow using Microsoft security tools. The lab simulates a real-world credential phishing attack, token theft, and subsequent security operations center (SOC) analyst investigation and triage.

---

## 🔧 Technologies & Tools Used

### Cloud Infrastructure
- **Microsoft Azure** - Cloud platform and VM hosting
- **Azure Virtual Machine** - Simulated user endpoint (Kali Linux)

### Security & Identity
- **Microsoft Entra ID P2** (formerly Azure AD) - Identity and access management
- **Microsoft 365 E5** - Enterprise productivity and security suite
- **Microsoft Defender for Office 365** - Email and collaboration protection
- **Microsoft Defender for Cloud Apps** - Cloud access security broker (CASB)

### Attack Simulation
- **Evilginx** - Advanced phishing framework for man-in-the-middle attacks
- **O365 Phishlet** - Pre-configured phishing template for Microsoft 365

### Detection & Response
- **Microsoft Defender Portal** - Unified security operations platform
- **Entra ID Protection** - Risk-based conditional access and identity protection
- **Microsoft Sentinel** - SIEM and SOAR capabilities

---

## 📋 Table of Contents

1. [Lab Architecture](#lab-architecture)
2. [Environment Setup](#environment-setup)
3. [Attack Simulation](#attack-simulation)
4. [Detection & Alerts](#detection--alerts)
5. [Incident Investigation](#incident-investigation)
6. [Triage & Response](#triage--response)
7. [Key Findings](#key-findings)
8. [Skills Demonstrated](#skills-demonstrated)
9. [Lessons Learned](#lessons-learned)
10. [Future Enhancements](#future-enhancements)

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ATTACK INFRASTRUCTURE                   │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Kali Linux VM (Azure)                              │    │
│  │  - Evilginx Framework                               │    │
│  │  - O365 Phishlet                                    │    │
│  │  - Token Capture Server                             │    │
│  └────────────────┬───────────────────────────────────┘    │
└────────────────────┼────────────────────────────────────────┘
                     │
                     │ Phishing Link
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    TARGET ENVIRONMENT                        │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Victim User (jayinternalthreat@studmemt.com)      │    │
│  │  - Enters credentials on fake O365 page             │    │
│  │  - Session token captured                           │    │
│  └────────────────┬───────────────────────────────────┘    │
└────────────────────┼────────────────────────────────────────┘
                     │
                     │ Token Replay Attack
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                 MICROSOFT 365 ENVIRONMENT                    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Microsoft Entra ID (studmemt.onmicrosoft.com)     │    │
│  │  ├─ Conditional Access Policies                     │    │
│  │  ├─ Identity Protection                             │    │
│  │  └─ Risk-based Detection                            │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Microsoft Defender for Office 365                  │    │
│  │  ├─ Anti-phishing Policies                          │    │
│  │  ├─ Safe Links                                      │    │
│  │  └─ Safe Attachments                                │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────┼────────────────────────────────────────┘
                     │
                     │ Security Alerts
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  SECURITY OPERATIONS CENTER                  │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Microsoft Defender Portal                          │    │
│  │  ├─ Alert Monitoring                                │    │
│  │  ├─ Incident Management                             │    │
│  │  ├─ Threat Investigation                            │    │
│  │  └─ Response Actions                                │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---








### Phase 13: Post-Incident Activities

#### 13.1 Lessons Learned

**Detection Strengths:**
- ✅ Microsoft Entra ID Protection successfully identified anomalous sign-in patterns
- ✅ Multi-layered detection (location, device, IP, ASN changes)
- ✅ Automated risk scoring accelerated triage
- ✅ Defender for Cloud Apps detected API token activity

**Detection Gaps:**
- ⚠️ Initial phishing email delivered (though later quarantined)
- ⚠️ Session token replay not immediately blocked
- ⚠️ User completed authentication before alert generated

---

#### 13.2 Remediation Recommendations

**Immediate Actions:**
1. ✅ **Password Reset:** Force change for compromised account
2. ✅ **Session Revocation:** Invalidate all active tokens
3. ✅ **MFA Verification:** Re-register authentication methods
4. ✅ **Mailbox Audit:** Review sent items and rule changes

**Short-term Improvements:**
1. 🎯 **Enhanced Conditional Access:**
   - Require compliant devices for sensitive accounts
   - Block legacy authentication protocols
   - Implement location-based access restrictions

2. 🎯 **Phishing-Resistant MFA:**
   - Deploy FIDO2 security keys or Windows Hello for Business
   - Disable SMS/phone call MFA methods for privileged accounts

3. 🎯 **User Education:**
   - Conduct phishing awareness training
   - Implement simulated phishing campaigns
   - Educate on token theft risks

**Long-term Strategy:**
1. 📊 **Zero Trust Architecture:**
   - Implement continuous verification
   - Enforce least-privilege access
   - Deploy device compliance policies

2. 📊 **Advanced Threat Hunting:**
   - Create custom KQL queries for token replay detection
   - Correlate sign-in logs with network traffic patterns
   - Baseline user behavior for anomaly detection

---

### Security Posture Assessment

**Strengths:**
- ✅ Comprehensive logging and monitoring
- ✅ Automated threat detection and alerting
- ✅ Integration between identity and email security
- ✅ User risk policies with automatic remediation

**Weaknesses:**
- ⚠️ Session token replay not immediately blocked
- ⚠️ Phishing email initially bypassed filters
- ⚠️ Limited visibility into attack infrastructure
- ⚠️ Manual triage required for complex incidents

---

## 💪 Skills Demonstrated

### Technical Competencies

#### Offensive Security
- ✅ Phishing infrastructure deployment (Evilginx)
- ✅ Man-in-the-middle attack execution
- ✅ Token-based authentication exploitation
- ✅ Social engineering simulation

#### Defensive Security
- ✅ SIEM/SOAR platform configuration (Microsoft Defender)
- ✅ Identity protection and conditional access policies
- ✅ Email security controls (anti-phishing, Safe Links)
- ✅ Cloud application security (Defender for Cloud Apps)

#### Incident Response
- ✅ Alert triage and prioritization
- ✅ Incident investigation and root cause analysis
- ✅ Timeline reconstruction and evidence collection
- ✅ Remediation action planning and execution

#### Cloud Security
- ✅ Azure infrastructure deployment and management
- ✅ Microsoft 365 security stack configuration
- ✅ Entra ID (Azure AD) identity governance
- ✅ Multi-product integration and orchestration

---

## 📚 Lessons Learned

### What Went Well

1. **Comprehensive Detection Coverage:**
   - Multiple security products provided overlapping detection capabilities
   - No single point of failure in threat detection

2. **Realistic Attack Simulation:**
   - Evilginx accurately mimics real-world phishing campaigns
   - Token theft demonstrated modern attack techniques used by threat actors

3. **Rapid Alert Generation:**
   - Security tools generated alerts within seconds
   - Automated risk scoring enabled efficient triage

---

### Challenges Encountered

1. **Azure VM Configuration:**
   - Initial networking issues with Evilginx setup
   - Required proper DNS and SSL certificate configuration
   - Azure firewall rules needed adjustment for phishing server

2. **License Management:**
   - E5 licensing complexity across multiple products
   - Understanding which features require specific licenses
   - Assignment delays for newly created users

3. **Alert Correlation:**
   - Multiple alerts for single incident required manual correlation
   - Determining true positive vs. false positive needed experience
   - Understanding detection logic required deep product knowledge

4. **Policy Tuning:**
   - Balancing security controls with usability
   - Avoiding alert fatigue with too many low-severity alerts
   - Fine-tuning phishing thresholds to catch threats without blocking legitimate email

---

#### Security Best Practices Learned

1. **Defense in Depth:**
   - No single control will stop all attacks
   - Layered security provides redundancy and resilience
   - Email security + identity protection + CASB = comprehensive coverage

2. **Phishing-Resistant Authentication:**
   - Traditional MFA (SMS, TOTP) is vulnerable to phishing
   - FIDO2/WebAuthn hardware keys resist session hijacking
   - Certificate-based authentication provides stronger assurance

3. **Behavioral Analytics:**
   - User behavior baseline is critical for anomaly detection
   - Geographic location tracking detects impossible travel
   - Device fingerprinting identifies suspicious authentication attempts

4. **Automated Response:**
   - Manual response is too slow for modern threats
   - Risk-based conditional access blocks threats in real-time
   - Automated remediation reduces attacker dwell time

---

## 🚀 Future Enhancements

### Planned Improvements

#### Phase 14: Advanced Detection Engineering (Coming Soon)

**Microsoft Sentinel Integration:**
- Deploy Sentinel workspace for advanced SIEM capabilities
- Create custom KQL queries for threat hunting
- Build automated playbooks for incident response
- Develop correlation rules across multiple data sources

**Custom Detection Rules:**
```kql
// Example: Detect token replay attacks
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0" // Successful sign-in
| where RiskState == "atRisk"
| where DeviceDetail.deviceId != UserPrincipalName // Unfamiliar device
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
```

---

#### Phase 15: Incident Response Playbook Development

**Planned Playbooks:**

1. **Phishing Email Response:**
   - Email analysis and triage steps
   - Mailbox investigation procedures
   - User communication templates
   - Remediation checklists

2. **Compromised Account Response:**
   - Account lockdown procedures
   - Password reset and MFA re-enrollment
   - Session revocation steps
   - Mailbox forensics workflow

3. **Token Theft Response:**
   - Token revocation procedures
   - Session hijacking detection
   - Continuous access evaluation enforcement
   - Post-incident recovery steps

---

#### Phase 16: Threat Intelligence Integration

**Planned Enhancements:**
- Integrate MITRE ATT&CK framework mappings
- Document Tactics, Techniques, and Procedures (TTPs)
- Create threat actor profiles based on observed behaviors
- Build indicators of compromise (IOC) database

**MITRE ATT&CK Mapping (Initial Analysis):**
- **TA0001** - Initial Access: Phishing (T1566)
- **TA0006** - Credential Access: Steal Web Session Cookie (T1539)
- **TA0005** - Defense Evasion: Use Alternate Authentication Material (T1550)
- **TA0009** - Collection: Email Collection (T1114)

---

#### Phase 17: Automation & Orchestration

**Planned Automation:**
1. **Automated Threat Response:**
   - Logic Apps for automated remediation
   - Power Automate workflows for user notifications
   - API-driven response actions

2. **Security Orchestration:**
   - SOAR playbook development
   - Multi-product automation workflows
   - Incident enrichment automation

3. **Reporting Automation:**
   - Automated incident reports
   - Executive dashboard creation
   - Compliance reporting workflows

---

## 📊 Project Statistics

### Environment Metrics

| Metric | Value |
|--------|-------|
| **Duration** | October 2025 |
| **Cloud Resources** | 1 Azure VM, 304 user identities |
| **Security Products** | 5 (Entra ID P2, M365 E5, Defender for Office 365, Defender for Cloud Apps, Defender Portal) |
| **Policies Configured** | 7+ (Anti-phishing, Safe Links, Conditional Access, User Risk, Activity Monitoring) |
| **Total Incidents** | 4 |
| **Alerts Generated** | 10+ |
| **Users Impacted** | 1 (jayinternalthreat@studmemt.onmicrosoft.com) |

---

### Detection Coverage

| Detection Type | Status | Product |
|----------------|--------|---------|
| Unfamiliar Sign-in Properties | ✅ Detected | Entra ID Protection |
| Atypical Travel | ✅ Detected | Entra ID Protection |
| Phishing Email | ✅ Detected | Defender for Office 365 |
| API Token Activity | ✅ Detected | Defender for Cloud Apps |
| Session Hijacking | ⚠️ Partial | Entra ID Protection (post-authentication) |
| Risky Sign-in | ✅ Detected | Entra ID Protection |

---

### Response Metrics

| Response Action | Time to Execute | Status |
|-----------------|-----------------|--------|
| Alert Triage | < 5 minutes | ✅ Completed |
| Incident Investigation | 15-30 minutes | ✅ Completed |
| Password Reset | < 2 minutes | ✅ Completed |
| Session Revocation | < 1 minute | ✅ Completed |
| Documentation | 1-2 hours | ✅ Completed |

---

## 🛠️ Repository Structure

```
phishing-lab-project/
│
├── README.md                          # This file - complete project documentation
├── LICENSE                            # MIT License
│
├── screenshots/                       # All lab screenshots organized by phase
│   ├── 01-environment-setup/
│   │   ├── 01-azure-vm-setup.png
│   │   ├── 02-m365-users.png
│   │   ├── 03-identity-protection-users-at-risk.png
│   │   └── 04-user-risk-policy.png
│   │
│   ├── 02-security-configuration/
│   │   ├── 05-preset-security-policies.png
│   │   ├── 06-anti-phishing-policy.png
│   │   ├── 07-safe-links-policy.png
│   │   └── 08-defender-alerts.png
│   │
│   ├── 03-attack-simulation/
│   │   ├── 11-evilginx-azure-token.png
│   │   └── (additional attack screenshots)
│   │
│   ├── 04-detection-alerts/
│   │   ├── 12-unfamiliar-signin-alert.png
│   │   ├── 13-risky-signin-timeline.png
│   │   ├── 14-api-token-alerts.png
│   │   └── (additional detection screenshots)
│   │
│   └── 05-incident-response/
│       ├── 18-incidents-dashboard.png
│       ├── 19-incident-unfamiliar-signin-timeline.png
│       └── (additional response screenshots)
│
├── docs/                              # Additional documentation (future)
│   ├── playbooks/                     # Incident response playbooks
│   ├── kql-queries/                   # Sentinel/Defender KQL queries
│   └── threat-intelligence/           # IOCs and threat reports
│
└── scripts/                           # Automation scripts (future)
    ├── detection-rules/
    └── response-automation/
```

---

## 📖 How to Use This Repository

### For Security Professionals

1. **Review Attack Methodology:**
   - Study the Evilginx setup process
   - Understand token-based authentication attacks
   - Learn modern phishing techniques

2. **Replicate Detection:**
   - Use this as a blueprint for your own lab
   - Configure similar policies in your environment
   - Test your organization's detection capabilities

3. **Develop Response Procedures:**
   - Adapt triage workflows to your organization
   - Build incident response playbooks
   - Train SOC analysts using this scenario

---

### For Hiring Managers & Recruiters

**This project demonstrates:**

✅ **Hands-on Technical Skills:**
- Cloud infrastructure deployment (Azure)
- Security product configuration (Microsoft security stack)
- Attack simulation and execution
- Log analysis and investigation

✅ **SOC Analyst Competencies:**
- Alert triage and prioritization
- Incident investigation methodology
- Root cause analysis
- Remediation planning

✅ **Communication Skills:**
- Clear technical documentation
- Visual representation of complex data
- Structured incident narratives
- Actionable recommendations

✅ **Proactive Learning:**
- Self-directed skill development
- Initiative to build practical experience
- Continuous improvement mindset
- Investment in career development

---

## 🔗 Resources & References

### Microsoft Documentation

- [Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/)
- [Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/)
- [Microsoft Defender Portal](https://learn.microsoft.com/en-us/defender-xdr/)
- [Conditional Access Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)

### Security Tools

- [Evilginx Framework](https://github.com/kgretzky/evilginx2)
- [Message Header Analyzer](https://mha.azurewebsites.net/)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)

### Industry Standards

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Incident Response Process](https://www.sans.org/white-papers/)

---

## ⚖️ Legal Disclaimer

**Important Notice:**

This project was conducted in a controlled, authorized lab environment for educational and skill development purposes only. All activities were performed on infrastructure and accounts that I own and control.

**Ethical Guidelines:**
- ✅ All testing conducted on personal Azure subscription
- ✅ No unauthorized access to third-party systems
- ✅ Educational purpose only - demonstrating defensive security capabilities
- ✅ Complies with applicable laws and regulations

**Warning:**
Unauthorized access to computer systems is illegal. Tools and techniques demonstrated in this project should only be used:
- In authorized penetration testing engagements
- In personal lab environments
- For educational purposes with proper authorization
- With explicit written permission from system owners

**The author assumes no liability for misuse of information contained in this repository.**

---

## 📅 Project Timeline

```
October 2025
│
├── Week 1: Environment Setup
│   ├── Azure infrastructure deployment
│   ├── Microsoft 365 licensing
│   ├── User account creation
│   └── Initial security configuration
│
├── Week 2: Security Stack Configuration
│   ├── Entra ID Protection policies
│   ├── Defender for Office 365 setup
│   ├── Anti-phishing policies
│   ├── Safe Links configuration
│   └── Defender Portal setup
│
├── Week 3: Attack Simulation
│   ├── Evilginx deployment
│   ├── O365 phishlet configuration
│   ├── Credential harvesting
│   └── Token replay attack
│
└── Week 4: Detection, Investigation & Documentation
    ├── Alert analysis
    ├── Incident triage
    ├── Root cause investigation
    ├── Remediation actions
    └── Project documentation
```

---

## 🎯 Project Objectives - Status

| Objective | Status | Notes |
|-----------|--------|-------|
| Deploy cloud lab environment | ✅ Complete | Azure VM + M365 tenant |
| Configure Microsoft security stack | ✅ Complete | 5 products integrated |
| Simulate phishing attack | ✅ Complete | Evilginx with O365 phishlet |
| Capture authentication tokens | ✅ Complete | Session hijacking successful |
| Generate security alerts | ✅ Complete | 10+ alerts across products |
| Investigate incidents | ✅ Complete | 4 incidents triaged |
| Document findings | ✅ Complete | Comprehensive GitHub repo |
| Create response playbooks | 🔄 In Progress | Coming in Phase 14 |
| Develop KQL queries | 📅 Planned | Sentinel integration Phase 15 |
|
