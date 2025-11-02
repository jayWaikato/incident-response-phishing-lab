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

