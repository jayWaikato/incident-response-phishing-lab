## ⚙️ Environment Setup

### Phase 1: Azure Infrastructure Deployment

**Objective:** Create isolated cloud environment for security testing

1. **Created Azure Subscription**
   - Provisioned dedicated resource group for security lab
   - Deployed Ubuntu/Kali Linux VM for attack simulation

2. **Configured Virtual Machine**
   - VM Name: `phishlog (1) - 20.124.88.102:3389`
   - Operating System: Kali Linux 2024.1
   - Purpose: Host Evilginx phishing framework

**Screenshot Reference:** `01-azure-vm-setup.png`

---

### Phase 2: Microsoft 365 Security Stack Configuration

**Objective:** Deploy enterprise-grade security tools for detection and response

#### 2.1 License Procurement & Assignment
- ✅ **Microsoft Entra ID P2** - Advanced identity protection and conditional access
- ✅ **Microsoft 365 E5** - Full security and compliance suite
- ✅ **Defender for Cloud Apps** - Cloud application security broker
- ✅ **Defender for Office 365** - Advanced email threat protection

#### 2.2 User Account Creation
Created test users to simulate organizational structure:
- `guest@studmemt.onmicrosoft.com` - Standard user account
- `jayinternalthreat@studmemt.onmicrosoft.com` - **Target victim account**
- `jaychampaneri@studmemt.onmicrosoft.com` - SOC analyst account
- Additional accounts for realistic environment

**Screenshot Reference:** `02-m365-users.png`

#### 2.3 Identity Protection Configuration

**Entra ID Protection Settings:**
- Configured user risk policies (Low and above threshold)
- Enabled automatic password change remediation
- Set up alert notifications for Global Administrators

**Screenshot Reference:** `03-identity-protection-users-at-risk.png`

**Risk Policy Configuration:**
- Policy Name: "User risk remediation policy"
- Assignments: All users
- User Risk Level: Low and above
- Access Control: Require password change
- Policy Enforcement: Enabled

**Screenshot Reference:** `04-user-risk-policy.png`

---
