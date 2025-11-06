
### Lab Detection Example

![](sign-in-again.png)


**Account at Risk**
```
Account: jaychampaneri@studmemt.onmicrosoft.com
Status: Your account is at risk
Message: "We've detected suspicious activity on your account"
Action Required: Verify identity
```

![](account-at-risk.png)

**Account Blocked**
```
Account: jayinternalthreat@studmemt.onmicrosoft.com
Status: Your account is blocked
Message: "Sorry, the organization you are trying to access restricts at-risk users"
Action: Contact admin / Learn more
```

![](blocked.png)

**MFA Challenge**
```
Account: jaychampaneri@studmemt.onmicrosoft.com
Action: Enter code from authenticator app
Purpose: Identity verification before access granted
```

![](mfa.png)

**Forced Password Change**
```
Account: jaychampaneri@studmemt.onmicrosoft.com
Message: "Since someone else may have access to your account, you need to choose a new password"
Required Fields:
- Current password
- New password
- Confirm password
```

![](change-password.png)


### Incident Analysis

```
Multiple "Anonymous IP address" alerts visible
Severity: Mixed (High and Medium)
Status: Some resolved, some in progress
Automation: Linked to incidents
- Alert linked to incident #29
- Alert linked to incident #30
- Auto-assigned to jaychampaneri@studmemt.onmicrosoft.com
```

![](automation-action-in-incident.png)


**Automation Actions:**
- Auto-Handle Confirmed Phishing playbook executed
- Status changed from "New" to "In progress"
- Automatic assignment to security analyst


## 🤖 Automated Response Integration

### Playbook Workflow

```mermaid
graph TD
    A[Detection Rule Fires] --> B{Risk Level?}
    B -->|High| C[Block Account Immediately]
    B -->|Medium| D[Require MFA Re-auth]
    B -->|Low| E[Log & Monitor]
    
    C --> F[Force Password Reset]
    D --> G[Identity Verification]
    
    F --> H[Revoke All Sessions]
    G --> H
    
    H --> I[Create Sentinel Incident]
    I --> J[Notify SOC Team]
    J --> K[Manual Investigation]
```