## 🎯 Query 2: IdentityInfo Enrichment - User Context & Blast Radius Analysis

### Purpose
This query enriches authentication events with comprehensive user identity context, including role assignments, group memberships, and organizational hierarchy. Critical for understanding the potential impact (blast radius) of compromised accounts.

### The Problem
When investigating a phishing incident, you need to answer:
- What privileges does this compromised user have?
- What systems can they access?
- How severe is this breach?
- Who is their manager (for notification)?

Basic sign-in logs don't include this context.

### The Solution

```kusto
IdentityInfo
| where TimeGenerated > ago(10d)
| extend 
    // Parse assigned roles from JSON format
    ParsedRoles = iff(isnotempty(AssignedRoles) 
        and AssignedRoles != "[]"
        , parse_json(AssignedRoles)
        , dynamic([]))
    // Parse group memberships from JSON format
    , ParsedGroups = iff(isnotempty(GroupMembership) 
        and GroupMembership != "[]"
        , parse_json(GroupMembership)
        , dynamic([]))
    // Check for privileged roles
    , IsAdmin = iff(isnotempty(AssignedRoles) 
        and AssignedRoles != "[]"
        , true, false),
    IsPrivilegedRole = iff(
        AssignedRoles has_any("Global Administrator"
            , "Privileged Role Administrator", "User Administrator"
            , "SharePoint Administrator", "Exchange Administrator"
            , "Hybrid Identity Administrator", "Application Administrator"
            , "Cloud Application Administrator")
            , true, false
    ),
    // Check for privileged group memberships
    IsInPrivilegedGroup = iff(
        GroupMembership has_any("AdminAgents"
        , "Azure AD Joined Device Local Administrators"
        , "Directory Synchronization Accounts"
        , "Domain Admins", "Enterprise Admins"
        , "Schema Admins", "Key Admins")
        , true, false
    ),
    Department = Department
    , JobTitle = JobTitle
    , Manager = Manager
| summarize arg_max(TimeGenerated, *) by AccountObjectId;
```

### Deep Dive Explanation

#### Section 1: JSON Parsing
```kusto
ParsedRoles = iff(isnotempty(AssignedRoles) 
    and AssignedRoles != "[]"
    , parse_json(AssignedRoles)
    , dynamic([]))
```

**What it does:**
- `AssignedRoles` in IdentityInfo is stored as a JSON string like `["Global Administrator", "User Administrator"]`
- This converts it to a proper array for easier querying
- Returns empty array `dynamic([])` if no roles assigned

**Why it matters:**
- Enables counting roles: `array_length(ParsedRoles)`
- Allows checking specific roles: `ParsedRoles has "Global Administrator"`
- Facilitates intersection operations with privilege lists

#### Section 2: Administrative Role Detection
```kusto
IsPrivilegedRole = iff(
    AssignedRoles has_any("Global Administrator"
        , "Privileged Role Administrator", "User Administrator"
        , "SharePoint Administrator", "Exchange Administrator"
        , "Hybrid Identity Administrator", "Application Administrator"
        , "Cloud Application Administrator")
        , true, false
)
```

**What it does:**
- Creates a boolean flag for high-impact administrative roles
- Uses `has_any()` for efficient multi-value matching

**Privileged Roles Detected:**
| Role | Risk Level | Why It Matters |
|------|------------|----------------|
| **Global Administrator** | 🔴 Critical | Full tenant control - can do anything |
| **Privileged Role Administrator** | 🔴 Critical | Can assign ANY role including Global Admin |
| **User Administrator** | 🟠 High | Can reset passwords, modify users |
| **SharePoint/Exchange Admin** | 🟠 High | Access to all organizational data |
| **Application Administrator** | 🟠 High | Can create service principals, access secrets |
| **Hybrid Identity Administrator** | 🟠 High | Controls on-prem to cloud sync |

**Why it matters:**
- Compromised admin = organization-wide breach
- Triggers different response procedures
- Changes incident severity classification

#### Section 3: Privileged Group Detection
```kusto
IsInPrivilegedGroup = iff(
    GroupMembership has_any("AdminAgents"
    , "Azure AD Joined Device Local Administrators"
    , "Directory Synchronization Accounts"
    , "Domain Admins", "Enterprise Admins"
    , "Schema Admins", "Key Admins")
    , true, false
)
```

**What it does:**
- Detects membership in groups that grant elevated access
- Covers both cloud (Entra ID) and hybrid (AD) environments

**High-Risk Groups:**
| Group | Environment | Access Level |
|-------|-------------|--------------|
| **Domain Admins** | On-Premises AD | Complete domain control |
| **Enterprise Admins** | AD Forest | Multi-domain administrative access |
| **Schema Admins** | AD Forest | Can modify Active Directory schema |
| **Key Admins** | AD/Entra | Manage authentication keys and certificates |
| **Directory Synchronization Accounts** | Hybrid | AD Connect sync accounts |
| **AdminAgents** | Defender | Can manage security policies |

**Why it matters:**
- Group membership often overlooked in initial triage
- Can grant equivalent or greater access than direct role assignment
- Hybrid environment visibility (cloud + on-prem)

#### Section 4: Most Recent Data Selection
```kusto
| summarize arg_max(TimeGenerated, *) by AccountObjectId;
```

**What it does:**
- `arg_max()` returns the most recent record for each user
- Groups by `AccountObjectId` (unique user identifier)
- Asterisk (*) means "keep all columns from that record"

**Why it matters:**
- Identity data changes over time (role assignments, group memberships)
- Using stale data leads to incorrect blast radius assessment
- 10-day lookback ensures recent but complete data

### Practical Application: Phishing Incident Triage

**Scenario:** Alert fires for suspicious sign-in by `jayinternalthreat@studmemt.onmicrosoft.com`

```kusto
// Step 1: Get enriched identity context
let CompromisedUser = "jayinternalthreat@studmemt.onmicrosoft.com";
let IdentityContext = IdentityInfo
    | where TimeGenerated > ago(10d)
    | extend 
        ParsedRoles = parse_json(AssignedRoles),
        IsPrivilegedRole = AssignedRoles has_any("Global Administrator", "Privileged Role Administrator")
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | where AccountUPN == CompromisedUser;

// Step 2: Join with suspicious sign-ins
SigninLogs
| where UserPrincipalName == CompromisedUser
| where RiskLevelDuringSignIn == "high"
| join kind=inner IdentityContext on $left.UserId == $right.AccountObjectId
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    IsPrivilegedRole,
    ParsedRoles,
    Manager, // For incident notification
    Department // For impact assessment
```

**Output shows:**
- ✅ User has no admin roles → **Lower priority** incident
- ❌ User is Global Admin → **Critical priority** - escalate immediately
- 📧 Manager = "Caroline Curtis" → Send notification
- 🏢 Department = "Engineering" → Potential access to source code

### Blast Radius Severity Classification

```kusto
| extend 
    BlastRadiusSeverity = case(
        IsPrivilegedRole == true, "Critical",
        IsAdmin == true or IsInPrivilegedGroup == true, "High",
        RoleCount > 0, "Medium",
        "Low"
    )
```

**Severity Levels:**
- 🔴 **Critical**: Privileged role (Global Admin, etc.) - Full tenant compromise risk
- 🟠 **High**: Any admin role or privileged group - Multi-system access
- 🟡 **Medium**: Standard roles assigned - Limited scope
- 🟢 **Low**: No roles - Single user impact only

### Benefits for SOC Analysts

1. **Faster Triage**: Instantly know if compromised user is high-value target
2. **Better Prioritization**: Critical accounts get immediate response
3. **Informed Response**: Know what systems are at risk
4. **Stakeholder Communication**: Manager field enables rapid notification
5. **Compliance**: Documentation of who had access to what

---

