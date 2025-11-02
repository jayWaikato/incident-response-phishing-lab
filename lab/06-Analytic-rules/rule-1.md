# Advanced KQL Detection Queries

## 📊 Custom Detection Rules for Microsoft Sentinel

This section contains production-ready KQL (Kusto Query Language) queries used for advanced threat detection and investigation in Microsoft Sentinel and Defender environments.

---

## 🔍 Query 1: UnifiedSignInLogs - Consolidated Authentication Analysis

### Purpose
This custom function merges interactive and non-interactive sign-in logs into a single, normalized dataset, making authentication analysis more efficient and comprehensive.

### The Challenge
Microsoft stores authentication data in two separate tables:
- **SigninLogs** - Interactive user sign-ins (browser, mobile app)
- **AADNonInteractiveUserSignInLogs** - Service principals, managed identities, API calls

Security analysts often need to correlate both types, but inconsistent schema between tables makes this difficult.

### The Solution

```kusto
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
// Rename all columns named _dynamic to normalize the column names
| extend ConditionalAccessPolicies = iff(isempty(ConditionalAccessPolicies_dynamic), todynamic(ConditionalAccessPolicies_string), ConditionalAccessPolicies_dynamic)
| extend Status = iff(isempty(Status_dynamic), todynamic(Status_string), Status_dynamic)
| extend MfaDetail = iff(isempty(MfaDetail_dynamic), todynamic(MfaDetail_string), MfaDetail_dynamic)
| extend DeviceDetail = iff(isempty(DeviceDetail_dynamic), todynamic(DeviceDetail_string), DeviceDetail_dynamic)
| extend LocationDetails = iff(isempty(LocationDetails_dynamic), todynamic(LocationDetails_string), LocationDetails_dynamic)
| extend TokenProtection = iff(isempty(TokenProtectionStatusDetails_dynamic), todynamic(TokenProtectionStatusDetails_string), TokenProtectionStatusDetails_dynamic)
// Remove duplicated columns
| project-away *_dynamic, *_string
```

### How It Works

**Step 1: Union Operation**
```kusto
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
```
- `isfuzzy=true` allows the union even if column names don't match exactly
- Combines both authentication log sources into one stream

**Step 2: Schema Normalization**
```kusto
| extend ConditionalAccessPolicies = iff(isempty(ConditionalAccessPolicies_dynamic), todynamic(ConditionalAccessPolicies_string), ConditionalAccessPolicies_dynamic)
```
- Some columns exist as both `_dynamic` and `_string` types depending on the source table
- This logic checks which version has data and converts to dynamic type
- Ensures consistent field types across all records

**Step 3: Cleanup**
```kusto
| project-away *_dynamic, *_string
```
- Removes duplicate columns after normalization
- Keeps only the unified fields

### Why This Matters for Phishing Detection

1. **Complete Attack Timeline**: Phishing attacks often start with interactive login (user enters credentials) followed by non-interactive API calls (attacker enumerates data)
2. **Token Theft Detection**: Session hijacking involves both interactive and programmatic access
3. **Simplified Queries**: One query covers all authentication types instead of separate investigations

### Usage Example

```kusto
// Detect suspicious authentication patterns across all sign-in types
UnifiedSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0 // Successful
| where RiskLevelDuringSignIn in ("high", "medium")
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    SignInTypes = make_set(AppDisplayName)
    by UserPrincipalName, Location
| where UniqueIPs > 3 // Multiple locations in 24h
```


### Credit
Original concept by **Fabian Bader** - Enhanced with additional fields and token protection telemetry.

---

