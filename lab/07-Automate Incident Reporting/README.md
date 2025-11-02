🏗️ Architecture
Playbook Workflow
graph TD
    A[Microsoft Sentinel] -->|New Incident Detected| B[Trigger: Incident Creation]
    B --> C[Action 1: Select Entities]
    C --> D[Action 2: Create HTML Table - Entities]
    D --> E[Action 3: Select Alerts]
    E --> F[Action 4: Create HTML Table - Alerts]
    F --> G[Action 5: Compose Entity Count]
    G --> H[Action 6: Compose Email Response]
    H --> I[Action 7: Send Email]
    I --> J[Security Team Notified]
    
    style A fill:#0078D4,color:#fff
    style B fill:#00BCF2,color:#fff
    style C fill:#7FBA00,color:#fff
    style D fill:#7FBA00,color:#fff
    style E fill:#7FBA00,color:#fff
    style F fill:#7FBA00,color:#fff
    style G fill:#FFB900,color:#000
    style H fill:#FFB900,color:#000
    style I fill:#E81123,color:#fff
    style J fill:#00B294,color:#fff
Data Flow
Sentinel Incident
    ↓
Extract Related Entities (Accounts, IPs, URLs, Files, etc.)
    ↓
Parse into HTML Table for readability
    ↓
Extract Associated Alerts (Detection rules triggered)
    ↓
Parse into HTML Table
    ↓
Calculate Metrics (Entity count, Alert count, Severity)
    ↓
Compose Rich HTML Email with:
    • Executive Summary
    • Timeline
    • MITRE ATT&CK Tactics
    • Entity & Alert Details
    • Recommended Actions
    ↓
Send to Security Operations Team

🔍 Step-by-Step Breakdown
Step 1: Trigger - Microsoft Sentinel Incident
Purpose: Monitors Microsoft Sentinel for new incident creation
Configuration:
json{
    "type": "ApiConnectionWebhook",
    "inputs": {
        "host": {
            "connection": {
                "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
        },
        "body": {
            "callback_url": "@{listCallbackUrl()}"
        },
        "path": "/incident-creation"
    }
}
How It Works:

Sentinel registers a webhook with the Logic App
When a new incident is created, Sentinel sends incident data via POST request
Trigger captures the full incident object including:

Incident properties (title, severity, description)
Related entities (users, IPs, devices, etc.)
Associated alerts
MITRE ATT&CK tactics
Timeline information



Real-World Example:
Incident Detected: "Unfamiliar sign-in properties involving one user"
Severity: Medium
Entities: 1 user account, 1 IP address
Alerts: "Risky sign-in detected from unusual location"
→ Playbook triggered automatically

Step 2: Select Entities
Purpose: Extract and format related entities from the incident
Logic:
json{
    "type": "Select",
    "inputs": {
        "from": "@triggerBody()?['object']?['properties']?['relatedEntities']",
        "select": {
            "Entity": "@item()?['properties']?['friendlyName']",
            "Entity Type": "@item()?['kind']"
        }
    }
}
What It Does:

Iterates through relatedEntities array from Sentinel
Extracts friendlyName (human-readable name) and kind (entity type)
Creates a simplified array for table generation

Entity Types Captured:
Entity TypeExampleWhy It MattersAccountjayinternalthreat@studmemt.comCompromised user identityIP Address20.124.88.102Source of attackHostDESKTOP-ABC123Compromised deviceURLhttps://phishing-site.comMalicious linkFilemalware.exeMalicious fileMailMessagePhishing email subjectAttack vectorProcesspowershell.exeSuspicious execution
Output Example:
json[
    {
        "Entity": "jayinternalthreat@studmemt.onmicrosoft.com",
        "Entity Type": "Account"
    },
    {
        "Entity": "20.124.88.102",
        "Entity Type": "IP"
    }
]

Step 3: Create HTML Table with Entities
Purpose: Convert entity array into formatted HTML table for email
Logic:
json{
    "type": "Table",
    "inputs": {
        "from": "@body('Select_Entities')",
        "format": "HTML"
    }
}
Output:
html<table>
    <thead>
        <tr>
            <th>Entity</th>
            <th>Entity Type</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>jayinternalthreat@studmemt.onmicrosoft.com</td>
            <td>Account</td>
        </tr>
        <tr>
            <td>20.124.88.102</td>
            <td>IP</td>
        </tr>
    </tbody>
</table>
Why HTML Tables:

✅ Professional appearance in email clients
✅ Easy to scan for SOC analysts
✅ Maintains structure across different email platforms
✅ Supports styling for visual hierarchy


Step 4: Select Alerts
Purpose: Extract alert information from the incident
Logic:
json{
    "type": "Select",
    "inputs": {
        "from": "@triggerBody()?['object']?['properties']?['alerts']",
        "select": {
            "Alert": "@item()?['properties']?['alertDisplayName']"
        }
    }
}
What It Does:

Iterates through all alerts that contributed to the incident
Extracts the display name of each alert
Multiple alerts can correlate into a single incident

Real Example from Lab:
json[
    {
        "Alert": "Unfamiliar sign-in properties"
    },
    {
        "Alert": "Atypical travel detected"
    },
    {
        "Alert": "API token suspicious activity"
    }
]
Why This Matters:

Shows the full attack chain
Helps analysts understand correlation logic
Identifies which detection rules fired
Enables tuning of detection rules based on patterns


Step 5: Create HTML Table with Alerts
Purpose: Format alerts into readable HTML table
Logic:
json{
    "type": "Table",
    "inputs": {
        "from": "@body('Select_Alerts')",
        "format": "HTML"
    }
}
Output:
html<table>
    <thead>
        <tr>
            <th>Alert</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Unfamiliar sign-in properties</td>
        </tr>
        <tr>
            <td>Atypical travel detected</td>
        </tr>
    </tbody>
</table>

Step 6: Compose Entity Count
Purpose: Calculate total number of entities for metrics dashboard
Logic:
json{
    "type": "Compose",
    "inputs": "@length(triggerBody()?['object']?['properties']?['relatedEntities'])"
}
What It Does:

Counts array length of relatedEntities
Used in the metrics section of email
Helps assess incident scope at a glance

Interpretation:
Entity CountLikely ScenarioSeverity Impact1-2Single user compromiseLower priority3-5Multiple users or lateral movementMedium priority6-10Widespread attack or network scanHigh priority10+Major incident or automated attackCritical priority

Step 7: Compose Email Response
Purpose: Build comprehensive, visually appealing HTML email with all incident details
Key Features:
1. Professional Design
css/* Gradient header with company branding */
.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

/* Severity-based color coding */
.severity-high { background-color: #d32f2f; }
.severity-medium { background-color: #f57c00; }
.severity-low { background-color: #fbc02d; }
2. Executive Summary Section

Incident Title: Clear description of the threat
Incident Number: Unique identifier for tracking
Description: Detailed explanation from Sentinel

3. Key Metrics Dashboard
html<div class="metrics">
    <div class="metric">
        <div class="metric-value">3</div>
        <div class="metric-label">Alerts</div>
    </div>
    <div class="metric">
        <div class="metric-value">2</div>
        <div class="metric-label">Entities</div>
    </div>
    <div class="metric">
        <div class="metric-value">Medium</div>
        <div class="metric-label">Severity</div>
    </div>
</div>
Why This Works:

At-a-glance severity assessment
Quick scope understanding
No need to read full email for triage

4. Timeline Section
html<div class="timeline">
    <div class="timeline-item">
        <div class="timeline-time">First Activity: 23/10/2025 23:24:36</div>
        <div class="timeline-desc">Initial suspicious activity detected</div>
    </div>
    <div class="timeline-item">
        <div class="timeline-time">Incident Created: 23/10/2025 23:25:01</div>
        <div class="timeline-desc">Incident generated in Microsoft Sentinel</div>
    </div>
</div>
Value:

Shows attack progression
Helps establish incident timeline
Documents response time

5. MITRE ATT&CK Mapping
html<div class="section-title">MITRE ATT&CK Tactics</div>
<div class="info-value">
    Initial Access<br>
    Credential Access<br>
    Defense Evasion
</div>
Why Include This:

Maps incident to known attack techniques
Helps understand adversary behavior
Enables threat intelligence correlation
Supports reporting and metrics

Common Tactics in Phishing Attacks:
TacticTechniqueExample from LabInitial AccessT1566 - PhishingEvilginx phishing pageCredential AccessT1539 - Steal Web Session CookieToken captureDefense EvasionT1550 - Use Alternate Authentication MaterialToken replay attackCollectionT1114 - Email CollectionMailbox access after compromise
6. Related Entities & Alerts Tables

Embedded HTML tables from previous steps
Styled for readability
Hover effects for better UX

7. Recommended Actions
html<div class="recommendations">
    <ul>
        <li>Review the incident details in Microsoft Sentinel</li>
        <li>Investigate all related entities and alerts</li>
        <li>Verify if the activity is legitimate or malicious</li>
        <li>Document findings and take appropriate remediation steps</li>
        <li>Update incident status once investigation is complete</li>
    </ul>
</div>
Why This Matters:

Provides clear next steps for analysts
Reduces decision paralysis
Ensures consistent response process
Helps junior analysts know what to do

8. Call-to-Action Button
html<a href="[Sentinel Incident URL]" class="button">
    Investigate in Sentinel →
</a>
Single-click navigation directly to the incident in Sentinel portal

Step 8: Send Email
Purpose: Deliver the formatted email to security operations team
Configuration:
json{
    "type": "ApiConnection",
    "inputs": {
        "host": {
            "connection": {
                "name": "@parameters('$connections')['office365']['connectionId']"
            }
        },
        "method": "post",
        "body": {
            "To": "jaychampaneri@studmemt.onmicrosoft.com",
            "Subject": "New Microsoft Sentinel Incident - [Incident Title]",
            "Body": "<p>@{outputs('Compose_Email_Response')}</p>",
            "Importance": "High"
        },
        "path": "/v2/Mail"
    }
}
Email Properties:
PropertyValuePurposeToSecurity team emailPrimary recipientsSubjectDynamic incident titleEasy filtering and searchingBodyHTML formattedProfessional appearanceImportanceHighFlags for priority attention
