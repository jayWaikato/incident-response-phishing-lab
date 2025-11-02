{
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {
            "Microsoft_Sentinel_incident": {}
        },
        "actions": {
            "Select_Entities": {
                "type": "Select",
                "runAfter": {}
            },
            "Create_HTML_table_with_Entities": {
                "type": "Table",
                "runAfter": {
                    "Select_Entities": [
                        "Succeeded"
                    ]
                }
            },
            "Select_Alerts": {
                "type": "Select",
                "runAfter": {
                    "Create_HTML_table_with_Entities": [
                        "Succeeded"
                    ]
                }
            },
            "Create_HTML_table_with_Alerts": {
                "type": "Table",
                "runAfter": {
                    "Select_Alerts": [
                        "Succeeded"
                    ]
                }
            },
            "Compose_Entity_Count": {
                "type": "Compose",
                "runAfter": {
                    "Create_HTML_table_with_Alerts": [
                        "Succeeded"
                    ]
                }
            },
            "Compose_Email_Response": {
                "type": "Compose",
                "runAfter": {
                    "Compose_Entity_Count": [
                        "Succeeded"
                    ]
                }
            }
        },
        "outputs": {},
        "parameters": {
            "SecOpsEmail": {
                "defaultValue": "security@company.com",
                "type": "String"
            },
            "dateTimeFormat": {
                "defaultValue": "dd/MM/yyyy HH:mm:ss",
                "type": "String"
            },
            "emailLogoHeader": {
                "defaultValue": "https://your-logo-url.com/logo.png",
                "type": "String"
            },
            "reportName": {
                "defaultValue": "Security Incident Report",
                "type": "String"
            },
            "$connections": {
                "type": "Object",
                "defaultValue": {}
            }
        }
    },
    "parameters": {
        "$connections": {
            "type": "Object",
            "value": {
                "azuresentinel": {
                    "id": "/subscriptions/e4c18f04-ee94-44fa-986e-e45be35cb293/providers/Microsoft.Web/locations/North Central US/managedApis/azuresentinel",
                    "connectionId": "/subscriptions/e4c18f04-ee94-44fa-986e-e45be35cb293/resourceGroups/data_traiage/providers/Microsoft.Web/connections/azuresentinel",
                    "connectionName": "azuresentinel"
                },
                "office365": {
                    "id": "/subscriptions/e4c18f04-ee94-44fa-986e-e45be35cb293/providers/Microsoft.Web/locations/North Central US/managedApis/office365",
                    "connectionId": "/subscriptions/e4c18f04-ee94-44fa-986e-e45be35cb293/resourceGroups/data_traiage/providers/Microsoft.Web/connections/office365",
                    "connectionName": "office365"
                }
            }
        }
    }
}
