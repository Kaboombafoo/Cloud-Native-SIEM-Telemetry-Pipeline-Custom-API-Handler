# Cloud-Native SIEM Telemetry Pipeline & Custom API Handler

## 📋 Project Overview
This project demonstrates the design, deployment, and optimization of a cloud-native Security Information and Event Management (SIEM) telemetry pipeline. The architecture links a local Windows 11 endpoint to an enterprise-grade log collection engine hosted in the cloud, utilizing kernel-level event auditing to capture advanced host manipulation tactics. High-severity threats are surgically parsed and distributed to an operational engineering channel via a custom Python 3 native API integration.

### Key Infrastructure Capabilities
- **Proactive Boundary Telemetry:** Secure, cross-platform log transport spanning cloud perimeters and local endpoints.
- **Kernel-Level Audit Depth:** Advanced process, network, and file integrity tracing via Microsoft Sysmon.
- **Micro-Engineered Alerting:** A native Python automated handler that bypasses brittle legacy compatibility frameworks to provide zero-loss JSON payload delivery.
- **Framework Alignment:** Automatic behavioral mapping to the **MITRE ATT&CK Matrix**.

---

## 🏗️ System Architecture & Data Flow

1. **Endpoint Generation:** Microsoft Sysmon monitors kernel activities on the Windows host and records events to the `Microsoft-Windows-Sysmon/Operational` event channel.
2. **Log Ingestion & Transport:** The local Wazuh Agent monitors the Sysmon event log channel in real time and ships encrypted logs over the WAN to the cloud manager.
3. **Rules Engine & Analysis:** The Cloud Wazuh Manager processes incoming events against built-in and user-configured signature rule sets.
4. **Integration Daemon Activation:** When an event meets or exceeds the defined severity gate (Level 7), the manager invokes the background integration daemon (`wazuh-integratord`).
5. **API Delivery:** The custom Python integration script formats the alert payload into a native Discord Embed structure and executes an HTTP POST to the live webhook target.

---

## 🛠️ Components & Technologies
- **SIEM Core:** Wazuh Manager & Agent (v4.x)
- **Host Telemetry Engine:** Microsoft Sysmon (v15.20) + SwiftOnSecurity Configuration Framework
- **Cloud Infrastructure:** Ubuntu Server hosted on Oracle Cloud Infrastructure (OCI)
- **Automation & Scripting:** Python 3 (using `requests`, `sys`, and `json` modules)
- **Alert Target:** Discord Native Webhook API

---

## 💻 Script Configuration: Native Discord Integration

This script sits at `/var/ossec/integrations/slack` on the cloud manager. It replaces the legacy Slack-translation wrapper to communicate natively with Discord's API, eliminating syntax failures induced by unmapped or null event fields.

```python
#!/usr/bin/env python3
import sys
import json
import requests

# Read the arguments passed by the Wazuh daemon
alert_file = sys.argv[1]
hook_url = sys.argv[3]

# Read and parse the raw alert JSON data
with open(alert_file, 'r') as f:
    alert = json.load(f)

# Extract core metadata safely with default fallbacks
description = alert.get('rule', {}).get('description', 'Wazuh Security Alert')
rule_id = alert.get('rule', {}).get('id', 'N/A')
level = alert.get('rule', {}).get('level', 0)
agent_name = alert.get('agent', {}).get('name', 'Cloud Manager')
agent_id = alert.get('agent', {}).get('id', '000')

# Dynamically set embed card color based on severity levels
if level >= 10:
    card_color = 15158332  # Red for high severity threats
elif level >= 5:
    card_color = 15105570  # Orange for warning severity
else:
    card_color = 3066993   # Green for low severity informational

# Build a pristine, native Discord Embed payload
payload = {
    "embeds": [
        {
            "title": f"⚠️ Security Alert — Level {level}",
            "description": description,
            "color": card_color,
            "fields": [
                {"name": "Rule ID", "value": str(rule_id), "inline": True},
                {"name": "Agent Source", "value": f"({agent_id}) {agent_name}", "inline": True}
            ],
            "footer": {"text": "Wazuh Homelab Monitor"}
        }
    ]
}

# Ship the native JSON payload directly to Discord
requests.post(hook_url, json=payload)
