"""
LLM Component - NexusGuard Project
Author: Tharupathi Bandaranayake ")
Date: 2025-10-28

Description:
------------
This script represents the reasoning engine of the NexusGuard system.(TESTING)
It receives processed telemetry data from the ML model, maps it to MITRE ATT&CK context,
and generates a natural-language explanation and mitigation recommendation......

Future versions will integrate a real Large Language Model (LLM) such as Gemma 3:1B using Ollama,
to provide dynamic reasoning and adaptive threat analysis.
"""

import json
from datetime import datetime

# Step 1: Simulated input from the ML model-----------------
sample_input = {
    "timestamp": str(datetime.utcnow()),
    "sensor_id": "WSL-124",
    "command": "rm -rf / --no-preserve-root",
    "risk_score": 91,
    "ml_label": "Malicious Command"
}

# Step 2: Example MITRE ATT&CK mapping for simulation-----------------------
mitre_mapping = {
    "rm -rf": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and system files to interrupt normal operations."
    },
    "curl http": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may download malicious tools or payloads from external servers."
    }
}

# Step 3: Function to match command with MITRE ATT&CK context
def get_mitre_context(command):
    for keyword, data in mitre_mapping.items():
        if keyword in command:
            return data
    return None

# Step 4: Simulated LLM reasoning logic ---------- 
def llm_reasoning(event):
    context = get_mitre_context(event["command"])
    if not context:
        return "No MITRE context found. Event appears benign or low-risk."

    reasoning = f"""
🚨 Threat Detected: {event['ml_label']}
-----------------------------------
Risk Score: {event['risk_score']}%
Command: {event['command']}

MITRE Technique: {context['technique_name']} ({context['technique_id']})
Tactic: {context['tactic']}
Description: {context['description']}

Reasoning:
The command matches behavior consistent with {context['technique_name']} activity.
It indicates potential {context['tactic'].lower()} behavior within the WSL environment.

🛡️ Recommended Mitigation:
- Immediately isolate the affected container or WSL environment.
- Revoke elevated privileges or root access.
- Review recent file deletions or network downloads.
- Restore from secure backups if data loss is detected.
"""
    return reasoning.strip()

# Step 5: Main execution block
if __name__ == "__main__":
    print("=== NexusGuard LLM Component ===")
    print(json.dumps(sample_input, indent=4))
    print("\n--- LLM Reasoning Output ---\n")
    print(llm_reasoning(sample_input))
