# LLM Reasoning Engine – NexusGuard

### Overview
The LLM Reasoning Engine is the intelligence layer of **NexusGuard**.  
It interprets anomaly detections from the ML model, maps them to MITRE ATT&CK techniques, and produces natural-language reasoning and mitigation steps.

### Features
- Accepts telemetry data from the ML model  
- Maps malicious patterns to MITRE ATT&CK framework  
- Generates contextual explanations and mitigations  
- Outputs formatted results to the web dashboard  

### Example Run
```bash
python3 llm_component.py
