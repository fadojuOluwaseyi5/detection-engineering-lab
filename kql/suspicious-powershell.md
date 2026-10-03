
# Suspicious PowerShell Execution Detection

## Objective

Detect potentially suspicious PowerShell activity that may indicate execution of malicious commands, scripts, or payloads.

## Data Source

Microsoft Defender XDR 'DeviceProcessEvents' telemetry.

Relevant fields include:

- 'Timestamp'
- 'DeviceName'
- 'AccountName'
- 'FileName'
- 'ProcessCommandLine'
- 'InitiatingProcessFileName'
- 'InitiatingProcessCommandLine'

## Detection Logic

The detection looks for PowerShell processes containing command-line patterns commonly associated with potentially malicious activity, including:

- Encoded PowerShell commands
- Base64 decoding
- Downloading content
- In-memory execution

The presence of one of these indicators does not automatically mean the activity is malicious. The alert should be investigated in context.

## KQL Query
```kql

DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc",
    "-encodedcommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "Net.WebClient"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

Investigation Steps

When this detection triggers:
Identify the affected device and user.
Review the complete PowerShell command line.
Examine the parent/initiating process.
Determine how PowerShell was launched.
Check for downloaded files, scripts, or payloads.
Review network connections associated with the process.
Check the user's recent activity for related suspicious events.
Review the process tree for additional malicious activity.
Determine whether the activity is legitimate administrative activity or potentially malicious.
Escalate or contain the endpoint according to the confirmed risk.

MITRE ATT&CK Mapping
T1059.001 — Command and Scripting Interpreter: PowerShell

PowerShell can be abused by attackers to execute commands, download payloads, perform reconnaissance, and execute malicious scripts.

Potential False Positives

Legitimate PowerShell activity may trigger this detection, including:
IT administration scripts
Software deployment
Security tooling
Automation
System maintenance
Legitimate scripts containing download or encoded-command functionality

The command line and surrounding activity should therefore be reviewed before classifying the alert as malicious.

Detection Tuning

Potential tuning opportunities include:
Excluding known trusted administrative scripts where appropriate.
Excluding approved management tools.
Correlating PowerShell activity with the initiating process.
Adding user, device, and process reputation/context.
Increasing severity when multiple suspicious indicators occur together.
Creating separate detections for high-confidence behaviors rather than relying on a single keyword.

Response Considerations

If the investigation confirms malicious activity, response actions may include:
Isolating the affected endpoint.
Terminating malicious processes.
Removing malicious files or scripts.
Resetting compromised credentials where appropriate.
Blocking confirmed malicious infrastructure.
Escalating the incident for further investigation.

Notes

This detection is designed for educational and portfolio purposes. It does not use confidential production data or proprietary detection logic





