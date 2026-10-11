# Suspicious Authentication Detection

## Objective

Identify accounts with multiple failed sign-in attempts followed by a successful sign-in within a short time window. This pattern may indicate password guessing or a compromised account.

## Data Source

Microsoft Sentinel — `SigninLogs`

Relevant fields:
- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `ResultType`
- `ResultDescription`
- `AppDisplayName`
- `Location`
- `ConditionalAccessStatus`

## Detection Logic

The query identifies accounts with at least five failed sign-in attempts followed by a successful sign-in from the same IP address within 30 minutes.

This pattern is suspicious but does not independently confirm an account compromise.

## KQL Query

```kql
let FailedAttempts =
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType != "0"
    | summarize
        FailedCount = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by UserPrincipalName, IPAddress
    | where FailedCount >= 5;
let SuccessfulLogins =
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == "0"
    | project
        UserPrincipalName,
        IPAddress,
        SuccessTime = TimeGenerated,
        AppDisplayName,
        Location,
        ConditionalAccessStatus;
FailedAttempts
| join kind=inner SuccessfulLogins on UserPrincipalName, IPAddress
| where SuccessTime between (LastFailure .. LastFailure + 30m)
| project
    UserPrincipalName,
    IPAddress,
    FailedCount,
    FirstFailure,
    LastFailure,
    SuccessTime,
    AppDisplayName,
    Location,
    ConditionalAccessStatus
| order by SuccessTime desc
```

## Investigation Steps

1. Identify the affected user and source IP address.
2. Review the number and timing of failed attempts.
3. Confirm whether a successful sign-in followed the failures.
4. Review the application accessed and sign-in location.
5. Examine MFA results and Conditional Access details.
6. Compare the IP address and device with the user's normal activity.
7. Review subsequent sign-ins and activity for signs of account misuse.
8. Determine whether the activity is legitimate, suspicious, or confirmed malicious.
9. Escalate and recommend containment when supported by the evidence.

## MITRE ATT&CK Mapping

- **T1110 — Brute Force**
- **T1078 — Valid Accounts**

These techniques may be relevant depending on the investigation findings.

## Potential False Positives

- Users repeatedly entering an incorrect password.
- Automated services using outdated credentials.
- Shared corporate NAT or VPN addresses.
- Legitimate authentication retries.

## Detection Tuning

- Adjust the failed-attempt threshold based on the environment.
- Consider user and IP reputation.
- Correlate with MFA failures and unfamiliar sign-in locations.
- Use approved allowlists carefully.
- Consider separate detections for distributed password guessing.

## Response Considerations

If compromise is suspected or confirmed:
- Investigate related authentication and account activity.
- Revoke active sessions where appropriate.
- Reset credentials if necessary.
- Review MFA registration and authentication methods.
- Escalate according to the incident response procedure.

## Limitations

This query is a starting point for a lab or portfolio. It requires validation against representative sign-in data. It correlates failures and successes by account and IP address, so it will not detect every password-guessing scenario. The time-window logic and result fields should be tested in the target environment.

## Disclaimer

This project is for educational and portfolio purposes. It uses no confidential employer or customer data.
