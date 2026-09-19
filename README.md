# Ishaq Aslam - Microsoft Sentinel Account Takeover Detection Lab

## Overview 
- This project demonstrates a safe, isolated Microsoft Sentinel lab built within a personal Microsoft Entra ID tenant and Azure subscription. The lab simulates suspicious authentication behaviour against a dedicated test account and walks through a complete SIEM workflow:
- Authentication activity --> Log ingestion --> KQL investigation --> Detection rule --> Sentinel incident --> Investigation --> Security controls
The goal is to showcase practical experience with Microsoft Sentinel, detection engineering, KQL, and incident response concepts in a controlled environment.

## Objectives

-  Collect Microsoft Entra ID sign in logs in Microsoft Sentinel
- Investigate authentication activity using KQL
- Detect repeated failed sign ins within a defined time window
- Create a scheduled analytics rule in Sentinel
- Generate and analyse a Sentinel incident
- Identify relevant security controls and response actions, as a security analyst would 
- Document the investigation in a portfolio ready format

## Lab architecture
Personal Microsoft account
        |
        +-- Azure subscription
        |      |
        |      +-- Log Analytics workspace
        |             |
        |             +-- Microsoft Sentinel
        |
        +-- Personal Microsoft Entra tenant
               |
               +-- Dedicated test user
                      |
                      +-- Sign-in activity
                             |
                             v
                        SignInLogs
                             |
                             v
                       KQL investigation
                             |
                             v
                    Analytics detection rule
                             |
                             v
                         Incident
                             |
                             v
                    Investigation + response

## Detection

The analytics rule detects two or more failed authentication attempts, for the same user and IP address within a 10-minute window.

### KQL logic:

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 2
| order by FailedAttempts desc
```

### Rule configuration

- **Rule name:** Potential Account Takeover - Multiple Failed Sign-ins
- **Severity:** Medium
- **Frequency:** Every 10 minutes
- **Lookback:** Last 10 minutes
- **Threshold:** More than 0 query results
- **Event grouping:** Single alert
- **Incident creation:** Enabled
- **Detection window:** 10 minutes

## Investigation

The investigation used Microsoft Sentinel/Log Analytics and KQL to examine:

-   Target user account
-   Authentication outcome
-   Timestamp and time pattern
-   Source IP address
-   Result type and error description
-   Application and resource
-   Location data
-   Device information (where available)

The simulated activity generated repeated failed sign ins for the dedicated lab account. This met the detection criteria and resulted in an automatically created Sentinel incident, which was then triaged and investigated.

## Important interpretation

This lab demonstrates **suspicious authentication activity**, not a
confirmed real account takeover.

Repeated failed sign-ins can have several explanations, including a user
entering an incorrect password or an automated authentication attempt. A
real SOC investigation would require additional context before
confirming malicious activity.

## Recommended security controls

### Multi-factor authentication

Require MFA so that a password alone is not sufficient to authenticate, such as Microsoft authenticator or biometric authentication. 

### Conditional Access

Apply Conditional Access policies to apply stronger controls based on
user, device, location and authentication risk.

### Least privilege

Keep normal users separate from privileged administrator accounts and
grant only the permissions required for their role, by using PIM can help achieve least privelleged access through JIT activation also. 

### Authentication monitoring

Monitor sign-in failures, unusual locations, unfamiliar devices and
repeated authentication attempts.

### Password protection

Use strong password controls and account protection mechanisms to reduce
password-guessing risk. Including Microsoft Entra ID password protection, which bans globally common passwords or custom banned words in a corporation to prevent brute force attacks. 

### Incident response

Create a documented workflow for triage, validation, containment,
remediation and recovery when suspicious authentication activity is
detected.

## What was implemented vs recommended

### Implemented in this lab

-   Personal isolated Entra ID tenant
-   Dedicated test user
-   Entra sign-in log ingestion
-   Microsoft Sentinel
-   KQL investigations
-   Scheduled analytics rule
-   Automated incident creation
-   Incident investigation

### Recommended controls not claimed as implemented

-   MFA policy
-   Conditional Access policy
-   Production account lockout/remediation
-   Automated containment
-   Enterprise-wide monitoring

This distinction keeps the project technically accurate.

## Learning outcomes

This project demonstrates practical exposure to:

-   Microsoft Sentinel
-   Microsoft Entra ID
-   Log Analytics
-   KQL
-   SIEM investigation
-   Detection engineering
-   Alert and incident creation
-   Authentication monitoring
-   IAM and access-control concepts
-   Security controls
-   Incident-response thinking

## Disclaimer

This is an isolated educational lab using a dedicated test identity and
personal cloud environment. No university, employer or third-party
production systems were targeted or modified.
