# Security Controls and Response

## Preventive controls

### MFA

Require multi-factor authentication to reduce the impact of stolen or guessed passwords. Also Require MFA so that a password alone is not sufficient to authenticate, such as Microsoft authenticator or biometric authentication. 

### Conditional Access

Apply authentication controls based on factors such as user, device,location and risk. Also so that a password alone is not sufficient to authenticate, such as Microsoft authenticator or biometric authentication. 

### Least privilege

Keep the test/standard user separate from privileged identities and
minimise administrative permissions.

### Password protection

Use strong password policies such as Micorsofts Entra ID's password protection and appropriate identity protection mechanisms, to reduce attacks like brute force or password spray techniques. 

## Detective controls

-   Monitor failed authentication attempts.
-   Detect repeated failures from the same IP.
-   Monitor unusual locations and unfamiliar devices.
-   Correlate failed and successful sign-ins.
-   Forward relevant identity telemetry to the SIEM.

## Response controls

If suspicious activity is confirmed:

1.  Validate the activity with the account owner.
2.  Investigate related sign-ins and applications.
3.  Revoke active sessions where appropriate.
4.  Reset credentials if compromise is suspected.
5.  Review MFA and Conditional Access activity.
6.  Search for additional activity involving the same account/IP.
7.  Record the investigation and resolution.

## MITRE ATT&CK context

Repeated authentication attempts can be investigated in the context of credential-access techniques, but the specific technique should only be assigned when the available evidence supports it.

This lab is not a confirmed credential attack merely because
of multiple sign-ins failed. Also no real accounts were used or compromised, all accounts were test accounts for the purpose of this lab to demonstrate my understanding of using Sentinel, Entra ID and the Azure portal. 



