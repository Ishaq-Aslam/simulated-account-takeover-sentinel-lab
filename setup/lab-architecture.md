# Lab Architecture

## Environment
- Microsoft Entra ID: personal/default directory
- Azure subscription: personal subscription
- Log Analytics workspace: `law-account-takeover`
- Microsoft Sentinel: connected to the Log Analytics workspace
- Test identity: dedicated lab account

## Data flow

1. Test authentication activity is generated against the dedicated lab identity (Michael Smith).

2. Microsoft Entra ID records the authentication event in `SigninLogs`.

3. The Entra sign-in data is available in Log Analytics/Sentinel.

4. KQL is used to investigate authentication events.

5. A scheduled analytics rule searches for repeated failed sign-ins.

6. The rule generates an alert when the detection query returns results.

7. Sentinel creates an incident from the alert.

8. The incident is investigated using account, IP, timestamp and authentication details.

## Isolation

The project uses a separate personal Entra tenant and Azure environment. 
