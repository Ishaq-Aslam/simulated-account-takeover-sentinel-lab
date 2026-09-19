# Investigation Report

## Scenario

This lab investigates repeated failed authentication attempts against a dedicated test account.

The purpose is to demonstrate an account-takeover detection workflow in Microsoft Sentinel.

## Initial observation

Microsoft Entra `SigninLogs` contained failed authentication events associated with the lab account.

A KQL aggregation identified multiple failures from the same source IP within a 10-minute period, indicating brute-force-style activity rather than password spraying. 

## Detection query

``` kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 2
| order by FailedAttempts desc
```

## Investigation questions

### Who was targeted?

The lab test account (Michael smith)

### What happened?

Multiple authentication attempts failed within the detection window, suggesting repeated password guessing on the test account. 

### Where did the activity originate?

The source IP address was visible in the sign-in logs. 

### When did it happen?

The timestamps are recorded in the Entra sign-in logs and were used by the detection query.

### Was an account takeover confirmed?

No, The evidence demonstrates repeated failed authentication activity. It does not by itself prove that an account was compromised, however it is important to always investigate these kinds of risks. 

## Result

The analytics rule I generated in Sentinel, flagged it as a Medium-severity incident for the repeated failed sign-ins. Which then i investigated using KQL and triaged. Followed by a report, on remediation actions to take. 

## Analyst response

A real SOC analyst would:

1.  Validate whether the activity was expected.
2.  Review the account's recent sign-in history.
3.  Check source IP reputation and context.
4.  Review application, location and device information.
5.  Look for successful authentication after repeated failures.
6.  Assess whether MFA or Conditional Access was triggered.
7.  Contain the account if compromise is confirmed.
8.  Reset credentials and revoke sessions where appropriate.
9.  Document the incident and close it with an evidence-based
    conclusion.

## Conclusion

The lab successfully demonstrates the flow from raw authentication telemetry to a KQL-based detection and Sentinel incident. It is a useful detection-and-investigation exercise rather than evidence of a real compromise.
