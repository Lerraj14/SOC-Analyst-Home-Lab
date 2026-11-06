# Incident 002: Multiple Failed SSH Authentication Attempts

## 1. Executive Summary

A controlled SSH authentication exercise was performed against SOC-Ubuntu-01 to simulate repeated unsuccessful login attempts.

The objective was to identify authentication patterns, analyze Linux security logs, and assess whether the observed behavior resembles a brute-force attack.

## 2. Incident Details

| Field | Details |
|---|---|
| Incident ID | SOC-002 |
| Incident Type | Repeated SSH Authentication Failures |
| Affected Host | SOC-Ubuntu-01 |
| Operating System | Ubuntu Server |
| Target Username | fakeuser |
| Source IP | YOUR_SERVER_IP |
| Number of Attempts | 5 |
| Severity | Informational / Low |
| Status | Investigation Exercise |

## 3. 5W Investigation

### WHO
Identify the source IP and targeted username using SSH logs.

### WHAT
Five controlled unsuccessful SSH authentication attempts were generated.

### WHEN
Record the first and last event timestamps.

### WHERE
The activity targeted the Ubuntu Server VM through its SSH service.

### WHY
The exercise was performed to understand repeated authentication failures and recognize patterns associated with brute-force activity.

## 4. Investigation Commands

```bash
sudo journalctl -u ssh --since "15 minutes ago"
```

```bash
sudo journalctl -u ssh --since "15 minutes ago" | grep -iE 'failed password|invalid user|authentication failure'
```

## 5. Findings

- Number of attempts: Verify from logs.
- Targeted username: fakeuser.
- Source IP: Verify from logs.
- Authentication results: Verify from logs.
- Successful login afterward: Verify from logs.

## 6. Initial Assessment

Repeated unsuccessful authentication attempts may indicate suspicious login activity.

The observed behavior resembles a brute-force pattern; however, the activity was deliberately generated in a controlled lab environment.

No system compromise is established.

## 7. Recommended Actions

- Monitor repeated SSH authentication failures.
- Restrict SSH access to trusted sources.
- Implement appropriate authentication controls.
- Consider automated detection and alerting.
- Investigate successful logins following repeated failures.

## 8. Conclusion

This exercise demonstrated how repeated SSH authentication failures can be identified and investigated through Linux system logs.

The investigation strengthened practical skills in authentication monitoring, event correlation, and incident documentation.
