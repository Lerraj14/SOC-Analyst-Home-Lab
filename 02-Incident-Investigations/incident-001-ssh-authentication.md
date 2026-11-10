
# Incident 001: Suspicious SSH Authentication Attempt

## 1. Executive Summary

A controlled unsuccessful SSH authentication attempt was generated against the Ubuntu Server virtual machine as part of a cybersecurity home lab exercise.

The objective was to simulate suspicious authentication activity and practice identifying, collecting, and analyzing Linux authentication logs.

## 2. Incident Details

| Field | Details |
|---|---|
| Incident ID | SOC-001 |
| Incident Name | Suspicious SSH Authentication Attempt |
| Incident Type | Authentication Failure |
| Environment | VMware Home Lab |
| Affected Host | SOC-Ubuntu-01 |
| Operating System | Ubuntu Server 26.04.1 LTS |
| Target Username | fakeuser |
| Source IP | 192.168.189.129|
| Timestamp |  Failed authentication: November 5  14:59:52 to 15:00:05 | Successful authentication November 5 15:21:40 to 15:22:57 |
| Severity | Informational / Low |
| Status | Investigation Exercise |

## 3. 5W Investigation

### WHO

The activity originated from a controlled test connection initiated from the Windows host to the Ubuntu Server virtual machine.

The attempted username was `fakeuser`.

### WHAT

An unsuccessful SSH authentication attempt was generated using a nonexistent username.

The activity was intended to simulate suspicious authentication behavior.

### WHEN

The exact event timestamp must be obtained from the Ubuntu authentication logs. 

It was happened  at Nov 5 from 14:51:21 to 15:23:26 showing password invalid for fakeuser.
While success login attempt has a timestamp of Nov 05 14:56:10 to 15:22:57 Accepted password for socadmin.

### WHERE

The activity targeted:

- Target IP: Ubuntu Server IP.
- Source IP: Windows host IP as observed by the server.
- Target hostname: SOC-Ubuntu-01.
- Service: OpenSSH.

### WHY

The exercise was conducted to understand how failed SSH authentication attempts are recorded and investigated by a SOC analyst.

## 4. Investigation Process

### Step 1: Generate the Authentication Event

Executed from Windows PowerShell:

```powershell
ssh fakeuser@192.168.189.129
```

The connection resulted in an unsuccessful authentication attempt because the specified username does not exist.

### Step 2: Collect SSH Logs

Executed on Ubuntu:

```bash
sudo journalctl -u ssh --since "15 minutes ago"
```

### Step 3: Filter Relevant Events

```bash
sudo journalctl -u ssh --since "15 minutes ago" | grep -iE 'invalid user|failed password|authentication failure'
```

### Step 4: Review Authentication Activity

```bash
sudo lastb -n 10
```

### Step 5: Review Related Sudo Activity

```bash
sudo journalctl --since "15 minutes ago" | grep -i sudo
```

## 5. Evidence Collection

Evidence to collect:

- SSH authentication failure log.
- Attempted username.
- Source IP address reported by the server.
- Event timestamp.
- Relevant SSH service messages.

Screenshots are stored in:

`Screenshots/ssh-investigation/`

Actual log output and timestamps should be added after verification.

## 6. Findings

The investigation identified an unsuccessful SSH authentication attempt against the Ubuntu Server virtual machine, SOC-Ubuntu-01.

The attempted username was fakeuser, which was used to simulate suspicious authentication activity in a controlled home lab environment.

The authentication logs also contained successful login events associated with the socadmin account. These events require separate verification to determine whether they represent legitimate administrative activity.

The source IP address and exact event timestamps must be confirmed using the server's authentication logs.

No evidence of unauthorized access or system compromise has been established based on the available evidence.

## 7. Initial Assessment

The observed failed authentication event represents a low-severity security event within the controlled lab environment.

A single failed authentication attempt does not establish brute-force activity or successful compromise.

Further investigation should include:

- Identifying the source IP address.

- Reviewing repeated failed authentication attempts.

- Correlating successful and unsuccessful login events.

- Verifying whether successful administrative logins were authorized.

- Reviewing relevant system and authentication logs.

Assessment: No confirmed compromise. Further investigation is required to establish the legitimacy of related authentication activity.

## 8. Recommended Security Measures

- Restrict SSH access to trusted networks.
- Use SSH key-based authentication where appropriate.
- Enforce strong authentication practices.
- Monitor repeated authentication failures.
- Review SSH configuration regularly.
- Consider centralized log monitoring through a SIEM.

## 9. Conclusion

This exercise demonstrated the process of generating and investigating failed SSH authentication activity in a controlled Linux environment.

It provided practical experience with Linux authentication logs, SSH troubleshooting, event analysis, and SOC incident documentation.

## 10. Lessons Learned

- Understanding Linux authentication logs is essential for SOC investigations.
- Event timestamps and source addresses are important during incident correlation.
- Failed authentication does not automatically indicate system compromise.
- Findings should be supported by collected evidence.
