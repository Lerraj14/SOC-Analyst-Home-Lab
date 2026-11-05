
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
| Source IP | To be verified from logs |
| Timestamp | To be verified from logs |
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

### WHERE

The activity targeted:

- Hostname: SOC-Ubuntu-01
- Operating System: Ubuntu Server
- Service: OpenSSH
- Network: VMware NAT

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

The lab generated an unsuccessful SSH authentication attempt against the Ubuntu Server.

The attempted username was `fakeuser`.

The source IP address, exact timestamp, and related authentication events must be verified using the collected server logs.

No successful unauthorized access or system compromise is established by this exercise.

## 7. Initial Assessment

The observed event represents an unsuccessful authentication attempt.

A single failed login is not sufficient evidence of a brute-force attack or successful compromise.

Further investigation would include:

- Checking for repeated attempts from the same source.
- Reviewing successful authentication events.
- Identifying targeted usernames.
- Correlating activity across authentication logs.

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
