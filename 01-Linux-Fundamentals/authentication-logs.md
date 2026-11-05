
# Linux Authentication Log Analysis

## Objective

Understand how Linux records authentication activity and how SOC analysts can use system logs to investigate suspicious login attempts.

## Log Sources

Primary log source:

- systemd journal
- SSH service logs
- Authentication-related sudo logs

## Commands Used

### 1. Review SSH Service Logs

```bash
sudo journalctl -u ssh --since "15 minutes ago"
```

### 2. Filter Failed SSH Authentication

```bash
sudo journalctl -u ssh --since "15 minutes ago" | grep -iE 'invalid user|failed password|authentication failure'
```

### 3. Review Sudo Activity

```bash
sudo journalctl --since "15 minutes ago" | grep -i sudo
```

### 4. Review Failed Login History

```bash
sudo lastb -n 10
```

Note: lastb relies on failed-login records maintained by the system. Results depend on the authentication logging configuration.

## Important Investigation Fields

| Field | Purpose |
|---|---|
| Timestamp | Establishes when activity occurred |
| Username | Identifies the targeted account |
| Source IP | Identifies the originating address |
| Authentication result | Determines success or failure |
| Service | Identifies SSH or another authentication service |

## SOC Analyst Considerations

- Identify repeated failed authentication attempts.
- Check for attempts against invalid usernames.
- Identify the source IP address.
- Review successful logins following failed attempts.
- Correlate events using timestamps.
- Determine whether activity is expected or suspicious.

## Learning Outcome

Practiced Linux authentication log analysis using journalctl and other command-line utilities.

