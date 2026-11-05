
# Linux Commands for SOC Analysts

## Objective

Document essential Linux commands used for system administration, security monitoring, troubleshooting, and incident investigation.

## 1. System Information

| Command | Description |
|---|---|
| hostnamectl | Displays system information |
| uname -a | Displays kernel information |
| uptime | Shows system uptime |
| free -h | Displays memory usage |
| df -h | Displays disk usage |

## 2. User and Session Investigation

| Command | Description |
|---|---|
| who | Shows logged-in users |
| w | Displays active user sessions |
| last -n 10 | Displays recent login history |
| id | Displays user and group information |
| lastb -n 10 | Displays recorded failed login attempts |

## 3. Log Investigation

| Command | Description |
|---|---|
| journalctl | Displays system journal logs |
| journalctl -u ssh | Displays SSH service logs |
| journalctl -p warning | Displays warning-level events and above |
| journalctl --since "1 hour ago" | Filters recent logs |
| grep -i | Searches logs without case sensitivity |

## 4. Network Investigation

| Command | Description |
|---|---|
| ip addr | Displays network interfaces |
| ss -tulpn | Displays listening ports and processes |
| ping | Tests network connectivity |
| hostname -I | Displays assigned IP addresses |

## 5. Process Investigation

| Command | Description |
|---|---|
| ps aux | Displays running processes |
| top | Monitors system processes |
| systemctl --failed | Displays failed system services |

## Practical Application

These commands were used during the initial configuration of SOC-Ubuntu-01 and the investigation of simulated SSH authentication activity.

## Key Takeaway

Linux command-line proficiency is essential for SOC analysts when reviewing authentication activity, identifying suspicious processes, analyzing system logs, and troubleshooting security events.

