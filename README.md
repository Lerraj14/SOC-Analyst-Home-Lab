# SOC-Analyst-Home-Lab
Project and Documentation for SOC Analyst

## Overview

This repository documents my hands-on cybersecurity home lab as I develop my skills toward becoming a SOC Analyst.

The lab uses VMware Workstation Pro and Ubuntu Server to practice Linux administration, security monitoring, log analysis, authentication investigation, and incident response.

## Lab Environment

| Component | Configuration |
|---|---|
| Host OS | Windows 11 |
| Hypervisor | VMware Workstation Pro |
| Virtual Machine | SOC-Ubuntu-01 |
| Operating System | Ubuntu Server 26.04.1 LTS |
| RAM | 2 GB |
| CPU | 2 vCPUs |
| Virtual Disk | 28 GB |
| Network | VMware NAT |
| SSH | Enabled |

## Learning Objectives

- Understand Linux system administration.
- Configure and manage SSH services.
- Analyze Linux authentication logs.
- Investigate suspicious login attempts.
- Understand security event timelines.
- Practice SOC L1 investigation methodologies.
- Develop incident documentation and reporting skills.
- Learn SIEM implementation and monitoring.

## Repository Structure

- `01-Linux-Fundamentals/` - Linux commands and authentication log analysis.
- `02-Incident-Investigations/` - Hands-on security investigations and reports.
- `03-SIEM/` - SIEM deployment and security monitoring exercises.
- `Screenshots/` - Evidence of lab configuration and investigation activities.

## Practical Investigations

### Incident 001: Suspicious SSH Authentication Attempt

Simulated an unsuccessful SSH login attempt against the Ubuntu Server virtual machine.

Investigation activities:
- Generated an unsuccessful SSH authentication attempt.
- Reviewed SSH service logs using journalctl.
- Identified the attempted username and source information.
- Reviewed authentication activity.
- Documented findings and recommendations.

## Tools and Technologies

- VMware Workstation Pro
- Ubuntu Server
- Linux CLI
- OpenSSH
- UFW Firewall
- systemd journalctl
- GitHub

## Disclaimer

All activities documented in this repository are performed in an isolated, controlled home lab environment for educational purposes.

No unauthorized systems are targeted.

## Author

Cybersecurity learner | CompTIA Security+ certified | Aspiring SOC Analyst L1
