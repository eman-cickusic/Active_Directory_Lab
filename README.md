# Active Directory Security Lab Environment

## 🔍 Project Overview 
A comprehensive security lab environment demonstrating Active Directory configuration, monitoring, and attack simulation. This project showcases security monitoring using Splunk, Windows event collection with Sysmon, and penetration testing capabilities through Kali Linux.

## 🎯 Learning Objectives
- Active Directory deployment and configuration
- Enterprise logging and monitoring setup
- Security Information and Event Management (SIEM) implementation
- Attack detection and analysis
- Windows domain security hardening
 
## 🛠️ Technologies Used
- Windows Server 2019/2022 (Domain Controller)
- Windows 10 (Target Machine)
- Ubuntu Server (Splunk Server)
- Kali Linux (Attack Machine)
- Splunk Enterprise
- Sysmon
- VirtualBox
- Active Directory Domain Services

## 💻 System Requirements
- Minimum 16GB RAM
- 250GB available disk space
- Virtualization-capable CPU
- Oracle VirtualBox

## 📊 Network Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐
│  Domain         │    │  Windows 10      │    │  Kali Linux    │
│  Controller     │◄───┤  Target Machine  │◄───┤  (Attacker)    │
│  192.168.1.10   │    │  192.168.1.20    │    │  192.168.1.40  │
└─────────────┬───┘    └──────────┬───────┘    └────────────────┘
              │                    │
              │                    │
              ▼                    ▼
        ┌────────────────────────────────┐
        │        Ubuntu Server           │
        │     Splunk (192.168.1.30)      │
        └────────────────────────────────┘
```

## 🚀 Setup Instructions

### 1. VirtualBox Configuration
1. Download and install Oracle VirtualBox
2. Create a NAT Network:
   - VirtualBox > File > Preferences > Network
   - Add new NAT Network (192.168.1.0/24)

### 2. Domain Controller Setup
1. Install Windows Server 2019/2022
   - RAM: 4GB
   - CPU: 2 cores
   - Storage: 50GB
   - Network: NAT Network
   - Static IP: 192.168.1.10

2. Install Active Directory Domain Services:
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

3. Promote to Domain Controller:
```powershell
Install-ADDSForest `
-DomainName "lab.local" `
-DomainNetBIOSName "LAB" `
-InstallDNS `
-Force
```

### 3. Windows 10 Target Configuration
1. Install Windows 10
   - RAM: 4GB
   - CPU: 2 cores
   - Storage: 50GB
   - Network: NAT Network
   - Static IP: 192.168.1.20

2. Join to Domain:
   - System Properties > Computer Name > Change
   - Set DNS to Domain Controller IP
   - Member of Domain: lab.local

### 4. Splunk Setup (Ubuntu Server)
1. Install Ubuntu Server
   - RAM: 4GB
   - CPU: 2 cores
   - Storage: 50GB
   - Static IP: 192.168.1.30

2. Install Splunk Enterprise:
```bash
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/[version]/linux/splunk.tgz'
tar xvzf splunk.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license
```

### 5. Sysmon Configuration
1. Download and install Sysmon on DC and Target:
```powershell
# Download Sysmon
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile 'C:\Sysmon.zip'
Expand-Archive -Path 'C:\Sysmon.zip' -DestinationPath 'C:\Sysmon'

# Install with SwiftOnSecurity config
.\Sysmon.exe -i sysmonconfig-export.xml
```

### 6. Splunk Forwarder Setup
1. Install Universal Forwarder on Windows machines:
```powershell
# Install Splunk Universal Forwarder
msiexec.exe /i splunkforwarder.msi RECEIVING_INDEXER="192.168.1.30:9997" /quiet
```

2. Configure forwarding:
```
[tcpout]
defaultGroup = splunk_indexers
disabled = 0

[tcpout:splunk_indexers]
server = 192.168.1.30:9997
```

### 7. Kali Linux Configuration
1. Install Kali Linux
   - RAM: 2GB
   - CPU: 2 cores
   - Storage: 50GB
   - Static IP: 192.168.1.40

2. Update and install required tools:
```bash
apt update && apt upgrade -y
apt install crackmapexec hydra enum4linux -y
```

## 🔥 Attack Simulation
1. Create test users in Active Directory
2. Configure Splunk monitoring:
   - Create index: windows_events
   - Create search for failed login attempts
   - Set up alerts for brute force detection

3. Execute brute force attack from Kali:
```bash
hydra -L users.txt -P passwords.txt smb://192.168.1.20
```

## 📊 Monitoring and Detection

### Splunk Queries for Security Monitoring

1. Failed Login Detection:
```
index=windows_events EventCode=4625 
| stats count by Account_Name, Source_Network_Address, Logon_Type 
| where count > 5 
| sort -count 
| eval severity=case(count>50, "Critical", count>20, "High", count>10, "Medium", true(), "Low")
```

2. New Process Creation Monitoring:
```
index=windows_events EventCode=1 
| stats count by Image, ParentImage, CommandLine 
| where not match(Image, "(?i)(C:\\Windows\\System32|C:\\Program Files)") 
| sort -count
```

3. Lateral Movement Detection:
```
index=windows_events (EventCode=4624 OR EventCode=4625) Logon_Type=3 
| stats count by Source_Network_Address, Account_Name, Workstation_Name 
| where count > 3
```

4. PowerShell Command Monitoring:
```
index=windows_events EventCode=4104 
| rex field=Message "(?<ScriptBlock>ScriptBlock Text = (?s).*)" 
| where NOT match(ScriptBlock, "(?i)(Get-|Set-|Add-)")
| table _time, ScriptBlock, Computer
```

5. Suspicious Network Connections:
```
index=windows_events EventCode=3 
| stats count by SourceIp, DestinationIp, DestinationPort 
| where DestinationPort IN (445, 135, 139, 3389, 5985, 5986)
```

### Enhanced Dashboard Configuration

#### 1. Security Overview Dashboard
```xml
<dashboard>
  <label>Security Overview</label>
  <row>
    <panel>
      <title>Failed Login Attempts (Last 24 Hours)</title>
      <chart>
        <search>
          <query>index=windows_events EventCode=4625 
          | timechart count by Account_Name</query>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  <!-- Additional panels -->
</dashboard>
```

#### 2. Active Directory Health Dashboard
- Domain Controller Status
- Replication Status
- DNS Health
- FSMO Roles Status
- Account Lockouts

#### 3. Network Activity Dashboard
- Connection Matrix
- Port Usage Statistics
- Geographic IP Mapping
- Protocol Analysis

## 🎯 Additional Attack Scenarios

### 1. Kerberoasting Attack
```bash
# From Kali Linux
GetUserSPNs.py lab.local/user:password -dc-ip 192.168.1.10 -request

# Monitor with Splunk
index=windows_events EventCode=4769 Service_Name!="*$" 
| stats count by User_Name, Service_Name, Client_Address
```

### 2. Password Spraying
```bash
# Attack execution
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success

# Detection query
index=windows_events EventCode=4648 
| stats count by Target_Server_Name, Account_Name 
| where count > 10
```

### 3. DCSync Attack Simulation
```bash
# Using Mimikatz
lsadump::dcsync /domain:lab.local /user:krbtgt

# Detection
index=windows_events EventCode=4662 
| search Properties="*Replication-Get-Changes-All*" 
| stats count by Account_Name
```

### 4. Golden Ticket Attack
```powershell
# Monitor for potential Golden Ticket usage
index=windows_events (EventCode=4624 OR EventCode=4634) 
| transaction Account_Name maxspan=1h 
| where duration > 10800 
| table Account_Name, duration, Security_ID
```

## 🔧 Troubleshooting Guide

### Domain Controller Issues

1. Replication Problems
```powershell
# Check replication status
repadmin /showrepl
repadmin /replsummary

# Fix replication
repadmin /syncall /AdeP
```

2. DNS Issues
```powershell
# Verify DNS records
dcdiag /test:DNS /DnsDelegation
dnscmd /enumrecords domain.local @ NS

# Fix DNS registration
ipconfig /registerdns
```

### Splunk Connectivity Issues

1. Universal Forwarder Troubleshooting
```bash
# Check forwarder status
splunk list forward-server
splunk display input

# Reset forwarder
splunk clean all
splunk clone-prep-clear-config
```

2. Network Connectivity
```bash
# Test ports
Test-NetConnection -ComputerName 192.168.1.30 -Port 9997
netstat -ano | findstr 9997

# Check firewall
Get-NetFirewallRule | Where-Object {$_.LocalPort -eq 9997}
```

### Sysmon Logging Issues

1. Verify Service Status
```powershell
# Check service
Get-Service Sysmon

# Verify logging
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1
```

2. Configuration Validation
```powershell
# Export current config
sysmon -c

# Reload configuration
sysmon -c config.xml
```

### Active Directory Authentication Issues

1. Kerberos Troubleshooting
```powershell
# Check Kerberos tickets
klist
klist -li 0x3e7

# Reset Kerberos tickets
klist purge
```

2. Account Lockout Resolution
```powershell
# Find locked accounts
Search-ADAccount -LockedOut

# Unlock account
Unlock-ADAccount -Identity username
```

## 🏗️ Lab Maintenance

### Regular Maintenance Tasks
1. Weekly Tasks:
   - Windows Updates
   - Splunk Log Rotation
   - Backup Domain Controller System State
   - Review Security Logs

2. Monthly Tasks:
   - Password Rotation
   - Group Policy Review
   - Network Configuration Audit
   - Update Attack Tools and Signatures

### Performance Optimization
1. Domain Controller:
   - Clean System State Backup
   - Defragment Database
   - Review and Clean Logs

2. Splunk:
   - Index Optimization
   - Search Head Optimization
   - Cache Management

## 📚 Documentation and Learning Resources
- [Microsoft Active Directory Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
- [Splunk Documentation](https://docs.splunk.com/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

---
