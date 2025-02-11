# Active Directory Security Lab Environment

## 🔍 Project Overview
A comprehensive security lab environment demonstrating Active Directory configuration, monitoring, and attack simulation. This project showcases enterprise-level security monitoring using Splunk, Windows event collection with Sysmon, and penetration testing capabilities through Kali Linux.

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
│  192.168.1.10   │    │  192.168.1.20   │    │  192.168.1.40  │
└─────────────┬───┘    └──────────┬───────┘    └────────────────┘
              │                    │
              │                    │
              ▼                    ▼
        ┌────────────────────────────────┐
        │        Ubuntu Server           │
        │     Splunk (192.168.1.30)     │
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
1. Splunk search for failed login attempts:
```
index=windows_events EventCode=4625 
| stats count by Account_Name, Source_Network_Address 
| where count > 5
```

2. Create dashboard for:
   - Failed login attempts
   - Successful authentications
   - Suspicious process creation
   - Network connections

## 🔒 Security Considerations
- Lab environment should be isolated from production networks
- Strong passwords for administrative accounts
- Regular system updates
- Network segmentation
- Limited user privileges

## 📚 Documentation and Learning Resources
- [Microsoft Active Directory Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
- [Splunk Documentation](https://docs.splunk.com/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

---
