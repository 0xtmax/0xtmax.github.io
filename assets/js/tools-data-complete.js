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
      id: "dnsrecon",
      name: "DNSrecon",
      description: "DNS enumeration script written in Python that provides comprehensive DNS reconnaissance capabilities.",
      category: "Information Gathering",
      commands: [
        { cmd: "dnsrecon -d example.com", desc: "Basic DNS reconnaissance" },
        { cmd: "dnsrecon -d example.com -t axfr", desc: "Attempt zone transfer" },
        { cmd: "dnsrecon -d example.com -t brt -D /path/to/wordlist.txt", desc: "Brute force subdomains" }
      ],
      docs: "https://github.com/darkoperator/dnsrecon"
    },
    {
      id: "theharvester",
      name: "theHarvester",
      description: "Tool for gathering e-mail accounts, subdomain names, virtual hosts, open ports, and banners from different public sources like search engines and PGP key servers.",
      category: "Information Gathering",
      commands: [
        { cmd: "theHarvester -d example.com -b google", desc: "Search domain in Google" },
        { cmd: "theHarvester -d example.com -b all", desc: "Search domain in all sources" },
        { cmd: "theHarvester -d example.com -b linkedin -l 500", desc: "Search LinkedIn with 500 results limit" }
      ],
      docs: "https://github.com/laramies/theHarvester"
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
    {
      id: "maltego",
      name: "Maltego",
      description: "Visual link analysis tool that displays relationships between entities on a graph for easy analysis and data mining.",
      category: "Information Gathering",
      commands: [
        { cmd: "maltego", desc: "Launch Maltego GUI" },
        { cmd: "# Create a new graph: File > New > Detailed Graph", desc: "Start a new investigation" },
        { cmd: "# Add entity: Right-click > Add Entity", desc: "Add domain, IP, person, etc." },
        { cmd: "# Run transform: Right-click entity > Run Transforms", desc: "Gather information about entity" }
      ],
      docs: "https://docs.maltego.com/"
    },
    {
      id: "netdiscover",
      name: "Netdiscover",
      description: "Active/passive ARP reconnaissance tool to discover hosts on a local network without sending packets to the targets.",
      category: "Information Gathering",
      commands: [
        { cmd: "netdiscover", desc: "Auto scan local network" },
        { cmd: "netdiscover -r 192.168.1.0/24", desc: "Scan specific range" },
        { cmd: "netdiscover -i eth0 -P", desc: "Passive mode on interface eth0" }
      ],
      docs: "https://github.com/alexxy/netdiscover"
    },
    {
      id: "fierce",
      name: "Fierce",
      description: "Semi-lightweight DNS scanner that helps locate non-contiguous IP space and hostnames against domains.",
      category: "Information Gathering",
      commands: [
        { cmd: "fierce --domain example.com", desc: "Basic domain scan" },
        { cmd: "fierce --domain example.com --subdomains subdomains.txt", desc: "Use custom subdomain list" },
        { cmd: "fierce --domain example.com --dns-servers 8.8.8.8", desc: "Use specific DNS server" }
      ],
      docs: "https://github.com/mschwager/fierce"
    },
    {
      id: "shodan",
      name: "Shodan",
      description: "Search engine for Internet-connected devices, allowing users to find specific devices and explore their vulnerabilities.",
      category: "Information Gathering",
      commands: [
        { cmd: "shodan init YOUR_API_KEY", desc: "Initialize with API key" },
        { cmd: "shodan search apache", desc: "Search for Apache servers" },
        { cmd: "shodan host 8.8.8.8", desc: "Get information about an IP" },
        { cmd: "shodan scan submit 192.168.1.0/24", desc: "Submit network for scanning (requires credits)" }
      ],
      docs: "https://cli.shodan.io/"
    },
    
    // Vulnerability Analysis
    {
      id: "nikto",
      name: "Nikto",
      description: "Web server scanner that performs comprehensive tests against web servers for multiple items, including dangerous files, outdated versions, and version-specific problems.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "nikto -h example.com", desc: "Basic scan of a website" },
        { cmd: "nikto -h example.com -ssl", desc: "Scan using SSL" },
        { cmd: "nikto -h example.com -p 80,443", desc: "Scan specific ports" },
        { cmd: "nikto -h example.com -Tuning x 6", desc: "Scan for XSS vulnerabilities" }
      ],
      docs: "https://github.com/sullo/nikto/wiki"
    },
    {
      id: "openvas",
      name: "OpenVAS",
      description: "Open Vulnerability Assessment Scanner, a full-featured vulnerability scanner with thousands of vulnerability tests.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "gvm-start", desc: "Start GVM/OpenVAS services" },
        { cmd: "gvm-check-setup", desc: "Check setup" },
        { cmd: "gvmd --create-scanner=Scanner --scanner-type=OpenVAS", desc: "Create scanner" },
        { cmd: "gvmd --create-target=Target --hosts=192.168.1.1", desc: "Create target" },
        { cmd: "gvmd --create-task=ScanTask --scanner=Scanner --target=Target", desc: "Create scan task" }
      ],
      docs: "https://greenbone.github.io/docs/"
    },
    {
      id: "lynis",
      name: "Lynis",
      description: "Security auditing tool for Unix/Linux systems that performs detailed security scans to detect software and security issues.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "lynis audit system", desc: "Perform full system audit" },
        { cmd: "lynis audit system --quick", desc: "Quick system scan" },
        { cmd: "lynis show groups", desc: "Show available test groups" },
        { cmd: "lynis audit system --tests-from-group malware", desc: "Run specific test group" }
      ],
      docs: "https://cisofy.com/documentation/lynis/"
    },
    {
      id: "nuclei",
      name: "Nuclei",
      description: "Fast and customizable vulnerability scanner based on templates that can be used to send requests across multiple targets.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "nuclei -u https://example.com", desc: "Basic scan of a target" },
        { cmd: "nuclei -l urls.txt", desc: "Scan multiple targets from a list" },
        { cmd: "nuclei -u https://example.com -t cves/", desc: "Scan for CVEs" },
        { cmd: "nuclei -u https://example.com -severity critical,high", desc: "Scan for critical and high severity issues" }
      ],
      docs: "https://nuclei.projectdiscovery.io/nuclei/get-started/"
    },
    {
      id: "searchsploit",
      name: "Searchsploit",
      description: "Command-line search tool for Exploit-DB that allows you to search for exploits and shellcode from the local exploit database.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "searchsploit apache 2.4.7", desc: "Search for Apache 2.4.7 exploits" },
        { cmd: "searchsploit -t oracle windows", desc: "Search for Oracle exploits on Windows" },
        { cmd: "searchsploit -m 12345", desc: "Copy exploit to current directory" },
        { cmd: "searchsploit --update", desc: "Update the exploit database" }
      ],
      docs: "https://www.exploit-db.com/searchsploit"
    },
    {
      id: "vulners",
      name: "Vulners",
      description: "Vulnerability database search tool that allows you to search for CVEs and exploits from the command line.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "vulners search apache 2.4.7", desc: "Search for Apache 2.4.7 vulnerabilities" },
        { cmd: "vulners search CVE-2021-44228", desc: "Search for a specific CVE" },
        { cmd: "vulners get CVE-2021-44228", desc: "Get details for a specific CVE" }
      ],
      docs: "https://github.com/vulnersCom/vulners-scanner"
    },
    {
      id: "w3af",
      name: "w3af",
      description: "Web Application Attack and Audit Framework designed to identify and exploit vulnerabilities in web applications.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "w3af_console", desc: "Start w3af console" },
        { cmd: "# In w3af console: profiles", desc: "List available profiles" },
        { cmd: "# In w3af console: target set target https://example.com", desc: "Set target" },
        { cmd: "# In w3af console: start", desc: "Start the scan" }
      ],
      docs: "http://docs.w3af.org/"
    },
    {
      id: "davtest",
      name: "DAVTest",
      description: "Tests WebDAV enabled servers for various vulnerabilities and insecure configurations.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "davtest -url http://example.com/webdav/", desc: "Test WebDAV server" },
        { cmd: "davtest -url http://example.com/webdav/ -auth user:pass", desc: "Test with authentication" },
        { cmd: "davtest -url http://example.com/webdav/ -uploadfile /path/to/file", desc: "Test with specific file upload" }
      ],
      docs: "https://github.com/cldrn/davtest"
    },
    {
      id: "unix-privesc-check",
      name: "unix-privesc-check",
      description: "Script that checks for misconfigurations that could allow local privilege escalation on Unix systems.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "unix-privesc-check standard", desc: "Run standard checks" },
        { cmd: "unix-privesc-check detailed", desc: "Run detailed checks" },
        { cmd: "unix-privesc-check standard > output.txt", desc: "Save output to file" }
      ],
      docs: "https://github.com/pentestmonkey/unix-privesc-check"
    },
    {
      id: "linpeas",
      name: "LinPEAS",
      description: "Linux Privilege Escalation Awesome Script that searches for possible paths to escalate privileges on Linux/Unix hosts.",
      category: "Vulnerability Analysis",
      commands: [
        { cmd: "./linpeas.sh", desc: "Run basic scan" },
        { cmd: "./linpeas.sh -a", desc: "Run all checks" },
        { cmd: "./linpeas.sh -s", desc: "Run with stealth mode (less output)" },
        { cmd: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", desc: "Download and run in one command" }
      ],
      docs: "https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS"
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
      id: "owasp-zap",
      name: "OWASP ZAP",
      description: "Open-source web application security scanner that finds vulnerabilities in web applications. It's designed to be used by people with a wide range of security experience.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "zap", desc: "Launch ZAP GUI" },
        { cmd: "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' https://example.com", desc: "Quick scan from command line" },
        { cmd: "# Automated scan: Automated Scan > URL to attack > Attack", desc: "Run automated scan from GUI" },
        { cmd: "# Spider: Right-click site > Attack > Spider", desc: "Crawl website for links" }
      ],
      docs: "https://www.zaproxy.org/docs/"
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
    {
      id: "xsser",
      name: "XSSer",
      description: "Automated framework to detect, exploit and report XSS vulnerabilities in web applications.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "xsser --url \"http://example.com/page.php?id=1\"", desc: "Basic XSS scan" },
        { cmd: "xsser --url \"http://example.com/page.php?id=1\" --auto", desc: "Automatic XSS testing" },
        { cmd: "xsser --url \"http://example.com/page.php?id=1\" --Fp \"<script>alert('XSS')</script>\"", desc: "Test specific payload" },
        { cmd: "xsser --url \"http://example.com/page.php?id=1\" --cookie=\"PHPSESSID=value\"", desc: "Test with cookie" }
      ],
      docs: "https://github.com/epsylon/xsser"
    },
    {
      id: "wpscan",
      name: "WPScan",
      description: "WordPress vulnerability scanner that checks for known vulnerabilities in WordPress core, plugins, and themes.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "wpscan --url https://example.com", desc: "Basic WordPress scan" },
        { cmd: "wpscan --url https://example.com --enumerate u", desc: "Enumerate users" },
        { cmd: "wpscan --url https://example.com --enumerate vp", desc: "Enumerate vulnerable plugins" },
        { cmd: "wpscan --url https://example.com --passwords wordlist.txt", desc: "Password brute force" }
      ],
      docs: "https://github.com/wpscanteam/wpscan"
    },
    {
      id: "dirb",
      name: "Dirb",
      description: "Web content scanner that looks for existing (and/or hidden) web objects by launching a dictionary-based attack against a web server.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "dirb http://example.com", desc: "Basic directory scan" },
        { cmd: "dirb http://example.com /usr/share/dirb/wordlists/big.txt", desc: "Use specific wordlist" },
        { cmd: "dirb http://example.com -a 'Mozilla/5.0'", desc: "Set custom user agent" },
        { cmd: "dirb http://example.com -x .php,.txt,.html", desc: "Scan for specific extensions" }
      ],
      docs: "https://tools.kali.org/web-applications/dirb"
    },
    {
      id: "gobuster",
      name: "Gobuster",
      description: "Directory/file and DNS busting tool written in Go that brute forces URIs (directories and files) in web sites and DNS subdomains.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "gobuster dir -u http://example.com -w wordlist.txt", desc: "Directory scan" },
        { cmd: "gobuster dns -d example.com -w wordlist.txt", desc: "DNS subdomain scan" },
        { cmd: "gobuster dir -u http://example.com -w wordlist.txt -x php,txt,html", desc: "Scan for specific extensions" },
        { cmd: "gobuster dir -u http://example.com -w wordlist.txt -c 'PHPSESSID=value'", desc: "Scan with cookie" }
      ],
      docs: "https://github.com/OJ/gobuster"
    },
    {
      id: "ffuf",
      name: "ffuf",
      description: "Fast web fuzzer written in Go that allows for fuzzing of various aspects of web applications, including directories, files, parameters, and more.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "ffuf -w wordlist.txt -u http://example.com/FUZZ", desc: "Directory fuzzing" },
        { cmd: "ffuf -w wordlist.txt -u http://example.com/FUZZ.php", desc: "File fuzzing with extension" },
        { cmd: "ffuf -w wordlist.txt -u http://example.com/ -H 'Cookie: FUZZ=value'", desc: "Header fuzzing" },
        { cmd: "ffuf -w wordlist.txt -u http://example.com/?param=FUZZ", desc: "Parameter value fuzzing" }
      ],
      docs: "https://github.com/ffuf/ffuf"
    },
    {
      id: "nikto-web",
      name: "Nikto",
      description: "Web server scanner that performs comprehensive tests against web servers for multiple items, including dangerous files, outdated versions, and version-specific problems.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "nikto -h example.com", desc: "Basic scan of a website" },
        { cmd: "nikto -h example.com -ssl", desc: "Scan using SSL" },
        { cmd: "nikto -h example.com -p 80,443", desc: "Scan specific ports" },
        { cmd: "nikto -h example.com -Tuning x 6", desc: "Scan for XSS vulnerabilities" }
      ],
      docs: "https://github.com/sullo/nikto/wiki"
    },
    {
      id: "whatweb",
      name: "WhatWeb",
      description: "Next generation web scanner that identifies websites, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.",
      category: "Web Application Analysis",
      commands: [
        { cmd: "whatweb example.com", desc: "Basic scan" },
        { cmd: "whatweb example.com -v", desc: "Verbose output" },
        { cmd: "whatweb example.com --aggression 3", desc: "More aggressive scan" },
        { cmd: "whatweb -i targets.txt", desc: "Scan multiple targets from file" }
      ],
      docs: "https://github.com/urbanadventurer/WhatWeb"
    }, 
    // Password Attacks
    {
      id: "hydra",
      name: "Hydra",
      description: "Brute-force login cracker",
      category: "Password Attacks",
      commands: [
        { cmd: "hydra -l user -P wordlist.txt target ssh", desc: "SSH brute force" }
      ],
      docs: "https://github.com/frizb/Hydra-Cheatsheet"
    },
    {
      id: "john",
      name: "John the Ripper",
      description: "Password cracker",
      category: "Password Attacks",
      commands: [
        { cmd: "john hashes.txt", desc: "Basic password cracking" }
      ],
      docs: "https://www.openwall.com/john/doc/"
    },
    {
      id: "hashcat",
      name: "Hashcat",
      description: "GPU password cracker",
      category: "Password Attacks",
      commands: [
        { cmd: "hashcat -m 0 hashes.txt wordlist.txt", desc: "Crack MD5 hashes" }
      ],
      docs: "https://hashcat.net/wiki/"
    },
    {
      id: "cewl",
      name: "CeWL",
      description: "Custom wordlist generator",
      category: "Password Attacks",
      commands: [
        { cmd: "cewl example.com -w wordlist.txt", desc: "Generate wordlist from website" }
      ],
      docs: "https://github.com/digininja/CeWL"
    },
    {
      id: "crunch",
      name: "Crunch",
      description: "Wordlist generator",
      category: "Password Attacks",
      commands: [
        { cmd: "crunch 8 12 -o wordlist.txt", desc: "Generate wordlist of 8-12 chars" }
      ],
      docs: "https://tools.kali.org/password-attacks/crunch"
    },
    {
      id: "medusa",
      name: "Medusa",
      description: "Login brute-forcer",
      category: "Password Attacks",
      commands: [
        { cmd: "medusa -h target -u user -P wordlist.txt -M ssh", desc: "SSH brute force" }
      ],
      docs: "https://github.com/jmk-foofus/medusa"
    },
    {
      id: "rsmangler",
      name: "RSMangler",
      description: "Wordlist mangling tool",
      category: "Password Attacks",
      commands: [
        { cmd: "cat wordlist.txt | rsmangler", desc: "Mangle wordlist" }
      ],
      docs: "https://github.com/digininja/RSMangler"
    },
    {
      id: "johnny",
      name: "Johnny",
      description: "GUI for John the Ripper",
      category: "Password Attacks",
      commands: [
        { cmd: "johnny", desc: "Open GUI password cracker" }
      ],
      docs: "https://github.com/openwall/johnny"
    },
    {
      id: "rainbowcrack",
      name: "RainbowCrack",
      description: "Cracks hashes using rainbow tables",
      category: "Password Attacks",
      commands: [
        { cmd: "rtgen md5 loweralpha 1 7 0 1000 0", desc: "Generate rainbow table" }
      ],
      docs: "https://project-rainbowcrack.com/index.htm"
    },
    {
      id: "ophcrack",
      name: "Ophcrack",
      description: "Windows password cracker",
      category: "Password Attacks",
      commands: [
        { cmd: "ophcrack", desc: "Launch Windows password cracker" }
      ],
      docs: "https://ophcrack.sourceforge.io/"
    },
    
    // Wireless Attacks
    {
      id: "aircrack-ng",
      name: "Aircrack-ng",
      description: "Crack WiFi passwords",
      category: "Wireless Attacks",
      commands: [
        { cmd: "aircrack-ng capture.cap -w wordlist.txt", desc: "Crack WiFi password" }
      ],
      docs: "https://www.aircrack-ng.org/doku.php?id=tutorial"
    },
    {
      id: "reaver",
      name: "Reaver",
      description: "WPS attack tool",
      category: "Wireless Attacks",
      commands: [
        { cmd: "reaver -i wlan0mon -b BSSID -vv", desc: "WPS brute force attack" }
      ],
      docs: "https://github.com/t6x/reaver-wps-fork-t6x"
    },
    {
      id: "wifite",
      name: "Wifite",
      description: "Automated WiFi attacks",
      category: "Wireless Attacks",
      commands: [
        { cmd: "wifite", desc: "Automated WiFi cracking" }
      ],
      docs: "https://github.com/derv82/wifite2"
    },
    {
      id: "kismet",
      name: "Kismet",
      description: "Wireless detector/sniffer",
      category: "Wireless Attacks",
      commands: [
        { cmd: "kismet", desc: "Start wireless detection" }
      ],
      docs: "https://www.kismetwireless.net/"
    },
    {
      id: "fern-wifi-cracker",
      name: "Fern WiFi Cracker",
      description: "GUI WiFi cracker",
      category: "Wireless Attacks",
      commands: [
        { cmd: "fern-wifi-cracker", desc: "Launch GUI WiFi cracker" }
      ],
      docs: "https://github.com/savio-code/fern-wifi-cracker"
    },
    {
      id: "bully",
      name: "Bully",
      description: "WPS brute force attack tool",
      category: "Wireless Attacks",
      commands: [
        { cmd: "bully wlan0mon -b BSSID", desc: "WPS brute force" }
      ],
      docs: "https://github.com/aanarchyy/bully"
    },
    {
      id: "wifi-phisher",
      name: "WiFi Phisher",
      description: "Rogue AP phishing",
      category: "Wireless Attacks",
      commands: [
        { cmd: "wifiphisher", desc: "Launch WiFi phishing attack" }
      ],
      docs: "https://github.com/wifiphisher/wifiphisher"
    },
    {
      id: "airodump-ng",
      name: "Airodump-ng",
      description: "Capture wireless traffic",
      category: "Wireless Attacks",
      commands: [
        { cmd: "airodump-ng wlan0mon", desc: "Capture wireless traffic" }
      ],
      docs: "https://www.aircrack-ng.org/doku.php?id=airodump-ng"
    },
    {
      id: "airolib-ng",
      name: "Airolib-ng",
      description: "Precompute WPA tables",
      category: "Wireless Attacks",
      commands: [
        { cmd: "airolib-ng db --import essid essids.txt", desc: "Import ESSID list" }
      ],
      docs: "https://www.aircrack-ng.org/doku.php?id=airolib-ng"
    },
    {
      id: "mdk3",
      name: "MDK3",
      description: "DoS and fuzzing wireless",
      category: "Wireless Attacks",
      commands: [
        { cmd: "mdk3 wlan0mon b -c 6", desc: "Beacon flood attack" }
      ],
      docs: "https://github.com/aircrack-ng/mdk4"
    },
    
    // Exploitation Tools
    {
      id: "metasploit-framework",
      name: "Metasploit Framework",
      description: "Exploitation framework",
      category: "Exploitation Tools",
      commands: [
        { cmd: "msfconsole", desc: "Start Metasploit console" }
      ],
      docs: "https://www.metasploit.com/documentation"
    },
    {
      id: "beef",
      name: "BeEF",
      description: "Browser exploitation",
      category: "Exploitation Tools",
      commands: [
        { cmd: "beef-xss", desc: "Start BeEF" }
      ],
      docs: "https://beefproject.com/"
    },
    {
      id: "msfvenom",
      name: "MSFvenom",
      description: "Payload generator",
      category: "Exploitation Tools",
      commands: [
        { cmd: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe", desc: "Generate Windows payload" }
      ],
      docs: "https://www.offensive-security.com/metasploit-unleashed/msfvenom/"
    },
    {
      id: "exploitdb",
      name: "Exploit-DB",
      description: "Exploit search tool",
      category: "Exploitation Tools",
      commands: [
        { cmd: "searchsploit apache", desc: "Search for Apache exploits" }
      ],
      docs: "https://www.exploit-db.com/"
    },
    {
      id: "setoolkit",
      name: "Social Engineering Toolkit",
      description: "Social engineering",
      category: "Exploitation Tools",
      commands: [
        { cmd: "setoolkit", desc: "Launch SET" }
      ],
      docs: "https://github.com/trustedsec/social-engineer-toolkit"
    },
    {
      id: "armitage",
      name: "Armitage",
      description: "GUI for Metasploit",
      category: "Exploitation Tools",
      commands: [
        { cmd: "armitage", desc: "Launch Metasploit GUI" }
      ],
      docs: "https://www.offensive-security.com/metasploit-unleashed/armitage/"
    },
    {
      id: "veil",
      name: "Veil Framework",
      description: "AV-evading payloads",
      category: "Exploitation Tools",
      commands: [
        { cmd: "veil-evasion", desc: "Generate AV-evading payload" }
      ],
      docs: "https://github.com/Veil-Framework/Veil"
    },
    {
      id: "shellnoob",
      name: "Shellnoob",
      description: "Shellcode writing tool",
      category: "Exploitation Tools",
      commands: [
        { cmd: "shellnoob", desc: "Shellcode development kit" }
      ],
      docs: "https://github.com/reyammer/shellnoob"
    },
    {
      id: "empire",
      name: "Empire",
      description: "PowerShell post-exploitation",
      category: "Exploitation Tools",
      commands: [
        { cmd: "empire", desc: "Start Empire framework" }
      ],
      docs: "https://github.com/BC-SECURITY/Empire"
    },
    
    // Sniffing & Spoofing
    {
      id: "wireshark",
      name: "Wireshark",
      description: "Network analyzer",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "wireshark", desc: "Launch network packet analyzer" }
      ],
      docs: "https://www.wireshark.org/docs/"
    },
    {
      id: "ettercap",
      name: "Ettercap",
      description: "MITM attacks",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "ettercap -T -q -i eth0", desc: "Text-mode MITM sniffing" }
      ],
      docs: "https://www.ettercap-project.org/documentation.html"
    },
    {
      id: "dsniff",
      name: "dsniff",
      description: "Password sniffer",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "dsniff -i eth0", desc: "Network password sniffer" }
      ],
      docs: "https://www.monkey.org/~dugsong/dsniff/"
    },
    {
      id: "mitmproxy",
      name: "mitmproxy",
      description: "Interactive HTTPS proxy",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "mitmproxy", desc: "Launch interactive proxy" }
      ],
      docs: "https://mitmproxy.org/"
    },
    {
      id: "bettercap",
      name: "Bettercap",
      description: "MITM + network attack tool",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "bettercap", desc: "Launch network attack tool" }
      ],
      docs: "https://www.bettercap.org/"
    },
    {
      id: "tcpdump",
      name: "tcpdump",
      description: "Packet capture",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "tcpdump -i eth0", desc: "Capture network packets" }
      ],
      docs: "https://www.tcpdump.org/"
    },
    {
      id: "macchanger",
      name: "Macchanger",
      description: "MAC address spoofing",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "macchanger -r eth0", desc: "Randomize MAC address" }
      ],
      docs: "https://github.com/alobbs/macchanger"
    },
    {
      id: "netsniff-ng",
      name: "Netsniff-ng",
      description: "Packet sniffing toolkit",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "netsniff-ng --dev eth0", desc: "Capture network packets" }
      ],
      docs: "https://netsniff-ng.org/"
    },
    {
      id: "responder",
      name: "Responder",
      description: "LLMNR/NBTNS poisoner",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "responder -I eth0", desc: "Launch LLMNR/NBTNS poisoner" }
      ],
      docs: "https://github.com/SpiderLabs/Responder"
    },
    {
      id: "sniffglue",
      name: "Sniffglue",
      description: "Rust-based packet sniffer",
      category: "Sniffing & Spoofing",
      commands: [
        { cmd: "sniffglue eth0", desc: "Capture network packets" }
      ],
      docs: "https://github.com/kpcyrd/sniffglue"
    },
    
    // Post Exploitation
    {
      id: "meterpreter",
      name: "Meterpreter",
      description: "Post-exploit shell",
      category: "Post Exploitation",
      commands: [
        { cmd: "sysinfo", desc: "Get system information" }
      ],
      docs: "https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/"
    },
    {
      id: "empire",
      name: "Empire",
      description: "PowerShell post-exploitation",
      category: "Post Exploitation",
      commands: [
        { cmd: "empire", desc: "Start Empire framework" }
      ],
      docs: "https://github.com/BC-SECURITY/Empire"
    },
    {
      id: "pupy",
      name: "Pupy",
      description: "Remote access tool",
      category: "Post Exploitation",
      commands: [
        { cmd: "pupy", desc: "Launch Pupy RAT" }
      ],
      docs: "https://github.com/n1nj4sec/pupy"
    },
    {
      id: "crackmapexec",
      name: "CrackMapExec",
      description: "Network exploitation tool",
      category: "Post Exploitation",
      commands: [
        { cmd: "crackmapexec smb 192.168.1.0/24", desc: "Scan SMB network" }
      ],
      docs: "https://github.com/byt3bl33d3r/CrackMapExec"
    },
    {
      id: "postenum",
      name: "PostEnum",
      description: "Linux post-exploitation",
      category: "Post Exploitation",
      commands: [
        { cmd: "postenum", desc: "Enumerate system information" }
      ],
      docs: "https://github.com/mbahadou/postenum"
    },
    {
      id: "bloodhound",
      name: "BloodHound",
      description: "Active Directory enumeration",
      category: "Post Exploitation",
      commands: [
        { cmd: "bloodhound", desc: "Launch AD enumeration tool" }
      ],
      docs: "https://github.com/BloodHoundAD/BloodHound"
    },
    {
      id: "powerview",
      name: "PowerView",
      description: "PowerShell AD recon tool",
      category: "Post Exploitation",
      commands: [
        { cmd: "Import-Module PowerView", desc: "Import PowerView module" }
      ],
      docs: "https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon"
    },
    {
      id: "secretdump",
      name: "Secretsdump.py",
      description: "Dump secrets from SAM",
      category: "Post Exploitation",
      commands: [
        { cmd: "secretsdump.py", desc: "Dump system secrets" }
      ],
      docs: "https://github.com/SecureAuthCorp/impacket"
    },
    {
      id: "impacket",
      name: "Impacket",
      description: "Python library for AD attacks",
      category: "Post Exploitation",
      commands: [
        { cmd: "python3 -m pip install impacket", desc: "Install Impacket" }
      ],
      docs: "https://github.com/SecureAuthCorp/impacket"
    },
    {
      id: "mimikatz",
      name: "Mimikatz",
      description: "Credential dumping",
      category: "Post Exploitation",
      commands: [
        { cmd: "mimikatz", desc: "Launch Mimikatz" }
      ],
      docs: "https://github.com/gentilkiwi/mimikatz"
    }
  ]
};

// Make the database available globally
window.toolsDatabase = toolsDatabase;
