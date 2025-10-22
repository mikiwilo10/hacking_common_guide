                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ nmap -sS -p- --open --min-rate 5000 -Pn -n 192.168.56.10 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 18:45 EDT
Nmap scan report for 192.168.56.10
Host is up (0.00036s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
55231/tcp open  unknown
55233/tcp open  unknown
57947/tcp open  unknown
57964/tcp open  unknown
MAC Address: 08:00:27:26:46:E5 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
                                                                                                                                                 
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','                                                              
135,139,3268,3269,389,445,464,49664,49668,53,55231,55233,57947,57964,593,5985,636,80,88,9389
                                                                                                                                                 
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ nmap -sVC -p135,139,3268,3269,389,445,464,49664,49668,53,55231,55233,57947,57964,593,5985,636,80,88,9389 -vvv -n -Pn 192.168.56.10 -oN fullscan.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 18:47 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:47
Completed NSE at 18:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:47
Completed NSE at 18:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:47
Completed NSE at 18:47, 0.00s elapsed
Initiating ARP Ping Scan at 18:47
Scanning 192.168.56.10 [1 port]
Completed ARP Ping Scan at 18:47, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:47
Scanning 192.168.56.10 [20 ports]
Discovered open port 445/tcp on 192.168.56.10
Discovered open port 135/tcp on 192.168.56.10
Discovered open port 53/tcp on 192.168.56.10
Discovered open port 139/tcp on 192.168.56.10
Discovered open port 80/tcp on 192.168.56.10
Discovered open port 389/tcp on 192.168.56.10
Discovered open port 88/tcp on 192.168.56.10
Discovered open port 55231/tcp on 192.168.56.10
Discovered open port 9389/tcp on 192.168.56.10
Discovered open port 49664/tcp on 192.168.56.10
Discovered open port 5985/tcp on 192.168.56.10
Discovered open port 3269/tcp on 192.168.56.10
Discovered open port 464/tcp on 192.168.56.10
Discovered open port 636/tcp on 192.168.56.10
Discovered open port 3268/tcp on 192.168.56.10
Discovered open port 57947/tcp on 192.168.56.10
Discovered open port 593/tcp on 192.168.56.10
Discovered open port 55233/tcp on 192.168.56.10
Discovered open port 49668/tcp on 192.168.56.10
Discovered open port 57964/tcp on 192.168.56.10
Completed SYN Stealth Scan at 18:47, 0.02s elapsed (20 total ports)
Initiating Service scan at 18:47
Scanning 20 services on 192.168.56.10
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Completed Service scan at 18:48, 53.58s elapsed (20 services on 1 host)
NSE: Script scanning 192.168.56.10.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:48
NSE Timing: About 99.96% done; ETC: 18:48 (0:00:00 remaining)
Completed NSE at 18:48, 40.10s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.32s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
Nmap scan report for 192.168.56.10
Host is up, received arp-response (0.00035s latency).
Scanned at 2025-10-22 18:47:24 EDT for 95s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 128 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: 40687F51E948B80EE92FA92DDBCA8283
|_http-title:  Neptune 
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2025-10-22 22:47:36Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: neptune.thl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: neptune.thl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
55231/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
55233/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
57947/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
57964/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:26:46:E5 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:26:46:e5 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   DC01<00>             Flags: <unique><active>
|   NEPTUNE<00>          Flags: <group><active>
|   NEPTUNE<1c>          Flags: <group><active>
|   DC01<20>             Flags: <unique><active>
|   NEPTUNE<1b>          Flags: <unique><active>
| Statistics:
|   08:00:27:26:46:e5:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: 4s
| smb2-time: 
|   date: 2025-10-22T22:48:24
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62115/tcp): CLEAN (Timeout)
|   Check 2 (port 27096/tcp): CLEAN (Timeout)
|   Check 3 (port 39390/udp): CLEAN (Timeout)
|   Check 4 (port 58446/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:48
Completed NSE at 18:48, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.67 seconds
           Raw packets sent: 21 (908B) | Rcvd: 21 (908B)
                                                                                                                                                 
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 
