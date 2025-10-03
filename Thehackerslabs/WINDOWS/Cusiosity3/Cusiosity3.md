
┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.56.19 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 18:07 EDT
Nmap scan report for 192.168.56.19
Host is up (0.00017s latency).
Not shown: 59284 closed tcp ports (reset), 6219 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
587/tcp   open  submission
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49684/tcp open  unknown
49688/tcp open  unknown
49691/tcp open  unknown
49711/tcp open  unknown
MAC Address: 08:00:27:15:CA:14 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','                                                                           
110,135,139,143,21,25,3268,3269,389,445,464,47001,49664,49665,49673,49674,49675,49676,49677,49678,49684,49688,49691,49711,53,587,593,5985,636,80,88,9389
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ nmap -sVC -p110,135,139,143,21,25,3268,3269,389,445,464,47001,49664,49665,49673,49674,49675,49676,49677,49678,49684,49688,49691,49711,53,587,593,5985,636,80,88,9389 -n -Pn -vvv 192.168.56.19 -oN fullscan.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 18:08 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:08
Completed NSE at 18:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:08
Completed NSE at 18:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:08
Completed NSE at 18:08, 0.00s elapsed
Initiating ARP Ping Scan at 18:08
Scanning 192.168.56.19 [1 port]
Completed ARP Ping Scan at 18:08, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:08
Scanning 192.168.56.19 [32 ports]
Discovered open port 80/tcp on 192.168.56.19
Discovered open port 139/tcp on 192.168.56.19
Discovered open port 143/tcp on 192.168.56.19
Discovered open port 445/tcp on 192.168.56.19
Discovered open port 21/tcp on 192.168.56.19
Discovered open port 25/tcp on 192.168.56.19
Discovered open port 135/tcp on 192.168.56.19
Discovered open port 110/tcp on 192.168.56.19
Discovered open port 53/tcp on 192.168.56.19
Discovered open port 587/tcp on 192.168.56.19
Discovered open port 49677/tcp on 192.168.56.19
Discovered open port 49673/tcp on 192.168.56.19
Discovered open port 636/tcp on 192.168.56.19
Discovered open port 389/tcp on 192.168.56.19
Discovered open port 49674/tcp on 192.168.56.19
Discovered open port 49688/tcp on 192.168.56.19
Discovered open port 49664/tcp on 192.168.56.19
Discovered open port 49675/tcp on 192.168.56.19
Discovered open port 3269/tcp on 192.168.56.19
Discovered open port 49684/tcp on 192.168.56.19
Discovered open port 593/tcp on 192.168.56.19
Discovered open port 464/tcp on 192.168.56.19
Discovered open port 49711/tcp on 192.168.56.19
Discovered open port 49665/tcp on 192.168.56.19
Discovered open port 49691/tcp on 192.168.56.19
Discovered open port 49676/tcp on 192.168.56.19
Discovered open port 9389/tcp on 192.168.56.19
Discovered open port 5985/tcp on 192.168.56.19
Discovered open port 49678/tcp on 192.168.56.19
Discovered open port 47001/tcp on 192.168.56.19
Discovered open port 3268/tcp on 192.168.56.19
Discovered open port 88/tcp on 192.168.56.19
Completed SYN Stealth Scan at 18:08, 0.02s elapsed (32 total ports)
Initiating Service scan at 18:08
Scanning 32 services on 192.168.56.19
Completed Service scan at 18:09, 59.65s elapsed (32 services on 1 host)
NSE: Script scanning 192.168.56.19.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:10, 8.51s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 1.60s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Nmap scan report for 192.168.56.19
Host is up, received arp-response (0.00042s latency).
Scanned at 2025-10-01 18:08:55 EDT for 70s

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 128 FileZilla ftpd 1.10.0
|_ssl-date: TLS randomness does not represent time
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla.
| ssl-cert: Subject: commonName=filezilla-server self signed certificate
| Issuer: commonName=filezilla-server self signed certificate
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2025-03-28T16:30:48
| Not valid after:  2026-03-29T16:35:48
| MD5:   8a08:e97c:70b5:0971:5e48:a80f:4b32:7140
| SHA-1: d6a4:ed76:ea54:f81c:2b57:02f1:ec33:b57d:4aa8:c89b
| -----BEGIN CERTIFICATE-----
| MIIBiDCCAS6gAwIBAgIUCHQLt09qVBuRVcboVVzBPAdZpKcwCgYIKoZIzj0EAwIw
| MzExMC8GA1UEAxMoZmlsZXppbGxhLXNlcnZlciBzZWxmIHNpZ25lZCBjZXJ0aWZp
| Y2F0ZTAeFw0yNTAzMjgxNjMwNDhaFw0yNjAzMjkxNjM1NDhaMDMxMTAvBgNVBAMT
| KGZpbGV6aWxsYS1zZXJ2ZXIgc2VsZiBzaWduZWQgY2VydGlmaWNhdGUwWTATBgcq
| hkjOPQIBBggqhkjOPQMBBwNCAARFgjWBQpmCx3tM2ABlvuwAjG4H9kpwAtQFXYzV
| z6GZHpSpzYNT6uyBLf8ualSag9YWfEsMnuE0C4QS4F8Vkb8zoyAwHjAOBgNVHQ8B
| Af8EBAMCBaAwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiA0N/eYbnan
| QNfnnNQdKW/h/h0/J9whwDhskmZnyD0pMgIhALLM/39BBKVe3JF8EM7sa1c/vc1X
| 1T1X8GRMiMggZbzR
|_-----END CERTIFICATE-----
|_ftp-anon: got code 503 "Use AUTH first.".
25/tcp    open  smtp          syn-ack ttl 128 hMailServer smtpd
| smtp-commands: CURIOSITY-DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        syn-ack ttl 128 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Nextech - Consultor\xC3\xADa Inform\xC3\xA1tica
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2025-10-01 22:09:03Z)
110/tcp   open  pop3          syn-ack ttl 128 hMailServer pop3d
|_pop3-capabilities: TOP USER UIDL
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack ttl 128 hMailServer imapd
|_imap-capabilities: OK IMAP4rev1 CHILDREN completed CAPABILITY RIGHTS=texkA0001 NAMESPACE QUOTA ACL SORT IMAP4 IDLE
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: curiosity.thl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
587/tcp   open  smtp          syn-ack ttl 128 hMailServer smtpd
| smtp-commands: CURIOSITY-DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: curiosity.thl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
47001/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49684/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49688/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49691/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49711/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:15:CA:14 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: CURIOSITY-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59348/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31319/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41578/udp): CLEAN (Timeout)
|   Check 4 (port 19125/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-01T22:09:57
|_  start_date: N/A
| nbstat: NetBIOS name: CURIOSITY-DC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:15:ca:14 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   CURIOSITY-DC<00>     Flags: <unique><active>
|   CURIOSITY<00>        Flags: <group><active>
|   CURIOSITY<1c>        Flags: <group><active>
|   CURIOSITY-DC<20>     Flags: <unique><active>
|   CURIOSITY<1b>        Flags: <unique><active>
| Statistics:
|   08:00:27:15:ca:14:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.86 seconds
           Raw packets sent: 33 (1.436KB) | Rcvd: 33 (1.436KB)
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ 




┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ netexec smb 192.168.56.19                                               
SMB         192.168.56.19   445    CURIOSITY-DC     [*] Windows 11 / Server 2025 Build 26100 x64 (name:CURIOSITY-DC) (domain:curiosity.thl) (signing:True) (SMBv1:False)
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/curiosity3]
└─$ 


192.168.56.19 curiosity.thl CURIOSITY-DC CURIOSITY-DC.curiosity.thl