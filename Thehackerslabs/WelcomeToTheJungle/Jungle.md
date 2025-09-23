┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.69.4 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-23 15:34 EDT
Nmap scan report for 192.168.69.4
Host is up (0.00032s latency).
Not shown: 59194 closed tcp ports (reset), 6328 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
MAC Address: 08:00:27:E4:F0:93 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 12.82 seconds
                                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
135,139,445,47001,49664,49665,49666,49667,49668,49669,49670,5985,80
                                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ nmap -sVC -p135,139,445,47001,49664,49665,49666,49667,49668,49669,49670,5985,80 -n -Pn -vvv 192.168.69.4 -oN fullscan.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-23 15:36 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:36
Completed NSE at 15:36, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:36
Completed NSE at 15:36, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:36
Completed NSE at 15:36, 0.00s elapsed
Initiating ARP Ping Scan at 15:36
Scanning 192.168.69.4 [1 port]
Completed ARP Ping Scan at 15:36, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:36
Scanning 192.168.69.4 [13 ports]
Discovered open port 139/tcp on 192.168.69.4
Discovered open port 445/tcp on 192.168.69.4
Discovered open port 135/tcp on 192.168.69.4
Discovered open port 80/tcp on 192.168.69.4
Discovered open port 49667/tcp on 192.168.69.4
Discovered open port 49670/tcp on 192.168.69.4
Discovered open port 49664/tcp on 192.168.69.4
Discovered open port 47001/tcp on 192.168.69.4
Discovered open port 49665/tcp on 192.168.69.4
Discovered open port 5985/tcp on 192.168.69.4
Discovered open port 49669/tcp on 192.168.69.4
Discovered open port 49668/tcp on 192.168.69.4
Discovered open port 49666/tcp on 192.168.69.4
Completed SYN Stealth Scan at 15:36, 0.02s elapsed (13 total ports)
Initiating Service scan at 15:36
Scanning 13 services on 192.168.69.4
Service scan Timing: About 53.85% done; ETC: 15:38 (0:00:46 remaining)
Completed Service scan at 15:37, 53.59s elapsed (13 services on 1 host)
NSE: Script scanning 192.168.69.4.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 5.26s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 0.04s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 0.00s elapsed
Nmap scan report for 192.168.69.4
Host is up, received arp-response (0.00043s latency).
Scanned at 2025-09-23 15:36:22 EDT for 59s

PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Welcome to the Jungle - The Hex Guns
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 128
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:E4:F0:93 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-09-23T19:37:18
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64570/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 24752/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 49544/udp): CLEAN (Timeout)
|   Check 4 (port 55758/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: THEHEXGUNS, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:e4:f0:93 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   THEHEXGUNS<00>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   THEHEXGUNS<20>       Flags: <unique><active>
| Statistics:
|   08:00:27:e4:f0:93:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.90 seconds
           Raw packets sent: 14 (600B) | Rcvd: 14 (600B)
                                                                                                                                          
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ netexec smb 192.168.69.4                                                                                                  
SMB         192.168.69.4    445    THEHEXGUNS       [*] Windows Server 2022 Build 20348 x64 (name:THEHEXGUNS) (domain:thehexguns) (signing:False) (SMBv1:False)                                                                                                                                                         
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ sudo nano /etc/hosts      
[sudo] password for kali: 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ smbclient //192.168.69.4 -N

\\192.168.69.4: Not enough '\' characters in service
Usage: smbclient [-?EgqBNPkV] [-?|--help] [--usage] [-M|--message=HOST] [-I|--ip-address=IP] [-E|--stderr] [-L|--list=HOST] [-T|--tar=<c|x>IXFvgbNan]
        [-D|--directory=DIR] [-c|--command=STRING] [-b|--send-buffer=BYTES] [-t|--timeout=SECONDS] [-p|--port=PORT] [-g|--grepable] [-q|--quiet]
        [-B|--browse] [-d|--debuglevel=DEBUGLEVEL] [--debug-stdout] [-s|--configfile=CONFIGFILE] [--option=name=value] [-l|--log-basename=LOGFILEBASE]
        [--leak-report] [--leak-report-full] [-R|--name-resolve=NAME-RESOLVE-ORDER] [-O|--socket-options=SOCKETOPTIONS] [-m|--max-protocol=MAXPROTOCOL]
        [-n|--netbiosname=NETBIOSNAME] [--netbios-scope=SCOPE] [-W|--workgroup=WORKGROUP] [--realm=REALM] [-U|--user=[DOMAIN/]USERNAME[%PASSWORD]]
        [-N|--no-pass] [--password=STRING] [--pw-nt-hash] [-A|--authentication-file=FILE] [-P|--machine-pass] [--simple-bind-dn=DN]
        [--use-kerberos=desired|required|off] [--use-krb5-ccache=CCACHE] [--use-winbind-ccache] [--client-protection=sign|encrypt|off] [-k|--kerberos]
        [-V|--version] [OPTIONS] service <password>
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ smbclient -I //192.168.69.4 -N
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ smbclient -L //192.168.69.4 -N
session setup failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ netexec smb 192.168.69.4 -u slash -p /usr/share/wordlists/rockyou.txt








https://github.com/RickdeJager/stegseek/releases



sudo apt install ./stegseek_0.6-1.deb







┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ strings commlink.exe | grep -i -E "flag|key|password|secret|ctf|jungle|paradise|404"

axl password: SoloMaster2025
ExceptionFlags
ContextFlags
