┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -sn 10.0.250.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:16 EDT
Nmap scan report for 10.0.250.1
Host is up (0.00051s latency).
MAC Address: 08:00:27:AA:D1:65 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.250.8
Host is up (0.00098s latency).
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.250.5
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.15 seconds
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -sS --min-rate 5000 -p- --open -n -Pn 10.0.250.8 -oN scan.txt  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:18 EDT
Nmap scan report for 10.0.250.8
Host is up (0.00018s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.37 seconds
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
22,2222,80
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -p22,80,2222 -sV -sC -Pn -vvv -n -oN fullScan.txt 10.0.250.8    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:22 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Initiating ARP Ping Scan at 17:22
Scanning 10.0.250.8 [1 port]
Completed ARP Ping Scan at 17:22, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:22
Scanning 10.0.250.8 [3 ports]
Discovered open port 22/tcp on 10.0.250.8
Discovered open port 80/tcp on 10.0.250.8
Discovered open port 2222/tcp on 10.0.250.8
Completed SYN Stealth Scan at 17:22, 0.02s elapsed (3 total ports)
Initiating Service scan at 17:22
Scanning 3 services on 10.0.250.8
Completed Service scan at 17:22, 6.08s elapsed (3 services on 1 host)
NSE: Script scanning 10.0.250.8.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.43s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Nmap scan report for 10.0.250.8
Host is up, received arp-response (0.00040s latency).
Scanned at 2025-09-17 17:22:34 EDT for 7s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.65 ((Debian))
|_http-server-header: Apache/2.4.65 (Debian)
|_http-title: Allsafe
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 7 (protocol 2.0)
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.43 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ 
-------------------------------------------------------------------------------------------------------------------------------



└─$ sudo nano /etc/hosts 
[sudo] password for kali: 
                                                                                                                                                           
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.0.250.8 allsafe.thl

-------------------------------------------------------------------------------------------------------------------------------

```bash 
wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -H "HOST: FUZZ.allsafe.thl" -u 10.0.250.8 
```

┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -H "HOST: FUZZ.allsafe.thl" -u 10.0.250.8 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.250.8/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000058:   302        0 L      0 W        0 Ch        "intranet - intranet"                                                                      

Total time: 6.135240
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 813.1710

                                                                                                                                                            

-------------------------------------------------------------------------------------------------------------------------------

```
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
#10.0.250.4 bloodhound.thl dc.bloodhound.thl
#10.0.250.7 adivinaadivinanza
10.0.250.8 allsafe.thl intranet.allsafe.thl
```