──(kali㉿kali)-[~/Documents/photographer]
└─$ nmap -sS -p- --open --min-rate 5000 -Pn -n 192.168.56.11 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 09:30 EDT
Nmap scan report for 192.168.56.11
Host is up (0.000098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:1A:F2:64 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.73 seconds





kali㉿kali)-[~/Documents/photographer]
└─$ nmap -sVC -p22,80 -vvv -n -Pn 192.168.56.11 -oN fullscan.txt   


PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.65 ((Debian))
|_http-title: Ethan | Blog
|_http-server-header: Apache/2.4.65 (Debian)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
MAC Address: 08:00:27:1A:F2:64 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:31
Completed NSE at 09:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:31
Completed NSE at 09:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:31
Completed NSE at 09:31, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
           Raw packets sent: 3 (116B) | Rcvd: 3 (116B)
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]








┌──(kali㉿kali)-[~/Documents/photographer]
└─$ gobuster dir -u http://192.168.56.11/ -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.11/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              css,js,txt,pdf,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://192.168.56.11/images/]
/index.html           (Status: 200) [Size: 6244]
/about.html           (Status: 200) [Size: 2750]
/.html                (Status: 403) [Size: 278]
/admin                (Status: 301) [Size: 314] [--> http://192.168.56.11/admin/]
/assets               (Status: 301) [Size: 315] [--> http://192.168.56.11/assets/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished







──(kali㉿kali)-[~/Documents/photographer]
└─$ gobuster dir -u http://192.168.56.11/admin/ -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.11/admin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              pdf,php,html,css,js,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 943]
/img                  (Status: 301) [Size: 318] [--> http://192.168.56.11/admin/img/]
/admin.php            (Status: 302) [Size: 1076] [--> index.php]
/upload.php           (Status: 500) [Size: 0]
/db.php               (Status: 200) [Size: 0]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/styles.css           (Status: 200) [Size: 1788]
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
Progress: 1179590 / 1543927 (76.40%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 1180618 / 1543927 (76.47%)
===============================================================
Finished
