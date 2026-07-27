TheHackersLabs — Inj3ctCrew [Write-Up]

1. Descripción Servidor:
Inj3ctCrew es una máquina de nivel principiante que nos enseña conceptos fundamentales de hacking ético como enumeración web, decodificación de información en Base64, cracking de hashes MD5, explotación de webshells, fuerza bruta de contraseñas SSH con Hydra, y escalada de privilegios mediante binarios con permisos SUDO. Es ideal para quienes están comenzando en el mundo del pentesting.

2. Reconocimiento
2.1 Escaneo de puertos con Nmap
Comenzamos realizando un escaneo de puertos para identificar qué servicios están corriendo en la máquina objetivo:

Resultados:

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Análisis:


3. Enumeración Web (Puerto 80)
3.1 Inspección inicial
Al visitar la web en el navegador, encontramos una página con el mensaje “Sigue buscando”. Esto sugiere que hay información oculta.


3.2 Análisis del código fuente


RWwgZGlyZWN0b3JpbyBkZSByZXNwYWxkbyBmdWUgY8y1zZvNisyQzJjMpsyYb8y1zYbNnc2EzZbNk8yYbcy0zJXNkMy

¿Qué es Base64?
Base64 es un sistema de codificación que convierte datos binarios en texto ASCII. Se usa frecuentemente para transportar datos en formatos que solo aceptan texto. No es cifrado, solo codificación, por lo que es fácilmente reversible.

3.3 Decodificación Base64
Decodificamos el texto usando el comando base64:

echo "CÓDIGOBASE64" | base64 -d

Resultado:

"El directorio de respaldo fue comprometido"

Esta pista nos indica que debemos buscar un directorio de respaldo (backup) en el servidor web.

4. Fuzzing de Directorios
4.1 Uso de Gobuster
Utilizamos Gobuster para descubrir directorios y archivos ocultos en el servidor web:

gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt
Explicación de parámetros:

Resultados importantes:

/index.html           (Status: 200) [Size: 1284]
/login.php            (Status: 200) [Size: 1311]
/backup.php           (Status: 200) [Size: 937]
Análisis:

Status: 200 significa que el recurso existe y es accesible
Encontramos tres páginas interesantes: index, login y backup


5. Exploración de backup.php
5.1 Análisis inicial
Al acceder a /backup.php, vemos un mensaje que confirma que el backup está comprometido.


5.2 Inspección del código fuente
Inspeccionamos nuevamente el código fuente y encontramos un comentario HTML con información crítica:



-Nosotros Inj3ctCrew, te hemos dejado una informacion importante en el directorio PwnedCredentials.html-
6. Obtención de Credenciales
6.1 Acceso a PwnedCredentials.html
Navegamos a /PwnedCredentials.html y encontramos:



Usuario: Admin
Contraseña: d8578edf8458ce06fbc5bb76a58c5ca4

6.2 Identificación del hash
La contraseña tiene el formato de un hash MD5:

MD5: Algoritmo de hash criptográfico que produce un valor de 128 bits (32 caracteres hexadecimales)
Características: Siempre produce la misma salida para la misma entrada, pero es imposible revertir el proceso matemáticamente
Vulnerabilidad: MD5 es considerado inseguro porque puede ser crackeado mediante tablas rainbow o fuerza bruta
6.3 Cracking del hash MD5
Usamos CrackStation, un servicio online que compara hashes contra bases de datos de contraseñas conocidas.



Credenciales finales:

Usuario: Admin
Contraseña: qwerty
7. Acceso a la Webshell
7.1 Login
Accedemos a /login.php e ingresamos las credenciales obtenidas.

7.2 Webshell
Una vez autenticados, encontramos una interfaz que nos permite ejecutar comandos del sistema. Esto es una webshell — una interfaz web que ejecuta comandos en el servidor.



7.3 Enumeración de usuarios
Ejecutamos el siguiente comando para listar los usuarios del sistema:

cat /etc/passwd
Explicación:

cat: Comando que muestra el contenido de un archivo
/etc/passwd: Archivo del sistema que contiene información de todos los usuarios


Usuario descubierto: nolen11

Get APS88’s stories in your inbox
Join Medium for free to get updates from this writer.

Enter your email
Subscribe

Remember me for faster sign in

Este usuario tiene una shell válida (/bin/bash), lo que significa que podemos intentar acceder vía SSH.

8. Fuerza Bruta SSH con Hydra
8.1 Ataque de diccionario
Utilizamos Hydra para realizar un ataque de fuerza bruta contra el servicio SSH:

hydra -l nolen11 -P /usr/share/wordlists/rockyou.txt ssh://<IP>
Explicación de parámetros:

hydra: Herramienta de fuerza bruta para servicios de red
nolen11: Especifica el nombre de usuario (login)
-l: Flag para un solo usuario
rockyou.txt: Diccionario de contraseñas
-P: Flag para archivo de contraseñas (wordlist)
rockyou.txt: Famosa lista con millones de contraseñas reales filtradas
ssh://<IP>: Protocolo y objetivo
¿Cómo funciona?
Hydra prueba cada contraseña del diccionario combinada con el usuario especificado hasta encontrar una válida.

Resultado:
Hydra encuentra la contraseña para el usuario nolen11.


9. Acceso SSH
9.1 Conexión
Nos conectamos al servidor mediante SSH:

ssh nolen11@<IP>
Cuando se solicite, ingresamos la contraseña encontrada con Hydra.

9.2 Enumeración inicial
Una vez dentro, listamos los archivos del directorio actual:

10. Escalada de Privilegios
10.1 Enumeración de permisos sudo
Verificamos qué comandos puede ejecutar el usuario con privilegios de root:

sudo -l
Explicación:

sudo: permite ejecutar comandos como otro usuario (por defecto, root)
-l: Lista los comandos que el usuario actual puede ejecutar con sudo
Resultado:



Análisis:

(ALL): Puede ejecutar como cualquier usuario
NOPASSWD: No requiere contraseña
/usr/bin/find: Puede ejecutar el binario find con privilegios de root
10.2 Consulta en GTFOBins
GTFOBins es una base de datos que documenta cómo binarios de Unix pueden ser explotados para escalar privilegios, bypass de restricciones, etc.

Buscamos find en GTFOBins y encontramos que puede ser usado para obtener una shell.



10.3 Explotación
Ejecutamos el siguiente comando:

sudo /usr/bin/find . -exec /bin/sh \; -quit
Resultado:
Obtenemos una shell con privilegios de root.

10.4 Verificación
Podemos verificar que somos root con:

