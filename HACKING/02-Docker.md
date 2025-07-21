# Introducción a Docker
Docker es una plataforma de contenedores de software que permite crear, distribuir y ejecutar aplicaciones en entornos aislados. Esto significa que se pueden empaquetar las aplicaciones con todas sus dependencias y configuraciones en un contenedor que se puede mover fácilmente de una máquina a otra, independientemente de la configuración del sistema operativo o del hardware.

Algunas de las ventajas que se presentan a la hora de practicar hacking usando Docker son:

Aislamiento: los contenedores de Docker están aislados entre sí, lo que significa que si una aplicación dentro de un contenedor es comprometida, el resto del sistema no se verá afectado.
Portabilidad: los contenedores de Docker se pueden mover fácilmente de un sistema a otro, lo que los hace ideales para desplegar entornos vulnerables para prácticas de hacking.
Reproducibilidad: los contenedores de Docker se pueden configurar de forma precisa y reproducible, lo que es importante en el hacking para poder recrear escenarios de ataque.


# Instalación de Docker en Linux

Para instalar Docker en Linux, se puede utilizar el comando “apt install docker.io“, que instalará el paquete Docker desde el repositorio de paquetes del sistema operativo. Es importante mencionar que, dependiendo de la distribución de Linux que se esté utilizando, el comando puede variar. Por ejemplo, en algunas distribuciones como CentOS o RHEL se utiliza “yum install docker” en lugar de “apt install docker.io“.

Una vez que Docker ha sido instalado, es necesario iniciar el demonio de Docker para que los contenedores puedan ser creados y administrados. Para iniciar el demonio de Docker, se puede utilizar el comando “service docker start“. Este comando iniciará el servicio del demonio de Docker, que es responsable de gestionar los contenedores y asegurarse de que funcionen correctamente.

Durante la clase, se mostrará cómo verificar que Docker ha sido instalado correctamente, además de comprobar si el demonio de Docker está en ejecución.



# Definiendo la estructura básica de Dockerfile

Un archivo Dockerfile se compone de varias secciones, cada una de las cuales comienza con una palabra clave en mayúsculas, seguida de uno o más argumentos.

Algunas de las secciones más comunes en un archivo Dockerfile son:

FROM: se utiliza para especificar la imagen base desde la cual se construirá la nueva imagen.
RUN: se utiliza para ejecutar comandos en el interior del contenedor, como la instalación de paquetes o la configuración del entorno.
COPY: se utiliza para copiar archivos desde el sistema host al interior del contenedor.
CMD: se utiliza para especificar el comando que se ejecutará cuando se arranque el contenedor.
Además de estas secciones, también se pueden incluir otras instrucciones para configurar el entorno, instalar paquetes adicionales, exponer puertos de red y más.



# Creación y construcción de imágenes

Para crear una imagen de Docker, es necesario tener un archivo Dockerfile que defina la configuración de la imagen. Una vez que se tiene el Dockerfile, se puede utilizar el comando “docker build” para construir la imagen. Este comando buscará el archivo ‘Dockerfile’ en el directorio actual y utilizará las instrucciones definidas en el mismo para construir la imagen.

Algunas de las instrucciones que vemos en esta clase son:

docker build: es el comando que se utiliza para construir una imagen de Docker a partir de un Dockerfile.
La sintaxis básica es la siguiente:

➜ docker build [opciones] ruta_al_Dockerfile

El parámetro “-t” se utiliza para etiquetar la imagen con un nombre y una etiqueta. Por ejemplo, si se desea etiquetar la imagen con el nombre “mi_imagen” y la etiqueta “v1“, se puede usar la siguiente sintaxis:

➜ docker build -t mi_imagen:v1 ruta_al_Dockerfile

El punto (“.“) al final de la ruta al Dockerfile se utiliza para indicar al comando que busque el Dockerfile en el directorio actual. Si el Dockerfile no se encuentra en el directorio actual, se puede especificar la ruta completa al Dockerfile en su lugar. Por ejemplo, si el Dockerfile se encuentra en “/home/usuario/proyecto/“, se puede usar la siguiente sintaxis:

➜ docker build -t mi_imagen:v1 /home/usuario/proyecto/

docker pull: es el comando que se utiliza para descargar una imagen de Docker desde un registro de imágenes.
La sintaxis básica es la siguiente:

➜ docker pull nombre_de_la_imagen:etiqueta

Por ejemplo, si se desea descargar la imagen “ubuntu” con la etiqueta “latest”, se puede usar la siguiente sintaxis:

➜ docker pull ubuntu:latest

docker images: es el comando que se utiliza para listar las imágenes de Docker que están disponibles en el sistema.
La sintaxis básica es la siguiente:

➜ docker images [opciones]

Durante la construcción de la imagen, Docker descargará y almacenará en caché las capas de la imagen que se han construido previamente, lo que hace que las compilaciones posteriores sean más rápidas.



# Carga de instrucciones en Docker y desplegando nuestro primer contenedor

Ya habiendo construido en la clase anterior nuestra primera imagen, ¡ya estamos preparados para desplegar nuestros contenedores!

El comando “docker run” se utiliza para crear y arrancar un contenedor a partir de una imagen. Algunas de las opciones más comunes para el comando “docker run” son:

“-d” o “–detach“: se utiliza para arrancar el contenedor en segundo plano, en lugar de en primer plano.
“-i” o “–interactive“: se utiliza para permitir la entrada interactiva al contenedor.
“-t” o “–tty“: se utiliza para asignar un seudoterminal al contenedor.
“–name“: se utiliza para asignar un nombre al contenedor.
Para arrancar un contenedor a partir de una imagen, se utiliza el siguiente comando:

➜ docker run [opciones] nombre_de_la_imagen

Por ejemplo, si se desea arrancar un contenedor a partir de la imagen “mi_imagen“, en segundo plano y con un seudoterminal asignado, se puede utilizar la siguiente sintaxis:

➜  docker run -dit mi_imagen

Una vez que el contenedor está en ejecución, se puede utilizar el comando “docker ps” para listar los contenedores que están en ejecución en el sistema. Algunas de las opciones más comunes son:

“-a” o “–all“: se utiliza para listar todos los contenedores, incluyendo los contenedores detenidos.
“-q” o “–quiet“: se utiliza para mostrar sólo los identificadores numéricos de los contenedores.
Por ejemplo, si se desea listar todos los contenedores que están en ejecución en el sistema, se puede utilizar la siguiente sintaxis:

➜  docker ps -a

Para ejecutar comandos en un contenedor que ya está en ejecución, se utiliza el comando “docker exec” con diferentes opciones. Algunas de las opciones más comunes son:

“-i” o “–interactive“: se utiliza para permitir la entrada interactiva al contenedor.
“-t” o “–tty“: se utiliza para asignar un seudoterminal al contenedor.
Por ejemplo, si se desea ejecutar el comando “bash” en el contenedor con el identificador “123456789“, se puede utilizar la siguiente sintaxis:

➜ docker exec -it 123456789 bash




# Comandos comunes para la gestión de contenedores

A continuación, se detallan algunos de los comandos vistos en esta clase:

docker rm $(docker ps -a -q) –force: este comando se utiliza para eliminar todos los contenedores en el sistema, incluyendo los contenedores detenidos. La opción “-q” se utiliza para mostrar sólo los identificadores numéricos de los contenedores, y la opción “–force” se utiliza para forzar la eliminación de los contenedores que están en ejecución. Es importante tener en cuenta que la eliminación de todos los contenedores en el sistema puede ser peligrosa, ya que puede borrar accidentalmente contenedores importantes o datos importantes. Por lo tanto, se recomienda tener precaución al utilizar este comando.

docker rm id_contenedor: este comando se utiliza para eliminar un contenedor específico a partir de su identificador. Es importante tener en cuenta que la eliminación de un contenedor eliminará también cualquier cambio que se haya realizado dentro del contenedor, como la instalación de paquetes o la modificación de archivos.

docker rmi $(docker images -q): este comando se utiliza para eliminar todas las imágenes de Docker en el sistema. La opción “-q” se utiliza para mostrar sólo los identificadores numéricos de las imágenes. Es importante tener en cuenta que la eliminación de todas las imágenes de Docker en el sistema puede ser peligrosa, ya que puede borrar accidentalmente imágenes importantes o datos importantes. Por lo tanto, se recomienda tener precaución al utilizar este comando.

docker rmi id_imagen: este comando se utiliza para eliminar una imagen específica a partir de su identificador. Es importante tener en cuenta que la eliminación de una imagen eliminará también cualquier contenedor que se haya creado a partir de esa imagen. Si se desea eliminar una imagen que tiene contenedores en ejecución, se deben detener primero los contenedores y luego eliminar la imagen.

En la siguiente clase, veremos cómo aplicar port fowarding y cómo jugar con monturas. El port forwarding nos permitirá redirigir el tráfico de red desde un puerto específico en el host a un puerto específico en el contenedor, lo que nos permitirá acceder a los servicios que se ejecutan dentro del contenedor desde el exterior.



# Port Forwarding en Docker y uso de monturas

El port forwarding, también conocido como reenvío de puertos, nos permite redirigir el tráfico de red desde un puerto específico en el host a un puerto específico en el contenedor. Esto nos permitirá acceder a los servicios que se ejecutan dentro del contenedor desde el exterior.

Para utilizar el port forwarding, se utiliza la opción “-p” o “–publish” en el comando “docker run“. Esta opción se utiliza para especificar la redirección de puertos y se puede utilizar de varias maneras. Por ejemplo, si se desea redirigir el puerto 80 del host al puerto 8080 del contenedor, se puede utilizar la siguiente sintaxis:

➜ docker run -p 80:8080 mi_imagen

Esto redirigirá cualquier tráfico entrante en el puerto 80 del host al puerto 8080 del contenedor. Si se desea especificar un protocolo diferente al protocolo TCP predeterminado, se puede utilizar la opción “-p” con un formato diferente. Por ejemplo, si se desea redirigir el puerto 53 del host al puerto 53 del contenedor utilizando el protocolo UDP, se puede utilizar la siguiente sintaxis:

➜ docker run -p 53:53/udp mi_imagen

Las monturas, por otro lado, nos permiten compartir un directorio o archivo entre el sistema host y el contenedor. Esto nos permitirá persistir la información entre ejecuciones de contenedores y compartir datos entre diferentes contenedores.

Para utilizar las monturas, se utiliza la opción “-v” o “–volume” en el comando “docker run“. Esta opción se utiliza para especificar la montura y se puede utilizar de varias maneras. Por ejemplo, si se desea montar el directorio “/home/usuario/datos” del host en el directorio “/datos” del contenedor, se puede utilizar la siguiente sintaxis:

➜ docker run -v /home/usuario/datos:/datos mi_imagen

Esto montará el directorio “/home/usuario/datos” del host en el directorio “/datos” del contenedor. Si se desea especificar una opción adicional, como la de montar el directorio en modo de solo lectura, se puede utilizar la opción “-v” con un formato diferente. Por ejemplo, si se desea montar el directorio en modo de solo lectura, se puede utilizar la siguiente sintaxis:

➜ docker run -v /home/usuario/datos:/datos:ro mi_imagen

En la siguiente clase, veremos cómo desplegar máquinas vulnerables usando Docker-Compose.

Docker Compose es una herramienta de orquestación de contenedores que permite definir y ejecutar aplicaciones multi-contenedor de manera fácil y eficiente. Con Docker Compose, podemos describir los diferentes servicios que componen nuestra aplicación en un archivo YAML y, a continuación, utilizar un solo comando para ejecutar y gestionar todos estos servicios de manera coordinada.


# Despliegue de máquinas vulnerables con Docker-Compose (1/2)


AVISO: En caso de que veáis que no estáis pudiendo instalar ‘nano‘ o alguna utilidad en el contenedor, eliminad todo el contenido del archivo ‘/etc/apt/sources.list‘ existente en el CONTENEDOR y metedle esta línea:

deb http://archive.debian.org/debian/ jessie contrib main non-free
Posteriormente, haced un ‘apt update‘ y probad a instalar nuevamente la herramienta que queráis, ya no os debería de dar problemas.

Si estáis enfrentando dificultades con el contenedor de Elasticsearch y notáis que el contenedor no se crea después de ejecutar ‘docker-compose up -d‘, intentad modificar un parámetro del sistema con el siguiente comando en la consola:

sudo sysctl -w vm.max_map_count=262144‘.
Después de hacerlo, intentad de nuevo ejecutar ‘docker-compose up -d‘, se debería solucionar el problema.

A continuación, os proporcionamos el enlace al proyecto de Github que estamos usando para esta clase:

Vulhub: https://github.com/vulhub/vulhub
Asimismo, por aquí os compartimos el enlace al recurso donde se nos ofrece el script en Javascript encargado de establecer la Reverse Shell:

NodeJS Reverse Shell: https://github.com/appsecco/vulnerable-apps/tree/master/node-reverse-shell



## Por si no pueden clonar el repositorio esta pagina sirve https://download-directory.github.io/


curl -s -X GET "http://localhost:5601/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd"



### reverse shell nodejs

https://github.com/appsecco/vulnerable-apps


script /dev/null -c bash


# Despliegue de máquinas vulnerables con Docker-Compose (2/2)

A continuación, os compartimos el enlace del proyecto correspondiente a la vulnerabilidad de ImageMagick (ImageTragick) que tocamos en esta clase:

Proyecto de Github: https://github.com/vulhub/vulhub/tree/master/imagemagick/imagetragick