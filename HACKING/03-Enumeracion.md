# Enumeración del servicio FTP

En esta clase, hablaremos sobre el protocolo de transferencia de archivos (FTP) y cómo aplicar reconocimiento sobre este para recopilar información.

FTP es un protocolo ampliamente utilizado para la transferencia de archivos en redes. La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

A continuación, se os proporciona el enlace al primer proyecto que tocamos en esta clase:

Docker-FTP-Server: https://github.com/garethflowers/docker-ftp-server
Una de las herramientas que usamos en esta clase para el primer proyecto que nos descargamos es ‘Hydra‘. Hydra es una herramienta de pruebas de penetración de código abierto que se utiliza para realizar ataques de fuerza bruta contra sistemas y servicios protegidos por contraseña. La herramienta es altamente personalizable y admite una amplia gama de protocolos de red, como HTTP, FTP, SSH, Telnet, SMTP, entre otros.

El siguiente de los proyectos que utilizamos para desplegar el contenedor que permite la autenticación de usuarios invitados para FTP, es el proyecto ‘docker-anon-ftp‘ de ‘metabrainz‘. A continuación, se os proporciona el enlace al proyecto:

Docker-ANON-FTP: https://github.com/metabrainz/docker-anon-ftp




# Enumeración del servicio SSH

En esta clase, exploraremos el protocolo SSH (Secure Shell) y cómo realizar reconocimiento para recopilar información sobre los sistemas que ejecutan este servicio.

SSH es un protocolo de administración remota que permite a los usuarios controlar y modificar sus servidores remotos a través de Internet mediante un mecanismo de autenticación seguro. Como una alternativa más segura al protocolo Telnet, que transmite información sin cifrar, SSH utiliza técnicas criptográficas para garantizar que todas las comunicaciones hacia y desde el servidor remoto estén cifradas.

SSH proporciona un mecanismo para autenticar un usuario remoto, transferir entradas desde el cliente al host y retransmitir la salida de vuelta al cliente. Esto es especialmente útil para administrar sistemas remotos de manera segura y eficiente, sin tener que estar físicamente presentes en el sitio.

A continuación, se os proporciona el enlace directo a la web donde copiamos todo el comando de ‘docker’ para desplegar nuestro contenedor:

Docker Hub OpenSSH-Server: https://hub.docker.com/r/linuxserver/openssh-server
Cabe destacar que a través de la versión de SSH, también podemos identificar el codename de la distribución que se está ejecutando en el sistema.

Por ejemplo, si la versión del servidor SSH es “OpenSSH 8.2p1 Ubuntu 4ubuntu0.5“, podemos determinar que el sistema está ejecutando una distribución de Ubuntu. El número de versión “4ubuntu0.5” se refiere a la revisión específica del paquete de SSH en esa distribución de Ubuntu. A partir de esto, podemos identificar el codename de la distribución de Ubuntu, que en este caso sería “Focal” para Ubuntu 20.04.

Todas estas búsquedas las aplicamos sobre el siguiente dominio:

Launchpad: https://launchpad.net/ubuntu