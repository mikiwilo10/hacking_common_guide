# Enumeración del servicio FTP

En esta clase, hablaremos sobre el protocolo de transferencia de archivos (FTP) y cómo aplicar reconocimiento sobre este para recopilar información.

FTP es un protocolo ampliamente utilizado para la transferencia de archivos en redes. La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

A continuación, se os proporciona el enlace al primer proyecto que tocamos en esta clase:

Docker-FTP-Server: https://github.com/garethflowers/docker-ftp-server



Una de las herramientas que usamos en esta clase para el primer proyecto que nos descargamos es ‘Hydra‘. Hydra es una herramienta de pruebas de penetración de código abierto que se utiliza para realizar ataques de fuerza bruta contra sistemas y servicios protegidos por contraseña. La herramienta es altamente personalizable y admite una amplia gama de protocolos de red, como HTTP, FTP, SSH, Telnet, SMTP, entre otros.

El siguiente de los proyectos que utilizamos para desplegar el contenedor que permite la autenticación de usuarios invitados para FTP, es el proyecto ‘docker-anon-ftp‘ de ‘metabrainz‘. A continuación, se os proporciona el enlace al proyecto:

Docker-ANON-FTP: https://github.com/metabrainz/docker-anon-ftp



cat /usr/share/wordlists/rockyou.txt | awk 'NR==132' 


hydra -l wilmer -P pasw.txt ftp://127.0.0.1 -t 15


└─$ cat /usr/share/wordlists/rockyou.txt | head -n 3000000 > pasw.txt



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


docker run -d \
  --name=openssh-server \
  --hostname=wcamas  \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true  \
  -e USER_PASSWORD=luis  \
  -e USER_NAME=wilmer  \
  -e LOG_STDOUT=  \
  -p 2222:2222 \
  -v /path/to/openssh-server/config:/config \
  --restart unless-stopped \
  lscr.io/linuxserver/openssh-server:latest


 ssh wilmer@127.0.0.1 -p 2222



# Enumeración del servicio HTTP y HTTPS

HTTP (Hypertext Transfer Protocol) es un protocolo de comunicación utilizado para la transferencia de datos en la World Wide Web. Se utiliza para la transferencia de contenido de texto, imágenes, videos, hipervínculos, etc. El puerto predeterminado para HTTP es el puerto 80.

HTTPS (Hypertext Transfer Protocol Secure) es una versión segura de HTTP que utiliza SSL / TLS para cifrar la comunicación entre el cliente y el servidor. Utiliza el puerto 443 por defecto. La principal diferencia entre HTTP y HTTPS es que HTTPS utiliza una capa de seguridad adicional para cifrar los datos, lo que los hace más seguros para la transferencia.

Una de las herramientas que vemos en esta clase para inspeccionar el certificado SSL es ‘Openssl‘. OpenSSL es una biblioteca de software libre y de código abierto que se utiliza para implementar protocolos de seguridad en línea, como TLS (Transport Layer Security), SSL (Secure Sockets Layer). La biblioteca OpenSSL proporciona una implementación de estos protocolos para permitir que las aplicaciones se comuniquen de manera segura y encriptada a través de la red.

Uno de los comandos que vemos en esta clase haciendo uso de esta herramienta es el siguiente:

➜ openssl s_client -connect ejemplo.com:443

Con este comando, podemos inspeccionar el certificado SSL de un servidor web. El comando se conecta al servidor en el puerto 443 y muestra información detallada sobre el certificado SSL, como la validez del certificado, la fecha de caducidad, el tipo de cifrado, etc.

Asimismo, otras de las herramientas que vemos en esta clase son ‘sslyze‘ y ‘sslscan‘. Sslyze es una herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. Proporciona información detallada sobre el cifrado utilizado, los protocolos admitidos y los certificados SSL. SSLScan es otra herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. Proporciona información detallada sobre los protocolos SSL / TLS admitidos, el cifrado utilizado y los certificados SSL.

La principal diferencia entre sslyze y sslscan es que sslyze se enfoca en la evaluación de la seguridad SSL/TLS de un servidor web mediante una exploración exhaustiva de los protocolos y configuraciones SSL/TLS, mientras que sslscan se enfoca en la identificación de los protocolos SSL/TLS admitidos por el servidor y los cifrados utilizados.

La identificación de las informaciones arrojadas por las herramientas de análisis SSL/TLS es de suma importancia, ya que nos puede permitir detectar vulnerabilidades en la configuración de un servidor y tomar medidas para proteger nuestra información confidencial.

Por ejemplo, Heartbleed es una vulnerabilidad de seguridad que afecta a la biblioteca OpenSSL y permite a los atacantes acceder a la memoria de un servidor vulnerable. Si un servidor web es vulnerable a Heartbleed y lo detectamos a través de estas herramientas, esto significa que un atacante podría potencialmente acceder a información confidencial, como claves privadas, nombres de usuario y contraseñas, etc.

A continuación, se proporciona el enlace al proyecto de Github donde desplegamos el laboratorio vulnerable a Heartbleed:

CVE-2014-0160: https://github.com/vulhub/vulhub/tree/master/openssl/CVE-2014-0160


**sslscan dominio.com**




# Enumeración del servicio SMB

SMB significa Server Message Block, es un protocolo de comunicación de red utilizado para compartir archivos, impresoras y otros recursos entre dispositivos de red. Es un protocolo propietario de Microsoft que se utiliza en sistemas operativos Windows.

Samba, por otro lado, es una implementación libre y de código abierto del protocolo SMB, que se utiliza principalmente en sistemas operativos basados en Unix y Linux. Samba proporciona una manera de compartir archivos y recursos entre dispositivos de red que ejecutan sistemas operativos diferentes, como Windows y Linux.

Aunque SMB y Samba comparten una funcionalidad similar, existen algunas diferencias notables. SMB es un protocolo propietario de Microsoft, mientras que Samba es un proyecto de software libre y de código abierto. Además, SMB es una implementación más completa y compleja del protocolo, mientras que Samba es una implementación más ligera y limitada.

A continuación, se os comparte el enlace correspondiente al proyecto de Github que utilizamos para desplegar un laboratorio de práctica con el que poder enumerar y explotar el servicio Samba:

Samba Authenticated RCE: https://github.com/vulhub/vulhub/tree/master/samba/CVE-2017-7494

Una de las herramientas que utilizamos para la fase de reconocimiento es ‘smbmap‘. Smbmap es una herramienta de línea de comandos utilizada para enumerar recursos compartidos y permisos en un servidor SMB (Server Message Block) o Samba. Es una herramienta muy útil para la enumeración de redes y para la identificación de posibles vulnerabilidades de seguridad.

Con smbmap, puedes enumerar los recursos compartidos en un servidor SMB y obtener información detallada sobre cada recurso, como los permisos de acceso, los usuarios y grupos autorizados, y los archivos y carpetas compartidos. También puedes utilizar smbmap para identificar recursos compartidos que no requieren autenticación, lo que puede ser un problema de seguridad.

Además, smbmap permite a los administradores de sistemas y a los auditores de seguridad verificar rápidamente la configuración de permisos en los recursos compartidos en un servidor SMB, lo que puede ayudar a identificar posibles vulnerabilidades de seguridad y a tomar medidas para remediarlas.

A continuación, se proporciona una breve descripción de algunos de los parámetros comunes de smbmap:

-H: Este parámetro se utiliza para especificar la dirección IP o el nombre de host del servidor SMB al que se quiere conectarse.
-P: Este parámetro se utiliza para especificar el puerto TCP utilizado para la conexión SMB. El puerto predeterminado para SMB es el 445, pero si el servidor SMB está configurado para utilizar un puerto diferente, este parámetro debe ser utilizado para especificar el puerto correcto.
-u: Este parámetro se utiliza para especificar el nombre de usuario para la conexión SMB.
-p: Este parámetro se utiliza para especificar la contraseña para la conexión SMB.
-d: Este parámetro se utiliza para especificar el dominio al que pertenece el usuario que se está utilizando para la conexión SMB.
-s: Este parámetro se utiliza para especificar el recurso compartido específico que se quiere enumerar. Si no se especifica, smbmap intentará enumerar todos los recursos compartidos en el servidor SMB.

Asimismo, otra de las herramientas que se ven en esta clase es ‘smbclient‘. Smbclient es otra herramienta de línea de comandos utilizada para interactuar con servidores SMB y Samba, pero a diferencia de smbmap que se utiliza principalmente para enumeración, smbclient proporciona una interfaz de línea de comandos para interactuar con los recursos compartidos SMB y Samba, lo que permite la descarga y subida de archivos, la ejecución de comandos remotos, la navegación por el sistema de archivos remoto, entre otras funcionalidades.

En cuanto a los parámetros más comunes de smbclient, algunos de ellos son:

-L: Este parámetro se utiliza para enumerar los recursos compartidos disponibles en el servidor SMB o Samba.
-U: Este parámetro se utiliza para especificar el nombre de usuario y la contraseña utilizados para la autenticación con el servidor SMB o Samba.
-c: Este parámetro se utiliza para especificar un comando que se ejecutará en el servidor SMB o Samba.
Estos son algunos de los parámetros más comunes utilizados en smbclient, aunque hay otros disponibles. La lista completa de parámetros y sus descripciones se pueden encontrar en la documentación oficial de la herramienta.

Por último, otra de las herramientas que utilizamos al final de la clase para enumerar el servicio Samba es ‘Crackmapexec‘. CrackMapExec (también conocido como CME) es una herramienta de prueba de penetración de línea de comandos que se utiliza para realizar auditorías de seguridad en entornos de Active Directory. CME se basa en las bibliotecas de Python ‘impacket‘ y es compatible con sistemas operativos Windows, Linux y macOS.

CME puede utilizarse para realizar diversas tareas de auditoría en entornos de Active Directory, como enumerar usuarios y grupos, buscar contraseñas débiles, detectar sistemas vulnerables y buscar vectores de ataque. Además, CME también puede utilizarse para ejecutar ataques de diccionario de contraseñas, ataques de Pass-the-Hash y para explotar vulnerabilidades conocidas en sistemas Windows. Asimismo, cuenta con una amplia variedad de módulos y opciones de configuración, lo que la convierte en una herramienta muy flexible para la auditoría de seguridad de entornos de Active Directory. La herramienta permite automatizar muchas de las tareas de auditoría comunes, lo que ahorra tiempo y aumenta la eficiencia del proceso de auditoría.

A continuación, os compartimos el enlace directo a la Wiki para que podáis instalar la herramienta:

CrackMapExec: https://wiki.porchetta.industries/getting-started/installation/installation-on-unix


### Puerto 445

### Sesiones Nulas   Listar recursos compartidos

smbclient -L 127.0.0.1  -N 


 
smbmap -H 127.0.0.1


### Conectarse al recurso compartido

smbclient //127.0.0.1/myshare  -N


### subir archivos con un sesion nula y ejecutar comandos

**Crear un archivo con Comando en Kali**

┌──(kali㉿kali)-[~/Downloads/hacking/vulhub vulhub master samba-CVE-2017-7494]
    └─$ whoami > output.txt

┌──(kali㉿kali)-[~/Downloads/hacking/vulhub vulhub master samba-CVE-2017-7494]
    └─$ cat output.txt
    kali



**Subir el archivo**

smbclient //127.0.0.1/myshare  -N


smb: \> put  output.txt
putting file output.txt as \output.txt (2.4 kb/s) (average 2.4 kb/s)
smb: \> dir
  .                                   D        0  Mon Jul 21 12:37:34 2025
  ..                                  D        0  Mon Jun 12 12:40:35 2017
  output.txt                          A        5  Mon Jul 21 12:37:34 2025

                82083148 blocks of size 1024. 47679100 blocks available


### Monturas en SMB

installar apt-get install cifs-utils

**Montar la caprteta comparito del SMB al directorio de Kali**


mount -t cifs //127.0.0.1/myshare /mnt/montado


ls /mnt/montado

output.txt



mount -t cifs //127.0.0.1/myshare /mnt/montado -o username=null,password=null,domain,rw


**Desmontar la caprteta comparito del SMB al directorio de Kali**

sudo umount /mnt/montado







# Enumeración de gestores de contenido (CMS) – WordPress (1/2)

En esta clase estaremos enseñando técnicas de enumeración para el gestor de contenido (CMS) WordPress. Un gestor de contenido es una herramienta que permite la creación, gestión y publicación de contenidos digitales en la web, como por ejemplo páginas web, blogs, tiendas en línea, entre otros.

WordPress es un CMS de código abierto muy popular que fue lanzado en 2003. Es utilizado por millones de sitios web en todo el mundo y se destaca por su facilidad de uso y flexibilidad. Con WordPress, los usuarios pueden crear y personalizar sitios web sin necesidad de conocimientos de programación avanzados. Además, cuenta con una amplia variedad de plantillas y plugins que permiten añadir funcionalidades adicionales al sitio.

El proyecto que utilizamos en esta clase para enumerar un WordPress es el siguiente:

DVWP: https://github.com/vavkamil/dvwp
Una de las herramientas que utilizamos en esta clase para enumerar este gestor de contenido es Wpscan. Wpscan es una herramienta de código abierto que se utiliza para escanear sitios web en busca de vulnerabilidades de seguridad en WordPress.

Con Wpscan, podemos realizar una enumeración completa del sitio web y obtener información detallada sobre la instalación de WordPress, como la versión utilizada, los plugins y temas instalados y los usuarios registrados en el sitio. También nos permite realizar pruebas de fuerza bruta para descubrir contraseñas débiles y vulnerabilidades conocidas en plugins y temas.

Wpscan es una herramienta muy útil para los administradores de sitios web que desean mejorar la seguridad de su sitio WordPress, ya que permite identificar y corregir vulnerabilidades antes de que sean explotadas por atacantes malintencionados. Además, es una herramienta fácil de usar y muy efectiva para identificar posibles debilidades de seguridad en nuestro sitio web.

El uso de esta herramienta es bastante sencillo, a continuación se indica la sintaxis básica:

➜ wpscan --url https://example.com

Si deseas enumerar usuarios o plugins vulnerables en WordPress utilizando la herramienta wpscan, puedes añadir los siguientes parámetros a la línea de comandos:

➜ wpscan --url https://example.com --enumerate u

En caso de querer enumerar plugins existentes los cuales sean vulnerables, puedes añadir el siguiente parámetro a la línea de comandos:

➜ wpscan --url https://example.com --enumerate vp

Asimismo, otro de los recursos que contemplamos en esta clase es el archivo xmlrpc.php. Este archivo es una característica de WordPress que permite la comunicación entre el sitio web y aplicaciones externas utilizando el protocolo XML-RPC.

El archivo xmlrpc.php es utilizado por muchos plugins y aplicaciones móviles de WordPress para interactuar con el sitio web y realizar diversas tareas, como publicar contenido, actualizar el sitio y obtener información.

Sin embargo, este archivo también puede ser abusado por atacantes malintencionados para aplicar fuerza bruta y descubrir credenciales válidas de los usuarios del sitio. Esto se debe a que xmlrpc.php permite a los atacantes realizar un número ilimitado de solicitudes de inicio de sesión sin ser bloqueados, lo que hace que la ejecución de un ataque de fuerza bruta sea relativamente sencilla.

En la siguiente clase estaremos desarrollando un script en Bash desde cero para realizar este tipo de ataques.


# Enumeración de gestores de contenido (CMS) – WordPress (2/2)

En esta clase, veremos cómo abusar del archivo xmlrpc.php para mediante la creación de un script de Bash aplicar fuerza bruta. El objetivo de este ejercicio será demostrar cómo los atacantes pueden utilizar este archivo existente en WordPress para intentar descubrir credenciales válidas y comprometer la seguridad del sitio web.

Para lograrlo, crearemos un script de Bash en el cual emplearemos la herramienta cURL para enviar solicitudes XML-RPC al archivo xmlrpc.php del sitio web WordPress. A través del método wp.getUsersBlogs, enviaremos una estructura XML que contendrá el nombre de usuario y la contraseña a probar.

En caso de que las credenciales no sean correctas, el servidor responderá con un mensaje de error que indica que las credenciales son incorrectas. Sin embargo, si las credenciales son válidas, la respuesta del servidor será diferente y no incluirá el mensaje de error.

De esta forma, podremos utilizar la respuesta del servidor para determinar cuándo hemos encontrado credenciales válidas y, de esta forma, tener acceso al sitio web de WordPress comprometido.

Cabe destacar que el método wp.getUsersBlogs no es el único método existente, ni mucho menos la única vulnerabilidad en xmlrpc.php. Existen otros métodos como wp.getUsers, wp.getAuthors o wp.getComments, entre otros, que también pueden ser utilizados por atacantes para realizar ataques de fuerza bruta y comprometer la seguridad del sitio web de WordPress.

Por lo tanto, es importante tener en cuenta que la seguridad de un sitio web de WordPress no solo depende de tener contraseñas seguras y actualizadas, sino también de estar atentos a posibles vulnerabilidades en el archivo xmlrpc.php y otras áreas del sitio web.


wpscan --url http://127.0.0.1 -U wilmer -P  /usr/share/wordlists/rockyou.txt


# Enumeración de gestores de contenido (CMS) – Joomla

AVISO: Han actualizado el proyecto de Github, ahora simplemente lo despliegas con ‘docker-compose up -d‘ y no hace falta realizar el proceso de instalación, ya te viene todo instalado por defecto 😊

En esta clase, estaremos viendo cómo enumerar el gestor de contenido Joomla. Joomla es un sistema de gestión de contenidos (CMS) de código abierto que se utiliza para crear sitios web y aplicaciones en línea. Joomla es muy popular debido a su facilidad de uso y flexibilidad, lo que lo hace una opción popular para sitios web empresariales, gubernamentales y de organizaciones sin fines de lucro.

Joomla es altamente personalizable y cuenta con una gran cantidad de extensiones disponibles, lo que permite a los usuarios añadir funcionalidades adicionales a sus sitios web sin necesidad de conocimientos de programación avanzados. Joomla también cuenta con una comunidad activa de desarrolladores y usuarios que comparten sus conocimientos y recursos para mejorar el CMS.

A continuación, se comparte el enlace del proyecto que estaremos desplegando en Docker para auditar un Joomla:

CVE-2015-8562: https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562

Una de las herramientas que usamos en esta clase es Joomscan. Joomscan es una herramienta de línea de comandos diseñada específicamente para escanear sitios web que utilizan Joomla y buscar posibles vulnerabilidades y debilidades de seguridad.

Joomscan utiliza una variedad de técnicas de enumeración para identificar información sobre el sitio web de Joomla, como la versión de Joomla utilizada, los plugins y módulos instalados y los usuarios registrados en el sitio. También utiliza una base de datos de vulnerabilidades conocidas para buscar posibles vulnerabilidades en la instalación de Joomla.

Para utilizar Joomscan, primero debemos descargar la herramienta desde su sitio web oficial. A continuación se os proporciona el enlace al proyecto:

Joomscan: https://github.com/OWASP/joomscan
Una vez descargado, podemos utilizar la siguiente sintaxis básica para escanear un sitio web de Joomla:

➜ perl joomscan.pl -u <URL>

Donde <URL> es la URL del sitio web que deseamos escanear. Joomscan escaneará el sitio web y nos proporcionará una lista detallada de posibles vulnerabilidades y debilidades de seguridad.

Es importante tener en cuenta que joomscan no es una herramienta infalible y puede generar falsos positivos o falsos negativos. Por lo tanto, es importante utilizar joomscan junto con otras herramientas y técnicas de seguridad para tener una imagen completa de la seguridad del sitio web de Joomla que estemos auditando.



# Enumeración de gestores de contenido (CMS) – Drupal

En esta clase, aprenderemos a enumerar el gestor de contenidos Drupal. Drupal es un sistema de gestión de contenido libre y de código abierto (CMS) utilizado para la creación de sitios web y aplicaciones web.

Drupal ofrece un alto grado de personalización y escalabilidad, lo que lo convierte en una opción popular para sitios web complejos y grandes. Drupal se utiliza en una amplia gama de sitios web, desde blogs personales hasta sitios web gubernamentales y empresariales. Es altamente flexible y cuenta con una amplia variedad de módulos y herramientas que permiten a los usuarios personalizar su sitio web para satisfacer sus necesidades específicas.

Una de las herramientas que veremos en esta clase para enumerar un Drupal es la herramienta droopescan. Droopescan es una herramienta de escaneo de seguridad especializada en la identificación de versiones de Drupal y sus módulos, y en la detección de vulnerabilidades conocidas en ellos. La herramienta realiza un escaneo exhaustivo del sitio web para encontrar versiones de Drupal instaladas, módulos activos y vulnerabilidades conocidas, lo que ayuda a los administradores de sistemas y desarrolladores a identificar y solucionar los problemas de seguridad en sus sitios web.

Con esta herramienta, se pueden llevar a cabo análisis de seguridad en sitios web basados en Drupal, lo que puede ayudar a prevenir posibles ataques y problemas de seguridad en el futuro.

A continuación, es proporciona el enlace directo al proyecto en Github:

Droopescan: https://github.com/SamJoan/droopescan
Su uso es bastante intuitivo, a continuación se comparte un ejemplo de uso de esta herramienta:

➜ droopescan scan drupal --url https://example.com

Donde “scan” indica que queremos realizar un escaneo, “drupal” especifica que estamos realizando un escaneo de Drupal y “–url https://example.com” indica la URL del sitio web que se va a escanear.

Asimismo, os compartimos a continuación el enlace al proyecto de Github correspondiente al laboratorio que estaremos desplegando en Docker:

CVE-2018-7600: https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600



# Enumeración de gestores de contenido (CMS) – Magento

En esta clase, veremos cómo enumerar el gestor de contenido Magento. Magento es una plataforma de comercio electrónico de código abierto, que se utiliza para construir tiendas en línea de alta calidad y escalables. Es una de las plataformas más populares para el comercio electrónico y es utilizado por grandes marcas como Nike, Coca-Cola y Ford.

Sin embargo, con la popularidad de Magento también ha surgido la preocupación por la seguridad. Una de las herramientas que veremos en esta clase es Magescan, una herramienta de escaneo de vulnerabilidades específica para Magento.

Magescan puede detectar vulnerabilidades comunes en Magento, incluyendo problemas con permisos de archivos, errores de configuración y vulnerabilidades conocidas en extensiones populares de Magento.

A continuación se proporciona el enlace directo al proyecto en Github:

Magescan: https://github.com/steverobbins/magescan
Su sintaxis y modo de uso es bastante sencillo, a continuación se comparte un ejemplo:

➜ php magescan.phar scan:all https://example.com

Donde “magescan.phar” es el archivo ejecutable de la herramienta “Magescan“, “scan:all” es el comando específico de Magescan que indica que se realizará un escaneo exhaustivo de todas las vulnerabilidades conocidas en el sitio web objetivo y “https://example.com” es la URL del sitio web objetivo que se escaneará en busca de vulnerabilidades.

Asimismo, se comparte el enlace al laboratorio que estaremos desplegando en Docker para configurar el Magento vulnerable:

Magento 2.2 SQL Injection: https://github.com/vulhub/vulhub/tree/master/magento/2.2-sqli
Una de las técnicas que explotaremos sobre este gestor de contenidos es la famosa SQL Injection. Esta vulnerabilidad se produce cuando los datos de entrada no son debidamente validados y se pueden insertar comandos SQL maliciosos en la consulta a la base de datos.

Un ataque de inyección SQL exitoso puede permitir al atacante obtener información confidencial, como credenciales de usuario o datos de pago, o incluso ejecutar comandos en la base de datos del sitio web.

En el caso del Magento que estaremos desplegando, explotaremos una inyección SQL con el objetivo de obtener una cookie de sesión, la cual podremos posteriormente utilizar para llevar a cabo un ataque de “Cookie Hijacking“. Este tipo de ataque nos permitirá como atacantes asumir la identidad del usuario legítimo y acceder a las funciones del usuario, que en este caso será administrador.




# Toma de apuntes con Obsidian

En esta clase, aprenderás a usar Obsidian, un potente software de gestión de conocimiento personal. Obsidian es una herramienta diseñada para ayudarte a organizar y conectar toda tu información en un solo lugar, lo que te permite crear y mantener una base de conocimiento personal cohesiva y accesible.

Obsidian utiliza un enfoque de vinculación de notas para conectar tus ideas, pensamientos y conceptos, permitiéndote construir una red de conocimiento sólida y fácil de navegar. Puedes crear enlaces entre notas para establecer conexiones y descubrir nuevas relaciones y patrones en tus pensamientos y conocimientos.

Además, Obsidian es altamente personalizable, lo que significa que puedes adaptar su configuración y características a tus necesidades específicas. Puedes utilizarlo para gestionar tus notas, listas de tareas, proyectos, metas e incluso tu diario personal.

Con Obsidian, puedes dejar atrás las complicadas carpetas y sistemas de archivos y tener todo lo que necesitas en una sola aplicación. Es una herramienta extremadamente útil y cómoda que te ayudará a ser más eficiente y efectivo en la gestión de tu información personal y profesional.

A continuación, se os proporciona el enlace de descarga a esta utilidad:

Obsidian: https://obsidian.md/download
