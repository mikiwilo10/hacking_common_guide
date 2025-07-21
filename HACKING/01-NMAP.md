# Técnicas de evasión de Firewalls (MTU, Data Length, Source Port, Decoy, etc.)

Cuando se realizan pruebas de penetración, uno de los mayores desafíos es evadir la detección de los Firewalls, que son diseñados para proteger las redes y sistemas de posibles amenazas. Para superar este obstáculo, Nmap ofrece una variedad de técnicas de evasión que permiten a los profesionales de seguridad realizar escaneos sigilosos y evitar así la detección de los mismos.

Algunos de los parámetros vistos en esta clase son los siguientes:

MTU (–mtu): La técnica de evasión de MTU o “Maximum Transmission Unit” implica ajustar el tamaño de los paquetes que se envían para evitar la detección por parte del Firewall. Nmap permite configurar manualmente el tamaño máximo de los paquetes para garantizar que sean lo suficientemente pequeños para pasar por el Firewall sin ser detectados.

Data Length (–data-length): Esta técnica se basa en ajustar la longitud de los datos enviados para que sean lo suficientemente cortos como para pasar por el Firewall sin ser detectados. Nmap permite a los usuarios configurar manualmente la longitud de los datos enviados para que sean lo suficientemente pequeños para evadir la detección del Firewall.

Source Port (–source-port): Esta técnica consiste en configurar manualmente el número de puerto de origen de los paquetes enviados para evitar la detección por parte del Firewall. Nmap permite a los usuarios especificar manualmente un puerto de origen aleatorio o un puerto específico para evadir la detección del Firewall.

Decoy (-D): Esta técnica de evasión en Nmap permite al usuario enviar paquetes falsos a la red para confundir a los sistemas de detección de intrusos y evitar la detección del Firewall. El comando -D permite al usuario enviar paquetes falsos junto con los paquetes reales de escaneo para ocultar su actividad.

Fragmented (-f): Esta técnica se basa en fragmentar los paquetes enviados para que el Firewall no pueda reconocer el tráfico como un escaneo. La opción -f en Nmap permite fragmentar los paquetes y enviarlos por separado para evitar la detección del Firewall.

Spoof-Mac (–spoof-mac): Esta técnica de evasión se basa en cambiar la dirección MAC del paquete para evitar la detección del Firewall. Nmap permite al usuario configurar manualmente la dirección MAC para evitar ser detectado por el Firewall.

Stealth Scan (-sS): Esta técnica es una de las más utilizadas para realizar escaneos sigilosos y evitar la detección del Firewall. El comando -sS permite a los usuarios realizar un escaneo de tipo SYN sin establecer una conexión completa, lo que permite evitar la detección del Firewall.

min-rate (–min-rate): Esta técnica permite al usuario controlar la velocidad de los paquetes enviados para evitar la detección del Firewall. El comando –min-rate permite al usuario reducir la velocidad de los paquetes enviados para evitar ser detectado por el Firewall.

Es importante destacar que, además de las técnicas de evasión mencionadas anteriormente, existen muchas otras opciones en Nmap que pueden ser utilizadas para realizar pruebas de penetración efectivas y evadir la detección del Firewall. Sin embargo, las técnicas que hemos mencionado son algunas de las más populares y ampliamente utilizadas por los profesionales de seguridad para superar los obstáculos que presentan los Firewalls en la realización de pruebas de penetración.

nmap -p22 ip -f --mtu 8

nmap -p22 ip -D

### Puerto de Salida manipular

**Cambiar el puerto de origen**

nmap -p22 i192.168.1.1 --open -T5 -v -n --source-port 53


**Cambiar el puerto de origen**

nmap -p22 i192.168.1.1 --open -T5 -v -n --source-port 53



# Uso de scripts y categorías en nmap para aplicar reconocimiento

Una de las características más poderosas de Nmap es su capacidad para automatizar tareas utilizando scripts personalizados. Los scripts de Nmap permiten a los profesionales de seguridad automatizar las tareas de reconocimiento y descubrimiento en la red, además de obtener información valiosa sobre los sistemas y servicios que se están ejecutando en ellos. El parámetro –script de Nmap permite al usuario seleccionar un conjunto de scripts para ejecutar en un objetivo de escaneo específico.

Existen diferentes categorías de scripts disponibles en Nmap, cada una diseñada para realizar una tarea específica. Algunas de las categorías más comunes incluyen:

- default: Esta es la categoría predeterminada en Nmap, que incluye una gran cantidad de scripts de reconocimiento básicos y útiles para la mayoría de los escaneos.
- discovery: Esta categoría se enfoca en descubrir información sobre la red, como la detección de hosts y dispositivos activos, y la resolución de nombres de dominio.
- safe: Esta categoría incluye scripts que son considerados seguros y que no realizan actividades invasivas que puedan desencadenar una alerta de seguridad en la red.
- intrusive: Esta categoría incluye scripts más invasivos que pueden ser detectados fácilmente por un sistema de detección de intrusos o un Firewall, pero que pueden proporcionar información valiosa sobre vulnerabilidades y debilidades en la red.
- vuln: Esta categoría se enfoca específicamente en la detección de vulnerabilidades y debilidades en los sistemas y servicios que se están ejecutando en la red.

En conclusión, el uso de scripts y categorías en Nmap es una forma efectiva de automatizar tareas de reconocimiento y descubrimiento en la red. El parámetro –script permite al usuario seleccionar un conjunto de scripts personalizados para ejecutar en un objetivo de escaneo específico, mientras que las diferentes categorías disponibles en Nmap se enfocan en realizar tareas específicas para obtener información valiosa sobre la red.


nmap -p- -sC -SV 192.168.100.1 


locate .nse 

locate .nse  | xargs grep "categories" 

locate .nse  | xargs grep "categories"  | grep -oP '".*?"' | sort -u


nmap -p22 --script="vuln or/and safe" 192.168.100.1 

nmap -p80 --script http-enum 192.168.100.1 


### Servidor WEB PYTHON

python3 -m http.server 80

### Que servicio esta en el Puerto

lsof -i:80



# Descubrimiento de equipos en la red local (ARP e ICMP) y Tips

El descubrimiento de equipos en la red local es una tarea fundamental en la gestión de redes y en las pruebas de seguridad. Existen diferentes herramientas y técnicas para realizar esta tarea, que van desde el escaneo de puertos hasta el análisis de tráfico de red.

En esta clase, nos enfocaremos en las técnicas de descubrimiento de equipos basadas en los protocolos ARP e ICMP. Además, se presentarán diferentes herramientas que pueden ser útiles para esta tarea, como Nmap, netdiscover, arp-scan y masscan.

Entre los modos de escaneo que se explican en la clase, se encuentra el uso del parámetro ‘-sn‘ de Nmap, que permite realizar un escaneo de hosts sin realizar el escaneo de puertos. También se presentan las herramientas netdiscover, arp-scan y masscan, que utilizan el protocolo ARP para descubrir hosts en la red.

Cada herramienta tiene sus propias ventajas y limitaciones. Por ejemplo, netdiscover es una herramienta simple y fácil de usar, pero puede ser menos precisa que arp-scan o masscan. Por otro lado, arp-scan y masscan son herramientas más potentes, capaces de descubrir hosts más rápido y en redes más grandes, pero también son más complejas y pueden requerir más recursos.

En definitiva, el descubrimiento de equipos en la red local es una tarea fundamental para cualquier administrador de redes o profesional de seguridad de la información. Con las técnicas y herramientas adecuadas, es posible realizar esta tarea de manera efectiva y eficiente.


namp -sn 192.168.100.0/24

arp-scan -I ens33 --localnet --ignoredups

timeout -1 bash -c "ping -c 1 192.168.1.1" &>/dev/null && echo "[+]EL host esta activo"

masscan -p21,22,139,445 -Pn 192.168.10.0/24 --rate=5000



# Validación del objetivo (Fijando un target en HackerOne)
En esta clase exploraremos la plataforma HackerOne, una plataforma de BugBounty que permite a empresas y organizaciones que desean ser auditadas, “conectar” con hackers éticos para encontrar vulnerabilidades de seguridad en sus sistemas y aplicaciones de forma legal.

Antes de iniciar una auditoría en esta plataforma, es fundamental fijar un objetivo claro, además de definir el alcance de la auditoría. Esto se logra a través del concepto de “Scope“, que establece los límites de la auditoría, así como los sistemas y aplicaciones que pueden ser auditados.

En esta clase, se explicará cómo validar un objetivo en HackerOne y cómo definir el alcance de la auditoría a través del Scope. Además, se discutirán los impedimentos y limitaciones que se pueden encontrar durante la fase de auditoría, evitando así posibles malentendidos durante el proceso de reporte de vulnerabilidades.

Enlace a la web de HackerOne: https://www.hackerone.com/


# Descubrimiento de correos electrónicos

En esta clase exploraremos la importancia de la recolección de información en la fase de OSINT durante una auditoría, en particular, la recolección de correos electrónicos. Los correos electrónicos pueden ser una valiosa fuente de información para la vulneración de posibles paneles de autenticación y la realización de campañas de Phishing.

Durante la clase se presentan diferentes herramientas online que pueden ayudar en este proceso. Por ejemplo, se explica cómo usar ‘hunter.io‘ para buscar correos electrónicos asociados a un dominio en particular. También se muestra cómo utilizar ‘intelx.io‘ para buscar información relacionada con direcciones de correo electrónico, nombres de usuarios y otros detalles.

Otra herramienta interesante que se presenta en la clase es ‘phonebook.cz‘, que permite buscar correos electrónicos y otros datos de contacto relacionados con empresas de todo el mundo.

Finalmente, se habla sobre el plugin ‘Clearbit Connect‘ para Gmail, que permite obtener información de contacto en tiempo real y añadirla directamente a los contactos de Gmail.

A continuación, se proporcionan los enlaces a las herramientas online vistas en esta clase:

Hunter: https://hunter.io/
Intelligence X: https://intelx.io/
Phonebook.cz: https://phonebook.cz/
Clearbit Connect: Chrome Extension
En conclusión, la recolección de correos electrónicos es una tarea importante en la fase inicial de OSINT y puede proporcionar información valiosa. Sin embargo, es importante tener en cuenta que la recolección de correos electrónicos por sí sola no permite identificar directamente posibles vulnerabilidades en una red o sistema.


# Reconocimiento de imágenes

En esta clase, exploraremos cómo las tecnologías de reconocimiento de imágenes pueden ser utilizadas para obtener información valiosa sobre las personas y los lugares.

Una de las herramientas en línea que vemos en esta clase es ‘PimEyes‘. PimEyes es una plataforma en línea que utiliza tecnología de reconocimiento facial para buscar imágenes similares en Internet en función de una imagen que se le proporciona como entrada. Esta herramienta puede ser útil en la detección de información personal de una persona, como sus perfiles en redes sociales, direcciones de correo electrónico, números de teléfono, nombres y apellidos, etc.

El funcionamiento de PimEyes se basa en el análisis de patrones faciales, que son comparados con una base de datos de imágenes en línea para encontrar similitudes. La plataforma también permite buscar imágenes de personas que aparecen en una foto en particular, lo que puede ser útil en la investigación de casos de acoso o en la búsqueda de personas desaparecidas.

Enlace a la web de PimEyes: https://pimeyes.com/en


# Enumeración de subdominios

IMPORTANTE: Recientemente, hemos notado un problema con la herramienta “sublist3r” del repositorio que presentamos en el vídeo: no está mostrando los subdominios del dominio que introduces durante el proceso de reconocimiento.

Aunque es probable que este error se corrija pronto, para quienes necesiten usar la herramienta sin inconvenientes en este momento, os sugiero descargarla desde este repositorio alternativo:

https://github.com/huntergregal/Sublist3r
 
La enumeración de subdominios es una de las fases cruciales en la seguridad informática para identificar los subdominios asociados a un dominio principal.

Los subdominios son parte de un dominio más grande y a menudo están configurados para apuntar a diferentes recursos de la red, como servidores web, servidores de correo electrónico, sistemas de bases de datos, sistemas de gestión de contenido, entre otros.

Al identificar los subdominios vinculados a un dominio principal, un atacante podría obtener información valiosa para cada uno de estos, lo que le podría llevar a encontrar vectores de ataque potenciales. Por ejemplo, si se identifica un subdominio que apunta a un servidor web vulnerable, el atacante podría utilizar esta información para intentar explotar la vulnerabilidad y acceder al servidor en cuestión.

Existen diferentes herramientas y técnicas para la enumeración de subdominios, tanto pasivas como activas. Las herramientas pasivas permiten obtener información sobre los subdominios sin enviar ninguna solicitud a los servidores identificados, mientras que las herramientas activas envían solicitudes a los servidores identificados para encontrar subdominios bajo el dominio principal.

Algunas de las herramientas pasivas más utilizadas para la enumeración de subdominios incluyen la búsqueda en motores de búsqueda como Google, Bing o Yahoo, y la búsqueda en registros DNS públicos como PassiveTotal o Censys. Estas herramientas permiten identificar subdominios asociados con un dominio, aunque no siempre son exhaustivas. Además, existen herramientas como CTFR que utilizan registros de certificados SSL/TLS para encontrar subdominios asociados a un dominio.

También se pueden utilizar páginas online como Phonebook.cz e Intelx.io, o herramientas como sublist3r, para buscar información relacionada con los dominios, incluyendo subdominios.

Por otro lado, las herramientas activas para la enumeración de subdominios incluyen herramientas de fuzzing como wfuzz o gobuster. Estas herramientas envían solicitudes a los servidores mediante ataques de fuerza bruta, con el objetivo de encontrar subdominios válidos bajo el dominio principal.

A continuación, os adjuntamos los enlaces a las herramientas vistas en esta clase:

Phonebook (Herramienta pasiva): https://phonebook.cz/
Intelx (Herramienta pasiva): https://intelx.io/
CTFR (Herramienta pasiva): https://github.com/UnaPibaGeek/ctfr
Gobuster (Herramienta activa): https://github.com/OJ/gobuster
Wfuzz (Herramienta activa): https://github.com/xmendez/wfuzz
Sublist3r (Herramienta pasiva): https://github.com/huntergregal/Sublist3r


wfuzz -c -hc=403 -t 20 -w /usr/share  http://facebook.com



# Credenciales y brechas de seguridad

La seguridad de la información es un tema crítico en el mundo digital actual, especialmente cuando se trata de datos sensibles como contraseñas, información financiera o de identidad. Los ataques informáticos son una amenaza constante para cualquier empresa u organización, y una de las principales técnicas utilizadas por los atacantes es la explotación de las credenciales y brechas de seguridad.

Una de las formas más comunes en que los atacantes aprovechan las brechas de seguridad es mediante el uso de leaks de bases de datos. Estos leaks pueden ser el resultado de errores de configuración, vulnerabilidades en el software o ataques malintencionados. Cuando una base de datos se ve comprometida, los atacantes pueden acceder a una gran cantidad de información sensible, como nombres de usuario, contraseñas y otra información personal.

Una vez que los atacantes tienen acceso a esta información, pueden utilizarla para realizar ataques de fuerza bruta, phishing y otros ataques de ingeniería social para acceder a sistemas y cuentas protegidas. En algunos casos, los atacantes pueden incluso vender esta información en el mercado negro para que otros atacantes la utilicen.

Es importante entender que muchas de estas bases de datos filtradas y vendidas en línea son accesibles públicamente y en algunos casos, incluso se venden por una pequeña cantidad de dinero. Esto significa que cualquier persona puede acceder a esta información y utilizarla para llevar a cabo ataques malintencionados.

A continuación, se proporciona el enlace a la utilidad online de ejemplo que se muestra en esta clase:

DeHashed: https://www.dehashed.com/



# Identificación de las tecnologías en una página web

Desde el punto de vista de la seguridad, es fundamental conocer las tecnologías y herramientas que se utilizan en una página web. La identificación de estas tecnologías permite a los expertos en seguridad evaluar los riesgos potenciales de un sitio web, identificar vulnerabilidades y diseñar estrategias efectivas para proteger la información sensible y los datos críticos.

Existen diversas herramientas y utilidades en línea que permiten identificar las tecnologías utilizadas en una página web. Algunas de las herramientas más populares incluyen Whatweb, Wappalyzer y builtwith.com. Estas herramientas escanean la página web y proporcionan información detallada sobre las tecnologías utilizadas, como el lenguaje de programación, el servidor web, los sistemas de gestión de contenido, entre otros.

La herramienta whatweb es una utilidad de análisis de vulnerabilidades que escanea la página web y proporciona información detallada sobre las tecnologías utilizadas. Esta herramienta también puede utilizarse para identificar posibles vulnerabilidades y puntos débiles en la página web.

Wappalyzer, por otro lado, es una extensión del navegador que detecta y muestra las tecnologías utilizadas en la página web. Esta herramienta es especialmente útil para los expertos en seguridad que desean identificar rápidamente las tecnologías utilizadas en una página web sin tener que realizar un escaneo completo.

Builtwith.com es una herramienta en línea que también permite identificar las tecnologías utilizadas en una página web. Esta herramienta proporciona información detallada sobre las tecnologías utilizadas, así como también estadísticas útiles como el tráfico y la popularidad de la página web.

A continuación, os proporcionamos los enlaces correspondientes a las herramientas vistas en esta clase:

Whatweb: https://github.com/urbanadventurer/WhatWeb
Wappalyzer: https://addons.mozilla.org/es/firefox/addon/wappalyzer/
Builtwith: https://builtwith.com/


# Fuzzing y enumeración de archivos en un servidor web (1/2)

En esta clase, hacemos uso de las herramientas Wfuzz y Gobuster para aplicar Fuzzing. Esta técnica se utiliza para descubrir rutas y recursos ocultos en un servidor web mediante ataques de fuerza bruta. El objetivo es encontrar recursos ocultos que podrían ser utilizados por atacantes malintencionados para obtener acceso no autorizado al servidor.

Wfuzz es una herramienta de descubrimiento de contenido y una herramienta de inyección de datos. Básicamente, se utiliza para automatizar los procesos de prueba de vulnerabilidades en aplicaciones web.

Permite realizar ataques de fuerza bruta en parámetros y directorios de una aplicación web para identificar recursos existentes. Una de las ventajas de Wfuzz es que es altamente personalizable y se puede ajustar a diferentes necesidades de pruebas. Algunas de las desventajas de Wfuzz incluyen la necesidad de comprender la sintaxis de sus comandos y que puede ser más lenta en comparación con otras herramientas de descubrimiento de contenido.

Por otro lado, Gobuster es una herramienta de descubrimiento de contenido que también se utiliza para buscar archivos y directorios ocultos en una aplicación web. Al igual que Wfuzz, Gobuster se basa en ataques de fuerza bruta para encontrar archivos y directorios ocultos. Una de las principales ventajas de Gobuster es su velocidad, ya que es conocida por ser una de las herramientas de descubrimiento de contenido más rápidas. También es fácil de usar y su sintaxis es simple. Sin embargo, una desventaja de Gobuster es que puede no ser tan personalizable como Wfuzz.

En resumen, tanto Wfuzz como Gobuster son herramientas útiles para pruebas de vulnerabilidades en aplicaciones web, pero tienen diferencias en su enfoque y características. La elección de una u otra dependerá de tus necesidades y preferencias personales.

A continuación, te proporcionamos el enlace a estas herramientas:

Wfuzz: https://github.com/xmendez/wfuzz
Gobuster: https://github.com/OJ/gobuster



**GOBUSTER**

Compilar goBuster

go build -ldflags "-s -w" .

upx gobuster

**Comandos**

### Estados 200

```bash
gobuster dir -u http://10.10.191.71 -w wordlist.txt dir -t 200 --add-slash -b 403,404
```

### Busqueda de extensiones de Archivos

```bash
gobuster dir -u http://10.10.191.71 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -b 403,404
```

```bash
gobuster dir -u http://10.10.191.71 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -s 200 -b ''
```



```bash
gobuster dir -u http://10.10.52.46/ -w /usr/share/wordlists/dirb/big.txt --exclude-length 0
```


**WFFUZ**

```bash
wfuzz -c --hc=404,403 -t 200 -w /usr/share/wordlists/dirb/big.txt http://10.10.52.46/FUZZ/
```



# Fuzzing y enumeración de archivos en un servidor web (2/2)

En esta clase, veremos cómo se pueden utilizar diferentes parámetros de Wfuzz para ajustar el alcance y la profundidad de nuestro reconocimiento en aplicaciones web. Algunos de los parámetros que cubriremos incluyen el parámetro ‘–sl‘, para filtrar por un número de líneas determinado, el parámetro ‘–hl‘ para ocultar un número de líneas determinado y por último el parámetro ‘-z‘ para indicar el tipo de dato que queremos usar de cara al reconocimiento que nos interese aplicar, abarcando opciones como diccionarios, listas y rangos numéricos.

Adicionalmente, otra de las herramientas que examinamos en esta clase, perfecta para la enumeración de recursos disponibles en una plataforma en línea, es BurpSuite. BurpSuite es una plataforma que integra características especializadas para realizar pruebas de penetración en aplicaciones web. Una de sus particularidades es la función de análisis de páginas en línea, empleada para identificar y enumerar los recursos accesibles en una página web.

BurpSuite cuenta con dos versiones: una versión gratuita (BurpSuite Community Edition) y una versión de pago (BurpSuite Pofessional).

BurpSuite Community Edition
Es la versión gratuita de esta plataforma, viene incluida por defecto en el sistema operativo. Su función principal es desempeñar el papel de proxy HTTP para la aplicación, facilitando la realización de pruebas de penetración.

Un proxy HTTP es un filtro de contenido de alto rendimiento, ampliamente usado en el hacking con el fin de interceptar el tráfico de red. Esto permite analizar, modificar, aceptar o rechazar todas las solicitudes y respuestas de la aplicación que se esté auditando.

Algunas de las ventajas que la versión gratuita ofrecen son:

Gratuidad: La versión Community Edition es gratuita, lo que la convierte en una opción accesible para principiantes y profesionales con presupuestos limitados.
Herramientas básicas: Incluye las herramientas esenciales para realizar pruebas de penetración en aplicaciones web, como el Proxy, el Repeater y el Sequencer.
Intercepción y modificación de tráfico: Permite interceptar y modificar las solicitudes y respuestas HTTP/HTTPS, facilitando la identificación de vulnerabilidades y la exploración de posibles ataques.
Facilidad de uso: La interfaz de usuario de la Community Edition es intuitiva y fácil de utilizar, lo que facilita su adopción por parte de usuarios con diversos niveles de experiencia.
Aprendizaje y familiarización: La versión gratuita permite a los usuarios aprender y familiarizarse con las funcionalidades y técnicas de pruebas de penetración antes de dar el salto a la versión Professional.
Comunidad de usuarios: La versión Community Edition cuenta con una amplia comunidad de usuarios que comparten sus conocimientos y experiencias en foros y blogs, lo que puede ser de gran ayuda para resolver problemas y aprender nuevas técnicas.
A pesar de que la Community Edition no ofrece todas las funcionalidades y ventajas de la versión Professional, sigue siendo una opción valiosa para aquellos que buscan comenzar en el ámbito de las pruebas de penetración o que necesitan realizar análisis de seguridad básicos sin incurrir en costos adicionales.

BurpSuite Proffesional
BurpSuite Proffessional es la versión de pago desarrollada por la empresa PortSwigger. Incluye, además del proxy HTTP, algunas herramientas de pentesting web como:

Escáner de seguridad automatizado: Permite identificar vulnerabilidades en aplicaciones web de manera rápida y eficiente, lo que ahorra tiempo y esfuerzo.
Integración con otras herramientas: Puede integrarse con otras soluciones de seguridad y entornos de desarrollo para mejorar la eficacia de las pruebas.
Extensibilidad: A través de su API, BurpSuite Professional permite a los usuarios crear y añadir extensiones personalizadas para adaptarse a necesidades específicas.
Actualizaciones frecuentes: La versión profesional recibe actualizaciones periódicas que incluyen nuevas funcionalidades y mejoras de rendimiento.
Soporte técnico: Los usuarios de BurpSuite Professional tienen acceso a un soporte técnico de calidad para resolver dudas y problemas.
Informes personalizables: La herramienta permite generar informes detallados y personalizados sobre las pruebas de penetración y los resultados obtenidos.
Interfaz de usuario intuitiva: La interfaz de BurpSuite Professional es fácil de utilizar y permite a los profesionales de seguridad trabajar de manera eficiente.
Herramientas avanzadas: Incluye funcionalidades avanzadas, como el módulo de intrusión, el rastreador de vulnerabilidades y el generador de payloads, que facilitan la identificación y explotación de vulnerabilidades en aplicaciones web.
En conclusión, tanto la Community Edition como la versión Professional de BurpSuite ofrecen un conjunto de herramientas útiles y eficientes para realizar pruebas de penetración en aplicaciones web. Sin embargo, la versión Professional brinda ventajas adicionales.

La elección entre ambas versiones dependerá del alcance y las necesidades específicas del proyecto o de la empresa. Si se requiere un conjunto básico de herramientas para pruebas de seguridad ocasionales, la Community Edition podría ser suficiente. No obstante, si se busca una solución más completa y personalizable, con soporte técnico y herramientas avanzadas para un enfoque profesional y exhaustivo, la versión Professional sería la opción más adecuada.




# Google Dorks / Google Hacking (Los 18 Dorks más usados)
El ‘Google Dork‘ es una técnica de búsqueda avanzada que utiliza operadores y palabras clave específicas en el buscador de Google para encontrar información que normalmente no aparece en los resultados de búsqueda regulares.

La técnica de ‘Google Dorking‘ se utiliza a menudo en el hacking para encontrar información sensible y crítica en línea. Es una forma eficaz de recopilar información valiosa de una organización o individuo que puede ser utilizada para realizar pruebas de penetración y otros fines de seguridad.

Al utilizar Google Dorks, un atacante puede buscar información como nombres de usuarios y contraseñas, archivos confidenciales, información de bases de datos, números de tarjetas de crédito y otra información crítica. También pueden utilizar esta técnica para identificar vulnerabilidades en aplicaciones web, sitios web y otros sistemas en línea.

Es importante tener en cuenta que la técnica de Google Dorking no es ilegal en sí misma, pero puede ser utilizada con fines maliciosos. Por lo tanto, es crucial utilizar esta técnica con responsabilidad y ética en el contexto de la seguridad informática y el hacking ético.



# Identificación y verificación externa de la versión del sistema operativo

El tiempo de vida (TTL) hace referencia a la cantidad de tiempo o “saltos” que se ha establecido que un paquete debe existir dentro de una red antes de ser descartado por un enrutador. El TTL también se utiliza en otros contextos, como el almacenamiento en caché de CDN y el almacenamiento en caché de DNS.

Cuando se crea un paquete de información y se envía a través de Internet, está el riesgo de que siga pasando de enrutador a enrutador indefinidamente. Para mitigar esta posibilidad, los paquetes se diseñan con una caducidad denominada tiempo de vida o límite de saltos. El TTL de los paquetes también puede ser útil para determinar cuánto tiempo ha estado en circulación un paquete determinado, y permite que el remitente pueda recibir información sobre la trayectoria de un paquete a través de Internet.

Cada paquete tiene un lugar en el que se almacena un valor numérico que determina cuánto tiempo debe seguir moviéndose por la red. Cada vez que un enrutador recibe un paquete, resta uno al recuento de TTL y lo pasa al siguiente lugar de la red. Si en algún momento el recuento de TTL llega a cero después de la resta, el enrutador descartará el paquete y enviará un mensaje ICMP al host de origen.

¿Qué tiene que ver esto con la identificación del sistema operativo? Bueno, resulta que diferentes sistemas operativos tienen diferentes valores predeterminados de TTL. Por ejemplo, en sistemas operativos Windows, el valor predeterminado de TTL es 128, mientras que en sistemas operativos Linux es 64.

Por lo tanto, si enviamos un paquete a una máquina y recibimos una respuesta que tiene un valor TTL de 128, es probable que la máquina esté ejecutando Windows. Si recibimos una respuesta con un valor TTL de 64, es más probable que la máquina esté ejecutando Linux.

Este método no es infalible y puede ser engañado por los administradores de red, pero puede ser útil en ciertas situaciones para identificar el sistema operativo de una máquina.

A continuación, se os comparte la página que mostramos en esta clase para identificar el sistema operativo correspondiente a los diferentes valores de TTL existentes.

Subin’s Blog: https://subinsb.com/default-device-ttl-values/
Asimismo, os compartimos el script de Python encargado de identificar el sistema operativo en función del TTL obtenido:

WhichSystem: https://pastebin.com/HmBcu7j2


https://github.com/Akronox/WichSystem.py/blob/main/wichSystem.py



mv wichSystem.py /usr/bin/ 

echo $ Path 
permisos con chmod de ejecucion .rwxr-xr-x

wichSystem.py 192.158.21.2