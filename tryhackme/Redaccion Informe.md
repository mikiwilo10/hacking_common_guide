# Instrucciones
Se realizó una prueba de penetración de aplicaciones web para TryBankMe, la subdivisión de TryHackMe que se encargará de las tareas bancarias. Necesitaban una prueba de penetración de su aplicación estrella, TryBankMe, donde los usuarios pueden crear cuentas y realizar tareas bancarias generales.

La prueba de penetración determinó que la aplicación era mayormente segura, pero existía una condición de carrera que podría explotarse en el sistema de transacciones para causar un fallo de dinero infinito.

Deberá redactar el informe en tres fases. En esta fase, deberá redactar el resumen basado en el informe de la prueba de penetración.

Arrastre y suelte las opciones en las secciones para asociarlas.
Solo puede asociar una opción a cada sección.
Puede haber más de una respuesta correcta, pero debe elegir la más adecuada para obtener la máxima puntuación.
Obtener una puntuación superior a 320 le otorgará la primera bandera.







### Opciones

- Aprovechar la condición de carrera podría permitir a los atacantes activar múltiples transacciones superpuestas, lo que les permite eludir las comprobaciones de saldo y generar créditos no autorizados.

- El error implica que los usuarios podrían engañar al sistema para que les otorgue dinero gratis haciendo clic repetidamente.

- La aplicación bancaria TryBankMe se probó desde una perspectiva externa. El enfoque se centró en funciones comunes como el registro y las transacciones para detectar cualquier vulnerabilidad antes de su lanzamiento.

- Intente corregir la ejecución simultánea de las transacciones y verifique más tarde si persiste. Quizás pueda agregar algunos registros.

- Asegúrese de que las transacciones no se superpongan y quizás agregue alertas para detectar problemas. También se debería considerar una nueva prueba.

- La aplicación mostró una buena seguridad en la mayoría de las áreas probadas, incluyendo el inicio de sesión y el control de acceso. Sin embargo, se detectó una condición de carrera en la función de transacciones que podría permitir a los usuarios manipular los saldos.

- Agregue bloqueo de transacciones y operaciones atómicas para evitar la manipulación de saldos. Incluya la monitorización de patrones inusuales y valide la solución mediante una nueva prueba específica.

- El error podría permitir que los usuarios envíen solicitudes superpuestas para generar dinero extra, lo que podría resultar en ganancias no autorizadas.

- La aplicación se veía bien en general, pero encontramos un error grave que podría permitir que alguien ganara dinero manipulando las transacciones.

- Se realizó una prueba de penetración de caja negra en la plataforma TryBankMe, el nuevo sistema de banca en línea de TryHackMe. La prueba se centró en las funciones bancarias principales, como el registro, el inicio de sesión y el procesamiento de transacciones, con el objetivo de identificar riesgos de seguridad antes de su lanzamiento público.

- La mayor parte de la aplicación parecía segura, pero identificamos un problema en la gestión de las transacciones. Esto podría causar problemas si se explota.

- Probamos la aplicación TryBankMe para detectar errores. Esto incluyó probar los registros y las transferencias de dinero antes de su lanzamiento.




## Resumen
- Se realizó una prueba de penetración de caja negra en la plataforma TryBankMe, el  nuevo sistema de banca en línea de TryHackMe. La prueba se centró en las funciones bancarias principales, como el registro, el inicio de sesión y el procesamiento de transacciones, con el objetivo de identificar riesgos de seguridad antes de su lanzamiento público.

# Resultado
- La aplicación mostró una buena seguridad en la mayoría de las áreas probadas, incluyendo el inicio de sesión y el control de acceso. Sin embargo, se detectó una condición de carrera en la función de transacciones que podría permitir a los usuarios manipular los saldos.


## impacto
- El error podría permitir que los usuarios envíen solicitudes superpuestas para generar dinero extra, lo que podría resultar en ganancias no autorizadas.


## Arreglo- Solucion

- Agregue bloqueo de transacciones y operaciones atómicas para evitar la manipulación de saldos. Incluya la monitorización de patrones inusuales y valide la solución mediante una nueva prueba específica.




------------------ 400 puntos

## Resumen
- Se realizó una prueba de penetración de caja negra en la plataforma TryBankMe, el nuevo sistema de banca en línea de TryHackMe. La prueba se centró en las funciones bancarias principales, como el registro, el inicio de sesión y el procesamiento de transacciones, con el objetivo de identificar riesgos de seguridad antes de su lanzamiento público.

# Resultado
- La aplicación mostró una buena seguridad en la mayoría de las áreas probadas, incluyendo el inicio de sesión y el control de acceso. Sin embargo, se detectó una condición de carrera en la función de transacciones que podría permitir a los usuarios manipular los saldos.


## impacto
- Aprovechar la condición de carrera podría permitir a los atacantes activar múltiples transacciones superpuestas, lo que les permite eludir las comprobaciones de saldo y generar créditos no autorizados.


## Arreglo- Solucion

- Agregue bloqueo de transacciones y operaciones atómicas para evitar la manipulación de saldos. Incluya la monitorización de patrones inusuales y valide la solución mediante una nueva prueba específica.




THM{Summarise.the.Business.Information}






-------------------------------------------------

La sección más grande de su informe serán los artículos sobre vulnerabilidades. Cada artículo debe explicar cuál es la vulnerabilidad, dónde se encontró, cómo se descubrió y, lo más importante, cómo debe remediarse. Esta sección está escrita principalmente para las partes interesadas que van a solucionar los problemas, como desarrolladores o administradores de sistemas. Sin embargo, otros, como analistas de seguridad y gerentes de proyectos, también pueden revisar estas secciones para realizar un seguimiento de la remediación, brindar apoyo o validar la gravedad.



-------------------------------------------


# Título - 
Un título breve y descriptivo (p. ej. "No autenticado SQL Inyección en el formulario de inicio de sesión")
Calificación de riesgo - Una calificación de riesgo para la vulnerabilidad descubierta. Las vulnerabilidades siempre deben calificarse de forma aislada, como si todas las demás vulnerabilidades no existieran y deben utilizar la matriz de calificación de riesgos del cliente o una pública, como CVSS.

# Resumen - 
Una breve explicación de la vulnerabilidad y su impacto potencial en un lenguaje sencillo.

# Antecedentes - 
Proporcionar contexto adicional para explicar la vulnerabilidad y por qué es importante. Esto es especialmente importante si el lector no está familiarizado con él. Recuerde que los desarrolladores que solucionarán la vulnerabilidad potencialmente no son expertos en seguridad, por lo que más orientación para ayudarlos a comprender la causa raíz de la vulnerabilidad los ayudará a remediar el problema con precisión.

# Detalles técnicos y evidencia - 
Dónde y cómo se encontró el problema. Incluya solicitudes, respuestas, cargas útiles y capturas de pantalla o fragmentos de código si es necesario.

# Impacto - 
Qué podría hacer un atacante de manera realista con esta vulnerabilidad. Esto demuestra que no se trata simplemente de proporcionar la vulnerabilidad sin pensar en cómo un actor de amenazas real podría aprovecharla en el sistema o aplicación específica donde la encontró. Por ejemplo, es común decir con XSS que el actor de la amenaza robaría la cookie del usuario para realizar un secuestro de sesión. ¿Pero qué pasa si la aplicación utiliza tokens en su lugar? ¿Significa eso ahora que el impacto es menor? Asegúrese de contextualizar el impacto en el sistema específico que está probando.

# Consejos de remediación - 
Pasos claros y viables para resolver el problema. Es fundamental asegurarse de que sus consejos de remediación aborden la causa raíz de la vulnerabilidad. Si bien es posible que desee proporcionar medidas adicionales que ayuden a una mayor mitigación, Su primera recomendación debe abordar la vulnerabilidad en su núcleo. Consideremos, por ejemplo, SQL Inyección. Si bien la desinfección y la validación de entradas pueden ayudar a mitigar la vulnerabilidad y dificultar su explotación, se requiere parametrización para abordar la vulnerabilidad en su núcleo. Esto garantiza que, independientemente de la entrada, no pueda haber confusión entre SQLcomando y entrada proporcionada por el usuario. Asegúrese siempre de que su recomendación resuelva completamente la vulnerabilidad, no solo mitigue su impacto. Si desea proporcionar más controles de defensa en profundidad, asegúrese de mencionar que estos no se pueden implementar de forma aislada.

# Referencias - 
(Opcional) Enlaces a documentación u orientación relevante del proveedor para respaldar la solución.






# Instrucciones
Se realizó una prueba de penetración de aplicaciones web para TryBankMe, la subdivisión de TryHackMe que se encargará de las tareas bancarias. Necesitaban una prueba de penetración de su aplicación estrella, TryBankMe, donde los usuarios pueden crear cuentas y realizar tareas bancarias generales.

La prueba de penetración determinó que la aplicación era mayormente segura, pero existía una condición de carrera que podría explotarse en el sistema de transacciones para causar un fallo de dinero infinito.

Esta es la segunda fase del desafío. En esta fase, deberás redactar el informe basado en la vulnerabilidad de la condición de carrera.

Arrastra las opciones y suéltalas en las secciones para que coincidan.
Solo se puede asociar una opción a cada sección.
Puede haber más de una respuesta correcta, pero debes elegir la más adecuada para obtener la máxima puntuación.
Obtener una puntuación superior a 500 te dará la bandera.




### Opciones

- Esto permite robar dinero de la aplicación haciendo clic rápido. Un gran problema si se implementa.

- Usamos un script simple de Python para enviar múltiples solicitudes simultáneamente a la función de transferencia. Esto provocaba que la aplicación permitiera más de una transacción sin actualizar el saldo correctamente.

- Un error bancario te permite obtener más dinero

- Soluciona el error impidiendo que los usuarios realicen transferencias demasiado rápido. Quizás implementando un retraso o bloqueando el botón.

- Las condiciones de carrera ocurren cuando un sistema realiza múltiples operaciones simultáneamente sin la gestión adecuada, lo que genera resultados inesperados. En aplicaciones web, esto suele afectar a los sistemas financieros donde el orden y la sincronización de las solicitudes son cruciales. Sin bloqueo de transacciones ni comprobaciones atómicas, los usuarios pueden aprovechar la sincronización para crear estados inconsistentes.

- Si haces clic lo suficientemente rápido, puedes obtener más dinero. Eso es básicamente lo que hace este error.

- Se encontró un problema donde los usuarios podían crear transacciones superpuestas y engañar al sistema para que acreditara fondos adicionales.

- Usamos un script para enviar spam al botón de transferencia de dinero y nos dio más efectivo del que teníamos. El servidor no pudo seguir el ritmo.

- Condición de Carrera en la Gestión de Transacciones Permite la Manipulación del Saldo

- Las condiciones de carrera son errores en los que los procesos ocurren demasiado rápido y la aplicación entra en pánico. Es como un fallo de sincronización.

- Una condición de carrera se produce cuando dos cosas ocurren al mismo tiempo y la aplicación no las gestiona correctamente. Este tipo de error es común en aplicaciones que gestionan dinero.

- Es bastante grave: las personas pueden engañar al sistema y enriquecerse rápidamente.

- El problema se confirmó al enviar múltiples solicitudes POST simultáneas al punto final /transfer utilizando el mismo saldo de cuenta. Mediante un script, iniciamos cinco solicitudes de transferencia idénticas simultáneamente. Todas las solicitudes se procesaron, lo que resultó en un saldo final que no reflejaba la deducción, duplicando los fondos.

- Condición de Carrera en Transacciones Bancarias

- Media: El error permite a los atacantes manipular el flujo de transacciones, pero no expone los datos directamente.

- Implementar bloqueos a nivel de transacción u operaciones atómicas en el backend para evitar el procesamiento paralelo de acciones que alteren el saldo. También se deben considerar medidas de seguridad adicionales, como la limitación de velocidad y la detección de anomalías en ransacciones rápidas o duplicadas. Validar las correcciones con nuevas pruebas específicas.

- Si no se soluciona, esta vulnerabilidad podría permitir a usuarios maliciosos generar fondos de la nada aprovechando las brechas de tiempo en la validación de transacciones. Esto podría provocar pérdidas financieras directas, daños a la reputación y posibles consecuencias legales por o proteger la integridad de las transacciones.

- Alto (puntuación base CVSS 3.1: 8,6): La explotación permite la inflación no autorizada del saldo sin necesidad de eludir la autenticación.

- Los atacantes podrían usar esto para obtener más dinero en su cuenta, lo que podría causar la pérdida de fondos y dañar la confianza en el sistema.

- Se descubrió una condición de carrera en el endpoint de la transacción que permite a los usuarios iniciar múltiples transferencias superpuestas, lo que resulta en aumentos no autorizados del saldo de la cuenta.

- Evite que los usuarios envíen demasiadas transferencias al mismo tiempo. También puede considerar limitar las solicitudes y detectar comportamientos sospechosos


### Título seccional

- Condición de Carrera en la Gestión de Transacciones Permite la Manipulación del Saldo

### Calificación de riesgo

- Alto (puntuación base CVSS 3.1: 8,6): La explotación permite la inflación no autorizada del saldo sin necesidad de eludir la autenticación.

### Resumen

- Se descubrió una condición de carrera en el endpoint de la transacción que permite a los usuarios iniciar múltiples transferencias superpuestas, lo que resulta en aumentos no autorizados del saldo de la cuenta.

### Antecedentes
- Las condiciones de carrera ocurren cuando un sistema realiza múltiples operaciones simultáneamente sin la gestión adecuada, lo que genera resultados inesperados. En aplicaciones web, esto suele afectar a los sistemas financieros donde el orden y la sincronización de las solicitudes son cruciales. Sin bloqueo de transacciones ni comprobaciones atómicas, los usuarios pueden aprovechar la sincronización para crear estados inconsistentes.

### Detalles técnicos y evidencia
- El problema se confirmó al enviar múltiples solicitudes POST simultáneas al punto final /transfer utilizando el mismo saldo de cuenta. Mediante un script, iniciamos cinco solicitudes de transferencia idénticas simultáneamente. Todas las solicitudes se procesaron, lo que resultó en un saldo final que no reflejaba la deducción, duplicando los fondos.


### Impacto
- Si no se soluciona, esta vulnerabilidad podría permitir a usuarios maliciosos generar fondos de la nada aprovechando las brechas de tiempo en la validación de transacciones. Esto podría provocar pérdidas financieras directas, daños a la reputación y posibles consecuencias legales por o proteger la integridad de las transacciones.

### Recomendaciones de remediación

- Implementar bloqueos a nivel de transacción u operaciones atómicas en el backend para evitar el procesamiento paralelo de acciones que alteren el saldo. También se deben considerar medidas de seguridad adicionales, como la limitación de velocidad y la detección de anomalías en ransacciones rápidas o duplicadas. Validar las correcciones con nuevas pruebas específicas.








THM{Race.Condition.Writeup.Goes.Vroom}






-------------------------------------------

# Los apéndices 
son especialmente útiles para las partes interesadas en la seguridad y los futuros evaluadores que puedan necesitar validar lo que se hizo, verificar el alcance o hacer un seguimiento después de la remediación. Generalmente no existe un formato fijo para los apéndices y el formato puede variar de un proyecto a otro. Sin embargo, hay dos apéndices principales que siempre debes intentar incluir en tu informe.




Appendix A: Testing Artefacts

During the course of the assessment, the following artefacts were created, stored, or modified within the TryBankMe environment:

A test user was created with the following credentials:
Username: testadmin
Password: P@ssw0rd123
The assessment used a script named`transfer_spammer_final_v2.py`uploaded to the `/scripts/tools` directory on the staging server. This script was removed, butno checksum was calculated to confirm its deletion
XSS payloads were dropped in various form fields, including theaccount name field which wepwned through a stored injection.
Session hijacking attempts involvedtampering with cookies. The tool"Burp Suite" was used extensivly during this phase.
We also messed around with the transaction queuetimings to reproduce the race condition, andthose results are shown below.



- Password: P@ssw0rd123    Unprofessional Language
Credentials should never be shown in clear text, even for test accounts.

- Burp Suite" was used extensivly    Spelling & Grammar
The word 'extensivly' is a misspelling. It should be 'extensively'.

- We also messed around with the transaction queue      Spelling & Grammar
'Messed around' is informal and should be replaced with a more professional phrase like 'conducted timing tests'.

- no checksum was calculated to confirm its deletion     Styling
This is a passive construction and vague. It would be clearer to say, 'No checksum was recorded to verify file removal.'

- pwned through a stored injection      Unprofessional Language
'Pwned' is slang and inappropriate in professional reporting.



THM{QA.Makes.Reports.Better}