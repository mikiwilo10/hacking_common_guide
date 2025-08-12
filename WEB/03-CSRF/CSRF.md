# CSRF sin ningún tipo de defensa
En esta clase abordamos un caso básico de vulnerabilidad CSRF, en el que una funcionalidad sensible —el cambio de correo electrónico— carece de cualquier tipo de protección. Esto nos permite forzar acciones en la cuenta de un usuario autenticado simplemente haciendo que cargue una página con un formulario oculto y autoenviado.

La técnica consiste en construir una petición POST con los mismos parámetros que la funcionalidad legítima, y luego alojarla en el servidor de explotación proporcionado. Al incluir un pequeño script que autoenvía el formulario al cargar la página, conseguimos que la víctima realice la acción sin saberlo, usando su propia sesión activa.

Este laboratorio representa el escenario más sencillo de explotación CSRF, y sienta las bases para los siguientes ejercicios donde se introducirán mecanismos de defensa como tokens, verificación de cabeceras o validaciones del lado servidor.



## Laboratorio: Vulnerabilidad CSRF sin defensas
APRENDIZ

LAB
No resuelto
La funcionalidad de cambio de correo electrónico de este laboratorio es vulnerable a CSRF.

Para resolver el laboratorio, cree un código HTML que utilice un ataque CSRF para cambiar la dirección de correo electrónico del espectador y cargarlo en su servidor de exploits.

Puede iniciar sesión en su propia cuenta utilizando las siguientes credenciales: wiener:peter

