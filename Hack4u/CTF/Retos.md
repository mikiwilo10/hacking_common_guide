# Criptografia

CaesarReloaded
RSAWeak
XORNightmare
HiddenKey
HashChain
LockedAway
RSAFactorize


Caesar Reloaded
Fácil
100 pts
Criptografía
Hemos interceptado un mensaje cifrado con una variante del cifrado César. El archivo contiene el texto cifrado y unas pistas sobre el desplazamiento usado. Descifra el mensaje para obtener la flag.



RSA Weak
Medio
200 pts
Criptografía
Un servidor está usando RSA con parámetros débiles para cifrar comunicaciones. Te proporcionamos la clave pública y un mensaje cifrado. Encuentra la clave privada y descifra el mensaje.
Descargar crypto-2.zip


XOR Nightmare
Medio
300 pts
Criptografía
Alguien pensó que hacer XOR con una clave repetida era suficiente para proteger sus secretos. Demuestra que estaba equivocado.
Descargar crypto-3.zip

Hidden Key
Difícil
200 pts
Criptografía
Un archivo cifrado con AES y una imagen. La clave está más cerca de lo que piensas. Examina todo lo que tienes.
Descargar crypto-4.zip


Hash Chain
Difícil
300 pts
Criptografía
10.000 líneas de datos cifrados con AES. La clave de cada línea se deriva de su posición. Solo 5 líneas contienen fragmentos legibles de la flag. Descífralas todas y encuentra las correctas.
Descargar crypto-5.zip


Locked Away
Medio
250 pts
Criptografía
Un ZIP protegido con contraseña y un archivo misterioso. La contraseña no es aleatoria. Está derivada de algo que ya tienes.
Descargar crypto-6.zip


RSA Factorize
Medio
400 pts
Criptografía
Una clave pública RSA y un mensaje cifrado. Los números parecen grandes, pero no lo suficiente. Factoriza y descifra.
Descargar crypto-7.zip






# Esteganografía

MetadataLeak BeyondEOF PixelSecrets ProtectedMessage FileInception AlphaChannel Matryoshka

Metadata Leak
Fácil
100 pts
Esteganografía
Esta imagen de Hack4u parece normal. Pero a veces la información más valiosa no está en lo que ves, sino en lo que acompaña al archivo.
Descargar stego-1.zip


Beyond EOF
Fácil
100 pts
Esteganografía
El archivo termina donde el formato dice que termina. Pero, ¿y si alguien añadió algo después?
Descargar stego-2.zip


Pixel Secrets
Medio
200 pts
Esteganografía
Los píxeles guardan más información de la que el ojo humano puede percibir. El bit menos significativo tiene mucho que contar.
Descargar stego-3.zip


Protected Message
Medio
200 pts
Esteganografía
Esta imagen JPEG esconde un mensaje protegido con una contraseña. La contraseña es algo muy relacionado con la plataforma.
Descargar stego-4.zip



File Inception
Medio
250 pts
Esteganografía
Un archivo dentro de otro archivo, y dentro otro secreto cifrado. La imagen guarda más de lo que parece, tanto en su interior como en sus propiedades.
Descargar stego-5.zip


Alpha Channel
Difícil
300 pts
Esteganografía
Las imágenes RGBA tienen 4 canales. Todo el mundo mira el rojo, verde y azul. Nadie mira el cuarto.
Descargar stego-6.zip



Matryoshka
Fácil
400 pts
Esteganografía
Como las muñecas rusas, este archivo contiene algo, que contiene algo, que contiene algo. ¿Cuántas capas puedes pelar?
Descargar stego-7.zip




# Forense
NetworkTraces,MemoryDump,DiskImage,LogAnalysis,RegistryHive,PhishingForensics,TimelineReconstruction


Network Traces
Fácil
100 pts
Forense
Hemos capturado tráfico de red sospechoso. Analiza el archivo .pcap y encuentra las credenciales filtradas.
Descargar forensics-1.zip


Memory Dump
Medio
200 pts
Forense
Un equipo ha sido comprometido. Te entregamos un volcado de memoria. Encuentra el proceso malicioso y extrae la flag.
Descargar forensics-2.zip



Disk Image
Difícil
300 pts
Forense
Este disco fue formateado pero no todo se borró correctamente. Recupera los archivos eliminados.
Descargar forensics-3.zip


Log Analysis
Fácil
100 pts
Forense
El servidor web fue atacado. Analiza los logs de acceso de Apache para identificar al atacante y el tipo de ataque utilizado.
Descargar forensics-4.zip



Registry Hive
Medio
250 pts
Forense
Se ha exportado el registro de Windows de un equipo comprometido. Encuentra los mecanismos de persistencia y la configuración del malware.
Descargar forensics-5.zip



Phishing Forensics
Medio
200 pts
Forense
El equipo de seguridad interceptó un email de phishing. Analiza las cabeceras, decodifica los adjuntos y extrae el payload malicioso.
Descargar forensics-6.zip



Timeline Reconstruction
Difícil
400 pts
Forense
Múltiples fuentes de evidencia: eventos Windows, logs de firewall, alertas IDS. Correlaciona todo para reconstruir el ataque completo.
Descargar forensics-7.zip






# Reversing
CrackMe,Obfuscated,MazeRunner,KeyGen,VirtualMachine,Python Bytecode


CrackMe
Medio
200 pts
Reversing
Un binario ELF que pide una contraseña. La flag no es visible con strings. Analízalo con un desensamblador o debugger.
Descargar reversing-1.zip



Obfuscated
Difícil
400 pts
Reversing
Binario con protección anti-debug, flag fragmentada en múltiples funciones con claves XOR rotativas. Solo los mejores lo resolverán.
Descargar reversing-2.zip



Maze Runner
Medio
200 pts
Reversing
Un laberinto 10x10 está oculto dentro del binario. No se muestra. Extrae los datos del laberinto, resuélvelo y proporciona el camino correcto.
Descargar reversing-3.zip




KeyGen
Difícil
350 pts
Reversing
Este programa valida un número de serie con restricciones matemáticas (XOR, suma, rotación de bits). Genera un serial válido.
Descargar reversing-4.zip



Virtual Machine
Difícil
500 pts
Reversing
Una máquina virtual personalizada protege la flag. Revisa el bytecode estático, entiende las instrucciones y extrae la clave.
Descargar reversing-5.zip



Python Bytecode
Medio
250 pts
Reversing
Un archivo .pyc compilado de Python. Descompílalo, entiende la lógica de validación e invierte el algoritmo.
Descargar reversing-6.zip





# Miscelánea
BaseAfterBase,BrokenArchive,Polyglot,SignalIntelligence,ClassifiedPDF,Esoteric


Base After Base
Fácil
100 pts
Miscelánea
Un mensaje fue codificado pasándolo por múltiples capas de encoding. Identifica cada capa y deshazlas todas.
Descargar misc-1.zip


Broken Archive
Medio
200 pts
Miscelánea
Un archivo fue dañado durante la transferencia. Algunos bytes clave han sido corrompidos. Repáralo para acceder al contenido.
Descargar misc-2.zip



Polyglot
Difícil
350 pts
Miscelánea
Este archivo no es lo que parece. Es válido en más de un formato. Analízalo en profundidad con diferentes herramientas.
Descargar misc-3.zip



Signal Intelligence
Medio
250 pts
Miscelánea
Se ha interceptado una transmisión de audio. La señal contiene un mensaje codificado. Analiza el audio para extraerlo.
Descargar misc-4.zip



Classified PDF
Difícil
400 pts
Miscelánea
Un documento PDF clasificado. La información sensible está fragmentada y oculta dentro de la estructura interna del archivo.
Descargar misc-5.zip



Esoteric
Difícil
300 pts
Miscelánea
Dos archivos, dos formatos, una flag. Uno de ellos está escrito en un lenguaje de programación esotérico.
Descargar misc-6.zip





# Scripting
BruteLogic,RaceAgainstTime,DataExtractor,HashCracker,MazeSolver,ProtocolReverse



Brute Logic
Medio
200 pts
Scripting
Un servidor con un PIN de 4 dígitos. Te da pistas (higher/lower) pero se bloquea tras 5 intentos. Escribe un script inteligente.
Descargar scripting-1.zip


Race Against Time
Difícil
400 pts
Scripting
50 operaciones matemáticas en 5 segundos. Un error y pierdes. Solo un script puede resolver esto a tiempo.
Descargar scripting-2.zip


Data Extractor
Fácil
100 pts
Scripting
5000 líneas de logs del servidor. La flag está fragmentada y oculta entre el ruido. Escribe un parser para extraerla.
Descargar scripting-3.zip


Hash Cracker
Medio
250 pts
Scripting
Cada carácter de la flag ha sido hasheado con SHA256 usando un salt posicional. Escribe un cracker por fuerza bruta.
Descargar scripting-4.zip

Maze Solver
Difícil
350 pts
Scripting
Un servidor genera 5 laberintos aleatorios de tamaño creciente (11x11 a 31x31). Implementa un pathfinding automático.
Descargar scripting-5.zip



Protocol Reverse
Difícil
450 pts
Scripting
Un servidor con un protocolo binario personalizado. Parsea los paquetes, identifica el tipo y responde correctamente 20 veces seguidas.
Descargar scripting-6.zip

