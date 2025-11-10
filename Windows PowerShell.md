Windows PowerShell

PowerShell fue diseñado para ampliar las capacidades del shell de comandos para ejecutar comandos de PowerShell llamados cmdlets. Los cmdlets son similares a los comandos de Windows pero proporcionan un lenguaje de programación más extensible. Podemos ejecutar comandos de Windows y cmdlets de PowerShell en PowerShell, pero el shell de comandos solo puede ejecutar comandos de Windows y no cmdlets de PowerShell. Replicemos los mismos comandos ahora usando Powershell.

Windows PowerShell

Interactuar con los servicios comunes




*Evil-WinRM* PS C:\tmp> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\tmp>
*Evil-WinRM* PS C:\tmp> ls


    Directory: C:\tmp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         11/7/2025  12:08 PM         770279 PowerView.ps1


*Evil-WinRM* PS C:\tmp> Import-Module PowerView.ps1
The specified module 'PowerView.ps1' was not loaded because no valid module file was found in any module directory.
At line:1 char:1
+ Import-Module PowerView.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (PowerView.ps1:String) [Import-Module], FileNotFoundException
    + FullyQualifiedErrorId : Modules_ModuleNotFound,Microsoft.PowerShell.Commands.ImportModuleCommand
*Evil-WinRM* PS C:\tmp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\tmp> Get-Domain


Forest                  : neptune.thl
DomainControllers       : {DC01.neptune.thl}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC01.neptune.thl
RidRoleOwner            : DC01.neptune.thl
