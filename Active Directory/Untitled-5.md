Overview:

During the security assessment conducted on the environment, a chain of configuration flaws was identified that led to the compromise of a domain host. The attack involved anonymous access to an SMB share, extraction of credentials stored in plain text, validation of those credentials in the WinRM service, and subsequent escalation of privileges to the Domain Admins level.

Scope:

The main attack vectors and findings were:

Anonymous SMB access: The \\10.200.150.20\Safe share was accessible without authentication.

Credential exposure: The resource contained a creds.zip file with a username and password in plain text.

Weak file protection: The ZIP file was protected with a trivial password (Passw0rd), cracked using a dictionary.

Credential reuse: The credentials John:VerySafePassword! were valid on the remote host.

WinRM exposure: Allowed remote access with the privileges of the John account.

Kerberoasting and hash cracking: j.phillips's (Welcome1) password was obtained via a Kerberoast attack.

Escalation to Domain Admin: The user j.phillips was added to the Domain Admins group, gaining full control of the domain.

Impact:

Unauthorized access to sensitive information via SMB.

Compromise of domain user accounts due to insecure credential storage.

Remote command execution on the host via WinRM (Evil-WinRM).

Exposure of Kerberos hashes and successful cracking of administrative credentials.

Privilege escalation to the Domain Admin level, with the ability to control the Domain Controller and the entire Active Directory infrastructure.

The final impact was a complete takeover of the domain, representing a critical risk to the confidentiality, integrity, and availability of the organization.

Conclusion:

The compromise was made possible by a series of insecure configurations: anonymous SMB access, weak and reused passwords, insecure secret storage, and unnecessary exposure of WinRM.

Key Recommendations:

Restrict anonymous SMB access and apply the minimum necessary ACLs.

Prohibit storing credentials in files without secure encryption.

Enforce strong password policies and periodic rotation.

Disable or restrict WinRM to authorized users.

Implement monitoring and alerts for Kerberoasting attempts and privilege escalations.