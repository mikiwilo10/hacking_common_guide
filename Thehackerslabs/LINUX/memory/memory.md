                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents]
└─$ strings memory.raw | grep -E "(.exe|bash|ssh)" | head -10 


----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents]
└─$ strings memory.raw | grep -E "(THL)" | head -10

DTHL{user_



┌──(kali㉿kali)-[~/Documents]
└─$ strings memory.raw | grep -E "flag" | head -10
flag_fragmented}
                                                                                                                                                            


THL{user_flag_fragmented}


----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents]
└─$ strings memory.raw | grep -E "(root)" | head -250
9       root@host:/# echo VEhMe3Jvb3RfZmxhZ19iYXNlNjRfZW5jb2RlZH0= | base64 -d
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents]
└─$ echo VEhMe3Jvb3RfZmxhZ19iYXNlNjRfZW5jb2RlZH0= | base64 -d

THL{root_flag_base64_encoded}                                                                                                                                                            


