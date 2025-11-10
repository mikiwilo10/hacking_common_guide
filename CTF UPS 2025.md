Hidden in Plain Sight
345
 0  0
Esta vez tenemos los logs de nuestro servidor web. Tu misión es encontrar la hora en la el hacker explotó la vulnerabilidad. La flag sigue el formato CTF{sha256(DD/MM/YYYY:HH:MM:SS +XXXX)}, donde sha256 es el resultado de sacar el hash"


──(kali㉿kali)-[~/Documents/RETOS]
└─$ grep "cmd=\|exec=\|system=" access.log 
96.127.149.186 - - [20/May/2015:02:05:13 +0000] "GET /wp-content/uploads/c99shell.php?cmd=cat+/var/www/s3cret_fl4g.txt HTTP/1.0" 200 296 "https://example.com" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:22.0) Gecko/20100101 Firefox/22.0"
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ echo -n "20/05/2015:02:05:13 +0000" | sha256sum

8cf18b90f5df3b589799fbf15d599007951291fd970d16f476c335ac8a504de5  -
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ 
CTF{8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4}


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Log Rolling


┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ grep "Accepted" auth.log 
Mar 12 18:44:08 r00tme sshd[97504]: Accepted password for ansible from 192.168.175.133 port 47446 ssh2
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ grep -E "Accepted|session opened|authentication success" auth.log         
Mar 12 18:44:08 r00tme sshd[97504]: Accepted password for ansible from 192.168.175.133 port 47446 ssh2
Mar 12 18:44:08 r00tme sshd[97504]: pam_unix(sshd:session): session opened for user ansible(uid=1001) by (uid=0)
Mar 12 18:44:08 r00tme systemd: pam_unix(systemd-user:session): session opened for user ansible(uid=1001) by (uid=0)
Mar 12 18:45:01 r00tme CRON[97737]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ grep -E "sshd.*Accepted|session opened" auth.log
Mar 12 18:44:08 r00tme sshd[97504]: Accepted password for ansible from 192.168.175.133 port 47446 ssh2
Mar 12 18:44:08 r00tme sshd[97504]: pam_unix(sshd:session): session opened for user ansible(uid=1001) by (uid=0)
Mar 12 18:44:08 r00tme systemd: pam_unix(systemd-user:session): session opened for user ansible(uid=1001) by (uid=0)
Mar 12 18:45:01 r00tme CRON[97737]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ 







Mar 12 18:44:08 r00tme sshd[97504]: Accepted password for ansible from 192.168.175.133 port 47446 ssh2
Mar 12 18:44:08 r00tme sshd[97504]: pam_unix(sshd:session): session opened for user ansible(uid=1001) by (uid=0)
Mar 12 18:44:08 r00tme systemd-logind[813]: New session 87 of user ansible.





┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ echo -n "ansible" | sha256sum
0cb87f727f31e5f5a59cca8a10c8f9b55622be05305d4e7e92c334f5911e1034  -
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/RETOS]
└─$ 

CTF{0cb87f727f31e5f5a59cca8a10c8f9b55622be05305d4e7e92c334f5911e1034}


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Hidden Vault



┌──(kali㉿kali)-[~/Documents/RETOS/Hidden_Vault]
└─$ cat hash_clean.txt

$veracrypt$157fe505e669fc76384c97fb40d005a4e3d7c452a788a1dfd786cf9dbeebabcf51e1cadd59c5592f6f0fde19d62af057cb5d615bf4b0750694649f7a0ba7c026$6f521f30f53f652ae6c4c0f90525a6ddbddaa1a435a09d92cdb0b1a45ed628aa48dcf288f1a12625baf1e3a5e1c31d4fdedca0de62e598e1cfb962a0f36a390189cabb3a409c1546ceb87827cef4f7b3bbfba11049eb046efba83e31ce448cbfdefca1ac1c9b65f32e3127e0e10e9dfe248565e192baa687925c7c815045f354eed2293f8d3caed470edf5ebfbb90adf4dda0e4de08716ef8b85f3cf62cd3532f7fa3a784727a4a5a174d9d8b9ae1d7afad14f06b07f3b13a4c4b3326acae9d2f7c248045a2f243e40d7f33f7a06669234f15f6f3a82b1ccd10e1923a1ea4873986e6a19688a206967162002affc0b9e8a28b08dd44cb19c31baa342119f4f170336fdd420b5414e54b493f21c32e98f1b4353d9c33b672be0dc5d37aa689cc1f86c16c18ba953c21aca80bb9f559b9a9137faa9a7c42c09bcb1b1c59739a637845274be1a7eead898b6c1c218cd3202966998f60fd7cdb357a565648ac8ffe1e779d212925c9bcf34ef239a86d3a1416a3cf5b88c3a94359439f282503b949753037ae6cab68d79929922e11b36a1c95432687a6f65ba552cb27135a06fe6ad1efb03489695925e410e9299cddcfc963f2d3375a0be40a4e690629249988f8a                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/RETOS/Hidden_Vault]
└─$ hashcat -m 13721 -a 0 hash_clean.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz, 1438/2941 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 128

No hashes loaded.
No hashes loaded.

Started: Mon Nov 10 14:36:46 2025
Stopped: Mon Nov 10 14:36:46 2025
                                                                                                                                                           
┌──(kali㉿kali)-[~/Documents/RETOS/Hidden_Vault]
└─$ 

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Broken_File


┌──(kali㉿kali)-[~/Documents/RETOS/Broken_File]
└─$ strings apt_1337_secrets.wad | head -500
IWAD
JFIF
"Exif
http://ns.adobe.com/xap/1.0/
<?xpacket begin="
" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 4.4.0-Exiv2">
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
                <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:plus="http://ns.useplus.org/ldf/xmp/1.0/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" xmlns:GettyImagesGIFT="http://xmp.gettyimages.com/gift/1.0/" plus:LicensorURL="http://www.gettyimages.com" photoshop:AuthorsPosition="Contributor" photoshop:Headline="Angry bear against and Russian flag" photoshop:DateCreated="2016-12-20T08:00Z" photoshop:Source="iStockphoto" photoshop:Instructions="Model and Property Released (MR&amp;PR) " photoshop:Credit="Getty Images/iStockphoto" photoshop:URL="http://www.gettyimages.com" photoshop:CopyrightFlag="true" GettyImagesGIFT:AssetID="635966596" GettyImagesGIFT:dlref="X0RwfU+LuGC5ZbIRNG3Tow==" GettyImagesGIFT:ImageRank="3">
                        <dc:subject>
                                <rdf:Bag>






--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.



Fragmented Truth



┌──(kali㉿kali)-[~/Documents/RETOS/Fragmented_Truth]
└─$ file disk_corrupted.dd 
disk_corrupted.dd: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x10,0,1), end-CHS (0x31f,3,32), startsector 2048, 100352 sectors
                   

┌──(kali㉿kali)-[~/Documents/RETOS/Fragmented_Truth]
└─$ mmls disk_corrupted.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000102399   0000100352   Linux (0x83)
                                                         



┌──(kali㉿kali)-[~/Documents/RETOS/Fragmented_Truth]
└─$ sudo losetup -f -o $((2048*512)) disk_corrupted.dd





──(kali㉿kali)-[/media/…/d2c6fdd8-bb64-46ff-a804-3ef58c206bd4/misc/old/confidential]
└─$ pwd               
/media/kali/d2c6fdd8-bb64-46ff-a804-3ef58c206bd4/misc/old/confidential
                                                                                                                                               
┌──(kali㉿kali)-[/media/…/d2c6fdd8-bb64-46ff-a804-3ef58c206bd4/misc/old/confidential]
└─$ cat mjsdnbvjsnofjsf.txt        
Q1RGezdlNDAzZWNjNWM0NmNhMWRmM2FhOGE3NmJmNmE1M2U3M2M5MTA0MDhlNTk1NDExNmQ4ODhlOGNhYjRiM2NkNDl9Cg==
                                                                                                                                               
┌──(kali㉿kali)-[/media/…/d2c6fdd8-bb64-46ff-a804-3ef58c206bd4/misc/old/confidential]
└─$ 






──(kali㉿kali)-[~/Downloads/Go-Hash]
└─$ python3 gohash.py    

                                                                                                                                               
     ██████╗  ██████╗       ██╗  ██╗ █████╗ ███████╗██╗  ██╗                                                                                   
    ██╔════╝ ██╔═══██╗      ██║  ██║██╔══██╗██╔════╝██║  ██║                                                                                   
    ██║  ███╗██║   ██║█████╗███████║███████║███████╗███████║                                                                                   
    ██║   ██║██║   ██║╚════╝██╔══██║██╔══██║╚════██║██╔══██║                                                                                   
    ╚██████╔╝╚██████╔╝      ██║  ██║██║  ██║███████║██║  ██║                                                                                   
     ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                                                                                   
            <<------ C O D E   B Y   H U N X ------>>                                                                                          
                       < Hash identified >                                                                                                     
                                                                                                                                               
  [+] Enter Your Hash : Q1RGezdlNDAzZWNjNWM0NmNhMWRmM2FhOGE3NmJmNmE1M2U3M2M5MTA0MDhlNTk1NDExNmQ4ODhlOGNhYjRiM2NkNDl9Cg==                       
                                                                                                                                               
  ===================== Show Algorithm Hash ====================                                                                               
                                                                                                                                               
  [+] Hash : Q1RGezdlNDAzZWNjNWM0NmNhMWRmM2FhOGE3NmJmNmE1M2U3M2M5MTA0MDhlNTk1NDExNmQ4ODhlOGNhYjRiM2NkNDl9Cg==                                  
  [+] Algorithm : Base64 Encoded String                                                                                                        
                                                                                                                                               
  ==============================================================                                                                               
                                                                                                                                               
  Do you want to identify the hash again? Y/N : N                                                                                              
  Exit ToolS !!!                                                                                                                               
                                                                                                                                               
┌──(kali㉿kali)-[~/Downloads/Go-Hash]
└─$ echo "Q1RGezdlNDAzZWNjNWM0NmNhMWRmM2FhOGE3NmJmNmE1M2U3M2M5MTA0MDhlNTk1NDExNmQ4ODhlOGNhYjRiM2NkNDl9Cg=="| base64 -d
CTF{7e403ecc5c46ca1df3aa8a76bf6a53e73c910408e5954116d888e8cab4b3cd49}
                                                                                                                                               
┌──(kali㉿kali)-[~/Downloads/Go-Hash]
└─$ 




--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.
Super Secure Login




ReverseMe.exe


┌──(kali㉿kali)-[~/Documents/RETOS/Super_Secure_Login]
└─$ echo 'Q1RGe2U5NjQzZmZlNmExYjc2OGE3OGQ4YTQ2ZjVhYzNiMjYwZGE1MTZmMTNkMmMwM2IxODJmOGQ5NGE2NDVhNGM0Y2J9' | base64 -d
CTF{e9643ffe6a1b768a78d8a46f5ac3b260da516f13d2c03b182f8d94a645a4c4cb}                                                                                                                                               
┌──(kali㉿kali)-[~/Documents/RETOS/Super_Secure_Login]
└─$ 



--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.
Suspicious Update



┌──(kali㉿kali)-[~/…/RETOS/Suspicious_Update/_paramo_firmware.bin.extracted/squashfs-root]
└─$ binwalk -e paramo_firmware.bin || true




┌──(kali㉿kali)-[~/…/RETOS/Suspicious_Update/_paramo_firmware.bin.extracted/squashfs-root]
└─$ grep -i "CTF" * -R
grep: boot/initrd.img-6.6.9-amd64: binary file matches
grep: boot/vmlinuz-6.6.9-amd64: binary file matches
etc/.flag.txt:CTF{d3364a120160f5fbed36d82ca6288df742423cb4af281f0980d5954dd993c0f9}
grep: etc/ld.so.cache: binary file matches
etc/ssl/certs/ca-certificates.crt:Us3ERo/ctfPYV3Me6ZQ5BL/T3jjetFPsaRyifsSP5BtwrfKi+fv3FmRmaZ9JUaLi
etc/ssl/certs/ca-certificates.crt:4LlAcTfFy0cOlypowCKVYhXbR9n10Cv/gkvJrT7eTNuQgFA/CYqEAOwwCj0Yzfv9
etc/ssl/certs/ca-certificates.crt:RatZe1E0+eyLinjF3WuvvcTfk0Uev5E4C64OFudBc/jbu9G4UeDLgztzOG53ig9Z
etc/ssl/certs/ca-certificates.crt:HyICc/sgCq+dVEuhzf9gR7A/Xe8bVr2XIZYtCtFenTgCR2y59PYjJbigapordwj6
etc/ssl/certs/ca-certificates.crt:zXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0NXfeD412lPFzYE
etc/ssl/certs/ca-certificates.crt:tshquDDIajjDbp7hNxbqBWJMWxJH7ae0s1hWx0nzfxJoCTFx8G34Tkf71oXuxVhA
grep: etc/os-release: No such file or direc




┌──(kali㉿kali)-[~/…/Suspicious_Update/_paramo_firmware.bin.extracted/squashfs-root/etc]
└─$ cat .flag.txt                     
CTF{d3364a120160f5fbed36d82ca6288df742423cb4af281f0980d5954dd993c0f9}
                                                                                                                                               
┌──(kali㉿kali)-[~/…/Suspicious_Update/_paramo_firmware.bin.extracted/squashfs-root/etc]
└─$ 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.




Key Flaw





 mousepád exploit_fermat_no_deps_fixed.py









#!/usr/bin/env python3
# exploit_fermat_no_deps_fixed.py
# Sin dependencias externas. Requiere: openssl en PATH.
# Uso: python3 exploit_fermat_no_deps_fixed.py

import subprocess, sys, math, binascii

PUBFILE = "public.pem"
CIPHERTEXT = "mensaje_cifrado.bin"

def get_modulus_and_exponent(pemfile):
    # Obtiene modulus en una sola línea (hex) usando -modulus
    try:
        mod_out = subprocess.check_output(["openssl", "rsa", "-pubin", "-in", pemfile, "-modulus", "-noout"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Error: openssl no pudo leer public.pem (verifica que sea una clave pública válida).")
        sys.exit(1)
    mod_line = mod_out.decode().strip()
    if mod_line.startswith("Modulus="):
        modhex = mod_line.split("=",1)[1].strip()
    else:
        # fallback: intentar extraer hex de la salida
        modhex = ''.join(ch for ch in mod_line if ch in "0123456789abcdefABCDEF")
    # Ahora obtener exponent
    try:
        text_out = subprocess.check_output(["openssl", "rsa", "-pubin", "-in", pemfile, "-text", "-noout"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Error: openssl text no pudo leer public.pem.")
        sys.exit(1)
    text = text_out.decode()
    exp = None
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("exponent:"):
            # "Exponent: 65537 (0x10001)"
            parts = line.split()
            try:
                exp = int(parts[1])
            except:
                # intentar extraer dígitos
                import re
                m = re.search(r"Exponent:\s*([0-9]+)", line, re.IGNORECASE)
                if m:
                    exp = int(m.group(1))
            break
    if exp is None:
        print("No pude extraer Exponent desde openssl. Muestra la salida de `openssl rsa -pubin -in public.pem -text -noout` para diagnosticar.")
        sys.exit(1)
    try:
        n = int(modhex, 16)
    except Exception as ex:
        print("Error convirtiendo modulus hex a int:", ex)
        print("Modhex (parcial):", modhex[:120])
        sys.exit(1)
    return n, exp

def is_square(n):
    if n < 0:
        return False
    r = math.isqrt(n)
    return r*r == n

def fermat_factor(n, max_iters=5_000_000):
    a = math.isqrt(n)
    if a*a < n:
        a += 1
    it = 0
    while it < max_iters:
        b2 = a*a - n
        if b2 >= 0 and is_square(b2):
            b = math.isqrt(b2)
            p = a - b
            q = a + b
            if p*q == n:
                return int(p), int(q)
        a += 1
        it += 1
    return None

def int_to_bytes(i):
    if i == 0:
        return b'\x00'
    l = (i.bit_length() + 7) // 8
    return i.to_bytes(l, 'big')

def try_pkcs1_v1_5_unpad(data_bytes):
    # formato: 00 02 PS (non-zero) 00 message
    if len(data_bytes) < 11:
        return None
    if data_bytes[0] != 0x00 or data_bytes[1] != 0x02:
        return None
    try:
        idx = data_bytes.index(0x00, 2)
    except ValueError:
        return None
    return data_bytes[idx+1:]

def main():
    print("[*] Extrayendo modulus y exponent con openssl ...")
    n, e = get_modulus_and_exponent(PUBFILE)
    print(f"[*] n bits: {n.bit_length()}, e: {e}")
    print("[*] Intentando factorizar con Fermat (primos cercanos)...")
    res = fermat_factor(n, max_iters=10_000_000)
    if not res:
        print("[-] Fermat falló en el límite. Prueba aumentar max_iters o usar herramientas como yafu/msieve.")
        sys.exit(1)
    p, q = res
    print(f"[+] Encontrado p={p}\n[+] Encontrado q={q}")
    if p > q:
        p, q = q, p
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    print("[*] Calculado d. Intentando desencriptar archivo ...")
    with open(CIPHERTEXT, "rb") as f:
        c = f.read()
    c_int = int.from_bytes(c, 'big')
    m_int = pow(c_int, d, n)
    m_bytes = int_to_bytes(m_int)
    k = (n.bit_length() + 7) // 8
    if len(m_bytes) < k:
        m_bytes = b'\x00' * (k - len(m_bytes)) + m_bytes
    msg = try_pkcs1_v1_5_unpad(m_bytes)
    if msg is not None:
        print("[+] Desencriptado con PKCS#1 v1.5. Mensaje (utf-8 si es texto):\n")
        try:
            print(msg.decode('utf-8'))
        except:
            print("No es UTF-8 imprimible. Escribiendo a mensaje_decrypted.bin")
            with open("mensaje_decrypted.bin", "wb") as out:
                out.write(msg)
        return
    print("[-] No se pudo desempaquetar como PKCS#1 v1.5. Guardando raw decrypted a mensaje_raw.bin")
    with open("mensaje_raw.bin", "wb") as out:
        out.write(m_bytes)
    print("[*] Guardado mensaje_raw.bin; puedes intentar 'file mensaje_raw.bin' y 'strings mensaje_raw.bin'")

if __name__ == "__main__":
    main()














┌──(kali㉿kali)-[~/Documents/RETOS/Key_Flaw]
└─$ python3 exploit_fermat_no_deps.py                                
[*] Extrayendo modulus y exponent con openssl ...
[*] n bits: 1023, e: 65537
[*] Intentando factorizar con Fermat (primos cercanos)...
[+] Encontrado p=8114166086355626469144788166739101392353048475231906478041669264910498479424248897281603728100389843919093385939652550387395675633406308148966297535669267
[+] Encontrado q=8114166086355626469144788166739101392353048475231906478041669264910498479424248897281603728100389843919093385939652550387395675633406308148966297535670071
[*] Calculado d. Intentando desencriptar archivo ...
[+] Desencriptado con PKCS#1 v1.5. Mensaje (utf-8 si es texto):

Toma tu flag: CTF{326f437d11205de9cdb2bf440f32c74e955a83e59c15b5e059068d0e23967e13}
                                                                                                                                               
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.
