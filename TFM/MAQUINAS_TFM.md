# Hackeando al Hacker
https://nohh022.github.io/posts/hackeando-al-hacker/

### Acceso SSH

- Usuario: phantom_ssh
- Contraseña: ThL_sh@d0w2026!

- ssh phantom_ssh@192.168.56.27

## Escalada de Privilegios#

sudo /bin/mount -o bind /bin/bash /bin/mount
sudo /bin/mount

```bash
phantom_ssh@shadowroot:~$ cat /etc/os-release
ERROR: ld.so: object '/tmp/malicious.so' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
phantom_ssh@shadowroot:~$ 
```



# 💾 Método para una configuración permanente (persistente)

```bash

sudo nano /etc/network/interfaces


Para DHCP (si tu red asigna IP automáticamente):


```bash
auto <nombre_interfaz>
iface <nombre_interfaz> inet dhcp
sudo systemctl restart networking
```





# Ejemplo de instalación en Debian/Ubuntu:


```bash
sudo apt install openscap-scanner
```

```bash
sudo oscap --version
```


# 🧑‍💻 Creación de un Usuario Dedicado para Auditoría
1️⃣ En cada nodo remoto (los sistemas a auditar)

```bash
sudo useradd -m -s /bin/bash auditor

sudo passwd auditor  # auditor2026

```

# 📂 Crear el Archivo de Sudo para el Usuario Auditor

### 1️⃣ Crear el directorio (si no existe)

```bash
# Verificar si existe el directorio
ls -la /etc/sudoers.d/
```

### Si no existe, créalo (normalmente ya existe en Debian)
```bash
sudo mkdir -p /etc/sudoers.d
```

## 2️⃣ Crear el archivo de configuración

### Crear el archivo para el usuario auditor
```bash
sudo visudo -f /etc/sudoers.d/auditor
```

Nota: Si visudo te dice que el archivo no existe, lo creará automáticamente. Si te da error, usa:


### Alternativa si visudo no puede crear el archivo
```bash
sudo touch /etc/sudoers.d/auditor

sudo visudo -f /etc/sudoers.d/auditor
```


## 3️⃣ Contenido del archivo

Dentro del editor (normalmente nano o vi), agrega:


### Permisos para el usuario auditor en escaneos OpenSCAP

```bash
auditor ALL=(ALL) NOPASSWD: /usr/bin/oscap
```

O si quieres ser más restrictivo y limitar también las opciones:


### Más restrictivo - solo permite evaluar con perfiles específicos

```bash
auditor ALL=(ALL) NOPASSWD: /usr/bin/oscap xccdf eval --profile *
```

## 4️⃣ Verificar la sintaxis

### Verificar que la configuración es correcta

```bash
sudo visudo -c
```

# 5️⃣ Verificar los permisos del archivo

```bash
# Los archivos en /etc/sudoers.d/ deben tener permisos 440
sudo chmod 440 /etc/sudoers.d/auditor

# Verificar
ls -la /etc/sudoers.d/auditor
```



# Si visudo -f no funciona
Si visudo -f te da error, usa este método alternativo:

```bash
# 1. Crear el archivo temporalmente
sudo nano /etc/sudoers.d/auditor

# 2. Agregar la línea:
auditor ALL=(ALL) NOPASSWD: /usr/bin/oscap

# 3. Guardar (Ctrl+O, Enter, Ctrl+X)

# 4. Verificar permisos
sudo chmod 440 /etc/sudoers.d/auditor

# 5. Validar configuración
sudo visudo -c

```


# 🔑 Generar la Llave SSH en Kali (Nodo Central)

```bash
ssh-keygen -t rsa -b 4096 -C "kali-auditor"
```

## Verificar que se crearon las llaves

```bash
ls -la ~/.ssh/
```

- Deberías ver:

```bash
id_rsa → Llave privada (¡NUNCA compartir!)

id_rsa.pub → Llave pública (esta es la que copiarás)
```



# 👤 Crear las llaves SSH en el Usuario Auditor

```bash
# 1. Verificar propietario y permisos del home de auditor
ls -la /home/ | grep auditor

# Debería ser: drwxr-xr-x 3 auditor auditor 4096 ... auditor


# 2. Si el propietario no es auditor:auditor, corregir
chown -R auditor:auditor /home/auditor


# 3. Crear el directorio .ssh correctamente
sudo mkdir -p /home/auditor/.ssh

chmod 700 /home/auditor/.ssh

touch /home/auditor/.ssh/authorized_keys

chmod 600 /home/auditor/.ssh/authorized_keys

chown -R auditor:auditor /home/auditor/.ssh

# 4. Verificar que todo quedó bien
ls -la /home/auditor/

ls -la /home/auditor/.ssh/

```


# Verificar la configuración de SSH

### Ver la configuración completa

```bash
sudo cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"
```

### Buscar configuraciones específicas que podrían bloquear
```bash
sudo grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|DenyUsers|AllowGroups|DenyGroups|PermitEmptyPasswords|ChallengeResponseAuthentication)" /etc/ssh/sshd_config
```

## 1️⃣ PasswordAuthentication deshabilitado

Si ves esto en /etc/ssh/sshd_config:

```bash
PasswordAuthentication no

Solución temporal (para permitir ssh-copy-id):
```

```bash
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

sudo systemctl restart ssh
```

## Agregar auditor a AllowUsers

```bash
# Editar la configuración
sudo nano /etc/ssh/sshd_config


AllowUsers phantom_ssh root auditor

```

## Reiniciar SSH
```bash
sudo systemctl restart ssh
```


# 📋 Copiar la Llave Desde el Nodo Local al Nodo Remoto

```bash
# Copiar la llave al usuario auditor
ssh-copy-id auditor@192.168.56.27

# Te pedirá la contraseña de auditor UNA SOLA VEZ

```

```bash
Opción B: Copia Manual
bash
# 1. Mostrar tu llave pública
cat ~/.ssh/id_rsa.pub

# 2. Copiar la salida (Ctrl+Shift+C)

# 3. Conectarte al remoto y agregarla
ssh phantom_ssh@192.168.56.27
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... (tu llave aquí) kali-auditor" | sudo tee -a /home/auditor/.ssh/authorized_keys

# 4. Ajustar permisos (si no lo hiciste antes)
sudo chmod 600 /home/auditor/.ssh/authorized_keys
sudo chown -R auditor:auditor /home/auditor/.ssh

# 5. Salir
exit

```





# 🚀 Ejecutar el escaneo completo

```bash
oscap-ssh auditor@192.168.56.27 22 \
  xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_standard \
  --report /home/kali/Documents/OSCAP/reporte-debian12-final.html \
  /usr/share/xml/scap/ssg/content/ssg-debian-12-ds.xml
```

## 📋 Si encuentras el error de LD_PRELOAD
Si el error de LD_PRELOAD aparece durante el escaneo, ejecuta primero este comando para limpiarlo en el remoto:

```bash
# Limpiar LD_PRELOAD en el remoto
ssh auditor@192.168.56.27 "unset LD_PRELOAD; sed -i '/LD_PRELOAD/d' ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null"
```