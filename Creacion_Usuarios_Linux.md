Para crear un usuario con privilegios de administrador (root) en Linux, la práctica estándar es crear un usuario estándar y añadirlo al grupo de administración **`sudo`** (en Ubuntu/Debian) o **`wheel`** (en Fedora/Arch/RHEL).

1. **Crear el usuario:** Paso 1.
Ejecuta el siguiente comando en tu terminal (reemplaza `nuevo_usuario` por el nombre que desees):

```bash
sudo adduser tfm

```

*(En distribuciones como Arch o RedHat, es más común usar `sudo useradd -m nuevo_usuario`)*.


2. **Asignar una contraseña:** Paso 2.
Si usaste el comando `useradd`, debes definir la contraseña manualmente:

```bash
sudo passwd TMwr45nrs

```

*(Si usaste `adduser` en Debian/Ubuntu, el sistema ya te habrá pedido asignarle una contraseña en el paso anterior)*.


3. **Darle privilegios de root:** Paso 3.
Agrega al usuario al grupo con permisos administrativos correspondiente a tu distribución:

* **Ubuntu, Debian, Linux Mint:**

```bash
sudo usermod -aG sudo tfm

```

* **Fedora, RHEL, CentOS, Arch Linux:**

```bash
sudo usermod -aG wheel tfm

```


4. **Verificar los permisos:** Paso 4.
Cambia a la sesión del nuevo usuario y prueba ejecutar un comando administrativo:

```bash
su - tfm
sudo whoami

```

Si el sistema solicita tu contraseña y responde **`root`**, la configuración fue exitosa.


sudo localectl set-keymap latam
