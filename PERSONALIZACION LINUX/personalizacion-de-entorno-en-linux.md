# Instalación y configuración de Bspwm y Sxhkd
En resumen, primeramente ejecutaremos el siguiente comando:

apt install build-essential git vim xcb libxcb-util0-dev libxcb-ewmh-dev libxcb-randr0-dev libxcb-icccm4-dev libxcb-keysyms1-dev libxcb-xinerama0-dev libasound2-dev libxcb-xtest0-dev libxcb-shape0-dev


Posteriormente, aplicaremos una actualización del sistema con el comando ‘apt update‘. Acto seguido, tenéis que dirigiros a la carpeta de descargas de vuestro equipo y descargar los proyectos ‘bswpm‘ y ‘sxhkd‘ con los siguientes comandos:

git clone https://github.com/baskerville/bspwm.git
git clone https://github.com/baskerville/sxhkd.git
Para instalar cada uno de estos, lo que debéis hacer es meteros en ambos directorios por separado y ejecutar los comandos ‘make‘ y ‘sudo make install‘.

# A continuación tenéis el enlace al archivo de configuración ‘bspwm_resize‘ que usamos al final de esta clase:

Archivo bspwm_resize

Bspwm (Binary Space Partitioning Window Manager)

Bspwm es un gestor de ventanas que utiliza la técnica de partición binaria del espacio para organizar las ventanas en el escritorio. Es conocido por su simplicidad y eficiencia, ya que se configura y se controla exclusivamente a través de scripts y comandos en la terminal. Bspwm no maneja teclados ni otros dispositivos de entrada por sí mismo, sino que delega esta tarea a otras herramientas, lo que permite una mayor personalización y flexibilidad.

Cada ventana se organiza automáticamente de manera que ocupe un área divisoria del espacio disponible en el escritorio, optimizando el uso del espacio y facilitando la navegación entre diferentes aplicaciones y documentos abiertos.






Sxhkd (Simple X Hotkey Daemon)

Sxhkd es un demonio de teclas de acceso rápido para sistemas X Window. Funciona en conjunto con gestores de ventanas como Bspwm y permite a los usuarios asignar acciones a combinaciones de teclas y botones del mouse. Su configuración se realiza a través de un archivo de texto plano, donde el usuario define las combinaciones de teclas y las acciones correspondientes que se deben ejecutar. Sxhkd es altamente configurable y ligero, diseñado para ser rápido y eficiente en el manejo de eventos de entrada, lo que lo hace ideal para entornos donde los recursos del sistema son limitados o cuando se busca una experiencia de usuario altamente personalizable y controlada.

Ambos programas son muy populares en la comunidad de entusiastas de Linux que prefieren un entorno de escritorio altamente personalizable y orientado al uso de teclado.




mkdir ~/.config/{bspwm,sxhkd}


┌──(kali㉿kali)-[~/Documents/bspwm/examples]
└─$ cp bspwmrc ~/.config/bspwm 
                                                                                                                           
┌──(kali㉿kali)-[~/Documents/bspwm/examples]
└─$ cp sxhkdrc ~/.config/sxhkd 
                                                                                                                           



└─$ sudo apt-get install kitty



https://hack4u.io/wp-content/uploads/2022/09/bspwm_resize.txt






/home/kali/.config/scripts/bspwm_size




usuario normal


#!/usr/bin/env dash

if bspc query -N -n focused.floating > /dev/null; then
	step=20
else
	step=100
fi

case "$1" in
	west) dir=right; falldir=left; x="-$step"; y=0;;
	east) dir=right; falldir=left; x="$step"; y=0;;
	north) dir=top; falldir=bottom; x=0; y="-$step";;
	south) dir=top; falldir=bottom; x=0; y="$step";;
esac

bspc node -z "$dir" "$x" "$y" || bspc node -z "$falldir" "$x" "$y"









└─# apt install polybar -y



apt install libconfig-dev libdbus-1-dev libegl-dev libev-dev libgl-dev libepoxy-dev libpcre2-dev libpixman-1-dev libx11-xcb-dev libxcb1-dev libxcb-composite0-dev libxcb-damage0-dev libxcb-glx0-dev libxcb-image0-dev libxcb-present-dev libxcb-randr0-dev libxcb-render0-dev libxcb-render-util0-dev libxcb-shape0-dev libxcb-util-dev libxcb-xfixes0-dev meson ninja-build uthash-dev -y













git clone https://github.com/yshui/picom



$ meson setup --buildtype=release build
$ ninja -C build



$ ninja -C build install



└─$ sudo apt install rofi

