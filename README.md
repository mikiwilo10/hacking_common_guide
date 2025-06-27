# Comandos para Pentesting

## Arp-Scan
Es una herramienta de reconocimiento utilizada en entornos de hacking (pentesting, auditorías de seguridad) para descubrir hosts activos en una red local. Funciona enviando solicitudes ARP (Address Resolution Protocol) y analizando las respuestas para identificar dispositivos conectados

```bash
sudo arp-scan -I eth1 -l
```

## Nmap
(Network Mapper) es una de las herramientas más poderosas en hacking y administración de redes. Se usa para descubrir hosts, puertos abiertos, servicios y vulnerabilidades en sistemas remotos. A diferencia de arp-scan (que opera en la capa 2), Nmap trabaja en las capas 3 (Red) y 4 (Transporte) del modelo OSI, permitiendo escaneos más avanzados.

Nmap envía paquetes personalizados (TCP, UDP, ICMP, etc.) a un objetivo y analiza las respuestas para determinar:

Hosts activos (si están "vivos").

Puertos abiertos (qué servicios están corriendo).

Versiones de software (ej: Apache 2.4, OpenSSH 7.6).

Sistema operativo (mediante fingerprinting).

Vulnerabilidades (usando scripts NSE).

## 🛠️ Comandos útiles de Nmap (Network Mapper)

| Comando                          | Descripción                                                                                     | Ejemplo de uso                                  |
|----------------------------------|-------------------------------------------------------------------------------------------------|------------------------------------------------|
| `nmap -sn <target>`              | Escaneo de descubrimiento de hosts (solo ping).                                                | `nmap -sn 192.168.1.0/24`                      |
| `nmap -p <puertos> <target>`     | Escanea puertos específicos.                                                                    | `nmap -p 80,443,22 192.168.1.100`              |
| `nmap -p- <target>`              | Escanea **todos** los puertos (1-65535).                                                       | `nmap -p- 192.168.1.100`                       |
| `nmap -sS <target>`              | Escaneo sigiloso SYN (requiere sudo).                                                          | `sudo nmap -sS 192.168.1.100`                  |
| `nmap -sV <target>`              | Detecta versiones de servicios.                                                                | `nmap -sV 192.168.1.100`                       |
| `nmap -sC <target>`              | Ejecuta scripts básicos de Nmap (NSE) para buscar vulnerabilidades o información adicional.    | `nmap -sV 192.168.1.100`                       |
| `nmap -O <target>`               | Detecta el sistema operativo del objetivo.                                                     | `sudo nmap -O 192.168.1.100`                   |
| `nmap -A <target>`               | Escaneo agresivo (SO, versiones, scripts).                                                     | `sudo nmap -A 192.168.1.100`                   |
| `nmap --script <script> <target>`| Ejecuta scripts NSE (ej: vulnerabilidades).                                                    | `nmap --script vuln 192.168.1.100`             |
| `nmap -sU -p <puertos> <target>` | Escaneo UDP (para servicios como DNS, SNMP).                                                   | `sudo nmap -sU -p 53,161 192.168.1.100`        |
| `nmap -T4 <target>`              | Escaneo rápido (T0: lento, T5: agresivo).                                                     | `nmap -T4 192.168.1.100`                       |
| `nmap -oN <file> <target>`       | Guarda resultados en formato de texto.                                                         | `nmap -oN scan.txt 192.168.1.100`              |
| `nmap -f <target>`               | Fragmenta paquetes para evadir firewalls.                                                      | `sudo nmap -f 192.168.1.100`                   |
| `nmap -D <decoy1,decoy2> <target>`| Escaneo con IPs señuelo.                                                                      | `sudo nmap -D RND:5 192.168.1.100`             |
| `nmap -Pn <target>`              |Omite el descubrimiento de hosts (asume que el objetivo está activo). Útil si bloquea ICMP (ping). | `nmap -Pn 192.168.1.100`             |
| `nmap -n <target>`              Evita que Nmap realice búsquedas DNS (resolución inversa de nombres de dominio para las IPs escaneadas). | `nmap -Pn 192.168.1.100`             |



## 🛠️ Ejemplo de uso escaneo agresivo de puertos con Nmap

```bash
sudo nmap -sS --min-rate 5000 -p- --open 192.168.219.133 -oN scan.txt
```


**¿Qué hace este comando en la práctica?:**  

- Escanea todos los puertos TCP (1-65535) del host 192.168.219.133.

- Usa técnicas sigilosas (SYN Scan) para evitar logs en el objetivo.

- Prioriza velocidad (5000 paquetes/segundo), lo que puede ser ruidoso.

- Filtra solo puertos abiertos (ignora cerrados/filtrados).

- Guarda el resultado en scan.txt para análisis posterior.

**Ejemplo de salida (scan.txt):**  

<p align="center">
<img src="https://github.com/user-attachments/assets/109e0ab9-1436-48f8-8e90-d86477d0feb6"  alt="Mi logo">
</p>


**Extraer puertos abiertos de un escaneo de Nmap (scan.txt) y formatearlos para usarlos en otras herramientas.**

```bash
grep '^[0-9]' scan.txt | cut -d '/' -f1 | sort -u | xargs | tr ' ' ','
```

1. grep '^[0-9]' scan.txt 
- Filtra líneas en scan.txt que comienzan con un número (^[0-9]). grep selecciona estas líneas y descarta las demás (como encabezados o puertos cerrados).

2. cut -d '/' -f1 
- Divide cada línea por el carácter / (-d '/') y selecciona el primer campo (-f1).

3. sort -u  
- Ordena los puertos numéricamente y elimina duplicados (-u = unique).
4. xargs  
- Convierte la lista de puertos (uno por línea) en una sola línea separada por espacios.
5. tr ' ' ','  
- Reemplaza espacios por comas para crear una lista legible.

**Ejemplo de salida (scan.txt):**  

<p align="center">
<img src="https://github.com/user-attachments/assets/ecce6a59-5300-4dd4-b653-1e8e7672f5c3"  alt="Mi logo">
</p>


**El comando realiza un escaneo dirigido con Nmap a la IP 192.168.219.133, enfocándose en puertos específicos y obteniendo información detallada de servicios. Aquí la explicación corta:**
```bash
nmap -p135,139,445,5000 -sV -sC -Pn -vvv 192.168.219.133 -oN fullScan.txt 
```

```bash
sudo nmap -p445 -sS -sC -sV --min-rate=5000 -vvv -n -Pn 192.168.219.135
```

<p align="center">
<img src="https://github.com/user-attachments/assets/50ce9217-ef58-47c0-94f3-30561aeaff9a"  alt="Mi logo">
</p>









## Gobuster para encontrar páginas web ocultas
**En el comando anterior, -u indica el sitio web que estamos escaneando, y -w toma una lista de palabras que itera para encontrar páginas ocultas.**

Gobuster le habrá indicado las páginas en la lista de nombres de páginas/directorios (indicadas por Estado: 200).
```bash
gobuster dir -u http://fakebank.thm -w wordlist.txt dir
```

```bash
gobuster dir -u http://10.10.191.71 -w wordlist.txt dir
```

```bash
gobuster dir -u http://10.10.191.71 -x php,html,css,js,txt,pdf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```bash
nmap -p80 --script http-enum 10.10.191.71

```bash
grep -R " "
```
