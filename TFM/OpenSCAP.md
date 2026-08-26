# OpenSCAP 

Es un ecosistema de código abierto que automatiza el cumplimiento de seguridad y la auditoría de sistemas Linux, basado en el estándar SCAP (Security Content Automation Protocol) de NIST . Funciona comparando el estado real de tu sistema contra una "receta" de seguridad predefinida para generar informes y, en muchos casos, solucionar automáticamente los problemas encontrados.

## Funcionamiento de OpenSCAP en Auditoría
El proceso se estructura en capas que trabajan juntas para evaluar la seguridad .

Definición de la Política de Seguridad (XCCDF): La auditoría comienza con un "benchmark" o lista de verificación, escrito en formato XCCDF. Este documento describe las reglas de seguridad, como "el SSH debe estar configurado para no permitir login root" . Dentro de este, los perfiles agrupan reglas para estándares específicos, como DISA STIG o PCI-DSS .

Evaluación de la Configuración (OVAL): Cada regla definida en el XCCDF se vincula a una verificación lógica escrita en el lenguaje OVAL (Open Vulnerability and Assessment Language) . Por ejemplo, para comprobar la regla del SSH, el OVAL examina el archivo /etc/ssh/sshd_config y busca la línea PermitRootLogin no .

Ejecución del Análisis (oscap): La herramienta principal es el comando oscap, que procesa los archivos XCCDF y OVAL. Realiza los chequeos (consultando el sistema a través de "sondas" o probes como file_probe o sysctl_probe), recopila los resultados y genera informes .

Remediación Automática: Una funcionalidad clave es la capacidad de generar automáticamente scripts de corrección (fix) basados en los fallos encontrados. Puede crear scripts Bash o playbooks de Ansible para intentar resolver los incumplimientos .

# Instalación de OpenSCAP en Ubuntu y Fedora

- openscap-scanner: Es el motor de ejecución en consola. Proporciona el comando oscap. Es la herramienta encargada de leer las reglas de seguridad, revisar el sistema operativo y determinar si cumple o no con la norma.
- libopenscap8: Es la biblioteca central de software (en C). Contiene todo el código lógico y los algoritmos necesarios para procesar los estándares SCAP. El escáner y la interfaz gráfica dependen de ella para poder funcionar.
- scap-security-guide: Es la base de datos de políticas. Contiene los archivos XML con miles de reglas de configuración predefinidas para estándares como CIS Benchmarks, DISA STIG o PCI-DSS. Sin este paquete, el escáner no tendría reglas contra las cuales comparar tu sistema.scap-workbench: Es la interfaz gráfica (GUI). Te permite seleccionar visualmente qué perfil de seguridad quieres aplicar, iniciar el escaneo con un solo clic y ver los resultados en gráficos de barras o colores de forma cómoda, en lugar de usar la terminal.
scap-security-guide está dividido en paquetes individuales o fragmentados según el sistema que desees analizar. 

## Actualizar repositorios
sudo apt update

## Instalar el escáner base de OpenSCAP
sudo apt install openscap-scanner libopenscap8 

## Instalar guías de seguridad (SCAP Security Guide)
sudo apt install scap-security-guide


## Instalar el escáner OpenSCAP y las guías de seguridad
- Instala el motor de escaneo (openscap-scanner) y los perfiles de seguridad base ejecutando:bash

```bash
sudo apt install openscap-scanner ssg-base ssg-debian ssg-debderived ssg-nondebian openscap-utils ssg-debian ssg-debderived
```

- openscap-scanner: Es la herramienta de consola (oscap) que ejecuta las auditorías.
- ssg-base: Contiene la infraestructura mínima del proyecto.
- ssg-debian y ssg-debderived: Contienen las políticas específicas para Debian, Ubuntu y sistemas derivados.
- ssg-nondebian: Añade políticas para otros entornos (como RHEL o Fedora) en caso de que necesites auditar máquinas remotas.



# Paso 2: Listar e identificar los Perfiles de Seguridad

- Cada archivo de guías (DataStream) contiene múltiples normativas internas (perfiles). Ejecuta el siguiente comando para leer el archivo de Debian e identificar qué estándares puedes medir

```bash 
oscap info /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

- Usa el código con precaución.(Si usas una versión anterior de Kali y no existe ese archivo, búscalo con ls /usr/share/xml/scap/ssg/content/ para ver si se llama ssg-debian11-ds.xml).
- En la salida de la terminal, busca la sección Profiles:. Verás opciones como:xccdf_org.ssgproject.content_profile_standard (Perfil de seguridad estándar)xccdf_org.ssgproject.content_profile_anssi_bp28_minimal (Norma de seguridad europea ANSSI)


# Paso 3: Ejecutar el análisis y generar el reporte web

- Una vez elegido tu perfil, ejecuta el análisis con el módulo xccdf eval. El comando inspeccionará tu Kali y guardará un reporte visual directamente en tu carpeta de trabajo ~/Documents/OSCAP:

```bash
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_standard \
  --report /home/kali/Documents/OSCAP/reporte_kali.html \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

```bash
sudo oscap xccdf eval \
  --fetch-remote-resources \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_workstation \
  --report /home/kali/Documents/OSCAP/reporte_kali.html \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

- --fetch-remote-resources: Este parámetro es clave. Le indica a OpenSCAP que descargue las definiciones de vulnerabilidades actualizadas de Debian para que tu análisis sea real y preciso.
- --profile: He seleccionado el perfil cis_level1_workstation (Nivel 1 para estaciones de trabajo), que se adapta perfectamente al entorno de escritorio de Kali Linux. Si prefieres un análisis más básico, puedes cambiarlo por xccdf_org.ssgproject.content_profile_standard

- --report: Define la ruta donde se creará tu documento interactivo en HTML







oscap-ssh phantom_ssh@192.168.56.27 22 \
  xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --report reporte-nodo1.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml