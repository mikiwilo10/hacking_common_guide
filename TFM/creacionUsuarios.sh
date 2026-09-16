#!/usr/bin/env bash
#
# setup_auditor_openscap.sh
# Configura usuario 'auditor', instala OpenSCAP y configura sudoers
# Compatible con Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky/Alma, openSUSE, Arch, Alpine
#
# Uso: sudo ./setup_auditor_openscap.sh

# 1. Guardar el script
#nano setup_auditor_openscap.sh

# 2. Darle permisos de ejecución
#chmod +x setup_auditor_openscap.sh

# 3. Ejecutarlo como root
#sudo ./setup_auditor_openscap.sh
#


set -euo pipefail

# ------------------------------------------------------------------
# Colores para la salida
# ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*" >&2; }
log_title() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# ------------------------------------------------------------------
# Verificar que se ejecuta como root
# ------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse como root (usa sudo)."
    exit 1
fi

# ------------------------------------------------------------------
# Variables configurables
# ------------------------------------------------------------------
AUDITOR_USER="auditor"
AUDITOR_PASS="auditor2026"
AUDITOR_SHELL="/bin/bash"
SUDOERS_FILE="/etc/sudoers.d/auditor"

# ------------------------------------------------------------------
# Detectar la distribución
# ------------------------------------------------------------------
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
        DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
        DISTRO_NAME="Desconocida"
    fi
    log_info "Distribución detectada: ${DISTRO_NAME}"
}

# ------------------------------------------------------------------
# Helper genérico: instalar paquetes según la distro
# Uso: pkg_install paquete1 paquete2 ...
# ------------------------------------------------------------------
pkg_install() {
    local pkgs=("$@")

    case "${DISTRO_ID}" in
        debian|ubuntu|linuxmint|pop|kali|raspbian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y "${pkgs[@]}"
            ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${pkgs[@]}"
            else
                yum install -y "${pkgs[@]}"
            fi
            ;;
        opensuse*|sles|suse)
            zypper --non-interactive install "${pkgs[@]}"
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm "${pkgs[@]}"
            ;;
        alpine)
            apk add --no-cache "${pkgs[@]}"
            ;;
        *)
            # Fallback según ID_LIKE
            if [[ "${DISTRO_LIKE}" == *"debian"* ]]; then
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -y && apt-get install -y "${pkgs[@]}"
            elif [[ "${DISTRO_LIKE}" == *"rhel"* || "${DISTRO_LIKE}" == *"fedora"* ]]; then
                (command -v dnf >/dev/null && dnf install -y "${pkgs[@]}") \
                    || yum install -y "${pkgs[@]}"
            elif [[ "${DISTRO_LIKE}" == *"suse"* ]]; then
                zypper --non-interactive install "${pkgs[@]}"
            elif [[ "${DISTRO_LIKE}" == *"arch"* ]]; then
                pacman -Sy --noconfirm "${pkgs[@]}"
            else
                log_error "Distribución no soportada automáticamente."
                return 1
            fi
            ;;
    esac
}

# ------------------------------------------------------------------
# 1) Instalar Python3 (requisito de Ansible)
# ------------------------------------------------------------------
install_python3() {
    log_title "Instalando Python3 (requisito de Ansible)"

    if command -v python3 >/dev/null 2>&1; then
        log_ok "Python3 ya está instalado: $(python3 --version 2>&1)"
    else
        log_info "Python3 no encontrado. Instalando..."

        case "${DISTRO_ID}" in
            alpine)
                # En Alpine el paquete se llama 'python3' igual
                pkg_install python3 py3-pip
                ;;
            opensuse*|sles|suse)
                pkg_install python3 python3-pip
                ;;
            arch|manjaro|endeavouros)
                pkg_install python python-pip
                ;;
            *)
                # Debian/Ubuntu/RHEL/Fedora/etc usan 'python3'
                pkg_install python3 python3-pip
                ;;
        esac

        if command -v python3 >/dev/null 2>&1; then
            log_ok "Python3 instalado: $(python3 --version 2>&1)"
        else
            log_error "No se pudo instalar Python3."
            return 1
        fi
    fi

    # Verificar pip3 (Ansible lo usa en algunos módulos)
    if command -v pip3 >/dev/null 2>&1; then
        log_ok "pip3 disponible: $(pip3 --version 2>&1 | awk '{print $1, $2}')"
    else
        log_warn "pip3 no está instalado. Algunos módulos de Ansible podrían requerirlo."
        log_info "Intentando instalar pip3..."
        case "${DISTRO_ID}" in
            alpine) pkg_install py3-pip || true ;;
            arch|manjaro|endeavouros) pkg_install python-pip || true ;;
            *) pkg_install python3-pip || true ;;
        esac
    fi
}

# ------------------------------------------------------------------
# 2) Instalar OpenSCAP según la distro
# ------------------------------------------------------------------
install_openscap() {
    log_title "Instalando OpenSCAP"

    if command -v oscap >/dev/null 2>&1; then
        log_ok "OpenSCAP ya está instalado: $(oscap --version | head -n1)"
        return 0
    fi

    log_info "OpenSCAP no encontrado. Instalando..."

    case "${DISTRO_ID}" in
        debian|ubuntu|linuxmint|pop|kali|raspbian)
            pkg_install openscap-scanner
            ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn)
            pkg_install openscap-scanner
            ;;
        opensuse*|sles|suse)
            pkg_install openscap
            ;;
        arch|manjaro|endeavouros)
            pkg_install openscap
            ;;
        alpine)
            pkg_install openscap
            ;;
        *)
            if [[ "${DISTRO_LIKE}" == *"debian"* || "${DISTRO_LIKE}" == *"rhel"* || \
                  "${DISTRO_LIKE}" == *"fedora"* ]]; then
                pkg_install openscap-scanner || return 1
            elif [[ "${DISTRO_LIKE}" == *"suse"* || "${DISTRO_LIKE}" == *"arch"* ]]; then
                pkg_install openscap || return 1
            else
                log_error "No se pudo instalar OpenSCAP automáticamente."
                return 1
            fi
            ;;
    esac

    if command -v oscap >/dev/null 2>&1; then
        log_ok "OpenSCAP instalado: $(oscap --version | head -n1)"
    else
        log_error "No se pudo instalar OpenSCAP."
        return 1
    fi
}

# ------------------------------------------------------------------
# 3) Crear usuario auditor
# ------------------------------------------------------------------
create_auditor_user() {
    log_title "Configurando usuario '${AUDITOR_USER}'"

    if id "${AUDITOR_USER}" >/dev/null 2>&1; then
        log_warn "El usuario '${AUDITOR_USER}' ya existe. Actualizando shell."
        usermod -s "${AUDITOR_SHELL}" "${AUDITOR_USER}"
    else
        if useradd --help 2>&1 | grep -q -- '-m'; then
            useradd -m -s "${AUDITOR_SHELL}" "${AUDITOR_USER}"
        else
            # Alpine / BusyBox
            adduser -D -s "${AUDITOR_SHELL}" "${AUDITOR_USER}" 2>/dev/null \
                || useradd -m -s "${AUDITOR_SHELL}" "${AUDITOR_USER}"
        fi
        log_ok "Usuario '${AUDITOR_USER}' creado."
    fi

    echo "${AUDITOR_USER}:${AUDITOR_PASS}" | chpasswd
    log_ok "Contraseña asignada a '${AUDITOR_USER}'."
}

# ------------------------------------------------------------------
# 4) Configurar sudoers
# ------------------------------------------------------------------
configure_sudoers() {
    log_title "Configurando sudoers para '${AUDITOR_USER}'"

    # Asegurar sudo instalado
    if ! command -v sudo >/dev/null 2>&1; then
        log_warn "sudo no está instalado. Instalando..."
        pkg_install sudo || true
    fi

    # Asegurar /etc/sudoers.d
    if [[ ! -d /etc/sudoers.d ]]; then
        log_warn "/etc/sudoers.d no existe. Creándolo..."
        mkdir -p /etc/sudoers.d
        chmod 750 /etc/sudoers.d
    fi

    # Detectar la ruta real de oscap
    local oscap_path
    oscap_path="$(command -v oscap || echo /usr/bin/oscap)"
    log_info "Ruta de oscap detectada: ${oscap_path}"

    # Crear archivo temporal y validar antes de instalar
    local tmp_file
    tmp_file="$(mktemp)"
    cat > "${tmp_file}" <<EOF
# Permisos para el usuario auditor en escaneos OpenSCAP
# Generado automáticamente por setup_auditor_openscap.sh

# Permitir ejecutar oscap sin contraseña (todas las opciones)
${AUDITOR_USER} ALL=(ALL) NOPASSWD: ${oscap_path}

# Permitir el resto de comandos con contraseña
${AUDITOR_USER} ALL=(ALL) NOPASSWD: ALL
EOF

    if ! visudo -cf "${tmp_file}" >/dev/null 2>&1; then
        log_error "La sintaxis del archivo sudoers generado es inválida."
        cat "${tmp_file}"
        rm -f "${tmp_file}"
        return 1
    fi

    install -m 0440 -o root -g root "${tmp_file}" "${SUDOERS_FILE}"
    rm -f "${tmp_file}"

    log_ok "Archivo ${SUDOERS_FILE} creado con permisos 440."
}

# ------------------------------------------------------------------
# 5) Verificar toda la configuración
# ------------------------------------------------------------------
verify_setup() {
    log_title "Verificando configuración"

    # --- Python3 ---
    if command -v python3 >/dev/null 2>&1; then
        log_ok "Python3: $(python3 --version 2>&1) en $(command -v python3)"
    else
        log_error "Python3 no encontrado."
    fi

    # --- OpenSCAP ---
    if command -v oscap >/dev/null 2>&1; then
        log_ok "oscap: $(command -v oscap)"
    else
        log_error "oscap no encontrado."
    fi

    # --- Sintaxis sudoers ---
    if visudo -c >/dev/null 2>&1; then
        log_ok "Sintaxis de /etc/sudoers y /etc/sudoers.d/ correcta."
    else
        log_error "Error en la sintaxis de sudoers. Revisa con: visudo -c"
        return 1
    fi

    # --- Permisos del archivo ---
    local perms
    perms="$(stat -c '%a' "${SUDOERS_FILE}" 2>/dev/null || stat -f '%Lp' "${SUDOERS_FILE}")"
    if [[ "${perms}" == "440" ]]; then
        log_ok "Permisos de ${SUDOERS_FILE}: ${perms}"
    else
        log_warn "Permisos inesperados (${perms}). Corrigiendo..."
        chmod 440 "${SUDOERS_FILE}"
    fi

    # --- Usuario auditor ---
    if id "${AUDITOR_USER}" >/dev/null 2>&1; then
        log_ok "Usuario '${AUDITOR_USER}': $(id ${AUDITOR_USER})"
    else
        log_error "Usuario '${AUDITOR_USER}' no encontrado."
        return 1
    fi

    # --- Prueba real: el auditor puede ejecutar oscap con sudo ---
    log_info "Comprobando que '${AUDITOR_USER}' puede ejecutar oscap sin contraseña..."
    if su - "${AUDITOR_USER}" -c "sudo -n oscap --version" >/dev/null 2>&1; then
        log_ok "El usuario auditor puede ejecutar 'sudo oscap' sin contraseña."
    else
        log_warn "No se pudo verificar la ejecución sin contraseña (revisar sudoers)."
    fi
}

# ------------------------------------------------------------------
# Ajustar PATH de la sesión del script
# ------------------------------------------------------------------
fix_path() {
    case ":${PATH}:" in
        *:/usr/sbin:*) ;;
        *) export PATH="${PATH}:/usr/sbin:/sbin:/usr/local/sbin" ;;
    esac
}

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
main() {
    echo "=============================================================="
    echo "  Configuración: Usuario Auditor + OpenSCAP + Python3"
    echo "  (Python3 necesario para Ansible)"
    echo "=============================================================="

    fix_path
    detect_distro

    # Orden importante: Python3 primero (Ansible lo requiere),
    # luego OpenSCAP, después usuario y sudoers.
    install_python3
    install_openscap
    create_auditor_user
    configure_sudoers
    verify_setup

    echo "=============================================================="
    log_ok "Configuración completada correctamente."
    echo
    echo "  Usuario   : ${AUDITOR_USER}"
    echo "  Password  : ${AUDITOR_PASS}"
    echo "  Sudoers   : ${SUDOERS_FILE}"
    echo "  Python3   : $(command -v python3 2>/dev/null || echo 'no encontrado')"
    echo "  OpenSCAP  : $(command -v oscap   2>/dev/null || echo 'no encontrado')"
    echo
    echo "Pruebas sugeridas:"
    echo "  su - ${AUDITOR_USER}"
    echo "  sudo oscap --version"
    echo "  python3 --version"
    echo
    echo "Prueba desde el nodo de control Ansible:"
    echo "  ansible -i inventario ${AUDITOR_USER} -m ping"
    echo "  ansible -i inventario ${AUDITOR_USER} -m command -a 'oscap --version'"
    echo "=============================================================="
}

main "$@"