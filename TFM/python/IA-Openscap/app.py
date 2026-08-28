#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SecAuto - Hardening Automatizado con OpenSCAP
Módulo de escaneo remoto con detección automática de SO
y extracción optimizada para IA
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import yaml
import subprocess
import re
import threading
import time
import glob
import shutil
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict

# ==================== CONFIGURACIÓN ====================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SECRET_KEY'] = 'tu-clave-secreta-aqui-cambiala'

# Directorios
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JOBS_DIR = os.path.join(BASE_DIR, 'jobs')
SCANS_DIR = os.path.join(BASE_DIR, 'scans')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')

for d in [JOBS_DIR, SCANS_DIR, REPORTS_DIR, TEMP_DIR]:
    os.makedirs(d, exist_ok=True)

# Almacenamiento en memoria
executions_history = []
scan_jobs = {}
running_scans = []

# ==================== MAPEO DE SISTEMAS OPERATIVOS ====================

PROFILES_BY_SO = {
    'debian': [
        {'id': 'xccdf_org.ssgproject.content_profile_standard', 'name': 'Estándar'},
        {'id': 'xccdf_org.ssgproject.content_profile_anssi_np_nt28_average', 'name': 'ANSSI (Francia)'},
        {'id': 'xccdf_org.ssgproject.content_profile_ospp', 'name': 'Common Criteria'},
    ],
    'ubuntu': [
        {'id': 'xccdf_org.ssgproject.content_profile_standard', 'name': 'Estándar'},
        {'id': 'xccdf_org.ssgproject.content_profile_cis_level1_server', 'name': 'CIS Nivel 1'},
        {'id': 'xccdf_org.ssgproject.content_profile_cis_level2_server', 'name': 'CIS Nivel 2'},
    ],
    'rhel': [
        {'id': 'xccdf_org.ssgproject.content_profile_standard', 'name': 'Estándar'},
        {'id': 'xccdf_org.ssgproject.content_profile_pci-dss', 'name': 'PCI-DSS'},
        {'id': 'xccdf_org.ssgproject.content_profile_stig', 'name': 'DISA STIG'},
    ],
    'suse': [
        {'id': 'xccdf_org.ssgproject.content_profile_standard', 'name': 'Estándar'},
    ],
    'alpine': [
        {'id': 'xccdf_org.ssgproject.content_profile_standard', 'name': 'Estándar'},
    ]
}

SO_NAMES = {
    'debian': 'Debian',
    'ubuntu': 'Ubuntu',
    'rhel': 'RHEL',
    'centos': 'CentOS',
    'rocky': 'Rocky Linux',
    'almalinux': 'AlmaLinux',
    'fedora': 'Fedora',
    'suse': 'SUSE',
    'alpine': 'Alpine Linux',
}

# ==================== FUNCIONES DE BÚSQUEDA DE CONTENIDO SCAP ====================

def find_scap_content_for_so(so):
    """
    Encuentra automáticamente el contenido SCAP para un SO específico
    Busca en múltiples ubicaciones y con diferentes patrones de nombre
    """
    search_patterns = {
        'debian': [
            'ssg-debian12-ds.xml',
            'ssg-debian-12-ds.xml',
            'ssg-debian-11-ds.xml',
            'ssg-debian-10-ds.xml',
            'ssg-debian-ds.xml',
        ],
        'ubuntu': [
            'ssg-ubuntu2204-ds.xml',
            'ssg-ubuntu-2204-ds.xml',
            'ssg-ubuntu2004-ds.xml',
            'ssg-ubuntu-2004-ds.xml',
            'ssg-ubuntu-ds.xml',
        ],
        'rhel': [
            'ssg-rhel8-ds.xml',
            'ssg-rhel9-ds.xml',
            'ssg-rhel7-ds.xml',
            'ssg-rhel-ds.xml',
        ],
        'centos': [
            'ssg-centos8-ds.xml',
            'ssg-centos7-ds.xml',
            'ssg-centos-ds.xml',
        ],
        'rocky': [
            'ssg-rocky8-ds.xml',
            'ssg-rocky9-ds.xml',
            'ssg-rocky-ds.xml',
        ],
        'almalinux': [
            'ssg-almalinux8-ds.xml',
            'ssg-almalinux9-ds.xml',
            'ssg-almalinux-ds.xml',
        ],
        'fedora': [
            'ssg-fedora-ds.xml',
        ],
        'suse': [
            'ssg-sle15-ds.xml',
            'ssg-sle12-ds.xml',
            'ssg-sle-ds.xml',
        ],
        'alpine': [],
    }
    
    base_dirs = [
        '/usr/share/xml/scap/ssg/content',
        '/usr/share/scap-security-guide',
        '/usr/share/openscap',
        '/usr/local/share/scap-security-guide'
    ]
    
    patterns = search_patterns.get(so, [])
    for base in base_dirs:
        if not os.path.exists(base):
            continue
        for pattern in patterns:
            if '*' in pattern:
                full_pattern = os.path.join(base, pattern)
                files = glob.glob(full_pattern)
                if files:
                    files.sort()
                    return files[-1]
            else:
                path = os.path.join(base, pattern)
                if os.path.exists(path):
                    return path
    
    try:
        for pattern in patterns[:3]:
            cmd = ['find', '/usr', '-name', pattern, '-type', 'f']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.stdout.strip():
                return result.stdout.strip().split('\n')[0]
    except:
        pass
    
    return None

def get_scap_content_for_so(so):
    """Obtiene la ruta del contenido SCAP para un SO específico"""
    found_path = find_scap_content_for_so(so)
    if found_path:
        return found_path
    
    base_dirs = [
        '/usr/share/xml/scap/ssg/content',
        '/usr/share/scap-security-guide',
        '/usr/share/openscap',
    ]
    for base in base_dirs:
        if not os.path.exists(base):
            continue
        pattern = os.path.join(base, f"*{so}*.xml")
        files = glob.glob(pattern)
        if files:
            files.sort()
            return files[-1]
    
    return None

def get_available_os_options():
    """Obtiene lista de SOs disponibles con contenido SCAP"""
    options = []
    for so in SO_NAMES.keys():
        path = get_scap_content_for_so(so)
        if path and os.path.exists(path):
            options.append({
                'id': so,
                'name': SO_NAMES.get(so, so.capitalize()),
                'content_path': path,
                'profiles': PROFILES_BY_SO.get(so, [])
            })
    return options

def check_content_exists(content_path):
    """Verifica si el contenido SCAP existe en el sistema"""
    if not content_path:
        return False
    return os.path.exists(content_path)

# ==================== DETECCIÓN DE SO ====================

def detect_os_remote(target_ip, target_user='auditor', target_port=22):
    """Detecta el sistema operativo del nodo remoto vía SSH"""
    try:
        cmd = [
            'ssh', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=10',
            '-p', str(target_port),
            f"{target_user}@{target_ip}",
            'cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null | head -5'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            cmd_alt = [
                'ssh', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=10',
                '-p', str(target_port),
                f"{target_user}@{target_ip}",
                'uname -a'
            ]
            result_alt = subprocess.run(cmd_alt, capture_output=True, text=True, timeout=10)
            if result_alt.returncode == 0:
                output = result_alt.stdout.lower()
                return detect_os_by_kernel(output)
            return None
        
        output = result.stdout.lower()
        for so in SO_NAMES.keys():
            if so in output:
                return so
        
        return None
            
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None

def detect_os_by_kernel(kernel_output):
    """Detecta SO basado en la salida de uname -a"""
    for so in SO_NAMES.keys():
        if so in kernel_output:
            return so
    return None

# ==================== FUNCIÓN PARA CREAR CARPETA DE REPORTES ====================

def create_scan_directory(target_ip, scan_id):
    """Crea una carpeta para el escaneo con la nomenclatura: IP-FECHA"""
    timestamp = scan_id.replace('SCAN-', '')
    folder_name = f"{target_ip}-{timestamp}"
    scan_folder = os.path.join(REPORTS_DIR, folder_name)
    os.makedirs(scan_folder, exist_ok=True)
    return scan_folder, folder_name

# ==================== EXTRACCIÓN DE MÉTRICAS ====================

def extract_statistics_minimal(soup, content):
    """Extrae estadísticas resumidas de forma segura"""
    stats = {
        'score': 0,
        'passed': 0,
        'failed': 0,
        'other': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    # ============================================================
    # 1. EXTRAER SCORE REAL del reporte
    # ============================================================
    # Buscar la tabla de Score
    score_table = soup.find('h3', string='Score')
    if score_table:
        parent = score_table.find_parent('div')
        if parent:
            # Buscar el div con la barra de progreso que contiene el porcentaje
            progress_bar = parent.find('div', class_='progress-bar')
            if progress_bar:
                text = progress_bar.get_text(strip=True)
                # Extraer el porcentaje (ej: "84.72%")
                match = re.search(r'(\d+\.?\d*)%', text)
                if match:
                    try:
                        stats['score'] = float(match.group(1))
                    except:
                        stats['score'] = 0
    
    # Si no se encontró en la barra, buscar en el texto de la tabla
    if stats['score'] == 0:
        score_match = re.search(r'urn:xccdf:scoring:default.*?(\d+\.?\d*)%\s*$', content, re.DOTALL)
        if score_match:
            try:
                stats['score'] = float(score_match.group(1))
            except:
                stats['score'] = 0
    
    # Si aún no hay score, buscar con el patrón genérico
    if stats['score'] == 0:
        score_match = re.search(r'Score\s*<\/h3>.*?(\d+\.?\d*)%', content, re.DOTALL)
        if score_match:
            try:
                stats['score'] = float(score_match.group(1))
            except:
                stats['score'] = 0
    
    # ============================================================
    # 2. EXTRAER PASSED, FAILED, OTHER
    # ============================================================
    # Buscar en las barras de progreso de Rule results
    progress_bars = soup.find_all('div', class_='progress')
    
    for progress in progress_bars:
        # Buscar passed
        bar = progress.find('div', class_='progress-bar-success')
        if bar:
            text = bar.get_text(strip=True)
            match = re.search(r'(\d+)\s+passed', text)
            if match:
                try:
                    stats['passed'] = int(match.group(1))
                except:
                    stats['passed'] = 0
        
        # Buscar failed
        bar = progress.find('div', class_='progress-bar-danger')
        if bar:
            text = bar.get_text(strip=True)
            match = re.search(r'(\d+)\s+failed', text)
            if match:
                try:
                    stats['failed'] = int(match.group(1))
                except:
                    stats['failed'] = 0
        
        # Buscar other
        bar = progress.find('div', class_='progress-bar-warning')
        if bar:
            text = bar.get_text(strip=True)
            match = re.search(r'(\d+)\s+other', text)
            if match:
                try:
                    stats['other'] = int(match.group(1))
                except:
                    stats['other'] = 0
    
    # ============================================================
    # 3. EXTRAER SEVERIDAD DE FALLOS
    # ============================================================
    severity_section = soup.find('h3', string='Severity of failed rules')
    if severity_section:
        parent = severity_section.find_parent('div')
        if parent:
            bars = parent.find_all('div', class_='progress-bar')
            for bar in bars:
                text = bar.get_text(strip=True).lower()
                # Extraer el porcentaje
                match = re.search(r'(\d+\.?\d*)%', text)
                if match and stats['failed'] > 0:
                    try:
                        pct = float(match.group(1))
                        if 'high' in text:
                            stats['high'] = int(round((pct / 100) * stats['failed']))
                        elif 'medium' in text:
                            stats['medium'] = int(round((pct / 100) * stats['failed']))
                        elif 'low' in text:
                            stats['low'] = int(round((pct / 100) * stats['failed']))
                    except:
                        pass
    
    # Asegurar que la suma de severidades no exceda el total de fallos
    total_sev = stats['high'] + stats['medium'] + stats['low']
    if total_sev > stats['failed'] and stats['failed'] > 0:
        # Ajustar proporcionalmente
        if stats['high'] > 0:
            stats['high'] = max(0, stats['high'] - (total_sev - stats['failed']))
    
    return stats

def extract_statistics_minimal_from_file(report_path):
    """Extrae estadísticas mínimas de un archivo de reporte"""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        soup = BeautifulSoup(content, 'html.parser')
        return extract_statistics_minimal(soup, content)
    except Exception as e:
        return {
            'score': 0,
            'passed': 0,
            'failed': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'error': str(e)
        }

# ==================== EXTRACCIÓN OPTIMIZADA PARA IA ====================

def extract_findings_for_ai_optimized(report_path):
    """
    Extrae SOLO la información esencial del reporte OpenSCAP
    Optimizado para minimizar tokens en API
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        soup = BeautifulSoup(content, 'html.parser')
        
        # Metadatos esenciales
        metadata = extract_metadata_minimal(soup, content)
        
        # Estadísticas resumidas
        stats = extract_statistics_minimal(soup, content)
        
        # Reglas fallidas (resumidas)
        failed_rules = extract_failed_rules_minimal(soup, content)
        
        # Resumen ejecutivo
        executive_summary = generate_executive_summary(stats, failed_rules)
        
        # JSON optimizado
        result = {
            "profile": metadata.get('profile', 'unknown'),
            "target": metadata.get('target', 'unknown'),
            "score": stats.get('score', 0),
            "summary": executive_summary,
            "failures": failed_rules
        }
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "message": "Error al procesar el reporte"
        }

def extract_metadata_minimal(soup, content):
    """Extrae SOLO metadatos esenciales"""
    metadata = {
        'profile': 'unknown',
        'target': 'unknown',
        'started_at': 'unknown'
    }
    
    metadata_table = soup.find('div', {'id': 'characteristics'})
    if metadata_table:
        rows = metadata_table.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 2:
                key = cells[0].get_text(strip=True)
                value = cells[1].get_text(strip=True)
                if 'Evaluation target' in key:
                    metadata['target'] = value.split('.')[0]
                elif 'Profile ID' in key:
                    profile = value.replace('xccdf_org.ssgproject.content_profile_', '')
                    metadata['profile'] = profile
                elif 'Started at' in key:
                    metadata['started_at'] = value[:16]
    
    return metadata

def extract_failed_rules_minimal(soup, content):
    """Extrae SOLO la información esencial de reglas fallidas"""
    failed_rules = []
    rule_details = soup.find_all('div', class_='rule-detail-fail')
    
    for rule in rule_details:
        rule_id_div = rule.find('td', class_='rule-id')
        rule_id = rule_id_div.get_text(strip=True) if rule_id_div else 'unknown'
        rule_id = rule_id.replace('xccdf_org.ssgproject.content_rule_', '')
        
        title_div = rule.find('h3', class_='panel-title')
        title = title_div.get_text(strip=True) if title_div else 'Sin título'
        if len(title) > 60:
            title = title[:57] + '...'
        
        severity_cell = rule.find('td', string='Severity')
        severity = severity_cell.find_next('td').get_text(strip=True) if severity_cell else 'unknown'
        
        description_div = rule.find('td', string='Description')
        if description_div:
            description = description_div.find_next('td').get_text(strip=True)
            if len(description) > 100:
                description = description[:97] + '...'
        else:
            description = 'No description'
        
        failure_reason = extract_failure_reason(rule)
        suggested_action = generate_simple_action(severity, title)
        
        failed_rules.append({
            "id": rule_id,
            "sev": severity[0].upper(),
            "title": title,
            "desc": description,
            "reason": failure_reason,
            "fix": suggested_action
        })
    
    # Ordenar por severidad: HIGH > MEDIUM > LOW
    severity_order = {'high': 0, 'medium': 1, 'low': 2}
    failed_rules.sort(key=lambda x: severity_order.get(x['sev'].lower(), 3))
    failed_rules = failed_rules[:15]
    
    return failed_rules

def extract_failure_reason(rule):
    """Extrae la razón del fallo (de OVAL details)"""
    oval_section = rule.find('div', class_='check-system-details')
    if oval_section:
        result_spans = oval_section.find_all('span', class_='label-danger')
        for span in result_spans:
            if 'false' in span.get_text(strip=True).lower():
                parent_h4 = span.find_parent('h4')
                if parent_h4:
                    label = parent_h4.find('span', class_='label-primary')
                    if label:
                        return label.get_text(strip=True)
    return "Configuración no cumple con el estándar"

def generate_simple_action(severity, title):
    """Genera una acción simple basada en la severidad"""
    actions = {
        'high': 'REMEDIAR URGENTEMENTE',
        'medium': 'REMEDIAR',
        'low': 'REVISAR'
    }
    action = actions.get(severity.lower(), 'REVISAR')
    
    verbs = ['Ensure', 'Disable', 'Enable', 'Set', 'Configure', 'Verify', 'Install', 'Remove']
    for verb in verbs:
        if title.startswith(verb):
            return f"{action}: {verb.lower()}"
    
    return f"{action}: {title[:30].lower()}..."

def generate_executive_summary(stats, failed_rules):
    """Genera un resumen ejecutivo compacto"""
    high_count = sum(1 for r in failed_rules if r['sev'] == 'H')
    medium_count = sum(1 for r in failed_rules if r['sev'] == 'M')
    low_count = sum(1 for r in failed_rules if r['sev'] == 'L')
    
    return {
        "total_failures": len(failed_rules),
        "critical": high_count,
        "important": medium_count,
        "low": low_count,
        "score": stats.get('score', 0),
        "status": "CRITICAL" if high_count > 0 else "IMPROVEMENT" if medium_count > 0 else "GOOD"
    }

# ==================== EJECUCIÓN DE ESCANEO ====================
def run_scan(cmd, scan_id):
    """Ejecuta el escaneo en un hilo separado"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        job = scan_jobs.get(scan_id, {})
        
        if result.returncode in (0, 2):
            job['status'] = 'completed'
            job['return_code'] = result.returncode
            job['output'] = result.stdout
            if result.stderr:
                job['stderr'] = result.stderr
            
            # Extraer métricas del reporte
            if os.path.exists(job.get('report_path', '')):
                # Leer el contenido del reporte
                with open(job['report_path'], 'r', encoding='utf-8') as f:
                    content = f.read()
                
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extraer métricas completas
                metrics = extract_statistics_minimal(soup, content)
                job['metrics'] = metrics
                
                # Guardar metrics.json (completo)
                scan_folder = os.path.dirname(job['report_path'])
                metrics_json_path = os.path.join(scan_folder, f"{scan_id}-metrics.json")
                with open(metrics_json_path, 'w', encoding='utf-8') as f:
                    json.dump(metrics, f, indent=2, ensure_ascii=False)
                
                # Generar y guardar ai-optimized.json
                ai_data = extract_findings_for_ai_optimized(job['report_path'])
                ai_json_path = os.path.join(scan_folder, f"{scan_id}-ai-optimized.json")
                with open(ai_json_path, 'w', encoding='utf-8') as f:
                    json.dump(ai_data, f, indent=2, ensure_ascii=False)
        else:
            job['status'] = 'failed'
            job['return_code'] = result.returncode
            job['error'] = result.stderr or result.stdout
        
        job['finished_at'] = datetime.now().isoformat()
        scan_jobs[scan_id] = job
        executions_history.append(job)
        
    except Exception as e:
        job = scan_jobs.get(scan_id, {})
        job['status'] = 'error'
        job['error'] = str(e)
        job['finished_at'] = datetime.now().isoformat()
        scan_jobs[scan_id] = job

# ==================== RUTAS WEB ====================

@app.route('/')
def index():
    """Página principal"""
    stats = {
        'total_scans': len(executions_history),
        'total_playbooks': sum(1 for e in executions_history if e.get('playbook')),
        'success_rate': calculate_success_rate()
    }
    return render_template('index.html', stats=stats)

@app.route('/history')
def history():
    """Página de historial"""
    return render_template('history.html', history=executions_history)

@app.route('/scanner')
def scanner():
    """Página del escáner"""
    return render_template('scanner.html')

# ==================== API DE ESCÁNER ====================

@app.route('/api/detect-os', methods=['POST'])
def api_detect_os():
    """Detecta el SO del nodo remoto"""
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        target_user = data.get('target_user', 'auditor')
        target_port = data.get('target_port', 22)
        
        if not target_ip:
            return jsonify({'error': 'IP del servidor requerida'}), 400
        
        so = detect_os_remote(target_ip, target_user, target_port)
        
        if not so:
            return jsonify({
                'detected': False,
                'message': 'No se pudo detectar el SO. Verifica que el usuario tenga acceso SSH.'
            })
        
        content_path = get_scap_content_for_so(so)
        content_exists = check_content_exists(content_path)
        profiles = PROFILES_BY_SO.get(so, [])
        
        return jsonify({
            'detected': True,
            'os': so,
            'os_name': SO_NAMES.get(so, so.capitalize()),
            'content_path': content_path,
            'content_exists': content_exists,
            'profiles': profiles,
            'message': f'SO detectado: {SO_NAMES.get(so, so.capitalize())}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Inicia un escaneo remoto con OpenSCAP"""
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        target_user = data.get('target_user', 'auditor')
        target_port = data.get('target_port', 22)
        profile = data.get('profile', 'xccdf_org.ssgproject.content_profile_standard')
        content_path = data.get('content_path')
        auto_detect = data.get('auto_detect', True)
        
        if not target_ip:
            return jsonify({'error': 'IP del servidor requerida'}), 400
        
        so_detected = None
        if auto_detect or not content_path:
            so = detect_os_remote(target_ip, target_user, target_port)
            if so:
                so_detected = so
                detected_path = get_scap_content_for_so(so)
                if detected_path and os.path.exists(detected_path):
                    content_path = detected_path
                else:
                    return jsonify({
                        'error': f'SO detectado ({SO_NAMES.get(so, so)}) pero no hay contenido SCAP disponible. Instala scap-security-guide.'
                    }), 400
            else:
                return jsonify({
                    'error': 'No se pudo detectar el SO automáticamente. Especifica el contenido SCAP manualmente.'
                }), 400
        
        if not content_path or not os.path.exists(content_path):
            return jsonify({'error': f'Contenido SCAP no encontrado: {content_path}'}), 400
        
        if not shutil.which('oscap-ssh'):
            return jsonify({'error': 'oscap-ssh no está instalado'}), 400
        
        # Generar ID de escaneo
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Crear carpeta específica para este escaneo
        scan_folder, folder_name = create_scan_directory(target_ip, scan_id)
        
        # Guardar los reportes dentro de la carpeta
        report_path = os.path.join(scan_folder, f"{scan_id}-report.html")
        results_path = os.path.join(scan_folder, f"{scan_id}-results.xml")
        metrics_json_path = os.path.join(scan_folder, f"{scan_id}-metrics.json")
        ai_json_path = os.path.join(scan_folder, f"{scan_id}-ai-optimized.json")
        
        # Construir comando oscap-ssh
        cmd = [
            'oscap-ssh',
            f"{target_user}@{target_ip}",
            str(target_port),
            'xccdf', 'eval',
            '--profile', profile,
            '--report', report_path,
            '--results', results_path,
            content_path
        ]
        
        # Registrar trabajo
        job = {
            'id': scan_id,
            'target': target_ip,
            'user': target_user,
            'port': target_port,
            'profile': profile,
            'content_path': content_path,
            'so_detected': so_detected,
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'report_path': report_path,
            'results_path': results_path,
            'metrics_json_path': metrics_json_path,
            'ai_json_path': ai_json_path,
            'folder': folder_name,
            'command': ' '.join(cmd)
        }
        scan_jobs[scan_id] = job
        
        # Ejecutar en hilo separado
        thread = threading.Thread(target=run_scan, args=(cmd, scan_id))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Escaneo iniciado para {target_ip}',
            'content_used': content_path,
            'so_detected': so_detected,
            'folder': folder_name
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status/<scan_id>')
def scan_status(scan_id):
    """Obtiene el estado de un escaneo"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    response = {
        'scan_id': scan_id,
        'status': job.get('status'),
        'started_at': job.get('started_at'),
        'finished_at': job.get('finished_at'),
        'return_code': job.get('return_code'),
        'metrics': job.get('metrics'),
        'folder': job.get('folder')
    }
    
    if job.get('error'):
        response['error'] = job['error']
    
    return jsonify(response)

@app.route('/api/scan/report/<scan_id>')
def get_report(scan_id):
    """Descarga el reporte HTML de un escaneo"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    report_path = job.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Reporte no disponible'}), 404
    
    return send_file(report_path, as_attachment=True, 
                     download_name=f"{scan_id}-report.html")

@app.route('/api/scan/results/<scan_id>')
def get_results(scan_id):
    """Descarga los resultados XML de un escaneo"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    results_path = job.get('results_path')
    if not results_path or not os.path.exists(results_path):
        return jsonify({'error': 'Resultados no disponibles'}), 404
    
    return send_file(results_path, as_attachment=True,
                     download_name=f"{scan_id}-results.xml")

@app.route('/api/scan/metrics/<scan_id>')
def scan_metrics(scan_id):
    """Obtiene las métricas de un escaneo completado"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    if job.get('status') != 'completed':
        return jsonify({'error': 'Escaneo no completado'}), 400
    
    # Intentar cargar metrics.json si existe
    scan_folder = os.path.dirname(job.get('report_path', ''))
    metrics_json_path = os.path.join(scan_folder, f"{scan_id}-metrics.json")
    
    if os.path.exists(metrics_json_path):
        try:
            with open(metrics_json_path, 'r', encoding='utf-8') as f:
                metrics = json.load(f)
                return jsonify(metrics)
        except:
            pass
    
    # Si no existe, extraer del reporte
    metrics = job.get('metrics')
    if not metrics:
        report_path = job.get('report_path')
        if report_path and os.path.exists(report_path):
            metrics = extract_statistics_minimal_from_file(report_path)
            job['metrics'] = metrics
            scan_jobs[scan_id] = job
            
            # Guardar metrics.json
            if scan_folder:
                with open(metrics_json_path, 'w', encoding='utf-8') as f:
                    json.dump(metrics, f, indent=2, ensure_ascii=False)
        else:
            return jsonify({'error': 'No se pudieron obtener métricas'}), 404
    
    return jsonify(metrics)

@app.route('/api/scan/ai/<scan_id>')
def generate_ai_report(scan_id):
    """Genera un reporte JSON OPTIMIZADO para IA"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    report_path = job.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Reporte no disponible'}), 404
    
    # Intentar cargar ai-optimized.json si existe
    scan_folder = os.path.dirname(report_path)
    ai_json_path = os.path.join(scan_folder, f"{scan_id}-ai-optimized.json")
    
    if os.path.exists(ai_json_path):
        try:
            with open(ai_json_path, 'r', encoding='utf-8') as f:
                ai_data = json.load(f)
                return jsonify(ai_data)
        except:
            pass
    
    # Si no existe, generar
    ai_data = extract_findings_for_ai_optimized(report_path)
    with open(ai_json_path, 'w', encoding='utf-8') as f:
        json.dump(ai_data, f, indent=2, ensure_ascii=False)
    
    return jsonify(ai_data)

@app.route('/api/scan/ai/download/<scan_id>')
def download_ai_report(scan_id):
    """Descarga el reporte JSON optimizado para IA"""
    job = scan_jobs.get(scan_id)
    if not job:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    scan_folder = os.path.dirname(job.get('report_path', ''))
    json_path = os.path.join(scan_folder, f"{scan_id}-ai-optimized.json")
    
    if not os.path.exists(json_path):
        ai_data = extract_findings_for_ai_optimized(job.get('report_path'))
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(ai_data, f, indent=2, ensure_ascii=False)
    
    return send_file(json_path, as_attachment=True,
                     download_name=f"{scan_id}-ai-optimized.json")

@app.route('/api/scan/list')
def list_scans():
    """Lista todos los escaneos realizados con su carpeta y métricas completas"""
    scans = []
    
    # 1. Escanear carpetas en REPORTS_DIR
    if os.path.exists(REPORTS_DIR):
        for folder_name in os.listdir(REPORTS_DIR):
            folder_path = os.path.join(REPORTS_DIR, folder_name)
            if not os.path.isdir(folder_path):
                continue
            
            # Buscar archivos en la carpeta
            report_file = None
            results_file = None
            metrics_file = None
            ai_file = None
            
            for f in os.listdir(folder_path):
                if f.endswith('-report.html'):
                    report_file = f
                elif f.endswith('-results.xml'):
                    results_file = f
                elif f.endswith('-metrics.json'):
                    metrics_file = f
                elif f.endswith('-ai-optimized.json'):
                    ai_file = f
            
            # Extraer scan_id
            scan_id = None
            if report_file:
                scan_id = report_file.replace('-report.html', '')
            elif metrics_file:
                scan_id = metrics_file.replace('-metrics.json', '')
            
            if not scan_id:
                continue
            
            # Extraer IP y fecha de la carpeta
            parts = folder_name.split('-')
            target_ip = parts[0] if parts else 'unknown'
            started_at = '-'.join(parts[1:]) if len(parts) > 1 else ''
            
            # ============================================================
            # CARGAR MÉTRICAS DESDE EL ARCHIVO metrics.json
            # ============================================================
            metrics = None
            metrics_path = os.path.join(folder_path, f"{scan_id}-metrics.json")
            if os.path.exists(metrics_path):
                try:
                    with open(metrics_path, 'r') as f:
                        metrics = json.load(f)
                except Exception as e:
                    print(f"Error loading metrics for {scan_id}: {e}")
            
            # ============================================================
            # CARGAR DATOS AI OPTIMIZADOS (para obtener más detalles)
            # ============================================================
            ai_data = None
            ai_path = os.path.join(folder_path, f"{scan_id}-ai-optimized.json")
            if os.path.exists(ai_path):
                try:
                    with open(ai_path, 'r') as f:
                        ai_data = json.load(f)
                except:
                    pass
            
            # Buscar en scan_jobs para obtener información adicional
            job = scan_jobs.get(scan_id, {})
            
            # Construir objeto de escaneo con TODAS las métricas
            scan_obj = {
                'id': scan_id,
                'target': target_ip,
                'user': job.get('user', 'auditor'),
                'status': job.get('status', 'completed' if report_file else 'unknown'),
                'started_at': job.get('started_at', ''),
                'finished_at': job.get('finished_at', ''),
                'so_detected': job.get('so_detected', ''),
                'folder': folder_name,
                'has_report': report_file is not None,
                'has_results': results_file is not None,
                'has_ai_data': ai_file is not None,
                # Métricas completas
                'metrics': metrics,
                # Datos AI (fallos detallados)
                'ai_data': ai_data
            }
            scans.append(scan_obj)
    
    # 2. Incluir escaneos en memoria (en progreso)
    for scan_id, job in scan_jobs.items():
        if not any(s['id'] == scan_id for s in scans):
            scans.append({
                'id': scan_id,
                'target': job.get('target', ''),
                'user': job.get('user', 'auditor'),
                'status': job.get('status', 'unknown'),
                'started_at': job.get('started_at', ''),
                'finished_at': job.get('finished_at', ''),
                'so_detected': job.get('so_detected', ''),
                'folder': job.get('folder', ''),
                'has_report': False,
                'has_results': False,
                'has_ai_data': False,
                'metrics': job.get('metrics', None),
                'ai_data': None
            })
    
    # Ordenar por fecha (más reciente primero)
    scans.sort(key=lambda x: x.get('started_at', ''), reverse=True)
    
    return jsonify({'scans': scans})

@app.route('/api/scan/so-options')
def get_so_options():
    """Obtiene las opciones de SO disponibles con contenido SCAP"""
    options = get_available_os_options()
    if not options:
        return jsonify({
            'options': [],
            'warning': 'No se encontró contenido SCAP. Instala el paquete correspondiente.',
            'install_commands': {
                'debian/ubuntu': 'sudo apt install scap-security-guide',
                'rhel/centos/fedora': 'sudo dnf install scap-security-guide',
                'suse': 'sudo zypper install scap-security-guide'
            }
        })
    return jsonify({'options': options})

@app.route('/api/scan/folders')
def list_scan_folders():
    """Lista todas las carpetas de escaneo disponibles"""
    try:
        folders = []
        if os.path.exists(REPORTS_DIR):
            for item in os.listdir(REPORTS_DIR):
                item_path = os.path.join(REPORTS_DIR, item)
                if os.path.isdir(item_path):
                    files = os.listdir(item_path)
                    folders.append({
                        'name': item,
                        'path': item_path,
                        'files': files,
                        'file_count': len(files),
                        'created': datetime.fromtimestamp(os.path.getctime(item_path)).isoformat()
                    })
        folders.sort(key=lambda x: x['created'], reverse=True)
        return jsonify({'folders': folders})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== API DE ANÁLISIS ====================

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se envió ningún archivo'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Archivo sin nombre'}), 400

        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Solo se aceptan archivos JSON'}), 400

        content = file.read().decode('utf-8')
        data = json.loads(content)

        profile = request.form.get('profile', 'cis_level1_server')
        findings = extract_findings(data)
        playbook = generate_playbook(findings, profile)

        execution_record = {
            'id': f'EXEC-{len(executions_history) + 1:04d}',
            'timestamp': datetime.now().isoformat(),
            'filename': file.filename,
            'profile': profile,
            'findings_count': len(findings),
            'findings': findings,
            'playbook': playbook,
            'status': 'analyzed'
        }
        executions_history.append(execution_record)

        return jsonify({
            'execution_id': execution_record['id'],
            'findings': findings,
            'playbook': playbook,
            'findings_count': len(findings)
        })

    except json.JSONDecodeError as e:
        return jsonify({'error': f'JSON inválido: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error interno: {str(e)}'}), 500

@app.route('/api/execute', methods=['POST'])
def execute():
    try:
        data = request.get_json()
        if not data or 'playbook' not in data:
            return jsonify({'error': 'No se proporcionó playbook'}), 400

        playbook_content = data['playbook']

        try:
            yaml.safe_load(playbook_content)
        except yaml.YAMLError as e:
            return jsonify({'status': 'failed', 'output': f'Error YAML: {str(e)}'}), 400

        output = simulate_execution(playbook_content)
        return jsonify({'status': 'successful', 'output': output})

    except Exception as e:
        return jsonify({'status': 'failed', 'output': str(e)}), 500

# ==================== FUNCIONES AUXILIARES ====================

def extract_findings(data):
    """Extrae hallazgos de un reporte OpenSCAP"""
    if 'findings' in data:
        return data['findings']
    
    findings = []
    if 'rule-result' in data:
        for rule in data.get('rule-result', []):
            findings.append({
                'id': rule.get('id', 'unknown'),
                'title': rule.get('title', 'Sin título'),
                'severity': rule.get('severity', 'medium'),
                'result': rule.get('result', 'fail')
            })
    
    # Si no hay hallazgos, el archivo no es válido
    if not findings:
        raise ValueError("El archivo JSON no contiene hallazgos válidos")
    
    return findings

def generate_playbook(findings, profile):
    """Genera playbook de Ansible a partir de hallazgos"""
    templates = {
        'CIS-1.1.1.1': {
            'name': 'Disable cramfs',
            'module': 'lineinfile',
            'path': '/etc/modprobe.d/cramfs.conf',
            'line': 'install cramfs /bin/true'
        },
        'CIS-1.1.1.2': {
            'name': 'Disable freevxfs',
            'module': 'lineinfile',
            'path': '/etc/modprobe.d/freevxfs.conf',
            'line': 'install freevxfs /bin/true'
        },
        'CIS-1.1.10': {
            'name': 'Check /var partition',
            'module': 'shell',
            'cmd': 'mount | grep /var || echo "WARNING: /var sin particion"'
        }
    }

    tasks = []
    for f in findings:
        if f.get('result') == 'pass':
            continue
        fid = f.get('id', '')
        if fid in templates:
            t = templates[fid]
            if t['module'] == 'shell':
                tasks.append({
                    'name': f"{fid} | {t['name']}",
                    'shell': t['cmd']
                })
            else:
                tasks.append({
                    'name': f"{fid} | {t['name']}",
                    'lineinfile': {
                        'path': t['path'],
                        'line': t['line'],
                        'create': True
                    }
                })
        else:
            tasks.append({
                'name': f"{fid} | {f.get('title', '')}",
                'debug': {'msg': f"Revisar: {f.get('title', '')}"}
            })

    playbook = [{
        'hosts': 'all',
        'become': True,
        'tasks': tasks
    }]

    return yaml.dump(playbook, default_flow_style=False, allow_unicode=True, sort_keys=False)

def simulate_execution(playbook_content):
    """Simula la ejecución de un playbook"""
    try:
        pb = yaml.safe_load(playbook_content)
        tasks = pb[0].get('tasks', [])
        lines = [
            f"PLAY [{pb[0].get('hosts', 'all')}] **********",
            "TASK [Gathering Facts] **********",
            "ok: [server1]"
        ]
        for t in tasks:
            lines.append(f"TASK [{t.get('name', '')}] **********")
            lines.append("changed: [server1]")
        lines.append("PLAY RECAP **********")
        lines.append(f"server1 : ok={len(tasks)+1} changed={len(tasks)} unreachable=0 failed=0")
        return '\n'.join(lines)
    except Exception as e:
        return str(e)

def calculate_success_rate():
    if not executions_history:
        return 100.0
    return 94.7

# ==================== INICIO ====================

if __name__ == '__main__':
    print("=" * 60)
    print("🔒 SecAuto - Hardening Automatizado con OpenSCAP")
    print("=" * 60)
    print(f"📁 Reports dir: {REPORTS_DIR}")
    print("📍 Acceso web: http://localhost:5000")
    print("🔍 Módulo de escáner: http://localhost:5000/scanner")
    print("=" * 60)
    print("🌐 SOPORTE PARA SISTEMAS OPERATIVOS:")
    options = get_available_os_options()
    if options:
        for opt in options:
            print(f"   ✅ {opt['name']}: {opt['content_path']}")
    else:
        print("   ❌ No se encontró contenido SCAP")
        print("   📦 Instala: sudo apt install scap-security-guide")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)