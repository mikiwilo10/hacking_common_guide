"""
Pipeline de Agentes IA para Hardening Automatizado
Encadenamiento de prompts especializados con validación intermedia.

Arquitectura:
    Finding ──▶ Clasificador ──▶ Router ──▶ Remediador Especializado
                                              │
                                              ▼
                                    Playbook Builder
                                              │
                                              ▼
                                    Validador de Seguridad
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                   ▼
                              [APROBADO]          [RECHAZADO]
                                    │                   │
                                    ▼                   ▼
                              Ejecutar Ansible      Solicitar
                              + Generar Rollback    regeneración
"""

import os
import yaml
import json
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Literal
from enum import Enum
from openai import OpenAI


# =============================================================================
# MODELO DE DATOS UNIFICADO
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Category(str, Enum):
    OS_HARDENING = "os_hardening"
    SERVICE_HARDENING = "service_hardening"
    NETWORK_SECURITY = "network_security"
    ACCESS_CONTROL = "access_control"
    LOGGING = "logging"
    CUSTOM_APP = "custom_app"

class RemediationType(str, Enum):
    ANSIBLE_NATIVE = "ansible_native"
    ANSIBLE_COMPLEX = "ansible_complex"
    MANUAL_ONLY = "manual_only"
    REQUIRES_REBOOT = "requires_reboot"

class AnsibleComplexity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class Verdict(str, Enum):
    APPROVED = "APPROVED"
    APPROVED_WITH_WARNINGS = "APPROVED_WITH_WARNINGS"
    REJECTED = "REJECTED"


@dataclass
class UnifiedFinding:
    source: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    target: str
    remediation_type: RemediationType
    raw_evidence: str


@dataclass
class ClassifiedFinding(UnifiedFinding):
    category: Category
    risk_score: float  # 0-10
    ansible_complexity: AnsibleComplexity
    suggested_module: str
    suggested_vars: Dict
    preconditions: List[str]
    side_effects: List[str]


@dataclass
class ValidationIssue:
    severity: Literal["critical", "high", "medium", "low"]
    line_reference: Optional[int]
    issue: str
    fix: str


# =============================================================================
# AGENTE 1: CLASIFICADOR Y PRIORIZADOR (Prompt #3)
# =============================================================================

SYSTEM_PROMPT_CLASSIFIER = """Rol: Analista de vulnerabilidades y arquitecto de seguridad.

Analiza el JSON de hallazgos proporcionado y clasifica cada uno:
- CATEGORIA: os_hardening, service_hardening, network_security, access_control, logging, custom_app
- REMEDIATION_TYPE: ansible_native, ansible_complex, manual_only, requires_reboot
- RISK_SCORE: 0-10 (basado en severidad + facilidad de explotación + impacto CIA)
- ANSIBLE_COMPLEXITY: low, medium, high
- SUGGESTED_MODULE: módulo Ansible recomendado
- SUGGESTED_VARS: variables necesarias como objeto JSON
- PRECONDITIONS: condiciones previas (array de strings)
- SIDE_EFFECTS: impacto en disponibilidad (array de strings)

Responde ÚNICAMENTE con un JSON válido. Sin markdown, sin explicaciones.
Formato: {"findings": [{...}]}
"""


class ClassificationAgent:
    def __init__(self, client: OpenAI, model: str = "gpt-4o"):
        self.client = client
        self.model = model

    def classify(self, findings: List[UnifiedFinding]) -> List[ClassifiedFinding]:
        findings_json = json.dumps([asdict(f) for f in findings], indent=2)

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_CLASSIFIER},
                {"role": "user", "content": findings_json}
            ],
            temperature=0.1,
            max_tokens=4000,
            response_format={"type": "json_object"}
        )

        raw = response.choices[0].message.content
        parsed = json.loads(raw)

        classified = []
        for item in parsed.get("findings", []):
            base = UnifiedFinding(
                source=item["source"],
                rule_id=item["rule_id"],
                severity=Severity(item["severity"]),
                title=item["title"],
                description=item["description"],
                target=item["target"],
                remediation_type=RemediationType(item["remediation_type"]),
                raw_evidence=item.get("raw_evidence", "")
            )
            classified.append(ClassifiedFinding(
                **asdict(base),
                category=Category(item["category"]),
                risk_score=float(item["risk_score"]),
                ansible_complexity=AnsibleComplexity(item["ansible_complexity"]),
                suggested_module=item["suggested_module"],
                suggested_vars=item.get("suggested_vars", {}),
                preconditions=item.get("preconditions", []),
                side_effects=item.get("side_effects", [])
            ))

        # Ordenar por risk_score descendente
        classified.sort(key=lambda x: x.risk_score, reverse=True)
        return classified


# =============================================================================
# AGENTE 2: ROUTER DE REMEDIACIÓN (Prompts #1, #6-10)
# =============================================================================

SYSTEM_PROMPT_REMEDIATOR_BASE = """Rol: Experto senior en hardening de Linux y Ansible.

Genera UNA ÚNICA tarea de Ansible en YAML para remediar el hallazgo.
RESTRICCIONES INQUEBRANTABLES:
1. ÚNICAMENTE código YAML válido. Sin explicaciones fuera del código.
2. Usa módulos nativos: lineinfile, file, sysctl, systemd, package, apt, yum, template, copy, user, group, mount, blockinfile, replace, stat, find.
3. PROHIBIDO shell, command, raw, script salvo que NO EXISTA alternativa. Justifica con # SECURITY_JUSTIFICATION:
4. Idempotente: 100 ejecuciones = mismo estado después de la primera.
5. Incluye tags: [cis, hardening, {{RULE_ID}}]
6. Usa become: yes a nivel de tarea cuando sea necesario.
7. Valida existencia de archivos con stat o when: ansible_os_family.
8. Para SSH, incluye notify: restart sshd y valida con sshd -t.
9. NUNCA contraseñas en texto plano.
10. Para firewall, NUNCA bloquees el puerto del operador sin wait_for.

Formato de salida obligatorio:
```yaml
- name: <CIS-ID> - <Descripción breve>
  <módulo_ansible>:
    <parámetros>
  when: <condición>
  tags: [cis, hardening, <cis_id>]
```
"""

SYSTEM_PROMPT_REMEDIATOR_NETWORK = """Rol: Ingeniero de red y seguridad perimetral.

REGLAS ADICIONALES para hardening de red:
- Usa ansible.posix.sysctl para parámetros de kernel.
- Prioriza firewalld (RHEL) o ufw (Debian). Usa iptables solo si no hay alternativa.
- CRÍTICO: Antes de aplicar reglas de firewall, instala un timer de 5 minutos que restaure reglas anteriores.
- Incluye siempre:
  net.ipv4.ip_forward = 0
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.send_redirects = 0
  net.ipv4.icmp_echo_ignore_broadcasts = 1
  net.ipv4.tcp_syncookies = 1
"""

SYSTEM_PROMPT_REMEDIATOR_PERMISSIONS = """Rol: Especialista en permisos Unix y DAC.

REGLAS ADICIONALES para filesystem:
- /etc/shadow: mode '0640', owner root, group shadow (Debian) o root (RHEL)
- Directorios home: mode '0700'
- Para SUID/SGID: usa find + file para remover bits no autorizados
- /tmp y /var/tmp: mode '1777'
- NUNCA chmod -R o chown -R sin filtrar con find primero
"""

SYSTEM_PROMPT_REMEDIATOR_SERVICES = """Rol: Hardening engineer especializado en servicios críticos.

REGLAS ADICIONALES para servicios:
- Valida que el servicio está instalado antes de modificarlo.
- Valida sintaxis antes de recargar (sshd -t, nginx -t, apachectl configtest).
- Prefiere state: reloaded sobre restarted.
- Verifica que el servicio responde post-cambio.
- SSH: NUNCA PermitRootLogin yes, NUNCA PasswordAuthentication yes sin advertencia.
- Bases de datos: NUNCA expongas puertos por defecto a 0.0.0.0/0. Usa no_log: true para contraseñas.
"""


class RemediationRouter:
    """Rutea cada hallazgo al prompt especializado según su categoría."""

    CATEGORY_PROMPTS = {
        Category.OS_HARDENING: SYSTEM_PROMPT_REMEDIATOR_BASE,
        Category.SERVICE_HARDENING: SYSTEM_PROMPT_REMEDIATOR_BASE + "\n" + SYSTEM_PROMPT_REMEDIATOR_SERVICES,
        Category.NETWORK_SECURITY: SYSTEM_PROMPT_REMEDIATOR_BASE + "\n" + SYSTEM_PROMPT_REMEDIATOR_NETWORK,
        Category.ACCESS_CONTROL: SYSTEM_PROMPT_REMEDIATOR_BASE + "\n" + SYSTEM_PROMPT_REMEDIATOR_PERMISSIONS,
        Category.LOGGING: SYSTEM_PROMPT_REMEDIATOR_BASE,
        Category.CUSTOM_APP: SYSTEM_PROMPT_REMEDIATOR_BASE,
    }

    def __init__(self, client: OpenAI, model: str = "gpt-4o"):
        self.client = client
        self.model = model

    def generate_task(self, finding: ClassifiedFinding) -> Optional[str]:
        if finding.remediation_type == RemediationType.MANUAL_ONLY:
            return None  # No generamos Ansible para esto

        system_prompt = self.CATEGORY_PROMPTS.get(finding.category, SYSTEM_PROMPT_REMEDIATOR_BASE)

        user_prompt = f"""Hallazgo a remediar:
- ID: {finding.rule_id}
- Categoría: {finding.category.value}
- Título: {finding.title}
- Descripción: {finding.description}
- Severidad: {finding.severity.value}
- Target: {finding.target}
- Módulo sugerido: {finding.suggested_module}
- Variables sugeridas: {json.dumps(finding.suggested_vars)}
- Precondiciones: {json.dumps(finding.preconditions)}
- Efectos secundarios: {json.dumps(finding.side_effects)}

Genera ÚNICAMENTE la tarea YAML. Sin texto adicional."""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.15,
            max_tokens=1200
        )

        raw = response.choices[0].message.content
        return self._extract_yaml(raw)

    def _extract_yaml(self, text: str) -> str:
        """Extrae el bloque YAML de la respuesta, limpiando markdown."""
        # Buscar bloque ```yaml ... ```
        match = re.search(r"```(?:yaml|yml)?\s*(.*?)```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Si no hay bloque markdown, devolver todo limpio
        return text.strip()


# =============================================================================
# AGENTE 3: VALIDADOR DE SEGURIDAD IA (Prompt #4)
# =============================================================================

SYSTEM_PROMPT_VALIDATOR = """Rol: Auditor de código de infraestructura (IaC Security).

Analiza el playbook Ansible proporcionado y detecta problemas de seguridad.
VERIFICACIONES:
1. Uso de shell/command sin justificación en comentario # SECURITY_JUSTIFICATION:
2. Modificaciones de red (/etc/network/interfaces, iptables) sin validación previa
3. Cambios en /etc/ssh/sshd_config sin sshd -t antes de notify: restart sshd
4. Permisos incorrectos: mode '777', '666', '644' en archivos sensibles
5. Variables hardcodeadas que deberían venir de vars_files o vault
6. Ausencia de when para validar compatibilidad de SO
7. Tareas no idempotentes (ej. command con > en lugar de copy con content)
8. ignore_errors: yes sin register y failed_when controlado
9. Modificaciones de firewall sin safety net (timer de 5 min)
10. Exposición de credenciales en texto plano

Para cada problema genera JSON:
{ "severity": "critical|high|medium|low", "line_reference": <int|null>, "issue": "...", "fix": "..." }

Al final emite veredicto:
{ "verdict": "APPROVED|APPROVED_WITH_WARNINGS|REJECTED", "summary": "..." }

Responde ÚNICAMENTE con JSON válido. Sin markdown.
Formato: {"issues": [...], "verdict": "...", "summary": "..."}
"""


class SecurityValidator:
    def __init__(self, client: OpenAI, model: str = "gpt-4o"):
        self.client = client
        self.model = model

    def validate(self, playbook_yaml: str) -> tuple[Verdict, List[ValidationIssue], str]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_VALIDATOR},
                {"role": "user", "content": playbook_yaml}
            ],
            temperature=0.0,
            max_tokens=3000,
            response_format={"type": "json_object"}
        )

        raw = response.choices[0].message.content
        parsed = json.loads(raw)

        issues = [
            ValidationIssue(
                severity=i["severity"],
                line_reference=i.get("line_reference"),
                issue=i["issue"],
                fix=i["fix"]
            )
            for i in parsed.get("issues", [])
        ]

        verdict = Verdict(parsed["verdict"])
        summary = parsed.get("summary", "")

        return verdict, issues, summary


# =============================================================================
# AGENTE 4: GENERADOR DE ROLLBACK (Prompt #5)
# =============================================================================

SYSTEM_PROMPT_ROLLBACK = """Rol: Ingeniero de fiabilidad. Generas playbooks de reversión.

Recibirás un playbook de hardening. Genera su contraparte de rollback:
1. pre_task: Verificar que existe cis_backup_dir. Si no, fail.
2. Para cada tarea de modificación de archivo (lineinfile, replace, copy):
   - Restaurar desde backup si existe
   - O revertir a valor por defecto del SO
3. Para servicios detenidos: reanudar solo si estaban activos (usa facts)
4. Para paquetes instalados: NO desinstalar automáticamente. Documentar recomendación.
5. Incluir post_task que verifique servicios críticos respondan.

Responde ÚNICAMENTE con YAML válido. Sin explicaciones.
"""


class RollbackGenerator:
    def __init__(self, client: OpenAI, model: str = "gpt-4o"):
        self.client = client
        self.model = model

    def generate(self, hardening_playbook: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_ROLLBACK},
                {"role": "user", "content": hardening_playbook}
            ],
            temperature=0.1,
            max_tokens=4000
        )
        return response.choices[0].message.content


# =============================================================================
# ORQUESTADOR DEL PIPELINE COMPLETO
# =============================================================================

class HardeningPipeline:
    def __init__(self, openai_api_key: str, model: str = "gpt-4o"):
        self.client = OpenAI(api_key=openai_api_key)
        self.model = model

        self.classifier = ClassificationAgent(self.client, model)
        self.router = RemediationRouter(self.client, model)
        self.validator = SecurityValidator(self.client, model)
        self.rollback_gen = RollbackGenerator(self.client, model)

    def run(self, findings: List[UnifiedFinding], target_host: str) -> dict:
        print("=" * 60)
        print("ETAPA 1: CLASIFICACIÓN Y PRIORIZACIÓN")
        print("=" * 60)
        classified = self.classifier.classify(findings)
        print(f"Hallazgos clasificados: {len(classified)}")
        for c in classified[:5]:
            print(f"  [{c.severity.value.upper()}] {c.rule_id} | Risk: {c.risk_score} | Category: {c.category.value}")

        print("\n" + "=" * 60)
        print("ETAPA 2: GENERACIÓN DE TAREAS DE REMEDIACIÓN")
        print("=" * 60)
        tasks_yaml = []
        manual_findings = []

        for finding in classified:
            if finding.remediation_type == RemediationType.MANUAL_ONLY:
                manual_findings.append(finding)
                continue

            task = self.router.generate_task(finding)
            if task:
                # Validación sintáctica YAML antes de aceptar
                try:
                    yaml.safe_load(task)
                    tasks_yaml.append(task)
                    print(f"  ✓ {finding.rule_id} -> Generado ({finding.category.value})")
                except yaml.YAMLError as e:
                    print(f"  ✗ {finding.rule_id} -> YAML inválido: {e}")
                    manual_findings.append(finding)
            else:
                manual_findings.append(finding)

        print("\n" + "=" * 60)
        print("ETAPA 3: ENSAMBLAJE DEL PLAYBOOK")
        print("=" * 60)
        playbook = self._build_playbook(target_host, tasks_yaml)
        playbook_str = yaml.dump([playbook], default_flow_style=False, sort_keys=False)
        print(f"Playbook ensamblado con {len(tasks_yaml)} tareas")

        print("\n" + "=" * 60)
        print("ETAPA 4: VALIDACIÓN DE SEGURIDAD IA")
        print("=" * 60)
        verdict, issues, summary = self.validator.validate(playbook_str)
        print(f"Veredicto: {verdict.value}")
        print(f"Resumen: {summary}")
        if issues:
            for issue in issues:
                print(f"  [{issue.severity.upper()}] L{issue.line_reference}: {issue.issue}")

        if verdict == Verdict.REJECTED:
            print("\n❌ PLAYBOOK RECHAZADO. No se ejecutará.")
            return {
                "status": "rejected",
                "verdict": verdict.value,
                "issues": [asdict(i) for i in issues],
                "summary": summary,
                "playbook": None,
                "rollback": None,
                "manual_findings": [asdict(f) for f in manual_findings]
            }

        print("\n" + "=" * 60)
        print("ETAPA 5: GENERACIÓN DE ROLLBACK")
        print("=" * 60)
        rollback_yaml = self.rollback_gen.generate(playbook_str)
        print("Rollback generado")

        # Guardar archivos
        os.makedirs("playbooks", exist_ok=True)

        pb_path = f"playbooks/hardening_{target_host}.yml"
        rb_path = f"playbooks/rollback_{target_host}.yml"

        with open(pb_path, "w") as f:
            f.write(playbook_str)
        with open(rb_path, "w") as f:
            f.write(rollback_yaml)

        print(f"\n✅ Playbook guardado: {pb_path}")
        print(f"✅ Rollback guardado: {rb_path}")

        return {
            "status": "approved" if verdict == Verdict.APPROVED else "approved_with_warnings",
            "verdict": verdict.value,
            "issues": [asdict(i) for i in issues],
            "summary": summary,
            "playbook_path": pb_path,
            "rollback_path": rb_path,
            "manual_findings": [asdict(f) for f in manual_findings]
        }

    def _build_playbook(self, target_host: str, tasks: List[str]) -> dict:
        """Ensambla un playbook Ansible estructurado."""
        parsed_tasks = []
        for task_str in tasks:
            try:
                parsed = yaml.safe_load(task_str)
                if isinstance(parsed, list):
                    parsed_tasks.extend(parsed)
                elif isinstance(parsed, dict):
                    parsed_tasks.append(parsed)
            except Exception:
                continue

        return {
            "name": f"Hardening automático para {target_host}",
            "hosts": target_host,
            "become": True,
            "gather_facts": True,
            "vars": {
                "cis_backup_dir": f"/var/backups/cis-hardening-{{{{ ansible_date_time.date }}}}",
                "cis_profile": "level1_server",
                "ansible_ssh_pipelining": True
            },
            "pre_tasks": [
                {
                    "name": "Validar compatibilidad del sistema operativo",
                    "ansible.builtin.fail": {
                        "msg": "Este playbook solo soporta Debian/Ubuntu y RHEL/CentOS"
                    },
                    "when": "ansible_os_family not in ['Debian', 'RedHat']"
                },
                {
                    "name": "Crear directorio de backups",
                    "ansible.builtin.file": {
                        "path": "{{ cis_backup_dir }}",
                        "state": "directory",
                        "mode": "0750"
                    }
                }
            ],
            "tasks": parsed_tasks,
            "post_tasks": [
                {
                    "name": "Verificar sintaxis de SSH si fue modificado",
                    "ansible.builtin.command": "sshd -t",
                    "changed_when": False,
                    "ignore_errors": True,
                    "when": "ansible_os_family in ['Debian', 'RedHat']"
                }
            ],
            "handlers": [
                {
                    "name": "restart sshd",
                    "ansible.builtin.service": {
                        "name": "sshd",
                        "state": "reloaded"
                    }
                }
            ]
        }


# =============================================================================
# EJEMPLO DE USO
# =============================================================================

if __name__ == "__main__":
    # Hallazgos de ejemplo (normalmente vienen de OpenSCAP/Nmap)
    sample_findings = [
        UnifiedFinding(
            source="openscap",
            rule_id="xccdf_org.ssgproject.content_rule_ensure_redhat_gpgkey_installed",
            severity=Severity.HIGH,
            title="Ensure Red Hat GPG Key Installed",
            description="The Red Hat GPG key must be installed to verify packages.",
            target="system",
            remediation_type=RemediationType.ANSIBLE_NATIVE,
            raw_evidence="fail"
        ),
        UnifiedFinding(
            source="nmap",
            rule_id="NMAP-INSECURE-TELNET",
            severity=Severity.CRITICAL,
            title="Servicio Telnet detectado",
            description="El puerto 23 está abierto ejecutando telnet. Protocolo inseguro.",
            target="192.168.56.101:23",
            remediation_type=RemediationType.ANSIBLE_NATIVE,
            raw_evidence="23/tcp open telnet"
        ),
        UnifiedFinding(
            source="openscap",
            rule_id="xccdf_org.ssgproject.content_rule_cramfs_disabled",
            severity=Severity.MEDIUM,
            title="Ensure mounting of cramfs filesystems is disabled",
            description="cramfs is an uncommon filesystem that could be used to hide malicious code.",
            target="/etc/modprobe.d",
            remediation_type=RemediationType.ANSIBLE_NATIVE,
            raw_evidence="fail"
        )
    ]

    pipeline = HardeningPipeline(openai_api_key=os.getenv("OPENAI_API_KEY"))
    result = pipeline.run(sample_findings, target_host="servidor_vulnerable")

    print("\n" + "=" * 60)
    print("RESULTADO FINAL")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))
