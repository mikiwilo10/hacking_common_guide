#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
oscap_parser.py
===============
Parser robusto de resultados OpenSCAP/XCCDF.

Objetivo:
- Leer un XML de resultados OpenSCAP/XCCDF.
- Identificar las reglas realmente evaluadas.
- Detectar reglas FAIL/WARN/ERROR.
- Relacionar cada rule-result con la definición de la regla cuando está disponible.
- Filtrar por severidad (por defecto: high y critical).
- Generar un JSON de alertas para la IA.
- Generar un JSON de métricas para evaluación del TFM.

Ejemplos:

    python3 oscap_parser.py \
        -i SCAN-results.xml \
        --rules-filename alertas.json \
        --metrics-filename stats.json

    python3 oscap_parser.py \
        -i SCAN-results.xml \
        -o ./resultados \
        --severity high critical

    python3 oscap_parser.py \
        -i SCAN-results.xml \
        -o ./resultados \
        --include-warn
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# NAMESPACES
# ---------------------------------------------------------------------------

XCCDF_NAMESPACES = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
}

XHTML_NS = "http://www.w3.org/1999/xhtml"


# ---------------------------------------------------------------------------
# UTILIDADES XML
# ---------------------------------------------------------------------------

def local_name(tag):
    """Devuelve el nombre local de un elemento XML."""
    return tag.split("}", 1)[-1]


def children_by_name(elem, name):
    """Busca hijos directos independientemente del namespace."""
    return [child for child in list(elem) if local_name(child.tag) == name]


def descendants_by_name(elem, name):
    """Busca descendientes independientemente del namespace."""
    return [
        child
        for child in elem.iter()
        if local_name(child.tag) == name
    ]


def first_child(elem, name):
    """Obtiene el primer hijo directo con determinado nombre."""
    for child in list(elem):
        if local_name(child.tag) == name:
            return child
    return None


def first_descendant(elem, name):
    """Obtiene el primer descendiente con determinado nombre."""
    for child in elem.iter():
        if local_name(child.tag) == name:
            return child
    return None


def element_text(elem, default="N/A"):
    """Obtiene todo el texto de un elemento."""
    if elem is None:
        return default

    text = "".join(elem.itertext()).strip()
    return text if text else default


def attr(elem, name, default=""):
    """Obtiene un atributo XML."""
    if elem is None:
        return default
    return elem.get(name, default)


def now_iso():
    """Fecha UTC en formato ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# REGLAS / BENCHMARK
# ---------------------------------------------------------------------------

def parse_rule(rule_elem):
    """Convierte una definición XCCDF Rule en un diccionario."""
    rule_id = attr(rule_elem, "id", "unknown")

    rule = {
        "id": rule_id,
        "severity": attr(rule_elem, "severity", "unknown").lower(),
        "title": element_text(first_child(rule_elem, "title")),
        "description": element_text(first_child(rule_elem, "description")),
        "rationale": element_text(first_child(rule_elem, "rationale")),
        "ident": [],
        "references": [],
        "checks": [],
        "fixes": [],
    }

    for ident in children_by_name(rule_elem, "ident"):
        rule["ident"].append({
            "system": attr(ident, "system"),
            "value": element_text(ident, ""),
        })

    for reference in children_by_name(rule_elem, "reference"):
        rule["references"].append({
            "href": attr(reference, "href"),
            "value": element_text(reference, ""),
        })

    for check in children_by_name(rule_elem, "check"):
        check_data = {
            "system": attr(check, "system"),
            "content": [],
        }

        for ref in descendants_by_name(check, "check-content-ref"):
            check_data["content"].append({
                "name": attr(ref, "name"),
                "href": attr(ref, "href"),
            })

        rule["checks"].append(check_data)

    for fix in children_by_name(rule_elem, "fix"):
        rule["fixes"].append({
            "system": attr(fix, "system"),
            "id": attr(fix, "id"),
            "content": element_text(fix, ""),
        })

    return rule


def extract_rule_definitions(root):
    """
    Extrae las definiciones Rule del XML.

    Algunos resultados OpenSCAP contienen el Benchmark completo y otros
    pueden contener únicamente los resultados. Por eso se devuelve lo que
    esté disponible sin asumir una estructura concreta.
    """
    rules = {}

    for elem in descendants_by_name(root, "Rule"):
        rule_id = attr(elem, "id")
        if rule_id:
            rules[rule_id] = parse_rule(elem)

    return rules


# ---------------------------------------------------------------------------
# RESULTADOS XCCDF
# ---------------------------------------------------------------------------

VALID_RESULTS = {
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "notchecked",
    "notselected",
    "informational",
    "fixed",
    "notperformed",
    "notimplemented",
    "new",
    "old",
}


def normalize_result(value):
    """Normaliza el resultado XCCDF."""
    value = (value or "unknown").strip().lower()

    aliases = {
        "not-applicable": "notapplicable",
        "not_applicable": "notapplicable",
        "not-checked": "notchecked",
        "not_checked": "notchecked",
        "not-selected": "notselected",
        "not_selected": "notselected",
        "not-performed": "notperformed",
        "not_performed": "notperformed",
    }

    return aliases.get(value, value)


def extract_rule_results(root):
    """
    Extrae los elementos Rule-result de los TestResult.

    Devuelve:
        {
            rule_id: {
                "result": "fail",
                "time": "...",
                "severity": "...",
                ...
            }
        }
    """
    results = {}

    for rule_result in descendants_by_name(root, "rule-result"):
        rule_id = attr(rule_result, "idref")

        if not rule_id:
            continue

        result_elem = first_child(rule_result, "result")

        result = normalize_result(element_text(result_elem, "unknown"))

        results[rule_id] = {
            "id": rule_id,
            "result": result,
            "time": attr(rule_result, "time"),
            "version": attr(rule_result, "version"),
            "role": attr(rule_result, "role"),
        }

    return results


def extract_test_results(root):
    """Extrae información general de los TestResult."""
    test_results = []

    for test_result in descendants_by_name(root, "TestResult"):
        test_results.append({
            "id": attr(test_result, "id"),
            "start_time": attr(test_result, "start-time"),
            "end_time": attr(test_result, "end-time"),
            "test_system": attr(test_result, "test-system"),
            "benchmark_ref": attr(test_result, "benchmark-ref"),
            "profile": attr(test_result, "profile"),
            "version": attr(test_result, "version"),
        })

    return test_results


# ---------------------------------------------------------------------------
# CONSTRUCCIÓN DE ALERTAS
# ---------------------------------------------------------------------------

def build_alerts(rule_definitions, rule_results, severities, include_warn=False):
    """
    Construye las alertas reales del escaneo.

    Importante:
    No devuelve simplemente todas las reglas high/critical del benchmark.
    Solo incluye reglas que aparecen en los resultados del escaneo y cuyo
    resultado representa un incumplimiento.
    """

    failing_results = {"fail", "error"}

    if include_warn:
        failing_results.add("unknown")

    alerts = []

    for rule_id, result_data in rule_results.items():

        result = result_data["result"]

        if result not in failing_results:
            continue

        definition = rule_definitions.get(rule_id, {})

        severity = definition.get(
            "severity",
            result_data.get("severity", "unknown")
        ).lower()

        # Si no conocemos la severidad, conservamos la alerta solamente
        # cuando el usuario haya solicitado unknown.
        if severity not in severities:
            continue

        alert = {
            "rule_id": rule_id,
            "result": result,
            "severity": severity,
            "title": definition.get("title", "N/A"),
            "description": definition.get("description", "N/A"),
            "rationale": definition.get("rationale", "N/A"),
            "ident": definition.get("ident", []),
            "references": definition.get("references", []),
            "checks": definition.get("checks", []),
            "fixes": definition.get("fixes", []),
            "evaluation": {
                "time": result_data.get("time", ""),
                "version": result_data.get("version", ""),
                "role": result_data.get("role", ""),
            },
        }

        alerts.append(alert)

    severity_order = {
        severity: index for index, severity in enumerate(severities)
    }

    alerts.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 999),
            item["rule_id"],
        )
    )

    return alerts


# ---------------------------------------------------------------------------
# METRICAS
# ---------------------------------------------------------------------------

def build_metrics(
    rule_definitions,
    rule_results,
    alerts,
    test_results,
    root,
):
    """Construye las métricas del escaneo."""

    result_distribution = Counter(
        data["result"] for data in rule_results.values()
    )

    severity_distribution = Counter()

    for rule_id, result_data in rule_results.items():
        definition = rule_definitions.get(rule_id, {})
        severity = definition.get("severity", "unknown").lower()
        severity_distribution[severity] += 1

    failed_rules = [
        rule_id
        for rule_id, data in rule_results.items()
        if data["result"] == "fail"
    ]

    error_rules = [
        rule_id
        for rule_id, data in rule_results.items()
        if data["result"] == "error"
    ]

    passed_rules = [
        rule_id
        for rule_id, data in rule_results.items()
        if data["result"] == "pass"
    ]

    rules_without_definition = [
        rule_id
        for rule_id in rule_results
        if rule_id not in rule_definitions
    ]

    rules_without_checks = [
        rule_id
        for rule_id, rule in rule_definitions.items()
        if len(rule.get("checks", [])) == 0
    ]

    rules_with_fixes = [
        rule_id
        for rule_id, rule in rule_definitions.items()
        if len(rule.get("fixes", [])) > 0
    ]

    total_evaluated = len(rule_results)
    total_fail = len(failed_rules)

    compliance_percentage = (
        round((len(passed_rules) / total_evaluated) * 100, 2)
        if total_evaluated
        else 0.0
    )

    failure_percentage = (
        round((total_fail / total_evaluated) * 100, 2)
        if total_evaluated
        else 0.0
    )

    # Grupos XCCDF
    group_counts = defaultdict(int)

    for group in descendants_by_name(root, "Group"):
        title = element_text(first_child(group, "title"), "")
        rules = children_by_name(group, "Rule")

        if title and rules:
            group_counts[title] += len(rules)

    top_groups = dict(
        sorted(
            group_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:15]
    )

    return {
        "metadata": {
            "fecha_generacion": now_iso(),
            "herramienta": "oscap_parser.py",
            "version_parser": "2.0",
            "benchmark_id": attr(root, "id", "unknown"),
            "benchmark_version": element_text(
                first_child(root, "version"),
                "unknown",
            ),
            "total_reglas_definidas": len(rule_definitions),
            "total_reglas_evaluadas": total_evaluated,
            "total_alertas": len(alerts),
            "total_test_results": len(test_results),
        },
        "resultados": {
            "distribucion": dict(result_distribution),
            "pass": len(passed_rules),
            "fail": len(failed_rules),
            "error": len(error_rules),
        },
        "cumplimiento": {
            "porcentaje_pass": compliance_percentage,
            "porcentaje_fail": failure_percentage,
        },
        "severidad": dict(severity_distribution),
        "riesgo": {
            "critical": sum(
                1 for a in alerts if a["severity"] == "critical"
            ),
            "high": sum(
                1 for a in alerts if a["severity"] == "high"
            ),
            "medium": sum(
                1 for a in alerts if a["severity"] == "medium"
            ),
            "low": sum(
                1 for a in alerts if a["severity"] == "low"
            ),
            "unknown": sum(
                1 for a in alerts if a["severity"] == "unknown"
            ),
        },
        "calidad_datos": {
            "reglas_sin_definicion": len(rules_without_definition),
            "reglas_sin_checks": len(rules_without_checks),
            "reglas_con_remediacion": len(rules_with_fixes),
        },
        "reglas_sin_definicion": rules_without_definition,
        "top_grupos": top_groups,
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def build_alerts_json(
    root,
    alerts,
    rule_definitions,
    rule_results,
    severities,
):
    """Construye el JSON destinado al procesamiento por IA."""

    return {
        "metadata": {
            "fecha_generacion": now_iso(),
            "herramienta": "oscap_parser.py",
            "version_parser": "2.0",
            "benchmark_id": attr(root, "id", "unknown"),
            "severidades_incluidas": severities,
            "total_reglas_definidas": len(rule_definitions),
            "total_reglas_evaluadas": len(rule_results),
            "total_alertas": len(alerts),
        },
        "instrucciones_contexto": {
            "descripcion": (
                "Estas son reglas que resultaron en FAIL o ERROR durante "
                "el escaneo OpenSCAP y cuya severidad coincide con el filtro."
            ),
            "uso_recomendado": (
                "Utilizar este JSON como contexto técnico para analizar "
                "incumplimientos CIS y generar remediaciones."
            ),
        },
        "reglas": alerts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Parser de resultados OpenSCAP/XCCDF para generar "
            "alertas y métricas JSON."
        )
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Archivo XML generado por OpenSCAP.",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="./resultados",
        help="Directorio de salida.",
    )

    parser.add_argument(
        "-s",
        "--severity",
        nargs="+",
        default=["high", "critical"],
        help="Severidades a incluir. Default: high critical.",
    )

    parser.add_argument(
        "--rules-filename",
        default="alertas.json",
        help="Nombre del JSON de alertas.",
    )

    parser.add_argument(
        "--metrics-filename",
        default="stats.json",
        help="Nombre del JSON de métricas.",
    )

    parser.add_argument(
        "--include-warn",
        action="store_true",
        help="Incluye resultados UNKNOWN como alertas.",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Genera JSON indentado.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        print(
            f"[ERROR] El archivo XML no existe: {input_path}",
            file=sys.stderr,
        )
        return 1

    if not input_path.is_file():
        print(
            f"[ERROR] La ruta no es un archivo: {input_path}",
            file=sys.stderr,
        )
        return 1

    output_dir = Path(args.output_dir)

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(
            f"[ERROR] No se pudo crear el directorio de salida: {exc}",
            file=sys.stderr,
        )
        return 1

    severities = {
        severity.lower()
        for severity in args.severity
    }

    print("=" * 70)
    print("OPENSCAP / XCCDF PARSER")
    print("=" * 70)
    print(f"[*] XML       : {input_path}")
    print(f"[*] Salida    : {output_dir}")
    print(f"[*] Severidad : {', '.join(sorted(severities))}")
    print()

    # -----------------------------------------------------------------------
    # Cargar XML
    # -----------------------------------------------------------------------

    try:
        tree = ET.parse(input_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        print(
            f"[ERROR] XML inválido: {exc}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(
            f"[ERROR] No se pudo leer el XML: {exc}",
            file=sys.stderr,
        )
        return 1

    print(f"[*] Root XML: {root.tag}")

    # -----------------------------------------------------------------------
    # Extraer información
    # -----------------------------------------------------------------------

    rule_definitions = extract_rule_definitions(root)
    rule_results = extract_rule_results(root)
    test_results = extract_test_results(root)

    print(
        f"[*] Definiciones de reglas : {len(rule_definitions)}"
    )
    print(
        f"[*] Reglas evaluadas       : {len(rule_results)}"
    )
    print(
        f"[*] TestResult encontrados : {len(test_results)}"
    )

    if not rule_results:
        print()
        print(
            "[WARN] No se encontraron elementos <rule-result>."
        )
        print(
            "[WARN] Verifica que el XML sea un resultado XCCDF "
            "generado por OpenSCAP."
        )

    # -----------------------------------------------------------------------
    # Generar alertas
    # -----------------------------------------------------------------------

    alerts = build_alerts(
        rule_definitions=rule_definitions,
        rule_results=rule_results,
        severities=severities,
        include_warn=args.include_warn,
    )

    print(f"[*] Alertas encontradas     : {len(alerts)}")

    # -----------------------------------------------------------------------
    # JSON alertas
    # -----------------------------------------------------------------------

    alerts_data = build_alerts_json(
        root=root,
        alerts=alerts,
        rule_definitions=rule_definitions,
        rule_results=rule_results,
        severities=sorted(severities),
    )

    alerts_path = output_dir / args.rules_filename

    try:
        with alerts_path.open("w", encoding="utf-8") as file:
            json.dump(
                alerts_data,
                file,
                indent=2 if args.pretty else None,
                ensure_ascii=False,
            )
    except OSError as exc:
        print(
            f"[ERROR] No se pudo escribir {alerts_path}: {exc}",
            file=sys.stderr,
        )
        return 1

    # -----------------------------------------------------------------------
    # JSON métricas
    # -----------------------------------------------------------------------

    metrics_data = build_metrics(
        rule_definitions=rule_definitions,
        rule_results=rule_results,
        alerts=alerts,
        test_results=test_results,
        root=root,
    )

    metrics_path = output_dir / args.metrics_filename

    try:
        with metrics_path.open("w", encoding="utf-8") as file:
            json.dump(
                metrics_data,
                file,
                indent=2 if args.pretty else None,
                ensure_ascii=False,
            )
    except OSError as exc:
        print(
            f"[ERROR] No se pudo escribir {metrics_path}: {exc}",
            file=sys.stderr,
        )
        return 1

    # -----------------------------------------------------------------------
    # Resumen
    # -----------------------------------------------------------------------

    result_distribution = Counter(
        data["result"] for data in rule_results.values()
    )

    print()
    print("=" * 70)
    print("RESUMEN DEL ESCANEO")
    print("=" * 70)

    for result, count in sorted(
        result_distribution.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        percentage = (
            round((count / len(rule_results)) * 100, 1)
            if rule_results
            else 0
        )

        print(
            f"  {result:16s}: {count:5d} ({percentage:5.1f}%)"
        )

    print()
    print(f"  Alertas high/critical : {len(alerts)}")
    print()
    print(f"[OK] Alertas : {alerts_path}")
    print(f"[OK] Métricas : {metrics_path}")
    print("=" * 70)
    print("Proceso finalizado correctamente.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
