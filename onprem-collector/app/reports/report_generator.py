"""
Deterministic Panama Ley 81 / DE 285 / Acuerdo 001-2022 SBP / Ley 68 Risk Engine,
Executive PDF/HTML Compiler (WeasyPrint with clean HTML fallback), and Ficha Técnica JSON generator.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import BaseLoader, Environment

try:
    from weasyprint import HTML

    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False


def get_regulatory_context(regulatory_profile: str = "ANTAI_LEY81") -> Dict[str, Any]:
    """Return accurate Panama regulatory metadata for ANTAI_LEY81, SBP_001_2022, or SALUD_LEY68."""
    profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
    sanctions = [
        "Multas administrativas de B/. 1,000 a B/. 10,000 según gravedad (Ley 81 de 2019)",
        "Clausura temporal o definitiva de los registros o bases de datos personales",
        "Publicación de sanciones firmes impuestas por la ANTAI",
        "Imprescriptibilidad de las faltas muy graves y agravantes por reincidencia",
        "Notificación obligatoria de brechas dentro de 72 horas con 5 elementos mínimos (DE 285 Art. 37 y Art. 48.3)",
    ]

    if profile == "SBP_001_2022":
        return {
            "profile": "SBP_001_2022",
            "framework_title": "Acuerdo 001-2022 SBP + Ley 81 de 2019 y DE 285 de 2021",
            "regulator": "Superintendencia de Bancos de Panamá (SBP) & ANTAI",
            "fine_range_pab": "B/. 1,000 a B/. 10,000 (ANTAI) + medidas prudenciales Acuerdo 001-2022 SBP",
            "retention_rule": "Retención máxima general de 7 años (2555 días) salvo obligación legal específica",
            "sanctions": sanctions,
        }

    if profile == "SALUD_LEY68":
        return {
            "profile": "SALUD_LEY68",
            "framework_title": "Ley 68 de 2003 (Expediente Clínico) + Ley 81 de 2019 y DE 285 de 2021",
            "regulator": "MINSA / CSS & ANTAI",
            "fine_range_pab": "B/. 1,000 a B/. 10,000 (ANTAI por datos sensibles de salud)",
            "retention_rule": (
                "Conservación mínima obligatoria de 20 años post-mortem para expedientes clínicos "
                "(Ley 68 de 2003, con trazabilidad / audit trail); registros no clínicos > 7 años se marcan para depuración"
            ),
            "sanctions": sanctions,
        }

    return {
        "profile": "ANTAI_LEY81",
        "framework_title": "Ley 81 de 2019 de Protección de Datos Personales y Decreto Ejecutivo 285 de 2021",
        "regulator": "Autoridad Nacional de Transparencia y Acceso a la Información (ANTAI)",
        "fine_range_pab": "B/. 1,000 a B/. 10,000",
        "retention_rule": "Retención máxima general de 7 años (2555 días) tras cumplir la finalidad del tratamiento",
        "sanctions": sanctions,
    }


def calculate_ley81_risk_score(
    total_shadow_ai_hits: int,
    unique_ai_domains_count: int,
    smb_pii_files_count: int,
    smb_guest_allowed: bool,
    box_unprotected_files_count: int,
    all_urls_extensions_count: int,
    audited_endpoints_count: int,
    adguard_live_hits: int = 0,
    db_findings_count: int = 0,
    db_sensitive_findings_count: int = 0,
    retention_violations_count: int = 0,
    regulatory_profile: str = "ANTAI_LEY81",
    dpo_registered: bool = False,
) -> Dict[str, Any]:
    """
    Deterministic Ley 81 / DE 285 / SBP 001-2022 / Ley 68 risk score (0-100)
    integrating AdGuard DNS, Endpoints, SMB, SQL DB findings, and retention violations.
    """
    profile = (regulatory_profile or "ANTAI_LEY81").strip().upper()
    reg_ctx = get_regulatory_context(profile)

    # 1. Shadow AI vector (40%): combines endpoint DNS cache + AdGuard live DNS hits
    effective_shadow_hits = max(total_shadow_ai_hits, adguard_live_hits) + (
        min(total_shadow_ai_hits, adguard_live_hits) // 2
    )
    hit_factor = min(70.0, effective_shadow_hits * 1.4)
    domain_factor = min(30.0, unique_ai_domains_count * 5.0)
    shadow_ai_subscore = round(min(100.0, hit_factor + domain_factor), 1)

    # 2. Storage, SQL DB & Retention vector (30%)
    smb_factor = min(40.0, smb_pii_files_count * 6.0)
    guest_penalty = 15.0 if smb_guest_allowed and smb_pii_files_count > 0 else 0.0
    box_factor = min(20.0, box_unprotected_files_count * 1.5)
    db_factor = min(25.0, (db_findings_count * 5.0) + (db_sensitive_findings_count * 6.0))
    retention_factor = min(20.0, retention_violations_count * 8.0)
    storage_exposure_subscore = round(
        min(100.0, smb_factor + guest_penalty + box_factor + db_factor + retention_factor),
        1,
    )

    # 3. Browser <all_urls> extensions & governance vector (30%)
    ext_density = all_urls_extensions_count * 18.0
    ext_ratio_bonus = (
        min(28.0, (all_urls_extensions_count / max(1, audited_endpoints_count)) * 20.0)
        if audited_endpoints_count > 0
        else 0.0
    )
    dpo_penalty = 0.0 if dpo_registered else 10.0
    extensions_subscore = round(min(100.0, ext_density + ext_ratio_bonus + dpo_penalty), 1)

    weighted_score = round(
        (shadow_ai_subscore * 0.40)
        + (storage_exposure_subscore * 0.30)
        + (extensions_subscore * 0.30),
        1,
    )

    if weighted_score >= 70:
        semaphore = "ROJO"
        semaphore_color = "#dc2626"
        compliance_level = "INCUMPLIMIENTO CRÍTICO - RIESGO INMINENTE DE SANCIÓN ANTAI"
        legal_exposure_range = (
            "Multas de B/. 1,000 a B/. 10,000, clausura temporal o definitiva de registros, "
            "publicación de sanciones ANTAI e imprescriptibilidad de faltas muy graves"
        )
    elif weighted_score >= 40:
        semaphore = "AMARILLO"
        semaphore_color = "#d97706"
        compliance_level = "CUMPLIMIENTO PARCIAL - BRECHAS EN TRANSFERENCIA, CUSTODIA Y RETENCIÓN"
        legal_exposure_range = (
            "Multas de B/. 1,000 a B/. 10,000 por incumplimiento de medidas técnicas de custodia, "
            "DPO o transferencias internacionales (Ley 81 Arts. 25, 32-33, 41.4 y 45)"
        )
    else:
        semaphore = "VERDE"
        semaphore_color = "#16a34a"
        compliance_level = "RIESGO CONTROLADO - HIGIENE DE DATOS Y GOBERNANZA ACTIVA"
        legal_exposure_range = (
            "Exposición sancionatoria baja (escala B/. 1,000 a B/. 10,000); mantener monitoreo "
            "continuo, Ficha Técnica actualizada y bitácoras de auditoría"
        )

    legal_conclusions: List[Dict[str, str]] = []

    if shadow_ai_subscore >= 25:
        legal_conclusions.append(
            {
                "articulo": "Ley 81 Arts. 25, 32-33 y 41.4 (Transferencias Internacionales y Tratamiento en Nube Pública)",
                "severidad": "CRÍTICA" if shadow_ai_subscore >= 65 else "ALTA",
                "hallazgo": (
                    f"Se detectaron {effective_shadow_hits} eventos DNS/Shadow AI hacia "
                    f"{unique_ai_domains_count} plataformas públicas de IA ({adguard_live_hits} vía AdGuard DNS)."
                ),
                "dictamen": (
                    "El envío de datos personales hacia servicios externos sin contrato DPA ni validación Edge DLP "
                    "vulnera las reglas de transferencia internacional (Ley 81 Arts. 32-33) y expone a sanciones de "
                    "B/. 1,000 a B/. 10,000 más publicación de sanciones ANTAI."
                ),
            }
        )

    if storage_exposure_subscore >= 20 or retention_violations_count > 0:
        ret_note = (
            " bajo Ley 68 de 2003 (conservación mínima de 20 años post-mortem en expedientes clínicos con audit trail; "
            "datos no clínicos > 7 años marcados para depuración)."
            if profile == "SALUD_LEY68"
            else " (límite general de 7 años / 2555 días bajo Ley 81 y DE 285)."
        )
        legal_conclusions.append(
            {
                "articulo": (
                    "Acuerdo 001-2022 SBP + Ley 81 Art. 41.4 y DE 285 (Custodia, Bases SQL y Retención)"
                    if profile == "SBP_001_2022"
                    else "Ley 68 de 2003 + Ley 81 Arts. 25 y 41.4 (Custodia de Repositorios, SQL y Retención)"
                    if profile == "SALUD_LEY68"
                    else "Ley 81 Arts. 25, 32-33 y 41.4; DE 285 (Custodia en Repositorios SMB/SQL y Retención)"
                ),
                "severidad": "CRÍTICA"
                if (smb_guest_allowed or db_sensitive_findings_count > 0 or retention_violations_count > 0)
                else "ALTA",
                "hallazgo": (
                    f"SMB: {smb_pii_files_count} archivos con PII; SQL DB: {db_findings_count} grupos de hallazgos "
                    f"({db_sensitive_findings_count} sensibles); Box sin DLP: {box_unprotected_files_count}; "
                    f"violaciones de retención: {retention_violations_count}{ret_note}"
                ),
                "dictamen": (
                    "La exposición de datos personales en repositorios internos o bases SQL sin segmentación ni "
                    "depuración oportuna conlleva riesgo de clausura de registros y sanciones de B/. 1,000 a B/. 10,000."
                ),
            }
        )

    if extensions_subscore >= 20:
        legal_conclusions.append(
            {
                "articulo": "DE 285 Art. 37 y Art. 48.3 (Notificación de Brechas en 72h) + Ley 81 Arts. 15-16 (ARCO-P)",
                "severidad": "ALTA",
                "hallazgo": (
                    f"Se identificaron {all_urls_extensions_count} extensiones de navegador con permisos <all_urls> "
                    "capaces de capturar formularios y documentos en sesión."
                ),
                "dictamen": (
                    "Un incidente de exfiltración exige notificación obligatoria ante ANTAI y titulares dentro de "
                    "72 horas con los 5 elementos del DE 285 Art. 37 (qué ocurrió, datos comprometidos, medidas adoptadas, "
                    "acciones para titulares y punto de contacto), manteniendo atención ARCO-P en 10 días hábiles "
                    "(Acceso/Portabilidad) y 5 días hábiles (Rectificación/Cancelación/Oposición)."
                ),
            }
        )

    if not dpo_registered:
        legal_conclusions.append(
            {
                "articulo": "Ley 81 Art. 45 / DE 285 Arts. 43, 44 y 47 (Oficial de Protección de Datos - DPO)",
                "severidad": "MEDIA",
                "hallazgo": "No consta registro formal de DPO ante ANTAI en la configuración local del colector.",
                "dictamen": (
                    "Se requiere designar y registrar al Oficial de Protección de Datos (DPO) conforme a la Ley 81 Art. 45 "
                    "y DE 285 Arts. 43, 44 y 47 para supervisar brechas de 72h, solicitudes ARCO-P y Ficha Técnica."
                ),
            }
        )

    if not legal_conclusions:
        legal_conclusions.append(
            {
                "articulo": "Ley 81 Art. 45 / DE 285 Arts. 43, 44 y 47 (Responsabilidad Proactiva)",
                "severidad": "BAJA",
                "hallazgo": "No se detectaron vectores críticos de exposición o exfiltración en el corte actual.",
                "dictamen": (
                    "Mantener la arquitectura híbrida Cloudflare Zero Trust + Collector On-Premise y actualizar "
                    "periódicamente la Ficha Técnica con verificación SHA-256."
                ),
            }
        )

    return {
        "total_score": weighted_score,
        "semaphore": semaphore,
        "semaphore_color": semaphore_color,
        "compliance_level": compliance_level,
        "legal_exposure_range": legal_exposure_range,
        "regulatory_profile": profile,
        "regulatory_context": reg_ctx,
        "breakdown": {
            "shadow_ai_subscore": shadow_ai_subscore,
            "shadow_ai_weighted": round(shadow_ai_subscore * 0.40, 1),
            "storage_exposure_subscore": storage_exposure_subscore,
            "storage_exposure_weighted": round(storage_exposure_subscore * 0.30, 1),
            "extensions_subscore": extensions_subscore,
            "extensions_weighted": round(extensions_subscore * 0.30, 1),
            "adguard_live_hits": adguard_live_hits,
            "db_findings_count": db_findings_count,
            "retention_violations_count": retention_violations_count,
        },
        "legal_conclusions": legal_conclusions,
    }


REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe Ejecutivo Ley 81 Panamá &amp; Arquitectura Híbrida - Vektor81</title>
    <style>
        @page {
            size: A4;
            margin: 18mm 16mm 18mm 16mm;
            @bottom-right {
                content: "Página " counter(page) " de " counter(pages);
                font-family: 'DejaVu Sans', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }
            @bottom-left {
                content: "CONFIDENCIAL — AUDITORÍA LEY 81 / DE 285 PANAMÁ (VEKTOR81)";
                font-family: 'DejaVu Sans', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'DejaVu Sans', Arial, sans-serif;
            color: #0f172a;
            line-height: 1.45;
            font-size: 9.5pt;
            margin: 0;
            padding: 0;
        }
        .cover-banner {
            background: #0f172a;
            color: #f8fafc;
            padding: 22px 26px;
            border-radius: 8px;
            border-left: 8px solid {{ risk.semaphore_color }};
            margin-bottom: 16px;
        }
        .cover-tag {
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 1.4px;
            color: #38bdf8;
            font-weight: bold;
            margin-bottom: 6px;
        }
        .cover-title { font-size: 19pt; font-weight: 800; margin: 0 0 6px 0; }
        .cover-subtitle { font-size: 9.5pt; color: #cbd5e1; margin: 0; }
        .score-box {
            display: table;
            width: 100%;
            margin-bottom: 16px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            background: #f8fafc;
            padding: 14px;
        }
        .score-left {
            display: table-cell;
            width: 32%;
            vertical-align: middle;
            text-align: center;
            border-right: 1px solid #cbd5e1;
            padding-right: 12px;
        }
        .score-right {
            display: table-cell;
            width: 68%;
            vertical-align: middle;
            padding-left: 16px;
        }
        .score-number { font-size: 32pt; font-weight: 900; color: {{ risk.semaphore_color }}; }
        .semaphore-badge {
            display: inline-block;
            margin-top: 6px;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 8.5pt;
            font-weight: bold;
            color: #ffffff;
            background-color: {{ risk.semaphore_color }};
        }
        .section-title {
            font-size: 12pt;
            font-weight: 800;
            color: #0f172a;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 4px;
            margin-top: 16px;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        table { width: 100%; border-collapse: collapse; margin-bottom: 12px; font-size: 8.5pt; }
        th { background-color: #1e293b; color: #ffffff; text-align: left; padding: 6px 8px; }
        td { padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
        tr:nth-child(even) td { background-color: #f8fafc; }
        .card {
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 10px 12px;
            margin-bottom: 10px;
            background: #ffffff;
        }
        .badge-crit { color: #991b1b; background: #fee2e2; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 7.5pt; }
        .badge-high { color: #92400e; background: #fef3c7; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 7.5pt; }
        .roadmap-phase {
            border-left: 4px solid #0284c7;
            background: #f0f9ff;
            padding: 10px 14px;
            margin-bottom: 10px;
            border-radius: 0 6px 6px 0;
        }
    </style>
</head>
<body>
    <div class="cover-banner">
        <div class="cover-tag">Auditoría Híbrida de Gobernanza IA &amp; Protección de Datos Personales</div>
        <h1 class="cover-title">INFORME EJECUTIVO: SHADOW AI &amp; CUMPLIMIENTO LEY 81 (PANAMÁ)</h1>
        <p class="cover-subtitle">
            Perfil Regulatorio: {{ risk.regulatory_context.framework_title }} | Generado UTC: {{ generated_at }}
        </p>
    </div>

    <div class="score-box">
        <div class="score-left">
            <div style="font-size: 8.5pt; font-weight: bold; color: #475569;">SCORE DE RIESGO LEY 81</div>
            <div class="score-number">{{ risk.total_score }}<span style="font-size: 14pt; color: #64748b;">/100</span></div>
            <div class="semaphore-badge">SEMÁFORO: {{ risk.semaphore }}</div>
        </div>
        <div class="score-right">
            <div style="font-weight: 800; font-size: 10pt; margin-bottom: 4px;">{{ risk.compliance_level }}</div>
            <p style="margin: 0 0 6px 0; font-size: 8.5pt; color: #334155;">
                <strong>Exposición Regulatoria ({{ risk.regulatory_context.regulator }}):</strong> {{ risk.legal_exposure_range }}
            </p>
            <table style="margin-bottom: 0; font-size: 8pt;">
                <thead>
                    <tr><th>Vector</th><th>Peso</th><th>Sub-Score</th><th>Aporte</th></tr>
                </thead>
                <tbody>
                    <tr><td>1. Shadow AI (AdGuard DNS + Endpoints)</td><td>40%</td><td>{{ risk.breakdown.shadow_ai_subscore }}/100</td><td><strong>{{ risk.breakdown.shadow_ai_weighted }} pts</strong></td></tr>
                    <tr><td>2. Exposición SMB / SQL DB / Box / Retención</td><td>30%</td><td>{{ risk.breakdown.storage_exposure_subscore }}/100</td><td><strong>{{ risk.breakdown.storage_exposure_weighted }} pts</strong></td></tr>
                    <tr><td>3. Extensiones &lt;all_urls&gt; &amp; Gobernanza DPO</td><td>30%</td><td>{{ risk.breakdown.extensions_subscore }}/100</td><td><strong>{{ risk.breakdown.extensions_weighted }} pts</strong></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="section-title">1. Dictamen Normativo (Ley 81, DE 285, Acuerdo 001-2022 SBP y Ley 68 de 2003)</div>
    <div class="card">
        <strong>Marco de Referencia y Sanciones Aplicables:</strong>
        <ul style="margin: 4px 0 0 0; padding-left: 18px; font-size: 8.5pt;">
            <li><strong>Régimen Sancionatorio:</strong> Multas de <strong>B/. 1,000 a B/. 10,000</strong>, clausura de registros, publicación de sanciones ANTAI e imprescriptibilidad de faltas muy graves.</li>
            <li><strong>Notificación de Brechas (72h):</strong> Obligatoria ante ANTAI y titulares conforme al <strong>DE 285 Art. 37 y Art. 48.3</strong> (5 elementos: naturaleza del incidente, datos comprometidos, medidas adoptadas, acciones para titulares y punto de contacto).</li>
            <li><strong>Derechos ARCO-P y DPO:</strong> Atención en 10 días hábiles (Acceso/Portabilidad) y 5 días hábiles (Rectificación/Cancelación/Oposición) según <strong>Ley 81 Arts. 15-16</strong>; Oficial de Protección de Datos (DPO) conforme a <strong>Ley 81 Art. 45 / DE 285 Arts. 43, 44, 47</strong>.</li>
            <li><strong>Transferencias y Retención:</strong> Control de transferencias internacionales y custodia local bajo <strong>Ley 81 Arts. 25, 32-33, 41.4</strong>; ciberseguridad bancaria bajo <strong>Acuerdo 001-2022 SBP</strong>; retención clínica mínima de <strong>20 años post-mortem con audit trail</strong> bajo <strong>Ley 68 de 2003</strong>.</li>
        </ul>
    </div>
    {% for item in risk.legal_conclusions %}
    <div class="card">
        <div style="margin-bottom: 4px;">
            <span class="{% if item.severidad == 'CRÍTICA' %}badge-crit{% else %}badge-high{% endif %}">{{ item.severidad }}</span>
            <strong style="margin-left: 6px; font-size: 9.5pt;">{{ item.articulo }}</strong>
        </div>
        <div style="font-size: 8.6pt; margin-bottom: 3px;"><strong>Hallazgo Técnico:</strong> {{ item.hallazgo }}</div>
        <div style="font-size: 8.6pt; color: #334155;"><strong>Conclusión Legal:</strong> {{ item.dictamen }}</div>
    </div>
    {% endfor %}

    <div class="section-title">2. Inventario de Endpoints, Shadow AI y Extensiones &lt;all_urls&gt;</div>
    <table>
        <thead>
            <tr><th>Hostname</th><th>Usuario</th><th>Hits DNS IA</th><th>Ext. &lt;all_urls&gt;</th><th>Archivos Box</th><th>DLP Box</th></tr>
        </thead>
        <tbody>
            {% for ep in endpoints %}
            <tr>
                <td><strong>{{ ep.hostname }}</strong></td>
                <td>{{ ep.username }}</td>
                <td>{{ ep.dns_hits_count }}</td>
                <td>{{ ep.risky_extensions_count }}</td>
                <td>{{ ep.box_exposed_files }}</td>
                <td>{% if ep.box_dlp_active %}ACTIVO{% else %}<span class="badge-crit">SIN DLP</span>{% endif %}</td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="text-align:center;">Sin endpoints registrados en el corte actual.</td></tr>
            {% endfor %}
        </tbody>
    </table>

    {% if top_ai_domains %}
    <table>
        <thead><tr><th>Dominio IA / Cloud</th><th>Categoría</th><th>Eventos</th></tr></thead>
        <tbody>
            {% for dom in top_ai_domains %}
            <tr><td><strong>{{ dom.domain }}</strong></td><td>{{ dom.category }}</td><td>{{ dom.count }}</td></tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <div class="section-title">3. Exposición PII en Windows Server (SMB), Bases SQL y Retención</div>
    {% if latest_smb %}
    <div class="card">
        <strong>Servidor SMB:</strong> {{ latest_smb.server_name }} ({{ latest_smb.target_ip }}) |
        <strong>Simulado:</strong> {{ 'Sí' if latest_smb.is_simulated else 'No (En vivo)' }} |
        <strong>Archivos con PII:</strong> {{ latest_smb.files_with_pii_count }} |
        <strong>Violaciones de Retención:</strong> {{ latest_smb.retention_violations_count | default(0) }}
    </div>
    {% endif %}
    {% if latest_db %}
    <div class="card">
        <strong>Base de Datos SQL:</strong> {{ latest_db.target_label }} ({{ latest_db.db_type }}) |
        <strong>Tablas Escaneadas:</strong> {{ latest_db.tables_scanned }} |
        <strong>Hallazgos Enmascarados:</strong> {{ latest_db.findings_count }} |
        <strong>Violaciones de Retención:</strong> {{ latest_db.retention_violations_count }}
    </div>
    {% endif %}
    {% if not latest_smb and not latest_db %}
    <div class="card">No se han ejecutado escaneos SMB o SQL en este corte.</div>
    {% endif %}

    <div class="section-title">4. Hoja de Ruta: Arquitectura Híbrida Cloudflare Zero Trust + Collector On-Premise</div>
    <div class="roadmap-phase">
        <strong>Fase 1 (0 - 15 Días): Contención Perimetral y Depuración de Retención</strong>
        <ul style="margin: 4px 0 0 0; padding-left: 18px;">
            <li>Activar políticas DNS en AdGuard Home y Cloudflare Gateway para bloquear convertidores PDF públicos y plataformas Shadow AI sin DPA.</li>
            <li>Revocar vía GPO extensiones con permiso <code>&lt;all_urls&gt;</code>, cerrar accesos SMB Guest y ejecutar saneamiento de datos que excedan 7 años (resguardando 20 años post-mortem para expedientes clínicos Ley 68).</li>
        </ul>
    </div>
    <div class="roadmap-phase" style="border-left-color: #16a34a; background: #f0fdf4;">
        <strong>Fase 2 (15 - 45 Días): Operación Híbrida Cloudflare + On-Premise Collector</strong>
        <ul style="margin: 4px 0 0 0; padding-left: 18px;">
            <li><strong>Soberanía Local (Ley 81 Art. 41.4):</strong> Los documentos crudos y bases de datos permanecen en Panamá; únicamente salen métricas enmascaradas y hashes SHA-256 por el túnel saliente <code>cloudflared</code> sin abrir puertos entrantes.</li>
            <li><strong>Edge DLP, AI Gateway y CASB en Cloudflare:</strong> Inspección en borde con Custom Validation Worker (RUCTB Mod-11), gobierno centralizado de prompts vía AI Gateway y remediación automática de enlaces públicos en Box/Microsoft 365.</li>
            <li><strong>Evidencia Continua:</strong> Registro Logpush cifrado en R2 y generación periódica de Ficha Técnica SHA-256, flujo ARCO-P (5/10 días hábiles) y borrador ANTAI de 72h (DE 285 Art. 37).</li>
        </ul>
    </div>
</body>
</html>
"""


def render_executive_html(context: Dict[str, Any]) -> str:
    """Render deterministic executive report HTML using Jinja2 autoescape."""
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(REPORT_HTML_TEMPLATE)
    return template.render(**context)


def generate_executive_pdf_bytes(context: Dict[str, Any]) -> Tuple[bytes, str, bool]:
    """
    Compile Executive PDF via WeasyPrint when native Pango/Cairo libraries are available,
    or cleanly fall back to UTF-8 HTML bytes with fallback=True.

    Returns (payload_bytes, media_type, is_html_fallback).
    """
    rendered_html = render_executive_html(context)
    if WEASYPRINT_AVAILABLE:
        pdf_bytes = HTML(string=rendered_html).write_pdf()
        return pdf_bytes, "application/pdf", False

    return rendered_html.encode("utf-8"), "text/html; charset=utf-8", True


def generate_ficha_tecnica_json(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate structured Panama Ley 81 Ficha Técnica JSON document with deterministic SHA-256 hash.
    """
    risk = context.get("risk") or {}
    kpis = context.get("kpis") or {}
    reg_ctx = risk.get("regulatory_context") or get_regulatory_context(
        str(risk.get("regulatory_profile", "ANTAI_LEY81"))
    )

    body = {
        "schema_version": "2.0.0",
        "document_type": "FICHA_TECNICA_LEY_81_PANAMA",
        "generated_at": context.get("generated_at")
        or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "tenant_id": context.get("tenant_id", "default-tenant"),
        "regulatory_framework": {
            **reg_ctx,
            "citations": [
                "Ley 81 de 2019 Arts. 15-16 (ARCO-P 10/5 días hábiles)",
                "Ley 81 de 2019 Arts. 25, 32-33 y 41.4 (Transferencias y Custodia)",
                "Ley 81 de 2019 Art. 45 / DE 285 Arts. 43, 44 y 47 (DPO)",
                "Decreto Ejecutivo 285 de 2021 Art. 37 y Art. 48.3 (Brechas 72h - 5 elementos)",
                "Acuerdo 001-2022 SBP (Ciberseguridad Bancaria)",
                "Ley 68 de 2003 (Expediente Clínico 20 años post-mortem y audit trail)",
            ],
        },
        "risk_posture": {
            "global_score": risk.get("total_score", 0.0),
            "semaphore": risk.get("semaphore", "VERDE"),
            "compliance_level": risk.get("compliance_level", ""),
            "legal_exposure_range": risk.get("legal_exposure_range", ""),
            "breakdown": risk.get("breakdown", {}),
        },
        "telemetry_summary": {
            "audited_endpoints": kpis.get("audited_endpoints", 0),
            "shadow_ai_events": kpis.get("shadow_ai_events", 0),
            "adguard_live_connected": context.get("adguard_status", {}).get(
                "adguard_live_connected", False
            ),
            "exposed_files_smb_box": kpis.get("exposed_files_smb_box", 0),
            "db_findings_count": kpis.get("db_findings_count", 0),
            "retention_violations_total": kpis.get("retention_violations_total", 0),
        },
        "legal_conclusions": risk.get("legal_conclusions", []),
        "architecture_model": "Hybrid Cloudflare Zero Trust + On-Premise Collector (Raw PII Sovereign in Panama)",
    }

    canonical_json = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    sha256_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    return {
        **body,
        "sha256_hash": sha256_hash,
    }
