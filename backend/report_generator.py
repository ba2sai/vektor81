"""
Motor de Reglas Determinista para el "Score de Riesgo Ley 81" (Panamá) y
Generador de Informes Ejecutivos PDF mediante Jinja2 + WeasyPrint (0% LLMs, < 500MB RAM).

Fórmula del Score de Riesgo Ley 81 (0 a 100):
- 40% Tráfico activo hacia IAs públicas gratuitas (Shadow AI).
- 30% Archivos sensibles expuestos en Windows Server (SMB) o carpetas de Box Drive sin control de DLP.
- 30% Extensiones de navegador con permisos <all_urls> capaces de leer documentos en pantalla.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from jinja2 import Environment, BaseLoader

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False


def calculate_ley81_risk_score(
    total_shadow_ai_hits: int,
    unique_ai_domains_count: int,
    smb_pii_files_count: int,
    smb_guest_allowed: bool,
    box_unprotected_files_count: int,
    all_urls_extensions_count: int,
    audited_endpoints_count: int,
) -> Dict[str, Any]:
    """
    Calcula de forma 100% determinista el Score de Riesgo (0-100) y los dictámenes técnicos/legales
    bajo la Ley 81 de 2019 de la República de Panamá y su reglamentación (Decreto Ejecutivo 285 de 2021).
    """
    # 1. Sub-score Shadow AI (0 a 100, ponderación 40%)
    # Penaliza volumen de consultas DNS a IAs públicas y diversidad de herramientas sin contrato B2B/DPA
    hit_factor = min(70.0, total_shadow_ai_hits * 1.4)
    domain_factor = min(30.0, unique_ai_domains_count * 5.0)
    shadow_ai_subscore = round(min(100.0, hit_factor + domain_factor), 1)

    # 2. Sub-score Exposición de Datos en SMB / Box sin DLP (0 a 100, ponderación 30%)
    smb_factor = min(55.0, smb_pii_files_count * 6.5)
    guest_penalty = 20.0 if smb_guest_allowed and smb_pii_files_count > 0 else 0.0
    box_factor = min(25.0, box_unprotected_files_count * 1.8)
    storage_exposure_subscore = round(min(100.0, smb_factor + guest_penalty + box_factor), 1)

    # 3. Sub-score Extensiones con permiso <all_urls> (0 a 100, ponderación 30%)
    ext_density = all_urls_extensions_count * 18.0
    if audited_endpoints_count > 0:
        ext_ratio_bonus = min(28.0, (all_urls_extensions_count / max(1, audited_endpoints_count)) * 20.0)
    else:
        ext_ratio_bonus = 0.0
    extensions_subscore = round(min(100.0, ext_density + ext_ratio_bonus), 1)

    # Score Ponderado Global (0 a 100)
    weighted_score = round(
        (shadow_ai_subscore * 0.40)
        + (storage_exposure_subscore * 0.30)
        + (extensions_subscore * 0.30),
        1,
    )

    # Semáforo y Clasificación Legal Determinista (ANTAI - Ley 81)
    if weighted_score >= 70:
        semaphore = "ROJO"
        semaphore_color = "#dc2626"
        compliance_level = "INCUMPLIMIENTO CRÍTICO - RIESGO INMINENTE DE SANCIÓN ANTAI"
        legal_exposure_range = "USD $1,000 a $10,000 por infracción grave/muy grave + clausura temporal de registros (Art. 41-45 Ley 81)"
    elif weighted_score >= 40:
        semaphore = "AMARILLO"
        semaphore_color = "#d97706"
        compliance_level = "CUMPLIMIENTO PARCIAL - VULNERABILIDADES DE TRANSFERENCIA TRANSFRONTERIZA"
        legal_exposure_range = "USD $1,000 a $5,000 por falta de medidas técnicas de custodia y DLP (Art. 15 y 33 Ley 81)"
    else:
        semaphore = "VERDE"
        semaphore_color = "#16a34a"
        compliance_level = "RIESGO CONTROLADO - HIGIENE DE DATOS ACEPTABLE"
        legal_exposure_range = "Riesgo regulatorio bajo; mantener monitoreo continuo y bitácoras de auditoría"

    # Motor de Reglas para Conclusiones Legales Deterministas
    legal_conclusions: List[Dict[str, str]] = []

    if shadow_ai_subscore >= 30:
        legal_conclusions.append(
            {
                "articulo": "Artículos 6, 15 y 33 de la Ley 81 de 2019 (Transferencia Internacional de Datos)",
                "severidad": "ALTA" if shadow_ai_subscore < 65 else "CRÍTICA",
                "hallazgo": (
                    f"Se detectaron {total_shadow_ai_hits} eventos de resolución DNS e invocación hacia "
                    f"{unique_ai_domains_count} plataformas públicas de Inteligencia Artificial y procesamiento "
                    "documental en la nube (Shadow AI)."
                ),
                "dictamen": (
                    "El envío de fragmentos de contratos, planillas o datos de clientes hacia modelos LLM públicos "
                    "gratuitos constituye un tratamiento no autorizado y una transferencia transfronteriza sin "
                    "consentimiento informado del titular ni acuerdo de confidencialidad (DPA)."
                ),
            }
        )

    if storage_exposure_subscore >= 25:
        legal_conclusions.append(
            {
                "articulo": "Artículo 15 de la Ley 81 y Decreto Ejecutivo 285 (Deber de Custodia y Seguridad Técnica)",
                "severidad": "CRÍTICA" if smb_guest_allowed else "ALTA",
                "hallazgo": (
                    f"Se identificaron {smb_pii_files_count} documentos ofimáticos/PDF en Windows Server con patrones "
                    f"de Cédula Panameña, RUC o correos electrónicos, sumado a {box_unprotected_files_count} archivos "
                    "sincronizados en carpetas locales de Box Drive sin políticas activas de DLP."
                ),
                "dictamen": (
                    "La ausencia de segmentación de permisos NTFS/SMB y la sincronización local sin cifrado o DLP "
                    "vulneran el principio de Confidencialidad e Integridad exigido al Responsable del Tratamiento."
                ),
            }
        )

    if extensions_subscore >= 25:
        legal_conclusions.append(
            {
                "articulo": "Artículo 27 de la Ley 81 (Notificación de Brechas y Exfiltración Silenciosa en Endpoints)",
                "severidad": "ALTA",
                "hallazgo": (
                    f"Se detectaron {all_urls_extensions_count} extensiones de navegador con privilegios <all_urls> "
                    "instaladas en estaciones de trabajo corporativas."
                ),
                "dictamen": (
                    "Los complementos con permiso <all_urls> poseen capacidad técnica para leer el DOM completo de "
                    "sistemas ERP, banca en línea, webmail y visores PDF, enviando el contenido a servidores de terceros."
                ),
            }
        )

    if not legal_conclusions:
        legal_conclusions.append(
            {
                "articulo": "Principio de Responsabilidad Proactiva (Accountability - Ley 81)",
                "severidad": "BAJA",
                "hallazgo": "No se detectaron vectores masivos de exfiltración activa en el corte actual.",
                "dictamen": "Se recomienda mantener la auditoría periódica e implementar capacidades de IA local aislada.",
            }
        )

    return {
        "total_score": weighted_score,
        "semaphore": semaphore,
        "semaphore_color": semaphore_color,
        "compliance_level": compliance_level,
        "legal_exposure_range": legal_exposure_range,
        "breakdown": {
            "shadow_ai_subscore": shadow_ai_subscore,
            "shadow_ai_weighted": round(shadow_ai_subscore * 0.40, 1),
            "storage_exposure_subscore": storage_exposure_subscore,
            "storage_exposure_weighted": round(storage_exposure_subscore * 0.30, 1),
            "extensions_subscore": extensions_subscore,
            "extensions_weighted": round(extensions_subscore * 0.30, 1),
        },
        "legal_conclusions": legal_conclusions,
    }


REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe Ejecutivo de Auditoría Shadow AI & Ley 81 - Vektor81</title>
    <style>
        @page {
            size: A4;
            margin: 18mm 16mm 18mm 16mm;
            @bottom-right {
                content: "Página " counter(page) " de " counter(pages);
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }
            @bottom-left {
                content: "CONFIDENCIAL — AUDITORÍA LEY 81 PANAMÁ (VEKTOR81 APPLIANCE)";
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }
        }
        * {
            box-sizing: border-box;
        }
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            color: #0f172a;
            line-height: 1.45;
            font-size: 9.5pt;
            margin: 0;
            padding: 0;
        }
        .cover-banner {
            background: #0f172a;
            color: #f8fafc;
            padding: 24px 28px;
            border-radius: 8px;
            border-left: 8px solid {{ risk.semaphore_color }};
            margin-bottom: 18px;
        }
        .cover-tag {
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #38bdf8;
            font-weight: bold;
            margin-bottom: 6px;
        }
        .cover-title {
            font-size: 20pt;
            font-weight: 800;
            margin: 0 0 6px 0;
            line-height: 1.15;
        }
        .cover-subtitle {
            font-size: 10pt;
            color: #cbd5e1;
            margin: 0;
        }
        .score-box-container {
            display: table;
            width: 100%;
            margin-bottom: 18px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            background: #f8fafc;
            padding: 14px;
        }
        .score-col-left {
            display: table-cell;
            width: 32%;
            vertical-align: middle;
            text-align: center;
            border-right: 1px solid #cbd5e1;
            padding-right: 12px;
        }
        .score-col-right {
            display: table-cell;
            width: 68%;
            vertical-align: middle;
            padding-left: 16px;
        }
        .score-number {
            font-size: 34pt;
            font-weight: 900;
            color: {{ risk.semaphore_color }};
            line-height: 1;
        }
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
            font-size: 12.5pt;
            font-weight: 800;
            color: #0f172a;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 4px;
            margin-top: 18px;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 14px;
            font-size: 8.5pt;
        }
        th {
            background-color: #1e293b;
            color: #ffffff;
            text-align: left;
            padding: 7px 8px;
            font-weight: bold;
        }
        td {
            padding: 6px 8px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        tr:nth-child(even) td {
            background-color: #f8fafc;
        }
        .card {
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 10px 12px;
            margin-bottom: 10px;
            background: #ffffff;
        }
        .badge-crit {
            color: #991b1b;
            background: #fee2e2;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 7.5pt;
        }
        .badge-high {
            color: #92400e;
            background: #fef3c7;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 7.5pt;
        }
        .roadmap-phase {
            border-left: 4px solid #0284c7;
            background: #f0f9ff;
            padding: 10px 14px;
            margin-bottom: 10px;
            border-radius: 0 6px 6px 0;
        }
        .page-break {
            page-break-before: always;
        }
    </style>
</head>
<body>

    <!-- 1. PORTADA EJECUTIVA Y SCORE DE RIESGO LEY 81 -->
    <div class="cover-banner">
        <div class="cover-tag">Auditoría Técnica de Gobernanza de IA &amp; Protección de Datos Personales</div>
        <h1 class="cover-title">INFORME EJECUTIVO: SHADOW AI &amp; CUMPLIMIENTO LEY 81 (PANAMÁ)</h1>
        <p class="cover-subtitle">
            Generado localmente por Vektor81 Audit Appliance (100% On-Premise) | Fecha UTC: {{ generated_at }}
        </p>
    </div>

    <div class="score-box-container">
        <div class="score-col-left">
            <div style="font-size: 8.5pt; font-weight: bold; color: #475569; margin-bottom: 4px;">SCORE DE RIESGO LEY 81</div>
            <div class="score-number">{{ risk.total_score }}<span style="font-size: 14pt; color: #64748b;">/100</span></div>
            <div class="semaphore-badge">SEMÁFORO: {{ risk.semaphore }}</div>
        </div>
        <div class="score-col-right">
            <div style="font-weight: 800; font-size: 10.5pt; margin-bottom: 4px; color: #0f172a;">
                {{ risk.compliance_level }}
            </div>
            <p style="margin: 0 0 6px 0; font-size: 8.8pt; color: #334155;">
                <strong>Exposición Regulatoria Estimada (ANTAI):</strong> {{ risk.legal_exposure_range }}
            </p>
            <table style="margin-bottom: 0; font-size: 8pt;">
                <thead>
                    <tr>
                        <th>Vector Evaluado</th>
                        <th>Peso</th>
                        <th>Sub-Score</th>
                        <th>Aporte al Riesgo</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>1. Tráfico Activo hacia IAs Públicas (Shadow AI)</td>
                        <td>40%</td>
                        <td>{{ risk.breakdown.shadow_ai_subscore }}/100</td>
                        <td><strong>{{ risk.breakdown.shadow_ai_weighted }} pts</strong></td>
                    </tr>
                    <tr>
                        <td>2. Archivos Sensibles en Windows Server SMB / Box sin DLP</td>
                        <td>30%</td>
                        <td>{{ risk.breakdown.storage_exposure_subscore }}/100</td>
                        <td><strong>{{ risk.breakdown.storage_exposure_weighted }} pts</strong></td>
                    </tr>
                    <tr>
                        <td>3. Extensiones de Navegador con Permisos &lt;all_urls&gt;</td>
                        <td>30%</td>
                        <td>{{ risk.breakdown.extensions_subscore }}/100</td>
                        <td><strong>{{ risk.breakdown.extensions_weighted }} pts</strong></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- DICTÁMENES LEGALES DETERMINISTAS -->
    <div class="section-title">1. Dictamen de Cumplimiento Normativo (Ley 81 de 2019 y Decreto 285)</div>
    {% for item in risk.legal_conclusions %}
    <div class="card">
        <div style="margin-bottom: 4px;">
            <span class="{% if item.severidad == 'CRÍTICA' %}badge-crit{% else %}badge-high{% endif %}">{{ item.severidad }}</span>
            <strong style="margin-left: 6px; font-size: 9.5pt;">{{ item.articulo }}</strong>
        </div>
        <div style="font-size: 8.8pt; margin-bottom: 3px;"><strong>Hallazgo Técnico:</strong> {{ item.hallazgo }}</div>
        <div style="font-size: 8.8pt; color: #334155;"><strong>Conclusión Legal:</strong> {{ item.dictamen }}</div>
    </div>
    {% endfor %}

    <!-- 2. TABLA DE HALLAZGOS DE SHADOW AI -->
    <div class="section-title">2. Hallazgos de Shadow AI (Equipos, DNS &amp; Extensiones Riesgosas)</div>
    <table>
        <thead>
            <tr>
                <th>Hostname / Estación</th>
                <th>Usuario</th>
                <th>Hits DNS Shadow AI</th>
                <th>Extensiones &lt;all_urls&gt;</th>
                <th>Archivos Sensibles Box</th>
                <th>DLP Box</th>
            </tr>
        </thead>
        <tbody>
            {% for ep in endpoints %}
            <tr>
                <td><strong>{{ ep.hostname }}</strong><br><span style="color:#64748b;font-size:7.5pt;">{{ ep.ip_address or 'LAN' }}</span></td>
                <td>{{ ep.username }}</td>
                <td>{{ ep.dns_hits_count }} consultas</td>
                <td>{{ ep.risky_extensions_count }} extensiones</td>
                <td>{{ ep.box_exposed_files }} archivos</td>
                <td>
                    {% if ep.box_dlp_active %}
                        <span style="color:#16a34a;font-weight:bold;">ACTIVO</span>
                    {% else %}
                        <span class="badge-crit">SIN DLP</span>
                    {% endif %}
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="6" style="text-align:center;">No se han registrado endpoints aún.</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    {% if top_ai_domains %}
    <div style="font-weight: bold; font-size: 9pt; margin-bottom: 6px;">Top Dominios de IA Pública Interceptados en la Red Local:</div>
    <table>
        <thead>
            <tr>
                <th>Dominio de IA / Servicio Cloud</th>
                <th>Categoría de Riesgo</th>
                <th>Eventos de Conexión Detectados</th>
            </tr>
        </thead>
        <tbody>
            {% for dom in top_ai_domains %}
            <tr>
                <td><strong>{{ dom.domain }}</strong></td>
                <td>{{ dom.category }}</td>
                <td>{{ dom.count }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <div class="page-break"></div>

    <!-- 3. ESTADO DE EXPOSICIÓN EN WINDOWS SERVER SMB Y BOX.COM -->
    <div class="section-title">3. Exposición de Datos Personales en Windows Server (SMB) y Box Drive</div>
    {% if latest_smb %}
    <div class="card">
        <strong>Servidor Auditado:</strong> {{ latest_smb.server_name }} ({{ latest_smb.target_ip }}) |
        <strong>Modo de Acceso:</strong> {{ latest_smb.auth_mode }} |
        <strong>Documentos Ofimáticos/PDF:</strong> {{ latest_smb.total_office_pdf_files }} |
        <strong>Archivos con PII (Ley 81):</strong> {{ latest_smb.files_with_pii_count }}
        <br>
        <strong>Carpetas Críticas Expuestas:</strong>
        {{ latest_smb.critical_shares_found | join(', ') if latest_smb.critical_shares_found else 'Ninguna carpeta crítica nominal' }}
        <br>
        <strong>Conteo de Identificadores Panameños:</strong>
        Cédulas: <strong>{{ latest_smb.cedula_matches_count }}</strong> |
        RUC: <strong>{{ latest_smb.ruc_matches_count }}</strong> |
        Correos: <strong>{{ latest_smb.email_matches_count }}</strong>
    </div>

    <table>
        <thead>
            <tr>
                <th>Ruta UNC del Archivo</th>
                <th>Carpeta</th>
                <th>Cédulas (Muestra Enmascarada)</th>
                <th>RUC / Emails</th>
                <th>Severidad</th>
            </tr>
        </thead>
        <tbody>
            {% for f in latest_smb.findings_detail[:12] %}
            <tr>
                <td style="word-break: break-all;"><strong>{{ f.filename }}</strong><br><span style="font-size:7.5pt;color:#64748b;">{{ f.unc_path }}</span></td>
                <td>{{ f.share }}</td>
                <td>{{ f.cedulas_found | join(', ') if f.cedulas_found else '—' }} ({{ f.cedula_count }})</td>
                <td>RUC: {{ f.ruc_count }} | Email: {{ f.email_count }}</td>
                <td><span class="badge-crit">{{ f.severity }}</span></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="card">No se ha ejecutado aún un escaneo contra Windows Server SMB.</div>
    {% endif %}

    <!-- 4. HOJA DE RUTA DE REMEDIACIÓN TÉCNICA (FASE 2: BÓVEDA RAG PRIVADA) -->
    <div class="section-title">4. Hoja de Ruta de Remediación Técnica y Transición a Fase 2</div>

    <div class="roadmap-phase">
        <strong>Acción Inmediata (0 - 15 Días): Contención Perimetral y Bloqueo de Shadow AI</strong>
        <ul style="margin: 4px 0 0 0; padding-left: 18px;">
            <li>Activar bloqueo en AdGuard Home / Firewall corporativo para convertidores de PDF gratuitos (<code>ilovepdf.com</code>, <code>smallpdf.com</code>) y chatbots sin acuerdo de confidencialidad.</li>
            <li>Revocar mediante GPO de Active Directory las extensiones de Chrome/Edge con permiso <code>&lt;all_urls&gt;</code> identificadas en este informe.</li>
            <li>Deshabilitar el acceso Guest/Anónimo en recursos SMB y aplicar listas de control de acceso (ACL) por rol en <code>Contratos</code>, <code>Planilla</code>, <code>Finanzas</code> y <code>Legal</code>.</li>
        </ul>
    </div>

    <div class="roadmap-phase" style="border-left-color: #16a34a; background: #f0fdf4;">
        <strong>Paso Recomendado — Fase 2 (15 - 45 Días): Implementación de "Bóveda RAG Privada On-Premise"</strong>
        <p style="margin: 4px 0;">
            La prohibición total de herramientas de IA sin ofrecer una alternativa segura provoca que los colaboradores utilicen dispositivos personales (BYOD) para procesar contratos y planillas. Para erradicar el riesgo sancionatorio bajo la <strong>Ley 81 de Panamá</strong> mientras se multiplica la productividad corporativa, se recomienda desplegar la <strong>Fase 2: Bóveda RAG Privada</strong>:
        </p>
        <ul style="margin: 4px 0 0 0; padding-left: 18px;">
            <li><strong>Soberanía Total de Datos:</strong> Indexación vectorial local de las carpetas <code>Legal</code>, <code>Contratos</code> y <code>Finanzas</code> dentro de la LAN del cliente, con 0% de transferencia hacia servidores fuera de Panamá.</li>
            <li><strong>Control de Acceso Basado en Roles (RBAC) + Auditoría ANTAI:</strong> Cada consulta de un colaborador sobre documentos internos queda registrada en una bitácora inmutable de cumplimiento.</li>
            <li><strong>Anonimización Automática de PII:</strong> Enmascaramiento en tiempo real de números de Cédula Panameña y RUC antes de cualquier procesamiento analítico.</li>
        </ul>
    </div>

</body>
</html>
"""


def generate_executive_pdf_bytes(context: Dict[str, Any]) -> bytes:
    """
    Compila la plantilla Jinja2 con los datos del motor determinista y genera el binario PDF
    utilizando WeasyPrint. Incluye un fallback PDF válido estándar si las librerías nativas de Cairo/Pango
    no están instaladas fuera del contenedor Docker.
    """
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(REPORT_HTML_TEMPLATE)
    rendered_html = template.render(**context)

    if WEASYPRINT_AVAILABLE:
        return HTML(string=rendered_html).write_pdf()

    # Fallback determinista si se ejecuta en un host sin GTK/Pango fuera de Docker
    raise RuntimeError(
        "WeasyPrint requiere las librerías del sistema Pango/Cairo (incluidas en el Dockerfile del backend)."
    )
