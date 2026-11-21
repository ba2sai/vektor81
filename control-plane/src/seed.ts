import { addPanamaBusinessDays, getDsarSlaBusinessDays } from './panama-calendar';
import { evaluateAndSyncHealth } from './health-monitor';
import { computeEndpointRiskScore } from './scoring';
import type { ComponentLayer, ComponentStatus, RegulatoryProfile } from './types';

interface DemoTenantSpec {
  id: string;
  name: string;
  industry: string;
  regulatory_profile: RegulatoryProfile;
  dpo_name: string;
  dpo_email: string;
  dpo_antai_registered: number;
  dpo_antai_reg_ref: string | null;
}

const DEMO_TENANTS: DemoTenantSpec[] = [
  {
    id: 'banco-istmo',
    name: 'Banco del Istmo S.A.',
    industry: 'Banca y Servicios Financieros',
    regulatory_profile: 'SBP_001_2022',
    dpo_name: 'Lic. Valeria Mendoza',
    dpo_email: 'dpo@bancoistmo.pa',
    dpo_antai_registered: 1,
    dpo_antai_reg_ref: 'ANTAI-DPO-2026-0142',
  },
  {
    id: 'clinica-pacifica',
    name: 'Clínica Hospital Pacífica Salud',
    industry: 'Salud y Expediente Clínico',
    regulatory_profile: 'SALUD_LEY68',
    dpo_name: 'Dr. Ricardo Salcedo',
    dpo_email: 'privacidad@clinicapacifica.pa',
    dpo_antai_registered: 1,
    dpo_antai_reg_ref: 'ANTAI-DPO-2026-0388',
  },
  {
    id: 'bufete-balboa',
    name: 'Bufete Balboa & Asociados',
    industry: 'Servicios Legales Corporativos',
    regulatory_profile: 'ANTAI_LEY81',
    dpo_name: 'Lic. Sofía Morales',
    dpo_email: 'smorales@bufetebalboa.pa',
    dpo_antai_registered: 0,
    dpo_antai_reg_ref: null,
  },
];

const ALL_LAYERS: Array<{ layer: ComponentLayer; suffix: string; label: string }> = [
  { layer: 'CONTROL_PLANE', suffix: 'ctrl-edge', label: 'Cloudflare Workers Control Plane' },
  { layer: 'TUNNEL', suffix: 'cf-tunnel-01', label: 'Cloudflare Zero Trust Tunnel' },
  { layer: 'ONPREM_COLLECTOR', suffix: 'collector-01', label: 'On-Premise Collector Core' },
  { layer: 'ADGUARD_DNS', suffix: 'adguard-dns-01', label: 'AdGuard DNS Shadow-AI Sensor' },
  { layer: 'ENDPOINT_AGENT', suffix: 'ep-agent-fleet', label: 'Windows Endpoint Fleet Agent' },
  { layer: 'DB_CONNECTOR', suffix: 'db-connector-01', label: 'SQL Server / PostgreSQL Connector' },
  { layer: 'SMB_CONNECTOR', suffix: 'smb-connector-01', label: 'Windows File Server SMB Connector' },
  { layer: 'WAZUH_FIM', suffix: 'wazuh-fim-01', label: 'Wazuh FIM Integrity Monitor' },
  { layer: 'CLOUDFLARE_DLP', suffix: 'cf-dlp-edge', label: 'Cloudflare Edge DLP Profiles' },
  { layer: 'CLOUDFLARE_CASB', suffix: 'cf-casb-01', label: 'Cloudflare CASB SaaS Integration' },
  { layer: 'LOGPUSH', suffix: 'cf-logpush-r2', label: 'Cloudflare Logpush to R2 Pipeline' },
];

export interface SeedResult {
  tenants_seeded: string[];
  components_seeded: number;
  alerts_active: number;
  findings_seeded: number;
  endpoints_seeded: number;
  dsars_seeded: number;
  breaches_seeded: number;
  transfers_seeded: number;
}

export async function seedDemoEnvironment(
  db: D1Database,
  now: Date = new Date()
): Promise<SeedResult> {
  const nowIso = now.toISOString();
  const min25AgoIso = new Date(now.getTime() - 25 * 60_000).toISOString();
  const min8AgoIso = new Date(now.getTime() - 8 * 60_000).toISOString();
  const hours30AgoIso = new Date(now.getTime() - 30 * 3600_000).toISOString();
  const hours20AgoIso = new Date(now.getTime() - 20 * 3600_000).toISOString();
  const hours3AgoIso = new Date(now.getTime() - 3 * 3600_000).toISOString();

  // Clear existing data strictly for the 3 demo tenants (keep any custom tenants and api_tokens)
  const tablesToClear = [
    'risk_history',
    'ficha_tecnica_snapshots',
    'data_transfers',
    'breach_incidents',
    'dsar_requests',
    'logpush_batches',
    'casb_events',
    'shadow_ai_events',
    'scan_findings',
    'endpoints',
    'operational_alerts',
    'component_heartbeats',
  ];

  for (const t of DEMO_TENANTS) {
    for (const tbl of tablesToClear) {
      await db.prepare(`DELETE FROM ${tbl} WHERE tenant_id = ?`).bind(t.id).run();
    }
    await db
      .prepare(
        `INSERT INTO tenants (id, name, industry, regulatory_profile, dpo_name, dpo_email, dpo_antai_registered, dpo_antai_reg_ref, active, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
         ON CONFLICT(id) DO UPDATE SET
           name = excluded.name,
           industry = excluded.industry,
           regulatory_profile = excluded.regulatory_profile,
           dpo_name = excluded.dpo_name,
           dpo_email = excluded.dpo_email,
           dpo_antai_registered = excluded.dpo_antai_registered,
           dpo_antai_reg_ref = excluded.dpo_antai_reg_ref,
           active = 1`
      )
      .bind(
        t.id,
        t.name,
        t.industry,
        t.regulatory_profile,
        t.dpo_name,
        t.dpo_email,
        t.dpo_antai_registered,
        t.dpo_antai_reg_ref,
        nowIso
      )
      .run();
  }

  let componentsSeeded = 0;
  let findingsSeeded = 0;
  let endpointsSeeded = 0;
  let dsarsSeeded = 0;
  let breachesSeeded = 0;
  let transfersSeeded = 0;

  for (const tenant of DEMO_TENANTS) {
    // 1. Seed 11 infrastructure + agent component heartbeats (with intentional OFFLINE/DEGRADED visibility)
    for (const item of ALL_LAYERS) {
      let reportedStatus: ComponentStatus = 'ONLINE';
      let lastHb = nowIso;
      let lastError: string | null = null;
      let latencyMs = 18;

      if (tenant.id === 'banco-istmo' && item.layer === 'SMB_CONNECTOR') {
        reportedStatus = 'OFFLINE';
        lastHb = min25AgoIso;
        lastError = 'SMB session timeout hacia \\\\FS-TESORERIA-01\\Planilla (puerto 445 inaccesible)';
        latencyMs = 0;
      } else if (tenant.id === 'banco-istmo' && item.layer === 'WAZUH_FIM') {
        reportedStatus = 'DEGRADED';
        lastHb = min8AgoIso;
        lastError = 'Cola de eventos FIM con retraso de 480s en nodo DMZ';
        latencyMs = 420;
      } else if (tenant.id === 'clinica-pacifica' && item.layer === 'DB_CONNECTOR') {
        reportedStatus = 'OFFLINE';
        lastHb = min25AgoIso;
        lastError = 'Credencial de lectura HIS-SQL expirada; sin conexión al repositorio clínico';
        latencyMs = 0;
      } else if (tenant.id === 'bufete-balboa' && item.layer === 'ADGUARD_DNS') {
        reportedStatus = 'DEGRADED';
        lastHb = min8AgoIso;
        lastError = 'Desfase de sincronización querylog > 5m en sucursal Obarrio';
        latencyMs = 310;
      }

      const compId = `${tenant.id}-${item.suffix}`;
      await db
        .prepare(
          `INSERT INTO component_heartbeats
           (id, tenant_id, component_layer, component_id, display_name, reported_status, computed_status, latency_ms, version, cpu_pct, ram_mb, uptime_pct_24h, last_error, metadata_json, last_heartbeat_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 'ONLINE', ?, '2.0.0', ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          item.layer,
          compId,
          item.label,
          reportedStatus,
          latencyMs,
          reportedStatus === 'ONLINE' ? 14.5 : 82.0,
          256,
          reportedStatus === 'OFFLINE' ? 91.2 : 99.8,
          lastError,
          JSON.stringify({ environment: 'panama-dc-01', profile: tenant.regulatory_profile }),
          lastHb,
          nowIso
        )
        .run();
      componentsSeeded += 1;
    }

    // 2. Endpoints
    const endpointSpecs = [
      {
        hostname: `${tenant.id.toUpperCase()}-PC-01`,
        username: 'PANAMA\\mrodriguez',
        ip: '10.10.20.14',
        dnsHits: tenant.id === 'bufete-balboa' ? 28 : 14,
        riskyExt: 2,
        boxFiles: 12,
        boxDlp: false,
        oneDriveFiles: 4,
        status: 'ONLINE' as ComponentStatus,
        lastSeen: nowIso,
      },
      {
        hostname: `${tenant.id.toUpperCase()}-PC-02`,
        username: 'PANAMA\\jcastillo',
        ip: '10.10.20.27',
        dnsHits: 9,
        riskyExt: 1,
        boxFiles: 5,
        boxDlp: tenant.id === 'banco-istmo',
        oneDriveFiles: 8,
        status: 'ONLINE' as ComponentStatus,
        lastSeen: nowIso,
      },
      {
        hostname: `${tenant.id.toUpperCase()}-LT-03`,
        username: 'PANAMA\\agonzalez',
        ip: '10.10.21.45',
        dnsHits: 3,
        riskyExt: 0,
        boxFiles: 0,
        boxDlp: true,
        oneDriveFiles: 2,
        status: 'STALE' as ComponentStatus,
        lastSeen: hours30AgoIso,
      },
    ];

    for (const ep of endpointSpecs) {
      const score = computeEndpointRiskScore({
        dnsHitsCount: ep.dnsHits,
        allUrlsExtensionsCount: ep.riskyExt,
        boxInstalled: ep.boxFiles > 0,
        boxDlpEnabled: ep.boxDlp,
        boxSensitiveFiles: ep.boxFiles,
        onedriveInstalled: ep.oneDriveFiles > 0,
        onedriveDlpEnabled: false,
        onedriveSensitiveFiles: ep.oneDriveFiles,
      });

      await db
        .prepare(
          `INSERT INTO endpoints
           (id, tenant_id, hostname, username, ip_address, os_version, agent_version, dns_hits_count, risky_extensions_count, box_exposed_files, box_dlp_active, onedrive_exposed_files, endpoint_risk_score, status, last_seen_at, details_json)
           VALUES (?, ?, ?, ?, ?, 'Windows 11 Pro 24H2', '2.0.0', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          ep.hostname,
          ep.username,
          ep.ip,
          ep.dnsHits,
          ep.riskyExt,
          ep.boxFiles,
          ep.boxDlp ? 1 : 0,
          ep.oneDriveFiles,
          score,
          ep.status,
          ep.lastSeen,
          JSON.stringify({
            risky_extensions:
              ep.riskyExt > 0
                ? [
                    {
                      extension_id: 'efaidnbmnnnibpcajpcglclefindmkaj',
                      name: 'AI PDF Reader & Summarizer',
                      browser: 'Chrome',
                      permissions: ['<all_urls>', 'tabs', 'storage'],
                      has_all_urls: true,
                    },
                  ]
                : [],
            box_sample_files: ep.boxFiles > 0 ? ['Planilla_Q4_****.xlsx', 'Contratos_Clientes_****.pdf'] : [],
          })
        )
        .run();
      endpointsSeeded += 1;
    }

    // 3. Scan Findings (strictly masked!)
    const findingsSpec =
      tenant.id === 'banco-istmo'
        ? [
            {
              source_type: 'SQL_DB',
              repo: 'CORE-TARJETAS-SQL',
              path: 'dbo.clientes_tarjetas.pan_enmascarado',
              entity: 'PA_TARJETA_PAGO',
              masked: '4532-****-****-0366',
              matches: 148,
              sensitive: 1,
              severity: 'CRITICAL',
              ageDays: 3100,
              retViol: 1,
            },
            {
              source_type: 'SMB',
              repo: '\\\\FS-TESORERIA\\Swift',
              path: 'Transferencias_2026/lote_corresponsal.csv',
              entity: 'PA_SWIFT_PA',
              masked: 'BAGEPAPA***',
              matches: 42,
              sensitive: 0,
              severity: 'HIGH',
              ageDays: 120,
              retViol: 0,
            },
            {
              source_type: 'OCR_IMAGE',
              repo: 'Expedientes-KYC-Scan',
              path: 'KYC_2026/cedulas_pendientes_09.png',
              entity: 'PA_IDENTIDAD_NATURAL',
              masked: '8-***-1234',
              matches: 19,
              sensitive: 0,
              severity: 'HIGH',
              ageDays: 45,
              retViol: 0,
            },
            {
              source_type: 'DLP_EDGE',
              repo: 'Cloudflare-AI-Gateway',
              path: 'POST https://chatgpt.com/backend-api/conversation',
              entity: 'PA_IDENTIDAD_NATURAL',
              masked: '8-***-9012',
              matches: 6,
              sensitive: 0,
              severity: 'CRITICAL',
              ageDays: 1,
              retViol: 0,
            },
          ]
        : tenant.id === 'clinica-pacifica'
          ? [
              {
                source_type: 'SQL_DB',
                repo: 'HIS-CLINICA-POSTGRES',
                path: 'public.historias_clinicas.diagnostico_cie10',
                entity: 'PA_DATO_SENSIBLE_SALUD',
                masked: 'CED 8-***-1234 | DX: [DATO SENSIBLE SALUD PROTEGIDO]',
                matches: 312,
                sensitive: 1,
                severity: 'CRITICAL',
                ageDays: 2400, // ~6.5 years: protected under Ley 68 (20 years post-mortem)
                retViol: 0,
              },
              {
                source_type: 'OCR_IMAGE',
                repo: 'Radiologia-DICOM-PDF',
                path: 'Urgencias/resultados_lab_442.pdf',
                entity: 'PA_DATO_SENSIBLE_SALUD',
                masked: 'E-8-***921 | LAB-SEROLOGIA',
                matches: 27,
                sensitive: 1,
                severity: 'CRITICAL',
                ageDays: 35,
                retViol: 0,
              },
              {
                source_type: 'SMB',
                repo: '\\\\FS-ADMIN\\Facturacion',
                path: 'Historico_2017/reclamos_aseguradoras.xlsx',
                entity: 'PA_PASAPORTE',
                masked: 'PA123****',
                matches: 14,
                sensitive: 0,
                severity: 'MEDIUM',
                ageDays: 3200, // Administrative data > 7y
                retViol: 1,
              },
            ]
          : [
              {
                source_type: 'SMB',
                repo: '\\\\FS-LITIGIOS\\Clientes',
                path: 'Sociedades/poder_notarial_8_714.docx',
                entity: 'PA_IDENTIDAD_NATURAL',
                masked: '8-***-2219',
                matches: 64,
                sensitive: 0,
                severity: 'HIGH',
                ageDays: 2900,
                retViol: 1,
              },
              {
                source_type: 'CASB',
                repo: 'Box-Drive-Socios',
                path: 'Fusiones_2026/due_diligence_fideicomiso.pdf',
                entity: 'PA_PASAPORTE',
                masked: 'PA998****',
                matches: 11,
                sensitive: 0,
                severity: 'CRITICAL',
                ageDays: 14,
                retViol: 0,
              },
              {
                source_type: 'DLP_EDGE',
                repo: 'Cloudflare-AI-Gateway',
                path: 'POST https://harvey.ai/api/draft',
                entity: 'EMAIL_PERSONAL',
                masked: 'c***@gmail.com',
                matches: 22,
                sensitive: 0,
                severity: 'HIGH',
                ageDays: 2,
                retViol: 0,
              },
            ];

    for (const f of findingsSpec) {
      await db
        .prepare(
          `INSERT INTO scan_findings
           (id, tenant_id, scan_id, source_type, repository_name, location_path, entity_type, masked_sample, value_sha256, match_count, is_sensitive, severity, retention_age_days, retention_violation, is_simulated, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          `demo-scan-${tenant.id}`,
          f.source_type,
          f.repo,
          f.path,
          f.entity,
          f.masked,
          `sha256-demo-${tenant.id}-${findingsSeeded}`,
          f.matches,
          f.sensitive,
          f.severity,
          f.ageDays,
          f.retViol,
          nowIso
        )
        .run();
      findingsSeeded += 1;
    }

    // 4. Shadow AI Events
    const shadowDomains = [
      { domain: 'chatgpt.com', category: 'LLM Conversacional', hits: 34, blocked: 0 },
      { domain: 'ilovepdf.com', category: 'Procesamiento PDF / Docs', hits: 21, blocked: 0 },
      { domain: 'deepseek.com', category: 'LLM Conversacional', hits: 12, blocked: 1 },
      { domain: 'claude.ai', category: 'LLM Conversacional', hits: 18, blocked: 0 },
    ];
    for (const sd of shadowDomains) {
      await db
        .prepare(
          `INSERT INTO shadow_ai_events
           (id, tenant_id, source, client_ip, hostname, domain, category, hits, blocked, recorded_at)
           VALUES (?, ?, 'ADGUARD_DNS', '10.10.20.14', ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          `${tenant.id.toUpperCase()}-PC-01`,
          sd.domain,
          sd.category,
          sd.hits,
          sd.blocked,
          nowIso
        )
        .run();
    }

    // 5. CASB Events
    const casbSpecs = [
      {
        eventId: `casb-${tenant.id}-01`,
        app: 'Microsoft 365',
        resource: 'SharePoint / Planilla_Panama_2026.xlsx',
        findingType: 'EXTERNAL_SHARING_LINK',
        exposure: 'PUBLIC_LINK',
        auto: 1,
        action: 'Revocado enlace público automáticamente por Cloudflare CASB',
        severity: 'CRITICAL',
        remAt: hours3AgoIso,
      },
      {
        eventId: `casb-${tenant.id}-02`,
        app: 'Box',
        resource: 'Carpeta Contratos / Expedientes_Clientes',
        findingType: 'UNENCRYPTED_PII_SYNC',
        exposure: 'PII_DETECTED',
        auto: 0,
        action: null,
        severity: 'HIGH',
        remAt: null,
      },
      {
        eventId: `casb-${tenant.id}-03`,
        app: 'Google Workspace',
        resource: 'OAuth App: Free AI Summarizer',
        findingType: 'RISKY_OAUTH_GRANT',
        exposure: 'OAUTH_RISKY',
        auto: 1,
        action: 'Token OAuth revocado por política Zero Trust',
        severity: 'HIGH',
        remAt: hours3AgoIso,
      },
    ];
    for (const ce of casbSpecs) {
      await db
        .prepare(
          `INSERT INTO casb_events
           (id, tenant_id, event_id, saas_app, resource_name, finding_type, exposure_level, remediated_automatically, remediation_action, severity, detected_at, remediated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          ce.eventId,
          ce.app,
          ce.resource,
          ce.findingType,
          ce.exposure,
          ce.auto,
          ce.action,
          ce.severity,
          hours20AgoIso,
          ce.remAt
        )
        .run();
    }

    // 6. Logpush Batches
    await db
      .prepare(
        `INSERT INTO logpush_batches
         (id, tenant_id, dataset, records_count, lag_seconds, encrypted_with_customer_key, r2_object_key, summary_json, ingested_at)
         VALUES (?, ?, 'dlp_forensic', 1420, 42.5, 1, ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        tenant.id,
        `logpush/${tenant.id}/dlp_forensic/latest.ndjson.gz`,
        JSON.stringify({ blocked_requests: 12, inspected_payloads: 1420 }),
        nowIso
      )
      .run();

    // 7. DSAR Requests (with Panama calendar SLAs)
    const dsarSpecs = [
      {
        name: 'Carlos Eduardo Quintero',
        maskedId: '8-***-4410',
        right: 'ACCESO' as const,
        received: hours20AgoIso,
        status: 'IN_PROGRESS',
        systems: ['CORE-SQL', 'SMB-FileServer', 'Microsoft 365'],
      },
      {
        name: 'Ana Lucía Villarreal',
        maskedId: '4-***-8821',
        right: 'CANCELACION' as const,
        received: new Date(now.getTime() - 12 * 86400_000).toISOString(),
        status: 'PENDING', // Intentionally overdue past 5 business days
        systems: ['CRM-Ventas', 'Box Drive'],
      },
    ];
    for (const d of dsarSpecs) {
      const slaDays = getDsarSlaBusinessDays(d.right);
      const dueAt = addPanamaBusinessDays(d.received, slaDays).toISOString();
      await db
        .prepare(
          `INSERT INTO dsar_requests
           (id, tenant_id, requester_name, requester_id_masked, right_type, sla_business_days, received_at, due_at, status, target_systems_json, notes, completed_at, evidence_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}')`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          d.name,
          d.maskedId,
          d.right,
          slaDays,
          d.received,
          dueAt,
          d.status,
          JSON.stringify(d.systems),
          `Solicitud ARCO de ${d.right} bajo Ley 81 de 2019`
        )
        .run();
      dsarsSeeded += 1;
    }

    // 8. Active 72h Breach Incident (all 5 DE 285 Art. 37 elements populated)
    const breachDetected = hours20AgoIso;
    const breachDeadline = new Date(Date.parse(breachDetected) + 72 * 3600_000).toISOString();
    await db
      .prepare(
        `INSERT INTO breach_incidents
         (id, tenant_id, title, severity, status, what_happened, compromised_data_types_json, affected_records_estimate, measures_adopted, titular_actions, contact_point, detected_at, deadline_72h_at, antai_notified_at)
         VALUES (?, ?, ?, 'HIGH', 'CONTAINING', ?, ?, 38, ?, ?, ?, ?, ?, NULL)`
      )
      .bind(
        crypto.randomUUID(),
        tenant.id,
        `Exposición temporal de carpeta sincronizada hacia plataforma externa (${tenant.name})`,
        'Se detectó sincronización no cifrada de documentos con números de cédula y correos corporativos en carpeta compartida sin política DLP activa.',
        JSON.stringify(['PA_IDENTIDAD_NATURAL', 'EMAIL_PERSONAL', 'Documentos contractuales']),
        'Revocación inmediata de enlaces externos vía Cloudflare CASB, rotación de tokens OAuth y aislamiento de estación origen.',
        'Notificación preventiva a los titulares afectados sobre cambio de credenciales y vigilancia de suplantación.',
        `${tenant.dpo_name} <${tenant.dpo_email}>`,
        breachDetected,
        breachDeadline
      )
      .run();
    breachesSeeded += 1;

    // 9. Cross-border Data Transfers
    const transferSpecs = [
      {
        recipient: 'Microsoft Corporation (Azure East US 2)',
        country: 'US',
        cross: 1,
        purpose: 'Almacenamiento y productividad corporativa M365',
        categories: ['Identificación básica', 'Correo corporativo'],
        basis: 'Cláusulas Contractuales Tipo + DPA firmado',
        dpa: 1,
        retention: 2555,
        destructor: 1,
      },
      {
        recipient: 'Public AI SaaS (Shadow AI sin contrato)',
        country: 'US',
        cross: 1,
        purpose: 'Procesamiento documental no autorizado detectado por DNS/DLP',
        categories: ['PA_IDENTIDAD_NATURAL', 'Contratos'],
        basis: 'Sin base legal válida (Shadow AI)',
        dpa: 0,
        retention: 365,
        destructor: 0,
      },
    ];
    for (const tr of transferSpecs) {
      await db
        .prepare(
          `INSERT INTO data_transfers
           (id, tenant_id, recipient_name, destination_country, is_cross_border, purpose, data_categories_json, legal_basis, dpa_contract_active, max_retention_days, destructor_verified, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          tr.recipient,
          tr.country,
          tr.cross,
          tr.purpose,
          JSON.stringify(tr.categories),
          tr.basis,
          tr.dpa,
          tr.retention,
          tr.destructor,
          nowIso
        )
        .run();
      transfersSeeded += 1;
    }

    // 10. 14-day Risk History
    const baseScore = tenant.id === 'bufete-balboa' ? 76 : tenant.id === 'banco-istmo' ? 62 : 58;
    for (let dayOffset = 13; dayOffset >= 0; dayOffset -= 1) {
      const d = new Date(now.getTime() - dayOffset * 86400_000);
      const dateStr = d.toISOString().slice(0, 10);
      const delta = (13 - dayOffset) * 0.6;
      const g = Math.max(25, Math.round((baseScore - delta) * 10) / 10);
      await db
        .prepare(
          `INSERT INTO risk_history
           (id, tenant_id, recorded_date, global_score, shadow_ai_score, storage_score, endpoints_score, casb_score, compliance_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          crypto.randomUUID(),
          tenant.id,
          dateStr,
          g,
          Math.min(100, g + 8),
          Math.max(10, g - 4),
          Math.max(10, g - 6),
          Math.max(10, g - 12),
          tenant.dpo_antai_registered ? 42 : 74
        )
        .run();
    }
  }

  // Run real health monitor evaluation to generate authentic operational alerts for OFFLINE/DEGRADED components
  const sync = await evaluateAndSyncHealth(db, null, now);

  return {
    tenants_seeded: DEMO_TENANTS.map((t) => t.id),
    components_seeded: componentsSeeded,
    alerts_active: sync.alertsCreated,
    findings_seeded: findingsSeeded,
    endpoints_seeded: endpointsSeeded,
    dsars_seeded: dsarsSeeded,
    breaches_seeded: breachesSeeded,
    transfers_seeded: transfersSeeded,
  };
}
