import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import { Layout } from '../components/Layout';
import { AssetsAdminPage } from '../pages/AssetsAdminPage';
import { CisoOverviewPage } from '../pages/CisoOverviewPage';
import { ComplianceDpoPage } from '../pages/ComplianceDpoPage';
import { SystemHealthPage } from '../pages/SystemHealthPage';
import type {
  AssetsDashboardResponse,
  CisoDashboardResponse,
  DpoDashboardResponse,
  HealthOverviewResponse,
  SocHealthDashboardResponse,
  Tenant,
} from '../types';

const TENANT_BANCO: Tenant = {
  id: 'banco-istmo',
  name: 'Banco del Istmo S.A.',
  industry: 'Banca y Servicios Financieros',
  regulatory_profile: 'SBP_001_2022',
  dpo_name: 'Lic. Valeria Mendoza',
  dpo_email: 'dpo@bancoistmo.pa',
  dpo_antai_registered: 1,
  dpo_antai_reg_ref: 'ANTAI-DPO-2026-0142',
  active: 1,
  created_at: '2026-11-21T10:00:00.000Z',
};

function makeHealthFixtures(): {
  overview: HealthOverviewResponse;
  socHealth: SocHealthDashboardResponse;
} {
  const nowIso = new Date().toISOString();
  const oldIso = new Date(Date.now() - 25 * 60_000).toISOString();

  const components = [
    {
      id: 'hb-ctrl',
      tenant_id: 'banco-istmo',
      component_layer: 'CONTROL_PLANE' as const,
      component_id: 'banco-istmo-ctrl-edge',
      display_name: 'Cloudflare Workers Control Plane',
      reported_status: 'ONLINE' as const,
      computed_status: 'ONLINE' as const,
      latency_ms: 14,
      version: '2.0.0',
      cpu_pct: 12.4,
      ram_mb: 128,
      uptime_pct_24h: 100,
      last_error: null,
      metadata_json: '{}',
      last_heartbeat_at: nowIso,
      updated_at: nowIso,
    },
    {
      id: 'hb-adguard',
      tenant_id: 'banco-istmo',
      component_layer: 'ADGUARD_DNS' as const,
      component_id: 'banco-istmo-adguard-dns-01',
      display_name: 'AdGuard DNS Shadow-AI Sensor',
      reported_status: 'OFFLINE' as const,
      computed_status: 'OFFLINE' as const,
      latency_ms: 0,
      version: '2.0.0',
      cpu_pct: 0,
      ram_mb: 256,
      uptime_pct_24h: 88.5,
      last_error: 'No response from http://adguard:3000/control/querylog',
      metadata_json: '{}',
      last_heartbeat_at: oldIso,
      updated_at: nowIso,
    },
  ];

  const alerts = [
    {
      id: 'alert-adguard-01',
      tenant_id: 'banco-istmo',
      component_id: 'banco-istmo-adguard-dns-01',
      component_layer: 'ADGUARD_DNS' as const,
      severity: 'CRITICAL' as const,
      status: 'OPEN' as const,
      title: '[ADGUARD_DNS] AdGuard DNS Shadow-AI Sensor en estado OFFLINE',
      details: 'Sin heartbeat por 25m (> 15m límite) | Último error: querylog timeout',
      triggered_at: nowIso,
      acknowledged_at: null,
      resolved_at: null,
    },
  ];

  const summary = {
    total_components: 2,
    online: 1,
    degraded: 0,
    offline: 1,
    stale: 0,
    open_alerts: 1,
    acknowledged_alerts: 0,
    resolved_alerts: 0,
    critical_alerts: 1,
    avg_latency_ms: 14,
  };

  return {
    overview: {
      tenant_id: 'banco-istmo',
      summary,
      components,
      alerts,
      sync: { evaluated: 2, statusUpdates: 0, alertsCreated: 0, alertsResolved: 0 },
    },
    socHealth: {
      tenant_id: 'banco-istmo',
      summary,
      layers: [],
      components,
      alerts,
      casb_summary: {
        total_events: 4,
        auto_remediated_count: 3,
        auto_remediation_pct: 75,
        recent_events: [],
      },
      logpush_summary: {
        total_batches: 1,
        total_records: 1420,
        avg_lag_seconds: 12.5,
        cmk_encrypted_pct: 100,
        recent_batches: [],
      },
      sync: { evaluated: 2, statusUpdates: 0, alertsCreated: 0, alertsResolved: 0 },
    },
  };
}

function makeCisoFixture(): CisoDashboardResponse {
  return {
    tenant: {
      id: 'banco-istmo',
      name: 'Banco del Istmo S.A.',
      industry: 'Banca y Servicios Financieros',
      regulatory_profile: 'SBP_001_2022',
      dpo_antai_registered: true,
    },
    risk: {
      global_score: 64.2,
      semaphore: 'AMARILLO',
      vectors: {
        shadow_ai: 72,
        storage: 68,
        casb: 41,
        endpoints: 55,
        compliance: 48,
      },
      regulatory_context: {
        profile: 'SBP_001_2022',
        framework_title: 'Acuerdo 001-2022 SBP (Ciberseguridad Bancaria) + Ley 81 / DE 285',
        primary_regulator: 'Superintendencia de Bancos de Panamá (SBP) & ANTAI',
        fine_range_pab: 'B/. 1,000 a B/. 10,000 (ANTAI) + sanciones prudenciales SBP',
        breach_notification_rule: 'DE 285 Art. 37 y Art. 48.3 (72h ANTAI)',
        retention_rule: 'Retención general máxima de 7 años',
        sanction_risks: [
          'Multas administrativas de B/. 1,000 a B/. 10,000 según gravedad',
          'Clausura temporal o definitiva del almacenamiento/registro de datos personales',
        ],
        profile_specific_mandates: [
          'Supervisión directa de Junta Directiva sobre ciberseguridad (Acuerdo 001-2022 SBP)',
        ],
      },
      kpis: {
        mttd_minutes: 4.5,
        mttr_minutes: 12.3,
        asset_coverage_pct: 91.7,
        casb_auto_remediation_pct: 75,
        total_shadow_ai_hits: 85,
        unblocked_shadow_ai_hits: 73,
        total_findings: 4,
        sensitive_findings: 1,
        retention_violations: 1,
        open_operational_alerts: 1,
        overdue_dsars: 1,
        active_breaches_within_72h: 1,
        overdue_breaches_72h: 0,
        unprotected_cross_border_transfers: 1,
      },
      heatmap: {
        entity_types: [
          'PA_IDENTIDAD_NATURAL',
          'PA_PASAPORTE',
          'PA_DATO_SENSIBLE_SALUD',
          'PA_TARJETA_PAGO',
          'PA_SWIFT_PA',
          'EMAIL_PERSONAL',
        ],
        source_types: ['SMB', 'SQL_DB', 'OCR_IMAGE', 'CASB', 'DLP_EDGE'],
        cells: [
          {
            entity_type: 'PA_TARJETA_PAGO',
            source_type: 'SQL_DB',
            findings_count: 1,
            total_matches: 148,
            sensitive_count: 1,
            max_severity: 'CRITICAL',
          },
          {
            entity_type: 'PA_IDENTIDAD_NATURAL',
            source_type: 'OCR_IMAGE',
            findings_count: 1,
            total_matches: 19,
            sensitive_count: 0,
            max_severity: 'HIGH',
          },
        ],
        matrix: {
          PA_IDENTIDAD_NATURAL: { SMB: 0, SQL_DB: 0, OCR_IMAGE: 19, CASB: 0, DLP_EDGE: 0 },
          PA_PASAPORTE: { SMB: 0, SQL_DB: 0, OCR_IMAGE: 0, CASB: 0, DLP_EDGE: 0 },
          PA_DATO_SENSIBLE_SALUD: { SMB: 0, SQL_DB: 0, OCR_IMAGE: 0, CASB: 0, DLP_EDGE: 0 },
          PA_TARJETA_PAGO: { SMB: 0, SQL_DB: 148, OCR_IMAGE: 0, CASB: 0, DLP_EDGE: 0 },
          PA_SWIFT_PA: { SMB: 42, SQL_DB: 0, OCR_IMAGE: 0, CASB: 0, DLP_EDGE: 0 },
          EMAIL_PERSONAL: { SMB: 0, SQL_DB: 0, OCR_IMAGE: 0, CASB: 0, DLP_EDGE: 0 },
        },
      },
      legal_findings: [
        {
          citation: 'Ley 81 de 2019 Art. 6, 15 y 33; DE 285 Art. 28-31',
          severity: 'CRITICAL',
          vector: 'SHADOW_AI_CROSS_BORDER',
          summary: '73 consultas Shadow AI sin bloqueo hacia dominios LLM.',
        },
      ],
    },
    risk_history: [
      {
        id: 'rh-1',
        tenant_id: 'banco-istmo',
        recorded_date: '2026-11-20',
        global_score: 66.0,
        shadow_ai_score: 74,
        storage_score: 68,
        endpoints_score: 55,
        casb_score: 41,
        compliance_score: 48,
      },
      {
        id: 'rh-2',
        tenant_id: 'banco-istmo',
        recorded_date: '2026-11-21',
        global_score: 64.2,
        shadow_ai_score: 72,
        storage_score: 68,
        endpoints_score: 55,
        casb_score: 41,
        compliance_score: 48,
      },
    ],
    top_shadow_ai_domains: [
      { domain: 'chatgpt.com', category: 'LLM Conversacional', hits: 34, blocked_hits: 0 },
      { domain: 'deepseek.com', category: 'LLM Conversacional', hits: 12, blocked_hits: 12 },
    ],
    top_risky_repositories: [
      {
        repository_name: 'CORE-TARJETAS-SQL',
        source_type: 'SQL_DB',
        findings_count: 1,
        total_matches: 148,
      },
    ],
  };
}

function makeDpoFixture(): DpoDashboardResponse {
  const futureDeadline = new Date(Date.now() + 50 * 3600_000).toISOString();
  const nowIso = new Date().toISOString();
  return {
    tenant: {
      id: 'banco-istmo',
      name: 'Banco del Istmo S.A.',
      industry: 'Banca y Servicios Financieros',
      regulatory_profile: 'SBP_001_2022',
    },
    regulatory_context: {
      profile: 'SBP_001_2022',
      framework_title: 'Acuerdo 001-2022 SBP + Ley 81 / DE 285',
      primary_regulator: 'SBP & ANTAI',
      fine_range_pab: 'B/. 1,000 a B/. 10,000',
      breach_notification_rule: 'DE 285 Art. 37 y Art. 48.3 (72h)',
      retention_rule: 'Retención general máxima de 7 años tras finalizar relación comercial',
      sanction_risks: [],
      profile_specific_mandates: [],
    },
    dpo_governance: {
      dpo_name: 'Lic. Valeria Mendoza',
      dpo_email: 'dpo@bancoistmo.pa',
      dpo_antai_registered: true,
      dpo_antai_reg_ref: 'ANTAI-DPO-2026-0142',
      compliant: true,
    },
    dsars: [
      {
        id: 'dsar-1',
        tenant_id: 'banco-istmo',
        requester_name: 'Carlos Eduardo Quintero',
        requester_id_masked: '8-***-4410',
        right_type: 'ACCESO',
        sla_business_days: 10,
        received_at: nowIso,
        due_at: new Date(Date.now() + 10 * 86400_000).toISOString(),
        status: 'IN_PROGRESS',
        target_systems_json: '["CORE-SQL"]',
        target_systems: ['CORE-SQL'],
        notes: null,
        completed_at: null,
        evidence_json: '{}',
        evidence: {},
        business_days_remaining: 8,
        is_overdue: false,
      },
      {
        id: 'dsar-2',
        tenant_id: 'banco-istmo',
        requester_name: 'Ana Lucía Villarreal',
        requester_id_masked: '4-***-8821',
        right_type: 'CANCELACION',
        sla_business_days: 5,
        received_at: nowIso,
        due_at: new Date(Date.now() - 2 * 86400_000).toISOString(),
        status: 'PENDING',
        target_systems_json: '["CRM-Ventas"]',
        target_systems: ['CRM-Ventas'],
        notes: null,
        completed_at: null,
        evidence_json: '{}',
        evidence: {},
        business_days_remaining: -2,
        is_overdue: true,
      },
    ],
    breaches: [
      {
        id: 'breach-1',
        tenant_id: 'banco-istmo',
        title: 'Exposición temporal de carpeta sincronizada',
        severity: 'HIGH',
        status: 'CONTAINING',
        what_happened: 'Sincronización indebida hacia carpeta externa.',
        compromised_data_types_json: '["PA_IDENTIDAD_NATURAL"]',
        compromised_data_types: ['PA_IDENTIDAD_NATURAL'],
        affected_records_estimate: 38,
        measures_adopted: 'Revocación de enlaces CASB y rotación de tokens.',
        titular_actions: 'Notificación preventiva a titulares afectados.',
        contact_point: 'Lic. Valeria Mendoza <dpo@bancoistmo.pa>',
        detected_at: nowIso,
        deadline_72h_at: futureDeadline,
        antai_notified_at: null,
        hours_remaining_72h: 50,
        is_overdue_72h: false,
        art37_complete: true,
        missing_art37_elements: [],
      },
    ],
    transfers: [
      {
        id: 'tr-1',
        tenant_id: 'banco-istmo',
        recipient_name: 'Public AI SaaS (Shadow AI)',
        destination_country: 'US',
        is_cross_border: true,
        purpose: 'Procesamiento documental sin contrato',
        data_categories_json: '["PA_IDENTIDAD_NATURAL"]',
        data_categories: ['PA_IDENTIDAD_NATURAL'],
        legal_basis: 'Sin base legal válida',
        dpa_contract_active: false,
        max_retention_days: 365,
        destructor_verified: false,
        dpa_gap: true,
        created_at: nowIso,
      },
    ],
    retention_summary: {
      total_findings_with_age: 4,
      violations_count: 1,
      max_age_days: 3100,
      rule_description: 'Retención general máxima de 7 años tras finalizar relación comercial',
    },
    ficha_tecnica_snapshots: [
      {
        id: 'ficha-1',
        tenant_id: 'banco-istmo',
        version_num: 1,
        regulatory_profile: 'SBP_001_2022',
        r2_object_key: 'ficha-tecnica/banco-istmo/v1.json',
        sha256_hash: 'a'.repeat(64),
        generated_by: 'MSSP_ADMIN:test',
        generated_at: nowIso,
      },
    ],
  };
}

describe('Vektor81 CISO / SOC / DPO Hybrid Dashboard', () => {
  beforeEach(() => {
    window.sessionStorage.setItem('vektor81_api_token', 'test-bearer-token');
  });

  it('renders Layout + SystemHealthPage with OFFLINE ADGUARD_DNS, global outage banner, OFFLINE badge and Ack action', async () => {
    const { overview, socHealth } = makeHealthFixtures();

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v2/dashboard/soc-health')) {
        return new Response(JSON.stringify(socHealth), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.includes('/api/v2/health/alerts/alert-adguard-01/ack')) {
        expect(init?.method).toBe('POST');
        expect((init?.headers as Record<string, string>)?.Authorization).toBe(
          'Bearer test-bearer-token'
        );
        return new Response(
          JSON.stringify({
            ok: true,
            alert: {
              ...socHealth.alerts[0],
              status: 'ACKNOWLEDGED',
              acknowledged_at: new Date().toISOString(),
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ error: 'Not mocked' }), { status: 404 });
    });

    vi.stubGlobal('fetch', fetchMock);

    render(
      <Layout
        activeTab="health"
        onSelectTab={vi.fn()}
        healthOverview={overview}
        tenants={[TENANT_BANCO]}
        selectedTenantId="banco-istmo"
        onSelectTenant={vi.fn()}
      >
        <SystemHealthPage tenantId="banco-istmo" />
      </Layout>
    );

    const banner = await screen.findByTestId('global-outage-banner');
    expect(banner).toHaveTextContent('1 OFFLINE');
    expect(banner).toHaveTextContent('AdGuard DNS Shadow-AI Sensor');

    const compCard = await screen.findByTestId('component-card-banco-istmo-adguard-dns-01');
    expect(within(compCard).getByText('OFFLINE')).toBeInTheDocument();

    const alertRow = screen.getByTestId('alert-row-alert-adguard-01');
    const ackBtn = within(alertRow).getByRole('button', { name: /^Ack$/i });
    expect(ackBtn).toBeInTheDocument();
    fireEvent.click(ackBtn);

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v2/health/alerts/alert-adguard-01/ack',
        expect.objectContaining({ method: 'POST' })
      );
    });
    expect(await within(alertRow).findByText('ACKNOWLEDGED')).toBeInTheDocument();
  });

  it('renders CisoOverviewPage with MTTD, MTTR, CASB Auto-Remediation %, B/. 1,000, and Heatmap', async () => {
    const cisoFixture = makeCisoFixture();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v2/dashboard/ciso')) {
        return new Response(JSON.stringify(cisoFixture), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({}), { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<CisoOverviewPage tenantId="banco-istmo" />);

    expect(await screen.findByText('SEMÁFORO AMARILLO')).toBeInTheDocument();
    expect(screen.getAllByText(/B\/\. 1,000 a B\/\. 10,000/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('MTTD (Detección)')).toBeInTheDocument();
    expect(screen.getByTestId('kpi-mttd')).toHaveTextContent('4.5');
    expect(screen.getByText('MTTR (Respuesta)')).toBeInTheDocument();
    expect(screen.getByTestId('kpi-mttr')).toHaveTextContent('12.3');
    expect(screen.getByText('Remediación Automática CASB')).toBeInTheDocument();
    expect(screen.getByTestId('kpi-casb-rem')).toHaveTextContent('75');

    const heatmapTable = screen.getByTestId('exposure-heatmap-table');
    expect(within(heatmapTable).getByText('PA_TARJETA_PAGO')).toBeInTheDocument();
    expect(within(heatmapTable).getByText('PA_IDENTIDAD_NATURAL')).toBeInTheDocument();

    const tarjetaSqlCell = screen.getByTestId('heatmap-cell-PA_TARJETA_PAGO-SQL_DB');
    expect(within(tarjetaSqlCell).getByText('148')).toBeInTheDocument();
    expect(within(tarjetaSqlCell).getByText('SENSIBLE')).toBeInTheDocument();
  });

  it('renders ComplianceDpoPage with 72h breach countdown, 5 DE 285 Art. 37 elements, and ARCO-P business-days SLA table', async () => {
    const dpoFixture = makeDpoFixture();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v2/dashboard/dpo')) {
        return new Response(JSON.stringify(dpoFixture), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.includes('/api/v2/compliance/ficha-tecnica')) {
        return new Response(
          JSON.stringify({
            tenant_id: 'banco-istmo',
            snapshots: dpoFixture.ficha_tecnica_snapshots,
            selected_snapshot: dpoFixture.ficha_tecnica_snapshots[0],
            integrity_verified: true,
            document: {},
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({}), { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ComplianceDpoPage tenantId="banco-istmo" />);

    const countdown = await screen.findByTestId('breach-countdown-breach-1');
    expect(countdown.textContent).toMatch(/restantes/);

    expect(screen.getByText('5/5 COMPLETO PARA ANTAI')).toBeInTheDocument();
    expect(screen.getByText(/1\. Qué ocurrió/)).toBeInTheDocument();
    expect(screen.getByText(/2\. Tipos de datos personales comprometidos/)).toBeInTheDocument();
    expect(screen.getByText(/3\. Medidas técnicas y organizativas adoptadas/)).toBeInTheDocument();
    expect(screen.getByText(/4\. Acciones recomendadas a los titulares/)).toBeInTheDocument();
    expect(screen.getByText(/5\. Punto de contacto/)).toBeInTheDocument();

    const arcoTable = screen.getByTestId('arco-dsar-table');
    expect(within(arcoTable).getByText('ACCESO')).toBeInTheDocument();
    expect(within(arcoTable).getByText('10 días hábiles')).toBeInTheDocument();
    expect(within(arcoTable).getByText('8 días hábiles')).toBeInTheDocument();
    expect(within(arcoTable).getByText('CANCELACION')).toBeInTheDocument();
    expect(within(arcoTable).getByText('5 días hábiles')).toBeInTheDocument();
    expect(within(arcoTable).getByText(/VENCIDO/)).toBeInTheDocument();

    expect(screen.getByText('SIN DPA ACTIVO')).toBeInTheDocument();
    expect(await screen.findByText('SHA-256 VERIFICADO R2')).toBeInTheDocument();
  });

  it('shows SOC/CISO Auth Gate when no token is present and keeps simulate_if_unreachable unchecked by default in AssetsAdminPage', async () => {
    window.sessionStorage.clear();
    render(<App />);
    expect(await screen.findByText('SOC / CISO Authentication Gate')).toBeInTheDocument();

    const assetsData: AssetsDashboardResponse = {
      tenant_id: 'banco-istmo',
      summary: {
        endpoints_total: 0,
        endpoints_with_all_urls: 0,
        endpoints_box_unprotected: 0,
        findings_total: 0,
        sensitive_findings_total: 0,
        shadow_ai_events_total: 0,
      },
      endpoints: [],
      findings: [],
      shadow_ai_events: [],
    };
    window.sessionStorage.setItem('vektor81_api_token', 'test-bearer-token');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify(assetsData), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    );

    render(<AssetsAdminPage tenantId="banco-istmo" tenants={[TENANT_BANCO]} />);
    const simCheckboxes = await screen.findAllByLabelText(/Simular si no hay red \(Demo\)/i);
    expect(simCheckboxes).toHaveLength(2);
    for (const cb of simCheckboxes) {
      expect((cb as HTMLInputElement).checked).toBe(false);
    }
  });
});
