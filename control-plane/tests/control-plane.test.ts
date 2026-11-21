import { describe, expect, it } from 'vitest';
import worker, { app } from '../src/index';
import { sha256Hex } from '../src/auth';
import { evaluateAndSyncHealth } from '../src/health-monitor';
import {
  addPanamaBusinessDays,
  businessDaysRemaining,
  getDsarSlaBusinessDays,
  getPanamaHolidaysForYear,
} from '../src/panama-calendar';
import { createTestEnv } from './mocks';

async function insertApiToken(
  db: D1Database,
  opts: { id: string; tenantId: string | null; rawToken: string; role: string; label: string }
) {
  const hash = await sha256Hex(opts.rawToken);
  await db
    .prepare(
      `INSERT INTO api_tokens (id, tenant_id, token_sha256, role, label, active, created_at)
       VALUES (?, ?, ?, ?, ?, 1, ?)`
    )
    .bind(opts.id, opts.tenantId, hash, opts.role, opts.label, new Date().toISOString())
    .run();
}

async function seedTwoTenants(env: ReturnType<typeof createTestEnv>) {
  const authHeaders = {
    Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
    'Content-Type': 'application/json',
  };

  await app.request(
    '/api/v2/tenants',
    {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        id: 'banco-istmo',
        name: 'Banco del Istmo S.A.',
        industry: 'Banca',
        regulatory_profile: 'SBP_001_2022',
        dpo_name: 'Lic. Valeria Mendoza',
        dpo_email: 'dpo@bancoistmo.pa',
        dpo_antai_registered: true,
        dpo_antai_reg_ref: 'ANTAI-2026-01',
      }),
    },
    env
  );

  await app.request(
    '/api/v2/tenants',
    {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        id: 'clinica-pacifica',
        name: 'Clínica Pacífica',
        industry: 'Salud',
        regulatory_profile: 'SALUD_LEY68',
        dpo_name: 'Dr. Ricardo Salcedo',
        dpo_email: 'privacidad@clinicapacifica.pa',
        dpo_antai_registered: true,
        dpo_antai_reg_ref: 'ANTAI-2026-02',
      }),
    },
    env
  );
}

describe('Vektor81 v2 Control Plane', () => {
  it('allows public health ping without auth and rejects missing/invalid Bearer tokens with 401', async () => {
    const env = createTestEnv();

    const pingRes = await app.request('/api/v2/health/ping', { method: 'GET' }, env);
    expect(pingRes.status).toBe(200);
    const pingJson = (await pingRes.json()) as { ok: boolean; service: string };
    expect(pingJson.ok).toBe(true);
    expect(pingJson.service).toBe('vektor81-control-plane');

    const unauthRes = await app.request('/api/v2/tenants', { method: 'GET' }, env);
    expect(unauthRes.status).toBe(401);

    const badTokenRes = await app.request(
      '/api/v2/tenants',
      {
        method: 'GET',
        headers: { Authorization: 'Bearer wrong-token' },
      },
      env
    );
    expect(badTokenRes.status).toBe(401);
  });

  it('rejects dev API key when ENVIRONMENT is production', async () => {
    const env = createTestEnv({
      ENVIRONMENT: 'production',
      CONTROL_PLANE_ENV: 'production',
    });
    const res = await app.request(
      '/api/v2/tenants',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}` },
      },
      env
    );
    expect(res.status).toBe(401);
  });

  it('enforces strict CORS origins and never emits wildcard with credentials', async () => {
    const env = createTestEnv();

    const allowedRes = await app.request(
      '/api/v2/health/ping',
      {
        method: 'GET',
        headers: { Origin: 'http://localhost:5173' },
      },
      env
    );
    expect(allowedRes.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:5173');
    expect(allowedRes.headers.get('Access-Control-Allow-Credentials')).toBe('true');

    const deniedRes = await app.request(
      '/api/v2/health/ping',
      {
        method: 'GET',
        headers: { Origin: 'https://malicious.attacker.invalid' },
      },
      env
    );
    expect(deniedRes.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });

  it('enforces multi-tenant isolation (403 on cross-tenant access) and RBAC roles', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);

    const bancoToken = 'tok-banco-ciso-secret';
    const collectorToken = 'tok-banco-collector-secret';
    const auditorToken = 'tok-banco-auditor-secret';

    await insertApiToken(env.DB, {
      id: 'tok-1',
      tenantId: 'banco-istmo',
      rawToken: bancoToken,
      role: 'CISO',
      label: 'CISO Banco del Istmo',
    });
    await insertApiToken(env.DB, {
      id: 'tok-2',
      tenantId: 'banco-istmo',
      rawToken: collectorToken,
      role: 'COLLECTOR',
      label: 'Collector Banco del Istmo',
    });
    await insertApiToken(env.DB, {
      id: 'tok-3',
      tenantId: 'banco-istmo',
      rawToken: auditorToken,
      role: 'AUDITOR',
      label: 'Auditor Banco del Istmo',
    });

    // Cross-tenant header rejected with 403
    const crossHeaderRes = await app.request(
      '/api/v2/dashboard/ciso',
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${bancoToken}`,
          'X-Tenant-Id': 'clinica-pacifica',
        },
      },
      env
    );
    expect(crossHeaderRes.status).toBe(403);

    // Cross-tenant query rejected with 403
    const crossQueryRes = await app.request(
      '/api/v2/dashboard/ciso?tenant_id=clinica-pacifica',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${bancoToken}` },
      },
      env
    );
    expect(crossQueryRes.status).toBe(403);

    // Tenant-scoped GET /tenants returns only own tenant
    const tenantsRes = await app.request(
      '/api/v2/tenants',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${bancoToken}` },
      },
      env
    );
    expect(tenantsRes.status).toBe(200);
    const tenantsBody = (await tenantsRes.json()) as { tenants: Array<{ id: string }> };
    expect(tenantsBody.tenants.map((t) => t.id)).toEqual(['banco-istmo']);

    // Create DSAR in clinica-pacifica using MSSP admin, verify banco-istmo CISO gets 403 on its ID
    const clinicaDsarRes = await app.request(
      '/api/v2/compliance/dsar',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: 'clinica-pacifica',
          requester_name: 'Paciente Prueba',
          requester_id_masked: '8-***-9999',
          right_type: 'ACCESO',
          target_systems: ['HIS-SQL'],
        }),
      },
      env
    );
    expect(clinicaDsarRes.status).toBe(201);
    const clinicaDsarBody = (await clinicaDsarRes.json()) as { dsar: { id: string } };

    const idorAttempt = await app.request(
      `/api/v2/compliance/dsar/${clinicaDsarBody.dsar.id}/export`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${bancoToken}` },
      },
      env
    );
    expect(idorAttempt.status).toBe(403);

    // RBAC: COLLECTOR cannot read dashboards, AUDITOR cannot create DSARs
    const collectorDashboard = await app.request(
      '/api/v2/dashboard/ciso',
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${collectorToken}` },
      },
      env
    );
    expect(collectorDashboard.status).toBe(403);

    const auditorWrite = await app.request(
      '/api/v2/compliance/dsar',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${auditorToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          requester_name: 'Test',
          requester_id_masked: '8-***-1111',
          right_type: 'ACCESO',
          target_systems: [],
        }),
      },
      env
    );
    expect(auditorWrite.status).toBe(403);
  });

  it('computes Panama business days accurately across November holidays and Easter holidays', async () => {
    const holidays2026 = getPanamaHolidaysForYear(2026);
    expect(holidays2026.has('2026-02-17')).toBe(true); // Martes de Carnaval 2026
    expect(holidays2026.has('2026-04-03')).toBe(true); // Viernes Santo 2026
    expect(holidays2026.has('2026-11-03')).toBe(true);
    expect(holidays2026.has('2026-11-04')).toBe(true);
    expect(holidays2026.has('2026-11-05')).toBe(true);
    expect(holidays2026.has('2026-11-10')).toBe(true);
    expect(holidays2026.has('2026-12-20')).toBe(true);

    // Mon Nov 2, 2026 + 5 business days skips Nov 3,4,5 (holidays), Nov 7,8 (weekend), Nov 10 (holiday) -> Fri Nov 13, 2026
    const start = '2026-11-02T15:00:00.000Z';
    const due5 = addPanamaBusinessDays(start, getDsarSlaBusinessDays('RECTIFICACION'));
    expect(due5.toISOString()).toBe('2026-11-13T15:00:00.000Z');
    expect(businessDaysRemaining(start, due5)).toBe(5);

    // +10 business days (ACCESO) lands on Fri Nov 20, 2026
    const due10 = addPanamaBusinessDays(start, getDsarSlaBusinessDays('ACCESO'));
    expect(due10.toISOString()).toBe('2026-11-20T15:00:00.000Z');
    expect(businessDaysRemaining(start, due10)).toBe(10);

    // Verify via POST /api/v2/compliance/dsar
    const env = createTestEnv();
    await seedTwoTenants(env);
    const res = await app.request(
      '/api/v2/compliance/dsar',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          requester_name: 'María Pérez',
          requester_id_masked: '8-***-5521',
          right_type: 'CANCELACION',
          target_systems: ['CORE-SQL'],
          received_at: start,
        }),
      },
      env
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as {
      dsar: { sla_business_days: number; due_at: string };
    };
    expect(body.dsar.sla_business_days).toBe(5);
    expect(body.dsar.due_at).toBe('2026-11-13T15:00:00.000Z');
  });

  it('auto-creates operational alerts on OFFLINE or >15m stale heartbeats and auto-resolves on recovery', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);

    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    // 1. Healthy heartbeat -> no alerts
    const hbOnline = await app.request(
      '/api/v2/health/heartbeat',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_layer: 'ONPREM_COLLECTOR',
          component_id: 'collector-01',
          display_name: 'On-Premise Collector Principal',
          status: 'ONLINE',
          latency_ms: 14,
        }),
      },
      env
    );
    expect(hbOnline.status).toBe(200);

    let overviewRes = await app.request(
      '/api/v2/health/overview?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    let overview = (await overviewRes.json()) as {
      summary: { open_alerts: number; offline: number };
      alerts: Array<{ id: string; status: string; severity: string }>;
    };
    expect(overview.summary.open_alerts).toBe(0);

    // 2. Heartbeat explicitly reports OFFLINE -> auto-creates CRITICAL OPEN alert
    await app.request(
      '/api/v2/health/heartbeat',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_layer: 'ONPREM_COLLECTOR',
          component_id: 'collector-01',
          display_name: 'On-Premise Collector Principal',
          status: 'OFFLINE',
          last_error: 'Tunnel connection reset',
        }),
      },
      env
    );

    overviewRes = await app.request(
      '/api/v2/health/overview?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    overview = (await overviewRes.json()) as typeof overview;
    expect(overview.summary.open_alerts).toBe(1);
    expect(overview.summary.offline).toBe(1);
    expect(overview.alerts[0].status).toBe('OPEN');
    expect(overview.alerts[0].severity).toBe('CRITICAL');

    // 3. Recovery heartbeat ONLINE -> auto-resolves alert
    await app.request(
      '/api/v2/health/heartbeat',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_layer: 'ONPREM_COLLECTOR',
          component_id: 'collector-01',
          display_name: 'On-Premise Collector Principal',
          status: 'ONLINE',
          latency_ms: 12,
        }),
      },
      env
    );

    overviewRes = await app.request(
      '/api/v2/health/overview?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    overview = (await overviewRes.json()) as typeof overview;
    expect(overview.summary.open_alerts).toBe(0);
    expect(overview.alerts[0].status).toBe('RESOLVED');

    // 4. Staleness > 15 minutes evaluated via scheduled health sync -> triggers OFFLINE & alert
    const futureNow = new Date(Date.now() + 16 * 60_000);
    const staleSync = await evaluateAndSyncHealth(env.DB, 'banco-istmo', futureNow);
    expect(staleSync.statusUpdates).toBe(1);
    expect(staleSync.alertsCreated).toBe(1);

    const compAfterStale = await env.DB.prepare(
      'SELECT computed_status FROM component_heartbeats WHERE tenant_id = ? AND component_id = ?'
    )
      .bind('banco-istmo', 'collector-01')
      .first<{ computed_status: string }>();
    expect(compAfterStale?.computed_status).toBe('OFFLINE');
  });

  it('generates 72h ANTAI breach draft containing all 5 DE 285 Art. 37 elements', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);

    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    const detectedAt = '2026-11-21T10:00:00.000Z';
    const createRes = await app.request(
      '/api/v2/compliance/breaches',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          title: 'Fuga temporal de listado de tarjetas en carpeta sin DLP',
          severity: 'CRITICAL',
          what_happened: 'Sincronización indebida de archivo CSV hacia cuenta externa sin cifrado.',
          compromised_data_types: ['PA_TARJETA_PAGO', 'PA_IDENTIDAD_NATURAL'],
          affected_records_estimate: 145,
          measures_adopted: 'Bloqueo de cuenta, revocación de sesión CASB y rotación de llaves.',
          titular_actions: 'Aviso inmediato a tarjetahabientes y monitoreo antifraude preventivo.',
          contact_point: 'Lic. Valeria Mendoza <dpo@bancoistmo.pa>',
          detected_at: detectedAt,
        }),
      },
      env
    );
    expect(createRes.status).toBe(201);
    const createJson = (await createRes.json()) as {
      breach: { id: string; deadline_72h_at: string };
    };
    expect(createJson.breach.deadline_72h_at).toBe('2026-11-24T10:00:00.000Z');

    const draftRes = await app.request(
      `/api/v2/compliance/breaches/${createJson.breach.id}/antai-draft`,
      { method: 'GET', headers },
      env
    );
    expect(draftRes.status).toBe(200);
    const draft = (await draftRes.json()) as {
      legal_basis: string;
      ready_for_submission: boolean;
      five_required_elements: {
        what_happened: string;
        compromised_data_types: string[];
        measures_adopted: string;
        titular_actions: string;
        contact_point: string;
      };
    };

    expect(draft.legal_basis).toContain('Art. 37');
    expect(draft.legal_basis).toContain('Art. 48.3');
    expect(draft.ready_for_submission).toBe(true);
    expect(draft.five_required_elements.what_happened).toContain('Sincronización indebida');
    expect(draft.five_required_elements.compromised_data_types).toEqual([
      'PA_TARJETA_PAGO',
      'PA_IDENTIDAD_NATURAL',
    ]);
    expect(draft.five_required_elements.measures_adopted).toContain('CASB');
    expect(draft.five_required_elements.titular_actions).toContain('tarjetahabientes');
    expect(draft.five_required_elements.contact_point).toContain('dpo@bancoistmo.pa');
  });

  it('generates Ficha Técnica snapshot, stores JSON in R2, and verifies SHA-256 integrity', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);

    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    const genRes = await app.request(
      '/api/v2/compliance/ficha-tecnica/generate',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({ tenant_id: 'banco-istmo' }),
      },
      env
    );
    expect(genRes.status).toBe(201);
    const genBody = (await genRes.json()) as {
      ok: boolean;
      sha256_hash: string;
      r2_object_key: string;
      snapshot: { version_num: number; sha256_hash: string };
    };
    expect(genBody.ok).toBe(true);
    expect(genBody.sha256_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(genBody.snapshot.version_num).toBe(1);

    const r2Obj = await env.EVIDENCE_BUCKET.get(genBody.r2_object_key);
    expect(r2Obj).not.toBeNull();
    const rawText = await r2Obj!.text();
    const expectedHash = await sha256Hex(rawText);
    expect(genBody.sha256_hash).toBe(expectedHash);

    const listRes = await app.request(
      '/api/v2/compliance/ficha-tecnica?tenant_id=banco-istmo&include_latest=true',
      { method: 'GET', headers },
      env
    );
    expect(listRes.status).toBe(200);
    const listBody = (await listRes.json()) as {
      integrity_verified: boolean;
      snapshots: Array<{ version_num: number }>;
    };
    expect(listBody.integrity_verified).toBe(true);
    expect(listBody.snapshots).toHaveLength(1);
  });

  it('ingests CASB webhooks and calculates auto-remediation percentage accurately', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);

    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    const payloads = [
      {
        tenant_id: 'banco-istmo',
        event_id: 'evt-1',
        saas_app: 'Microsoft 365',
        resource_name: 'SharePoint/Planilla.xlsx',
        finding_type: 'PUBLIC_SHARE',
        exposure_level: 'PUBLIC_LINK',
        remediated_automatically: true,
        remediation_action: 'Link revoked',
        severity: 'CRITICAL',
        detected_at: '2026-11-21T10:00:00.000Z',
        remediated_at: '2026-11-21T10:02:00.000Z',
      },
      {
        tenant_id: 'banco-istmo',
        event_id: 'evt-2',
        saas_app: 'Google Workspace',
        resource_name: 'Drive/Cedulas.pdf',
        finding_type: 'EXTERNAL_SHARE',
        exposure_level: 'EXTERNAL_SHARE',
        remediated_automatically: true,
        remediation_action: 'Removed external viewer',
        severity: 'HIGH',
        detected_at: '2026-11-21T10:05:00.000Z',
        remediated_at: '2026-11-21T10:07:00.000Z',
      },
      {
        tenant_id: 'banco-istmo',
        event_id: 'evt-3',
        saas_app: 'Box',
        resource_name: 'Contratos/Fideicomiso.docx',
        finding_type: 'PII_DETECTED',
        exposure_level: 'PII_DETECTED',
        remediated_automatically: true,
        remediation_action: 'Quarantined file',
        severity: 'HIGH',
        detected_at: '2026-11-21T10:10:00.000Z',
        remediated_at: '2026-11-21T10:12:00.000Z',
      },
      {
        tenant_id: 'banco-istmo',
        event_id: 'evt-4',
        saas_app: 'AWS S3',
        resource_name: 's3://istmo-backup-temp',
        finding_type: 'BUCKET_PUBLIC_ACL',
        exposure_level: 'PUBLIC_LINK',
        remediated_automatically: false,
        severity: 'CRITICAL',
        detected_at: '2026-11-21T10:15:00.000Z',
        remediated_at: null,
      },
    ];

    for (const p of payloads) {
      const res = await app.request(
        '/api/v2/ingest/casb-webhook',
        { method: 'POST', headers, body: JSON.stringify(p) },
        env
      );
      expect(res.status).toBe(200);
    }

    const cisoRes = await app.request(
      '/api/v2/dashboard/ciso?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    expect(cisoRes.status).toBe(200);
    const cisoBody = (await cisoRes.json()) as {
      risk: { kpis: { casb_auto_remediation_pct: number; mttr_minutes: number } };
    };
    expect(cisoBody.risk.kpis.casb_auto_remediation_pct).toBe(75);
    expect(cisoBody.risk.kpis.mttr_minutes).toBe(2);

    const socRes = await app.request(
      '/api/v2/dashboard/soc-health?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    expect(socRes.status).toBe(200);
    const socBody = (await socRes.json()) as {
      casb_summary: { total_events: number; auto_remediation_pct: number };
    };
    expect(socBody.casb_summary.total_events).toBe(4);
    expect(socBody.casb_summary.auto_remediation_pct).toBe(75);
  });

  it('seeds 3 Panamanian tenants via seed-demo with OFFLINE/DEGRADED visibility and runs scheduled cron', async () => {
    const env = createTestEnv();
    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    const seedRes = await app.request(
      '/api/v2/admin/seed-demo',
      { method: 'POST', headers },
      env
    );
    expect(seedRes.status).toBe(200);
    const seedBody = (await seedRes.json()) as {
      ok: boolean;
      tenants_seeded: string[];
      alerts_active: number;
    };
    expect(seedBody.ok).toBe(true);
    expect(seedBody.tenants_seeded).toEqual(['banco-istmo', 'clinica-pacifica', 'bufete-balboa']);
    expect(seedBody.alerts_active).toBeGreaterThanOrEqual(3);

    // Scheduled handler executes without throwing
    await expect(
      worker.scheduled(
        { cron: '*/5 * * * *', scheduledTime: Date.now(), noRetry: () => {} } as ScheduledController,
        env,
        { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext
      )
    ).resolves.toBeUndefined();

    // DPO view on clinica-pacifica reflects SALUD_LEY68 20-year retention mandate
    const clinicaDpo = await app.request(
      '/api/v2/dashboard/dpo?tenant_id=clinica-pacifica',
      { method: 'GET', headers },
      env
    );
    expect(clinicaDpo.status).toBe(200);
    const clinicaBody = (await clinicaDpo.json()) as {
      regulatory_context: { retention_rule: string };
      retention_summary: { violations_count: number };
    };
    expect(clinicaBody.regulatory_context.retention_rule).toContain('20 años');
    // Only the administrative 2017 billing finding counts as violation, not clinical history under 20y
    expect(clinicaBody.retention_summary.violations_count).toBe(1);

    // Outage simulator gated by ENABLE_DEMO_TOOLS
    const disabledEnv = createTestEnv({ ENABLE_DEMO_TOOLS: 'false' });
    const simBlocked = await app.request(
      '/api/v2/health/simulate-outage',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${disabledEnv.VEKTOR81_DEV_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_id: 'banco-istmo-collector-01',
          target_status: 'OFFLINE',
        }),
      },
      disabledEnv
    );
    expect(simBlocked.status).toBe(403);
  });

  it('ingests endpoint, findings, shadow-ai, logpush, transfers and renders assets & CISO heatmap', async () => {
    const env = createTestEnv();
    await seedTwoTenants(env);
    const headers = {
      Authorization: `Bearer ${env.VEKTOR81_DEV_API_KEY}`,
      'Content-Type': 'application/json',
    };

    // Endpoint ingest
    const epRes = await app.request(
      '/api/v2/ingest/endpoint',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          hostname: 'ISTMO-FIN-09',
          username: 'ISTMO\\jdoe',
          ip_address: '10.20.1.9',
          shadow_ai_dns_hits: [{ domain: 'chatgpt.com', count: 10, category: 'LLM Conversacional' }],
          risky_extensions: [
            {
              extension_id: 'ext-1',
              name: 'Free PDF AI',
              browser: 'Chrome',
              permissions: ['<all_urls>'],
              has_all_urls: true,
            },
          ],
          box_audit: {
            provider: 'BoxDrive',
            installed: true,
            sync_path: 'C:\\Users\\jdoe\\Box',
            total_synced_files: 40,
            sensitive_files_count: 4,
            dlp_enabled: false,
            sample_files_masked: ['Planilla_****.xlsx'],
          },
        }),
      },
      env
    );
    expect(epRes.status).toBe(200);

    // Findings batch ingest
    const findRes = await app.request(
      '/api/v2/ingest/findings',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          scan_id: 'scan-001',
          scanner_layer: 'SMB_CONNECTOR',
          is_simulated: false,
          total_assets_scanned: 50,
          scan_duration_ms: 420,
          findings: [
            {
              source_type: 'SMB',
              repository_name: '\\\\FS01\\Planilla',
              location_path: 'nomina_2026.xlsx',
              entity_type: 'PA_IDENTIDAD_NATURAL',
              masked_sample: '8-***-1234',
              value_sha256: 'abc123',
              match_count: 25,
              is_sensitive: false,
              severity: 'HIGH',
              retention_age_days: 120,
              retention_violation: false,
            },
            {
              source_type: 'SQL_DB',
              repository_name: 'CORE_SQL',
              location_path: 'dbo.clientes.dx',
              entity_type: 'PA_TARJETA_PAGO',
              masked_sample: '4532-****-****-0366',
              value_sha256: 'def456',
              match_count: 10,
              is_sensitive: true,
              severity: 'CRITICAL',
              retention_age_days: 3000,
              retention_violation: true,
            },
          ],
        }),
      },
      env
    );
    expect(findRes.status).toBe(200);

    // Shadow AI & Logpush & Transfer ingest
    const shadowRes = await app.request(
      '/api/v2/ingest/shadow-ai',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          source: 'ADGUARD_DNS',
          total_queries_inspected: 500,
          events: [
            {
              client_ip: '10.20.1.9',
              hostname: 'ISTMO-FIN-09',
              domain: 'claude.ai',
              category: 'LLM Conversacional',
              hits: 7,
              blocked: false,
            },
          ],
        }),
      },
      env
    );
    expect(shadowRes.status).toBe(200);

    const logpushRes = await app.request(
      '/api/v2/ingest/logpush',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          dataset: 'dlp_forensic',
          records_count: 250,
          lag_seconds: 15.2,
          encrypted_with_customer_key: true,
          summary_counts: { blocked: 4 },
        }),
      },
      env
    );
    expect(logpushRes.status).toBe(200);

    const transferRes = await app.request(
      '/api/v2/compliance/transfers',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          recipient_name: 'OpenAI API',
          destination_country: 'US',
          is_cross_border: true,
          purpose: 'Asistencia documental',
          data_categories: ['PA_IDENTIDAD_NATURAL'],
          legal_basis: 'Pendiente DPA',
          dpa_contract_active: false,
          max_retention_days: 30,
        }),
      },
      env
    );
    expect(transferRes.status).toBe(201);

    // Verify CISO heatmap & assets dashboard
    const cisoRes = await app.request(
      '/api/v2/dashboard/ciso?tenant_id=banco-istmo',
      { method: 'GET', headers },
      env
    );
    expect(cisoRes.status).toBe(200);
    const cisoJson = (await cisoRes.json()) as {
      risk: {
        heatmap: { matrix: Record<string, Record<string, number>> };
        kpis: { unprotected_cross_border_transfers: number };
      };
    };
    expect(cisoJson.risk.heatmap.matrix.PA_IDENTIDAD_NATURAL.SMB).toBe(25);
    expect(cisoJson.risk.heatmap.matrix.PA_TARJETA_PAGO.SQL_DB).toBe(10);
    expect(cisoJson.risk.kpis.unprotected_cross_border_transfers).toBe(1);

    const assetsRes = await app.request(
      '/api/v2/dashboard/assets?tenant_id=banco-istmo&source_type=SQL_DB',
      { method: 'GET', headers },
      env
    );
    expect(assetsRes.status).toBe(200);
    const assetsJson = (await assetsRes.json()) as {
      endpoints: Array<{ hostname: string }>;
      findings: Array<{ source_type: string }>;
    };
    expect(assetsJson.endpoints[0].hostname).toBe('ISTMO-FIN-09');
    expect(assetsJson.findings).toHaveLength(1);
    expect(assetsJson.findings[0].source_type).toBe('SQL_DB');

    // Heartbeat -> simulate outage -> ack -> resolve flow
    await app.request(
      '/api/v2/health/heartbeat',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_layer: 'TUNNEL',
          component_id: 'tunnel-istmo',
          display_name: 'Cloudflare Tunnel Istmo',
          status: 'ONLINE',
        }),
      },
      env
    );
    const simRes = await app.request(
      '/api/v2/health/simulate-outage',
      {
        method: 'POST',
        headers,
        body: JSON.stringify({
          tenant_id: 'banco-istmo',
          component_id: 'tunnel-istmo',
          target_status: 'DEGRADED',
          backdate_minutes: 7,
        }),
      },
      env
    );
    expect(simRes.status).toBe(200);
    const simJson = (await simRes.json()) as {
      alerts: Array<{ id: string; status: string }>;
    };
    const alertId = simJson.alerts[0].id;

    const ackRes = await app.request(
      `/api/v2/health/alerts/${alertId}/ack`,
      { method: 'POST', headers },
      env
    );
    expect(ackRes.status).toBe(200);
    expect(((await ackRes.json()) as { alert: { status: string } }).alert.status).toBe(
      'ACKNOWLEDGED'
    );

    const resolveRes = await app.request(
      `/api/v2/health/alerts/${alertId}/resolve`,
      { method: 'POST', headers },
      env
    );
    expect(resolveRes.status).toBe(200);
    expect(((await resolveRes.json()) as { alert: { status: string } }).alert.status).toBe(
      'RESOLVED'
    );
  });
});
