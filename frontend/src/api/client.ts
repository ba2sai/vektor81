import type {
  AlertSeverity,
  AntaiBreachDraftResponse,
  AssetsDashboardResponse,
  BreachCreatePayload,
  BreachIncident,
  BreachUpdatePayload,
  CisoDashboardResponse,
  DataTransfer,
  DbScanRequest,
  DnsStatsResponse,
  DpoDashboardResponse,
  DsarCreatePayload,
  DsarRequest,
  DsarUpdatePayload,
  EntityType,
  FichaTecnicaSnapshot,
  HealthOverviewResponse,
  OperationalAlert,
  SeedDemoResponse,
  SimulateOutagePayload,
  SmbScanRequest,
  SocHealthDashboardResponse,
  SourceType,
  Tenant,
  TenantCreatePayload,
  TenantUpdatePayload,
  TransferCreatePayload,
} from '../types';

export const API_TOKEN_STORAGE_KEY = 'vektor81_api_token';
export const COLLECTOR_TOKEN_STORAGE_KEY = 'vektor81_collector_token';

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(status: number, message: string, code = 'API_ERROR', details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

export function getStoredApiToken(): string {
  try {
    return window.sessionStorage.getItem(API_TOKEN_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setStoredApiToken(token: string): void {
  try {
    const trimmed = token.trim();
    if (trimmed) {
      window.sessionStorage.setItem(API_TOKEN_STORAGE_KEY, trimmed);
    } else {
      window.sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage access errors in restricted environments
  }
}

export function clearStoredApiToken(): void {
  try {
    window.sessionStorage.removeItem(API_TOKEN_STORAGE_KEY);
  } catch {
    // Ignore
  }
}

export function getStoredCollectorToken(): string {
  try {
    return window.sessionStorage.getItem(COLLECTOR_TOKEN_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setStoredCollectorToken(token: string): void {
  try {
    const trimmed = token.trim();
    if (trimmed) {
      window.sessionStorage.setItem(COLLECTOR_TOKEN_STORAGE_KEY, trimmed);
    } else {
      window.sessionStorage.removeItem(COLLECTOR_TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore
  }
}

export function clearStoredCollectorToken(): void {
  try {
    window.sessionStorage.removeItem(COLLECTOR_TOKEN_STORAGE_KEY);
  } catch {
    // Ignore
  }
}

async function parseErrorResponse(res: Response): Promise<ApiError> {
  let message = `HTTP ${res.status} ${res.statusText}`;
  let code = 'HTTP_ERROR';
  let body: unknown = undefined;

  try {
    const text = await res.text();
    if (text) {
      try {
        const json = JSON.parse(text) as { message?: string; detail?: string; error?: string };
        body = json;
        message = json.message || json.detail || json.error || message;
        code = json.error || code;
      } catch {
        message = text;
      }
    }
  } catch {
    // Keep default message
  }

  return new ApiError(res.status, message, code, body);
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  tenantId?: string | null;
  skipAuthCheck?: boolean;
  isCollectorApi?: boolean;
}

async function requestJson<T>(url: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};

  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (opts.isCollectorApi) {
    const collectorToken = getStoredCollectorToken();
    const apiToken = getStoredApiToken();
    const bearer = collectorToken || apiToken;
    if (bearer) {
      headers.Authorization = `Bearer ${bearer}`;
    }
  } else {
    const token = getStoredApiToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  if (opts.tenantId) {
    headers['X-Tenant-Id'] = opts.tenantId;
  }

  const res = await fetch(url, {
    method: opts.method ?? 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (!res.ok) {
    const err = await parseErrorResponse(res);
    if (res.status === 401 && !opts.skipAuthCheck && !opts.isCollectorApi && unauthorizedHandler) {
      unauthorizedHandler();
    }
    throw err;
  }

  return (await res.json()) as T;
}

async function requestBlobDownload(
  url: string,
  defaultFilename: string,
  opts: { tenantId?: string | null; openInNewTab?: boolean; isCollectorApi?: boolean } = {}
): Promise<void> {
  const headers: Record<string, string> = {};
  if (opts.isCollectorApi) {
    const collectorToken = getStoredCollectorToken();
    const bearer = collectorToken || getStoredApiToken();
    if (bearer) {
      headers.Authorization = `Bearer ${bearer}`;
    }
  } else {
    const token = getStoredApiToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  if (opts.tenantId) {
    headers['X-Tenant-Id'] = opts.tenantId;
  }

  const res = await fetch(url, { method: 'GET', headers });
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }

  const contentType = res.headers.get('content-type') ?? '';
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const isHtmlFallback =
    contentType.includes('text/html') && defaultFilename.toLowerCase().endsWith('.pdf');

  if (opts.openInNewTab || isHtmlFallback) {
    window.open(objectUrl, '_blank', 'noopener,noreferrer');
  } else {
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = defaultFilename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000);
}

export const apiClient = {
  // -------------------------------------------------------------------------
  // Control Plane (/api/v2/*)
  // -------------------------------------------------------------------------
  ping(): Promise<{
    ok: boolean;
    service: string;
    version: string;
    environment: string;
    timestamp: string;
  }> {
    return requestJson('/api/v2/health/ping', { skipAuthCheck: true });
  },

  getHealthOverview(tenantId?: string | null): Promise<HealthOverviewResponse> {
    return requestJson('/api/v2/health/overview', { tenantId });
  },

  getSocHealthDashboard(tenantId?: string | null): Promise<SocHealthDashboardResponse> {
    return requestJson('/api/v2/dashboard/soc-health', { tenantId });
  },

  getCisoDashboard(tenantId: string): Promise<CisoDashboardResponse> {
    return requestJson('/api/v2/dashboard/ciso', { tenantId });
  },

  getDpoDashboard(tenantId: string): Promise<DpoDashboardResponse> {
    return requestJson('/api/v2/dashboard/dpo', { tenantId });
  },

  getAssetsDashboard(
    tenantId: string,
    filters?: {
      source_type?: SourceType | '';
      entity_type?: EntityType | '';
      severity?: AlertSeverity | '';
    }
  ): Promise<AssetsDashboardResponse> {
    const params = new URLSearchParams();
    if (filters?.source_type) params.set('source_type', filters.source_type);
    if (filters?.entity_type) params.set('entity_type', filters.entity_type);
    if (filters?.severity) params.set('severity', filters.severity);
    const qs = params.toString();
    return requestJson(`/api/v2/dashboard/assets${qs ? `?${qs}` : ''}`, { tenantId });
  },

  getTenants(): Promise<{ tenants: Tenant[] }> {
    return requestJson('/api/v2/tenants');
  },

  createTenant(payload: TenantCreatePayload): Promise<{ ok: boolean; tenant: Tenant }> {
    return requestJson('/api/v2/tenants', { method: 'POST', body: payload });
  },

  updateTenant(
    tenantId: string,
    payload: TenantUpdatePayload
  ): Promise<{ ok: boolean; tenant: Tenant }> {
    return requestJson(`/api/v2/tenants/${encodeURIComponent(tenantId)}`, {
      method: 'PATCH',
      body: payload,
      tenantId,
    });
  },

  ackAlert(
    alertId: string,
    tenantId?: string | null
  ): Promise<{ ok: boolean; alert: OperationalAlert }> {
    return requestJson(`/api/v2/health/alerts/${encodeURIComponent(alertId)}/ack`, {
      method: 'POST',
      tenantId,
    });
  },

  resolveAlert(
    alertId: string,
    tenantId?: string | null
  ): Promise<{ ok: boolean; alert: OperationalAlert }> {
    return requestJson(`/api/v2/health/alerts/${encodeURIComponent(alertId)}/resolve`, {
      method: 'POST',
      tenantId,
    });
  },

  simulateOutage(payload: SimulateOutagePayload): Promise<{
    ok: boolean;
    component: unknown;
    sync: unknown;
    alerts: OperationalAlert[];
  }> {
    return requestJson('/api/v2/health/simulate-outage', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
    });
  },

  createDsar(payload: DsarCreatePayload): Promise<{ ok: boolean; dsar: DsarRequest }> {
    return requestJson('/api/v2/compliance/dsar', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
    });
  },

  updateDsar(
    dsarId: string,
    payload: DsarUpdatePayload,
    tenantId?: string | null
  ): Promise<{ ok: boolean; dsar: DsarRequest }> {
    return requestJson(`/api/v2/compliance/dsar/${encodeURIComponent(dsarId)}`, {
      method: 'PATCH',
      body: payload,
      tenantId,
    });
  },

  exportDsar(dsarId: string, tenantId?: string | null): Promise<Record<string, unknown>> {
    return requestJson(`/api/v2/compliance/dsar/${encodeURIComponent(dsarId)}/export`, {
      tenantId,
    });
  },

  createBreach(payload: BreachCreatePayload): Promise<{ ok: boolean; breach: BreachIncident }> {
    return requestJson('/api/v2/compliance/breaches', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
    });
  },

  updateBreach(
    breachId: string,
    payload: BreachUpdatePayload,
    tenantId?: string | null
  ): Promise<{ ok: boolean; breach: BreachIncident }> {
    return requestJson(`/api/v2/compliance/breaches/${encodeURIComponent(breachId)}`, {
      method: 'PATCH',
      body: payload,
      tenantId,
    });
  },

  getBreachAntaiDraft(
    breachId: string,
    tenantId?: string | null
  ): Promise<AntaiBreachDraftResponse> {
    return requestJson(`/api/v2/compliance/breaches/${encodeURIComponent(breachId)}/antai-draft`, {
      tenantId,
    });
  },

  createTransfer(payload: TransferCreatePayload): Promise<{ ok: boolean; transfer: DataTransfer }> {
    return requestJson('/api/v2/compliance/transfers', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
    });
  },

  generateFichaTecnica(
    tenantId?: string,
    generatedBy?: string
  ): Promise<{
    ok: boolean;
    snapshot: FichaTecnicaSnapshot;
    sha256_hash: string;
    r2_object_key: string;
    document: Record<string, unknown>;
  }> {
    return requestJson('/api/v2/compliance/ficha-tecnica/generate', {
      method: 'POST',
      body: { tenant_id: tenantId, generated_by: generatedBy },
      tenantId,
    });
  },

  getFichaTecnicas(
    tenantId: string,
    opts?: { snapshotId?: string; includeLatest?: boolean }
  ): Promise<{
    tenant_id: string;
    snapshots: FichaTecnicaSnapshot[];
    selected_snapshot: FichaTecnicaSnapshot | null;
    integrity_verified: boolean | null;
    document: Record<string, unknown> | null;
  }> {
    const params = new URLSearchParams();
    if (opts?.snapshotId) params.set('snapshot_id', opts.snapshotId);
    if (opts?.includeLatest) params.set('include_latest', 'true');
    const qs = params.toString();
    return requestJson(`/api/v2/compliance/ficha-tecnica${qs ? `?${qs}` : ''}`, {
      tenantId,
    });
  },

  seedDemo(): Promise<SeedDemoResponse> {
    return requestJson('/api/v2/admin/seed-demo', { method: 'POST' });
  },

  // -------------------------------------------------------------------------
  // On-Premise Collector (/api/v1/*)
  // -------------------------------------------------------------------------
  scanSmb(payload: SmbScanRequest): Promise<Record<string, unknown>> {
    return requestJson('/api/v1/scan-smb', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
      isCollectorApi: true,
    });
  },

  scanDb(payload: DbScanRequest): Promise<Record<string, unknown>> {
    return requestJson('/api/v1/scan-db', {
      method: 'POST',
      body: payload,
      tenantId: payload.tenant_id,
      isCollectorApi: true,
    });
  },

  getDnsStats(limit = 500, tenantId?: string | null): Promise<DnsStatsResponse> {
    return requestJson(`/api/v1/dns-stats?limit=${encodeURIComponent(String(limit))}`, {
      tenantId,
      isCollectorApi: true,
    });
  },

  downloadPdfReport(format: 'pdf' | 'html' = 'pdf', tenantId?: string | null): Promise<void> {
    const url = format === 'html' ? '/api/v1/report/pdf?format=html' : '/api/v1/report/pdf';
    return requestBlobDownload(url, `Informe_Ejecutivo_Ley81_${tenantId ?? 'vektor81'}.pdf`, {
      tenantId,
      openInNewTab: format === 'html',
      isCollectorApi: true,
    });
  },

  downloadPowershellAgent(tenantId?: string | null): Promise<void> {
    return requestBlobDownload('/api/v1/agent/powershell', 'Vektor81-EndpointCollector.ps1', {
      tenantId,
      openInNewTab: false,
      isCollectorApi: true,
    });
  },
};
