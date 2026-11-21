import type {
  AlertSeverity,
  AlertStatus,
  ComponentLayer,
  ComponentStatus,
  EntityType,
  RegulatoryProfile,
  SourceType,
} from '../types';

export const LAYER_LABELS: Record<ComponentLayer, string> = {
  CONTROL_PLANE: 'Control Plane (CF Workers)',
  TUNNEL: 'Cloudflare Tunnel',
  ONPREM_COLLECTOR: 'On-Premise Collector',
  ADGUARD_DNS: 'AdGuard DNS Sensor',
  ENDPOINT_AGENT: 'Endpoint Fleet Agents',
  DB_CONNECTOR: 'SQL DB Connector',
  SMB_CONNECTOR: 'SMB File Server Connector',
  WAZUH_FIM: 'Wazuh FIM Monitor',
  CLOUDFLARE_DLP: 'Cloudflare Edge DLP',
  CLOUDFLARE_CASB: 'Cloudflare CASB',
  LOGPUSH: 'Cloudflare Logpush → R2',
};

export const ALL_LAYERS_ORDER: ComponentLayer[] = [
  'CONTROL_PLANE',
  'TUNNEL',
  'ONPREM_COLLECTOR',
  'ADGUARD_DNS',
  'ENDPOINT_AGENT',
  'DB_CONNECTOR',
  'SMB_CONNECTOR',
  'WAZUH_FIM',
  'CLOUDFLARE_DLP',
  'CLOUDFLARE_CASB',
  'LOGPUSH',
];

export const ENTITY_LABELS: Record<EntityType, string> = {
  PA_IDENTIDAD_NATURAL: 'Cédula Panamá',
  PA_PASAPORTE: 'Pasaporte PA',
  PA_DATO_SENSIBLE_SALUD: 'Dato Sensible Salud',
  PA_TARJETA_PAGO: 'Tarjeta Pago (PAN)',
  PA_SWIFT_PA: 'Código SWIFT PA',
  EMAIL_PERSONAL: 'Email Personal',
};

export const SOURCE_LABELS: Record<SourceType, string> = {
  SMB: 'SMB',
  SQL_DB: 'SQL_DB',
  OCR_IMAGE: 'OCR_IMAGE',
  CASB: 'CASB',
  DLP_EDGE: 'DLP_EDGE',
};

export const PROFILE_META: Record<
  RegulatoryProfile,
  { label: string; shortLabel: string; badgeClass: string }
> = {
  ANTAI_LEY81: {
    label: 'ANTAI · Ley 81 / DE 285',
    shortLabel: 'ANTAI_LEY81',
    badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  },
  SBP_001_2022: {
    label: 'SBP Acuerdo 001-2022 + Ley 81',
    shortLabel: 'SBP_001_2022',
    badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/40',
  },
  SALUD_LEY68: {
    label: 'MINSA / Ley 68 (20a) + Ley 81',
    shortLabel: 'SALUD_LEY68',
    badgeClass: 'bg-teal-500/15 text-teal-300 border-teal-500/40',
  },
};

export type BadgeVariant = 'default' | 'destructive' | 'warning' | 'success' | 'outline' | 'purple';

export function statusBadgeVariant(status: ComponentStatus | string): BadgeVariant {
  switch (status) {
    case 'ONLINE':
      return 'success';
    case 'DEGRADED':
      return 'warning';
    case 'STALE':
      return 'purple';
    case 'OFFLINE':
      return 'destructive';
    default:
      return 'outline';
  }
}

export function severityBadgeVariant(severity: AlertSeverity | string): BadgeVariant {
  switch (severity) {
    case 'CRITICAL':
      return 'destructive';
    case 'HIGH':
      return 'warning';
    case 'MEDIUM':
      return 'default';
    case 'LOW':
    default:
      return 'outline';
  }
}

export function alertStatusBadgeVariant(status: AlertStatus | string): BadgeVariant {
  switch (status) {
    case 'OPEN':
      return 'destructive';
    case 'ACKNOWLEDGED':
      return 'warning';
    case 'RESOLVED':
      return 'success';
    default:
      return 'outline';
  }
}

export function formatRelativeTime(isoDate: string | null | undefined, nowMs = Date.now()): string {
  if (!isoDate) return 'Sin registro';
  const ts = Date.parse(isoDate);
  if (!Number.isFinite(ts)) return isoDate;
  const diffSec = Math.max(0, Math.floor((nowMs - ts) / 1000));
  if (diffSec < 60) return `hace ${diffSec}s`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `hace ${diffMin}m`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `hace ${diffHours}h`;
  const diffDays = Math.floor(diffHours / 24);
  return `hace ${diffDays}d`;
}

export function formatDateTime(isoDate: string | null | undefined): string {
  if (!isoDate) return '—';
  const d = new Date(isoDate);
  if (Number.isNaN(d.getTime())) return isoDate;
  return d.toLocaleString('es-PA', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatBreachCountdown(
  deadlineIso: string,
  status: string,
  fallbackHoursRemaining: number,
  nowMs = Date.now()
): { text: string; isOverdue: boolean; isNotified: boolean } {
  if (status === 'NOTIFIED_ANTAI' || status === 'CLOSED') {
    return {
      text: status === 'NOTIFIED_ANTAI' ? 'Notificado a ANTAI' : 'Incidente Cerrado',
      isOverdue: false,
      isNotified: true,
    };
  }
  const deadlineMs = Date.parse(deadlineIso);
  const diffMs = Number.isFinite(deadlineMs)
    ? deadlineMs - nowMs
    : fallbackHoursRemaining * 3600_000;
  const totalMinutes = Math.round(Math.abs(diffMs) / 60_000);
  const hours = Math.floor(totalMinutes / 60);
  const mins = totalMinutes % 60;

  if (diffMs < 0) {
    return {
      text: `VENCIDO (+${hours}h ${mins}m)`,
      isOverdue: true,
      isNotified: false,
    };
  }
  return {
    text: `${hours}h ${mins}m restantes`,
    isOverdue: false,
    isNotified: false,
  };
}

export function downloadJsonFile(filename: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 5000);
}
