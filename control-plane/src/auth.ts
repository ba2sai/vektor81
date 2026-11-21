import type { Context, Next } from 'hono';
import type { ApiTokenRow, AppVariables, AuthContext, Env, UserRole } from './types';

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function timingSafeEqualString(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  const maxLen = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;
  for (let i = 0; i < maxLen; i += 1) {
    const ba = i < aBytes.length ? aBytes[i] : 0;
    const bb = i < bBytes.length ? bBytes[i] : 0;
    diff |= ba ^ bb;
  }
  return diff === 0;
}

export function parseAllowedOrigins(raw?: string): string[] {
  if (!raw) {
    return ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost'];
  }
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && s !== '*');
}

export function corsMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: AppVariables }>, next: Next) => {
    const origin = c.req.header('Origin');
    const allowed = parseAllowedOrigins(c.env?.ALLOWED_ORIGINS);
    const isAllowed = Boolean(origin && allowed.includes(origin));

    if (c.req.method === 'OPTIONS') {
      const headers: Record<string, string> = {
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-Id',
        'Access-Control-Max-Age': '86400',
        Vary: 'Origin',
      };
      if (isAllowed && origin) {
        headers['Access-Control-Allow-Origin'] = origin;
        headers['Access-Control-Allow-Credentials'] = 'true';
      }
      return new Response(null, { status: 204, headers });
    }

    await next();

    c.header('Vary', 'Origin', { append: true });
    if (isAllowed && origin) {
      c.header('Access-Control-Allow-Origin', origin);
      c.header('Access-Control-Allow-Credentials', 'true');
      c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
      c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Tenant-Id');
    }
  };
}

function isDevMode(env: Env): boolean {
  const mode = (env.ENVIRONMENT ?? env.CONTROL_PLANE_ENV ?? '').toLowerCase();
  return mode !== 'production';
}

export function authMiddleware() {
  return async (c: Context<{ Bindings: Env; Variables: AppVariables }>, next: Next) => {
    // Public health ping endpoint
    if (c.req.method === 'GET' && c.req.path === '/api/v2/health/ping') {
      return next();
    }

    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized', message: 'Missing or invalid Bearer token' }, 401);
    }

    const token = authHeader.slice('Bearer '.length).trim();
    if (!token) {
      return c.json({ error: 'Unauthorized', message: 'Empty Bearer token' }, 401);
    }

    let authCtx: AuthContext | null = null;

    // 1. Check configured production/secret API key if provided
    if (c.env.VEKTOR81_API_KEY && timingSafeEqualString(token, c.env.VEKTOR81_API_KEY)) {
      authCtx = {
        tokenId: 'env-api-key',
        tenantId: null,
        role: 'MSSP_ADMIN',
        label: 'Environment API Key',
        isDevKey: false,
      };
    }

    // 2. Check development API key ONLY when not in production
    if (
      !authCtx &&
      isDevMode(c.env) &&
      c.env.VEKTOR81_DEV_API_KEY &&
      timingSafeEqualString(token, c.env.VEKTOR81_DEV_API_KEY)
    ) {
      authCtx = {
        tokenId: 'dev-api-key',
        tenantId: null,
        role: 'MSSP_ADMIN',
        label: 'Local Dev Key',
        isDevKey: true,
      };
    }

    // 3. Verify SHA-256 hash against D1 api_tokens table
    if (!authCtx) {
      const tokenHash = await sha256Hex(token);
      const row = await c.env.DB.prepare(
        'SELECT id, tenant_id, token_sha256, role, label, active, created_at FROM api_tokens WHERE token_sha256 = ? AND active = 1 LIMIT 1'
      )
        .bind(tokenHash)
        .first<ApiTokenRow>();

      if (row && timingSafeEqualString(row.token_sha256, tokenHash)) {
        authCtx = {
          tokenId: row.id,
          tenantId: row.tenant_id ?? null,
          role: row.role,
          label: row.label,
          isDevKey: false,
        };
      }
    }

    if (!authCtx) {
      return c.json({ error: 'Unauthorized', message: 'Invalid or inactive API token' }, 401);
    }

    const headerTenant = c.req.header('X-Tenant-Id')?.trim() || null;
    const queryTenant = c.req.query('tenant_id')?.trim() || null;

    if (headerTenant && queryTenant && headerTenant !== queryTenant) {
      return c.json(
        {
          error: 'Bad Request',
          message: 'Conflicting tenant_id between X-Tenant-Id header and query parameter',
        },
        400
      );
    }

    const requestedTenant = headerTenant ?? queryTenant;

    if (authCtx.tenantId !== null && requestedTenant !== null && requestedTenant !== authCtx.tenantId) {
      return c.json(
        {
          error: 'Forbidden',
          message: 'Cross-tenant access denied for tenant-scoped token',
        },
        403
      );
    }

    c.set('auth', authCtx);
    c.set('resolvedTenantId', authCtx.tenantId ?? requestedTenant);

    return next();
  };
}

export function requireRoles(...allowedRoles: UserRole[]) {
  return async (c: Context<{ Bindings: Env; Variables: AppVariables }>, next: Next) => {
    const auth = c.get('auth');
    if (!auth || !allowedRoles.includes(auth.role)) {
      return c.json(
        {
          error: 'Forbidden',
          message: `Role ${auth?.role ?? 'UNKNOWN'} lacks permission for this endpoint`,
        },
        403
      );
    }
    return next();
  };
}

/**
 * Validates that a payload's `tenant_id` matches the authenticated token scope
 * and any explicit `X-Tenant-Id` / `?tenant_id=` request scope.
 */
export function verifyPayloadTenantAccess(
  c: Context<{ Bindings: Env; Variables: AppVariables }>,
  payloadTenantId: string
): Response | null {
  const auth = c.get('auth');
  const resolvedTenant = c.get('resolvedTenantId');

  if (auth.tenantId !== null && payloadTenantId !== auth.tenantId) {
    return c.json(
      {
        error: 'Forbidden',
        message: 'Cross-tenant payload rejected for tenant-scoped token',
      },
      403
    );
  }

  if (resolvedTenant !== null && payloadTenantId !== resolvedTenant) {
    return c.json(
      {
        error: 'Forbidden',
        message: 'Payload tenant_id does not match X-Tenant-Id / tenant_id scope',
      },
      403
    );
  }

  return null;
}
