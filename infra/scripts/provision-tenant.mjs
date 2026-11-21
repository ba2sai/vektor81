#!/usr/bin/env node
/**
 * Vektor81 Cloudflare Partner/MSSP Tenant Provisioner (Pure Node ESM, Zero External Deps)
 *
 * Implements Cloudflare Organizations / Tenant API siloed account provisioning:
 *   1. POST /accounts                       -> Create isolated client Cloudflare account
 *   2. POST /accounts/{id}/subscriptions    -> Attach Zero Trust / DLP / CASB / Logpush MSSP plan
 *   3. POST /accounts/{id}/d1/database      -> Provision isolated per-tenant SQLite D1 database
 *   4. Generate Terraform v5 *.tfvars.json  -> Ready for infra/terraform/environments/example-tenant
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const VALID_PROFILES = Object.freeze({
  ANTAI_LEY81: {
    legal_framework: "Ley 81 de 2019 & Decreto Ejecutivo No. 285 de 2021 (Regimen General ANTAI)",
    dsar_access_business_days: 10,
    dsar_rectify_cancel_block_business_days: 5,
    breach_notification_hours: 72,
    retention_rule: "max_7_years_post_obligation",
    dlp_masking_level: "partial",
  },
  SBP_001_2022: {
    legal_framework: "Acuerdo No. 001-2022 de la Superintendencia de Bancos de Panama (SBP)",
    dsar_access_business_days: 10,
    dsar_rectify_cancel_block_business_days: 5,
    breach_notification_hours: 72,
    retention_rule: "max_7_years_post_obligation_plus_sbp_board_oversight",
    dlp_masking_level: "full",
  },
  SALUD_LEY68: {
    legal_framework: "Ley 68 de 2003 (Expediente Clinico Electronico) & Ley 81 Art. 4",
    dsar_access_business_days: 10,
    dsar_rectify_cancel_block_business_days: 5,
    breach_notification_hours: 72,
    retention_rule: "min_20_years_post_mortem_with_user_timestamp_audit",
    dlp_masking_level: "full",
  },
});

const VALID_REGIONS = new Set(["us", "fedramp", "eu", "global"]);

const D1_LOCATION_HINT_BY_REGION = Object.freeze({
  us: "enam",
  fedramp: "enam",
  eu: "weur",
  global: "enam",
});

function printUsage() {
  console.log(`Usage:
  node infra/scripts/provision-tenant.mjs [options]

Required options:
  --name <string>          Display / legal name of the Panamanian enterprise tenant
  --tenant-id <slug>       Lowercase slug identifier (e.g. banco-istmo)
  --profile <enum>         ANTAI_LEY81 | SBP_001_2022 | SALUD_LEY68

Optional flags:
  --dry-run                Print exact Cloudflare REST payloads and tfvars JSON without calling API
  --region <enum>          us | fedramp | eu | global (default: us)
  --control-plane-url <u>  Control plane CASB webhook URL
  --r2-bucket <name>       R2 bucket name for Logpush forensic vault (default: vektor81-forensic-vault)
  --org-unit-id <id>       Cloudflare Organizations MSSP sub-unit ID (optional)
  --out <path>             Write generated tfvars JSON to disk (in live mode or when explicitly passed)
  --help                   Show this help message
`);
}

function parseArgs(argv) {
  const opts = {
    dryRun: false,
    name: "",
    tenantId: "",
    profile: "",
    region: "us",
    controlPlaneUrl: "https://control.vektor81.example.pa/api/v2/ingest/casb-webhook",
    r2Bucket: "vektor81-forensic-vault",
    orgUnitId: process.env.CF_ORG_UNIT_ID || "mssp-panama-unit-01",
    out: "",
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") {
      opts.dryRun = true;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
      continue;
    }

    const eqIdx = arg.indexOf("=");
    const key = eqIdx >= 0 ? arg.slice(0, eqIdx) : arg;
    const readVal = () => {
      if (eqIdx >= 0) return arg.slice(eqIdx + 1);
      if (i + 1 >= argv.length) {
        throw new Error(`Missing value for CLI option ${key}`);
      }
      i += 1;
      return argv[i];
    };

    switch (key) {
      case "--name":
        opts.name = readVal();
        break;
      case "--tenant-id":
        opts.tenantId = readVal();
        break;
      case "--profile":
        opts.profile = readVal();
        break;
      case "--region":
        opts.region = readVal();
        break;
      case "--control-plane-url":
        opts.controlPlaneUrl = readVal();
        break;
      case "--r2-bucket":
        opts.r2Bucket = readVal();
        break;
      case "--org-unit-id":
        opts.orgUnitId = readVal();
        break;
      case "--out":
        opts.out = readVal();
        break;
      default:
        throw new Error(`Unknown CLI option: ${arg}`);
    }
  }

  return opts;
}

function validateOptions(opts) {
  if (!opts.name || !opts.name.trim()) {
    throw new Error("--name is required (e.g. --name \"Banco Istmo\").");
  }
  if (!/^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/.test(opts.tenantId)) {
    throw new Error("--tenant-id must match ^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$ (e.g. banco-istmo).");
  }
  if (!Object.hasOwn(VALID_PROFILES, opts.profile)) {
    throw new Error(
      `Invalid --profile "${opts.profile}". Expected one of: ${Object.keys(VALID_PROFILES).join(", ")}.`
    );
  }
  if (!VALID_REGIONS.has(opts.region)) {
    throw new Error(`Invalid --region "${opts.region}". Expected one of: ${[...VALID_REGIONS].join(", ")}.`);
  }
  if (!/^https?:\/\//.test(opts.controlPlaneUrl)) {
    throw new Error(`--control-plane-url must start with http:// or https://.`);
  }
}

function buildRestFlow(opts, accountIdPlaceholder = "{account_id}") {
  const profileSpec = VALID_PROFILES[opts.profile];
  const d1LocationHint = D1_LOCATION_HINT_BY_REGION[opts.region];

  const createAccountPayload = {
    name: `${opts.name} (${opts.tenantId})`,
    type: "standard",
    unit: {
      id: opts.orgUnitId,
    },
    settings: {
      enforce_twofactor: true,
    },
  };

  const attachSubscriptionPayload = {
    rate_plan: {
      id: "cf_one_enterprise_mssp",
      public_name: "Cloudflare One Contract MSSP (DLP + CASB + Logpush + DLS)",
      currency: "USD",
      scope: "account",
      sets: ["zero_trust_dlp", "zero_trust_casb", "logpush_r2", "data_localization_suite"],
    },
    component_values: [
      { name: "zero_trust_seats", value: 100 },
      { name: "casb_integrations", value: 10 },
      { name: "dlp_custom_entries_quota", value: 25 },
    ],
    frequency: "monthly",
    metadata: {
      tenant_id: opts.tenantId,
      regulatory_profile: opts.profile,
      data_localization_region: opts.region,
      legal_framework: profileSpec.legal_framework,
    },
  };

  const createD1DatabasePayload = {
    name: `vektor81-${opts.tenantId}-db`,
    primary_location_hint: d1LocationHint,
  };

  const baseUrl = "https://api.cloudflare.com/client/v4";

  return {
    createAccount: {
      step: 1,
      description: "Create isolated siloed Cloudflare client account via Tenant API",
      method: "POST",
      url: `${baseUrl}/accounts`,
      body: createAccountPayload,
    },
    attachSubscription: {
      step: 2,
      description: "Attach Cloudflare One Contract/Enterprise MSSP subscription (DLP, CASB, Logpush, DLS)",
      method: "POST",
      url: `${baseUrl}/accounts/${accountIdPlaceholder}/subscriptions`,
      body: attachSubscriptionPayload,
    },
    createD1Database: {
      step: 3,
      description: "Provision isolated per-tenant D1 SQLite database for control plane state",
      method: "POST",
      url: `${baseUrl}/accounts/${accountIdPlaceholder}/d1/database`,
      body: createD1DatabasePayload,
    },
  };
}

function buildTerraformTfvars(opts, accountId) {
  const profileSpec = VALID_PROFILES[opts.profile];
  const r2AccessKey = process.env.VEKTOR81_R2_ACCESS_KEY_ID || "<R2_ACCESS_KEY_ID>";
  const r2SecretKey = process.env.VEKTOR81_R2_SECRET_ACCESS_KEY || "<R2_SECRET_ACCESS_KEY>";
  const customerPubKey =
    process.env.VEKTOR81_CUSTOMER_DLP_PUBLIC_KEY ||
    "<BASE64_CUSTOMER_PUBLIC_KEY_FOR_DLP_PAYLOAD_ENCRYPTION>";
  const webhookSecret = opts.dryRun
    ? "<CF_WEBHOOK_AUTH_SECRET>"
    : process.env.VEKTOR81_WEBHOOK_SECRET || randomBytes(24).toString("hex");

  return {
    account_id: accountId,
    tenant_id: opts.tenantId,
    tenant_name: opts.name,
    regulatory_profile: opts.profile,
    validation_worker_name: "vektor81-dlp-validator",
    control_plane_webhook_url: opts.controlPlaneUrl,
    webhook_secret: webhookSecret,
    customer_dlp_public_key: customerPubKey,
    dlp_payload_masking_level: profileSpec.dlp_masking_level,
    r2_logpush_destination_conf: `r2://${opts.r2Bucket}/tenants/${opts.tenantId}?account-id=${accountId}&access-key-id=${r2AccessKey}&secret-access-key=${r2SecretKey}`,
    tunnel_name: `vektor81-collector-${opts.tenantId}`,
    data_localization_region: opts.region,
    ai_gateway_id: `vektor81-ai-gateway-${opts.tenantId}`,
    enable_logpush: true,
    casb_google_workspace_enabled: false,
    casb_box_enabled: false,
  };
}

function buildControlPlaneMetadata(opts, d1DatabaseId) {
  return {
    d1_database_id: d1DatabaseId,
    d1_database_name: `vektor81-${opts.tenantId}-db`,
    sla_rules: VALID_PROFILES[opts.profile],
  };
}

async function cfRequest(method, url, token, body) {
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success === false) {
    const errText = JSON.stringify(payload.errors || payload, null, 2);
    throw new Error(`Cloudflare API ${method} ${url} failed (HTTP ${response.status}): ${errText}`);
  }
  return payload.result;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printUsage();
    return;
  }

  validateOptions(opts);
  const profileSpec = VALID_PROFILES[opts.profile];

  if (opts.dryRun) {
    const simulatedAccountId = "00000000000000000000000000000000";
    const simulatedD1Id = "00000000-0000-4000-8000-000000000000";
    const restFlow = buildRestFlow(opts, "{account_id}");
    const tfvars = buildTerraformTfvars(opts, simulatedAccountId);
    const controlPlaneMetadata = buildControlPlaneMetadata(opts, simulatedD1Id);

    const output = {
      mode: "DRY_RUN",
      tenant: {
        name: opts.name,
        tenant_id: opts.tenantId,
        regulatory_profile: opts.profile,
        data_localization_region: opts.region,
        sla_rules: profileSpec,
      },
      cloudflare_tenant_api_requests: [
        {
          ...restFlow.createAccount,
          headers: {
            Authorization: "Bearer <CLOUDFLARE_API_TOKEN>",
            "Content-Type": "application/json",
          },
        },
        {
          ...restFlow.attachSubscription,
          headers: {
            Authorization: "Bearer <CLOUDFLARE_API_TOKEN>",
            "Content-Type": "application/json",
          },
        },
        {
          ...restFlow.createD1Database,
          headers: {
            Authorization: "Bearer <CLOUDFLARE_API_TOKEN>",
            "Content-Type": "application/json",
          },
        },
      ],
      control_plane_metadata: controlPlaneMetadata,
      generated_tfvars_json: tfvars,
    };

    if (opts.out) {
      const outPath = resolve(opts.out);
      await mkdir(dirname(outPath), { recursive: true });
      await writeFile(outPath, `${JSON.stringify(tfvars, null, 2)}\n`, "utf8");
      output.written_tfvars_path = outPath;
    }

    console.log(JSON.stringify(output, null, 2));
    return;
  }

  const apiToken = process.env.CLOUDFLARE_API_TOKEN;
  if (!apiToken) {
    throw new Error(
      "CLOUDFLARE_API_TOKEN environment variable is required when running without --dry-run."
    );
  }

  const initialFlow = buildRestFlow(opts, "{account_id}");
  console.error(`[1/3] Creating siloed Cloudflare account for "${opts.name}" (${opts.tenantId})...`);
  const accountResult = await cfRequest(
    initialFlow.createAccount.method,
    initialFlow.createAccount.url,
    apiToken,
    initialFlow.createAccount.body
  );
  const accountId = accountResult?.id;
  if (!accountId) {
    throw new Error("POST /accounts succeeded but did not return result.id");
  }

  const boundFlow = buildRestFlow(opts, accountId);
  console.error(`[2/3] Attaching Cloudflare One MSSP subscription to account ${accountId}...`);
  const subscriptionResult = await cfRequest(
    boundFlow.attachSubscription.method,
    boundFlow.attachSubscription.url,
    apiToken,
    boundFlow.attachSubscription.body
  );

  console.error(`[3/3] Creating isolated D1 database "vektor81-${opts.tenantId}-db"...`);
  const d1Result = await cfRequest(
    boundFlow.createD1Database.method,
    boundFlow.createD1Database.url,
    apiToken,
    boundFlow.createD1Database.body
  );
  const d1DatabaseId = d1Result?.uuid || d1Result?.id || "pending-d1-id";

  const tfvars = buildTerraformTfvars(opts, accountId);
  const controlPlaneMetadata = buildControlPlaneMetadata(opts, d1DatabaseId);
  const outPath = resolve(opts.out || `infra/terraform/environments/${opts.tenantId}.auto.tfvars.json`);
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${JSON.stringify(tfvars, null, 2)}\n`, "utf8");

  console.log(
    JSON.stringify(
      {
        mode: "LIVE",
        account_id: accountId,
        subscription_id: subscriptionResult?.id || null,
        control_plane_metadata: controlPlaneMetadata,
        written_tfvars_path: outPath,
        next_step: `Deploy validation worker "${tfvars.validation_worker_name}" to account ${accountId}, then run terraform apply -var-file="${outPath}"`,
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error(`ERROR: ${err.message}`);
  process.exit(1);
});
